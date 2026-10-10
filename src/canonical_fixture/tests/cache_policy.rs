//! Two-policy invariants and storage evidence. Neither policy changes bytes/schema/checks/sync.
use super::*;

const POLICIES: [CachePolicy; 2] = [CachePolicy::ExistingDefault, CachePolicy::Trial32MiB];
fn create(p: &Path, m: &FixtureManifest, policy: CachePolicy) -> CanonicalFixtureStore {
    CanonicalFixtureStore::create_anchored_fixture_with_cache_policy(p, m, policy).unwrap()
}
fn check_policy(s: &CanonicalFixtureStore, policy: CachePolicy) {
    assert_eq!(s.cache_policy().unwrap(), policy);
    let settings = s.settings().unwrap();
    assert_eq!(settings.cache_size, policy.pragma_value());
    assert_eq!(settings.journal_mode, "delete");
    assert_eq!(settings.synchronous, 3);
    assert!(settings.foreign_keys);
    let spill: i64 = s
        .conn()
        .query_row("PRAGMA cache_spill", [], |r| r.get(0))
        .unwrap();
    assert!(spill > 0);
}

#[test]
fn default_preserved_and_trial_verified_on_every_connection() {
    let d = TempDir::new().unwrap();
    let m = manifest(4);
    let path = d.path().join("same-format.db");
    let default = CanonicalFixtureStore::create_anchored_fixture(&path, &m).unwrap();
    check_policy(&default, CachePolicy::ExistingDefault);
    drop(default);
    // Policy is a caller-selected memory resource, not schema data. Both APIs can safely load the
    // exact same archive under different budgets; no upgrade/reseeding or new byte format occurs.
    let mut trial =
        CanonicalFixtureStore::reopen_with_cache_policy(&path, &m, CachePolicy::Trial32MiB)
            .unwrap();
    check_policy(&trial, CachePolicy::Trial32MiB);
    append(&mut trial, &vector("sequential"));
    trial.recover().unwrap();
    check_policy(&trial, CachePolicy::Trial32MiB);
    let expected = trial.snapshot().unwrap().clone();
    drop(trial);
    let ordinary = CanonicalFixtureStore::reopen(&path, &m).unwrap();
    check_policy(&ordinary, CachePolicy::ExistingDefault);
    assert_eq!(ordinary.snapshot().unwrap(), &expected);
    drop(ordinary);
    for policy in POLICIES {
        let mut s =
            CanonicalFixtureStore::recover_existing_with_cache_policy(&path, &m, policy).unwrap();
        check_policy(&s, policy);
        s.recover().unwrap();
        check_policy(&s, policy);
        assert_eq!(s.snapshot().unwrap(), &expected);
    }
    let one = d.path().join("schema1.db");
    let schema1 =
        disk::FixtureStore::create_fixture(&one, context(), m.initial.clone(), "schema1 preserved")
            .unwrap();
    assert_eq!(schema1.settings().unwrap().cache_size, -2000);
    drop(schema1);
    for policy in POLICIES {
        assert!(CanonicalFixtureStore::reopen_with_cache_policy(&one, &m, policy).is_err());
    }
}

#[test]
fn both_budgets_equivalent_validation_staleness_and_atomic_recovery() {
    let d = TempDir::new().unwrap();
    let m = manifest(4);
    let mut final_states = Vec::new();
    for policy in POLICIES {
        let path = d.path().join(format!("{policy:?}.db"));
        let mut s = create(&path, &m, policy);
        check_policy(&s, policy);
        let base = s.snapshot().unwrap().tip;
        let mut wrong = vector("single").header().clone();
        wrong.parent_hash = [0; 32];
        let wrong = NativeBlock::from_parts(
            wrong,
            "offline-validator".into(),
            vector("single").protocol_data().clone(),
            vector("single").transactions().to_vec(),
        )
        .unwrap();
        assert!(matches!(
            s.stage_received(&wrong.wire_bytes(), grant(base, &wrong)),
            Err(Error::Parent)
        ));
        let bad_nonce = transfer(1, 1, [0x22; 20], 0);
        let mut bad_sig = transfer(0, 1, [0x22; 20], 0);
        bad_sig[198] = 2;
        let bad = untrusted_body(base, vec![bad_nonce, bad_sig], 0, 0);
        phase_evidence::reset();
        assert!(matches!(
            s.stage_received(&bad.wire_bytes(), grant(base, &bad)),
            Err(Error::Body(BodyError {
                transaction_index: 1,
                ..
            }))
        ));
        assert_eq!(phase_evidence::counts(), (2, 0));
        let duplicate = transfer(0, 1, [0x22; 20], 0);
        let bad = untrusted_body(base, vec![duplicate.clone(), duplicate], 2000, 20000);
        assert!(matches!(
            s.stage_received(&bad.wire_bytes(), grant(base, &bad)),
            Err(Error::Body(BodyError {
                transaction_index: 1,
                cause: TransferError::NonceMismatch { .. }
            }))
        ));
        let stale = stage_next(&s, &[]);
        append(&mut s, &vector("sequential"));
        assert!(matches!(
            s.commit(stale),
            AppendOutcome::Aborted(Error::Stale)
        ));
        assert!(matches!(
            s.stage_received(
                &vector("sequential").wire_bytes(),
                grant(base, &vector("sequential"))
            ),
            Err(Error::AlreadyCommitted(_))
        ));
        let replay = untrusted_body(
            s.snapshot().unwrap().tip,
            vec![transfer(0, 2, [0x22; 20], 0)],
            1000,
            10000,
        );
        assert!(matches!(
            s.stage_received(
                &replay.wire_bytes(),
                grant(s.snapshot().unwrap().tip, &replay)
            ),
            Err(Error::Body(BodyError {
                cause: TransferError::NonceMismatch { .. },
                ..
            }))
        ));
        for p in [
            "accounts",
            "accounting",
            "block",
            "body",
            "indexes",
            "revision",
            "tip",
            "before_commit",
        ] {
            let old = s.snapshot().unwrap().clone();
            let st = stage_next(&s, &[]);
            s.hook = Some(hook_at(p));
            assert!(matches!(s.commit(st), AppendOutcome::Aborted(_)));
            assert_eq!(s.snapshot().unwrap(), &old);
            s.hook = None;
        }
        let old_overlay = stage_next(&s, &[]);
        let st = stage_next(&s, &[]);
        s.hook = Some(hook_at("after_commit"));
        assert!(matches!(s.commit(st), AppendOutcome::RecoveryRequired(_)));
        assert!(!s.is_ready());
        assert!(s.snapshot().is_err());
        assert!(s.cache_policy().is_err());
        assert!(s.prepare_next("offline-validator", 7, &[]).is_err());
        for p in [
            "recovery_reopen",
            "recovery_validate",
            "recovery_barrier",
            "recovery_install",
        ] {
            s.hook = Some(hook_at(p));
            assert!(s.recover().is_err());
            assert!(!s.is_ready());
        }
        s.hook = None;
        assert_eq!(s.recover().unwrap().attempted_present, Some(true));
        check_policy(&s, policy);
        assert!(matches!(
            s.commit(old_overlay),
            AppendOutcome::Aborted(Error::Stale)
        ));
        let expected = s.snapshot().unwrap().clone();
        drop(s);
        let reopened = CanonicalFixtureStore::reopen_with_cache_policy(&path, &m, policy).unwrap();
        assert_eq!(reopened.snapshot().unwrap(), &expected);
        check_policy(&reopened, policy);
        final_states.push(expected);
    }
    assert_eq!(final_states[0], final_states[1]);
}

#[test]
fn both_budgets_unsigned_boundaries_missing_paths_and_exact_attempt_identity() {
    let d = TempDir::new().unwrap();
    for policy in POLICIES {
        let c = AuthenticationContext::new(u64::MAX, context().network_id(), 1).unwrap();
        let anchor = NativeBlock::empty_fixture_anchor(
            &c,
            u64::MAX - 1,
            vector("anchor").hash(),
            "boundary-fixture".into(),
            u64::MAX,
        )
        .unwrap();
        let initial = TransferState::new(
            BTreeMap::from([(
                sender(),
                TransferAccount {
                    balance_quarks: u128::MAX,
                    nonce: u64::MAX - 1,
                },
            )]),
            u64::MAX - 1000,
            u128::MAX - 10000,
        );
        let m =
            FixtureManifest::new(c, anchor, initial, "explicit unsigned fixture".into()).unwrap();
        let path = d.path().join(format!("max-{policy:?}.db"));
        assert!(matches!(
            CanonicalFixtureStore::reopen_with_cache_policy(&path, &m, policy),
            Err(Error::Storage(StoreError::Missing))
        ));
        assert!(!path.exists());
        let mut s = create(&path, &m, policy);
        let tx = sign(
            UnsignedTransaction {
                encoding_version: 2,
                native_rules_version: 1,
                chain_id: u64::MAX,
                network_id: c.network_id(),
                kind: 0,
                sender: sender(),
                nonce: u64::MAX - 1,
                recipient: [0x22; 20],
                token_id: 0,
                value: 1,
                gas_limit: u64::MAX,
                valid_after_slot: u64::MAX,
            },
            &key(),
            &c,
        )
        .unwrap()
        .canonical_bytes()
        .unwrap()
        .to_vec();
        let prepared = s.prepare_next("boundary-fixture", u64::MAX, &[tx]).unwrap();
        let g = FixtureAdmissionGrant::explicit_offline(
            c,
            m.anchor().hash(),
            s.snapshot().unwrap().tip,
            prepared.block().hash(),
            u64::MAX,
        );
        assert!(matches!(
            s.commit(prepared.authorize(g).unwrap()),
            AppendOutcome::Committed { .. }
        ));
        let expected = s.snapshot().unwrap().clone();
        assert_eq!(expected.state.account(&sender()).nonce, u64::MAX);
        assert_eq!(
            (
                expected.state.gas_used_total(),
                expected.state.fees_burned_total()
            ),
            (u64::MAX, u128::MAX)
        );
        assert!(matches!(
            s.prepare_next("boundary-fixture", 1, &[]),
            Err(Error::Overflow)
        ));
        drop(s);
        assert_eq!(
            CanonicalFixtureStore::reopen_with_cache_policy(&path, &m, policy)
                .unwrap()
                .snapshot()
                .unwrap(),
            &expected
        );
        // Independently exercise a valid different stored row at the attempted revision.
        let m = manifest(1);
        let path = d.path().join(format!("attempt-{policy:?}.db"));
        let mut s = create(&path, &m, policy);
        let st = stage_next(&s, &[]);
        s.hook = Some(Box::new(|p| {
            if ["accounts", "rollback"].contains(&p) {
                Err(invalid(p))
            } else {
                Ok(())
            }
        }));
        assert!(matches!(s.commit(st), AppendOutcome::RecoveryRequired(_)));
        s.connection.take();
        s.hook = None;
        let mut other = CanonicalFixtureStore::reopen_with_cache_policy(&path, &m, policy).unwrap();
        let p = other.prepare_next("different-fixture", 8, &[]).unwrap();
        let g = grant(other.snapshot().unwrap().tip, p.block());
        assert!(matches!(
            other.commit(p.authorize(g).unwrap()),
            AppendOutcome::Committed { .. }
        ));
        drop(other);
        assert!(s.recover().is_err());
        assert!(!s.is_ready());
    }
}

#[test]
fn trial_fault_schedules_are_reenumerated() {
    io_sweeps(CachePolicy::Trial32MiB);
}
#[test]
fn trial_power_model_schedules_are_reenumerated() {
    power_loss_sweep(CachePolicy::Trial32MiB);
}

#[test]
fn budget_process_termination() {
    let initial = [
        "schema",
        "context",
        "fixture_account",
        "fixture_accounts",
        "initial_accounting",
        "anchor",
        "anchor_body",
        "initial_tip",
        "provenance",
        "marker",
        "init_before_commit",
        "init_journal_xwrite",
        "init_database_xwrite",
        "init_journal_xsync",
        "init_database_xsync",
        "init_xdelete",
        "init_after_commit",
        "init_directory_sync",
    ];
    let app = [
        "before_begin",
        "accounts",
        "accounting",
        "block",
        "body",
        "indexes",
        "revision",
        "tip",
        "before_commit",
        "journal_xwrite",
        "database_xwrite",
        "journal_xsync",
        "database_xsync",
        "xdelete",
        "after_commit",
        "after_install",
    ];
    for policy in POLICIES {
        for point in initial {
            let d = TempDir::new().unwrap();
            let path = d.path().join("s.db");
            let m = manifest(50_000);
            terminate_policy(&path, point, "initialization", policy, true);
            let result =
                CanonicalFixtureStore::recover_existing_with_cache_policy(&path, &m, policy);
            if ["init_after_commit", "init_directory_sync"].contains(&point) {
                let s = result.unwrap();
                check_policy(&s, policy);
                assert_eq!(s.snapshot().unwrap().state, m.initial);
            } else {
                assert!(matches!(
                    result,
                    Err(Error::Storage(StoreError::Uninitialized))
                ));
            }
        }
        for workload in ["empty", "transfer"] {
            for point in app {
                let d = TempDir::new().unwrap();
                let path = d.path().join("s.db");
                let m = manifest(50_000);
                let mut s = create(&path, &m, policy);
                ack_prefix(&mut s);
                drop(s);
                terminate_policy(&path, point, workload, policy, true);
                let s =
                    CanonicalFixtureStore::recover_existing_with_cache_policy(&path, &m, policy)
                        .unwrap();
                check_policy(&s, policy);
                let new = ["after_commit", "after_install"].contains(&point);
                assert_eq!(s.snapshot().unwrap().tip.revision, 2 + u64::from(new));
                assert_eq!(
                    s.snapshot().unwrap().transactions.len(),
                    usize::from(new && workload == "transfer")
                );
            }
        }
        println!(
            "cache_process policy={policy:?} initialization={} empty={} transfer={} actual_budget_preserved=true",
            initial.len(),
            app.len(),
            app.len()
        );
    }
}

#[test]
#[ignore = "isolated subprocess entry for real SQLite hard-heap allocation failure"]
fn allocation_child() {
    let Some(path) = std::env::var_os("ETX_CACHE_ALLOC_PATH") else {
        return;
    };
    let policy = if std::env::var("ETX_CACHE_ALLOC_POLICY").as_deref() == Ok("trial32") {
        CachePolicy::Trial32MiB
    } else {
        CachePolicy::ExistingDefault
    };
    let point = std::env::var("ETX_CACHE_ALLOC_POINT").unwrap();
    let m = bench::fixture(1000);
    let mut s = create(Path::new(&path), &m, policy);
    let b = bench::block(&s, &m, 3000, 1000).unwrap();
    let st = s
        .stage_received(&b.wire_bytes(), bench::grant(&s, &m, &b))
        .unwrap();
    let old = s.snapshot().unwrap().clone();
    let allocation_point = point.clone();
    // SQLite's real global heap cap is used only in this isolated child, avoiding allocator policy
    // changes in the node/library or concurrent correctness tests. It does not constrain Rust heap.
    s.hook = Some(Box::new(move |p| {
        if p == point {
            unsafe {
                let used = ffi::sqlite3_memory_used();
                ffi::sqlite3_hard_heap_limit64(used + 4096);
            }
        }
        Ok(())
    }));
    let outcome = s.commit(st);
    s.hook = None;
    unsafe {
        ffi::sqlite3_hard_heap_limit64(0);
    }
    let text = format!("{outcome:?}");
    assert!(
        text.contains("OutOfMemory") || text.contains("out of memory"),
        "actual SQLite allocation failure required: {text}"
    );
    assert!(!matches!(outcome, AppendOutcome::Committed { .. }));
    match &outcome {
        AppendOutcome::Aborted(_) => assert_eq!(s.snapshot().unwrap(), &old),
        AppendOutcome::RecoveryRequired(_) => {
            assert!(!s.is_ready());
            assert!(s.snapshot().is_err());
        }
        _ => unreachable!(),
    }
    let report = s.recover().unwrap();
    assert_eq!(report.tip.revision, 0);
    assert_eq!(s.snapshot().unwrap(), &old);
    check_policy(&s, policy);
    println!(
        "cache_allocation policy={policy:?} point={allocation_point} cap=sqlite_memory_used+4096 outcome={text} recovered_old_prefix=true"
    );
}
#[test]
fn real_sqlite_allocation_failures_have_explicit_outcomes_in_isolated_children() {
    for policy in POLICIES {
        for point in ["before_begin", "body"] {
            let d = TempDir::new().unwrap();
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "canonical_fixture::tests::cache_policy::allocation_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("ETX_CACHE_ALLOC_PATH", d.path().join("s.db"))
                .env(
                    "ETX_CACHE_ALLOC_POLICY",
                    if policy == CachePolicy::Trial32MiB {
                        "trial32"
                    } else {
                        "default"
                    },
                )
                .env("ETX_CACHE_ALLOC_POINT", point)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            print!("{}", String::from_utf8_lossy(&output.stdout));
        }
    }
}

#[test]
#[ignore = "bounded 400000-account real initialization spill/rollback stress, explicitly run in release"]
fn larger_budget_initialization_spill_and_rollback_stress() {
    if cfg!(debug_assertions) {
        panic!("release required");
    }
    let m = manifest(400_000);
    for policy in POLICIES {
        for fail in [false, true] {
            let d = TempDir::new().unwrap();
            let path = d.path().join("stress.db");
            let v = Harness::new();
            let mut before = 0usize;
            let mut actual = 0usize;
            let mut arm = v.arm_next_callback("xtruncate", ffi::SQLITE_IOERR_TRUNCATE, true);
            let result = CanonicalFixtureStore::create_inner_with_cache(
                &path,
                &m,
                policy,
                Some(v.name()),
                |p| {
                    if p == "context" {
                        before = v
                            .events()
                            .iter()
                            .filter(|e| {
                                e.kind == "xwrite"
                                    && !e.path.to_string_lossy().ends_with("-journal")
                            })
                            .count();
                    }
                    if p == "initial_accounting" {
                        actual = v
                            .events()
                            .iter()
                            .filter(|e| {
                                e.kind == "xwrite"
                                    && !e.path.to_string_lossy().ends_with("-journal")
                            })
                            .count()
                            .saturating_sub(before);
                        assert!(
                            actual > 0,
                            "real dirty database writes before COMMIT required at actual cache budget"
                        );
                        if fail {
                            arm();
                            return Err(invalid(
                                "real initializer rollback after actual budget spill",
                            ));
                        }
                    }
                    Ok(())
                },
            );
            if fail {
                assert!(matches!(
                    result,
                    Err(Error::Storage(StoreError::RecoveryRequired(_)))
                ));
                v.reset();
                assert!(matches!(
                    CanonicalFixtureStore::load_with_cache(&path, &m, policy, Some(v.name())),
                    Err(Error::Storage(StoreError::Uninitialized))
                ));
            } else {
                let s = result.unwrap();
                check_policy(&s, policy);
                assert_eq!(s.snapshot().unwrap().state, m.initial);
                drop(s);
                assert_eq!(
                    CanonicalFixtureStore::reopen_with_cache_policy(&path, &m, policy)
                        .unwrap()
                        .snapshot()
                        .unwrap()
                        .state,
                    m.initial
                );
            }
            println!(
                "cache_initialization_stress policy={policy:?} accounts=400000 actual_precommit_database_writes={actual} rollback_truncate_fault={fail}"
            );
        }
    }
}

fn cache_spills(s: &CanonicalFixtureStore) -> i64 {
    let mut n = 0i64;
    let mut high = 0i64;
    let rc = unsafe {
        ffi::sqlite3_db_status64(
            s.conn().handle(),
            ffi::SQLITE_DBSTATUS_CACHE_SPILL,
            &mut n,
            &mut high,
            0,
        )
    };
    assert_eq!(rc, ffi::SQLITE_OK);
    n
}
fn stress_key(n: usize) -> SigningKey {
    // Every scalar is an explicitly published deterministic toy integer (1..=3000), not a secret.
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&(n as u64 + 1).to_be_bytes());
    SigningKey::from_slice(&bytes).unwrap()
}
fn stress_address(n: usize) -> Address {
    let mut a = [0x66; 20];
    a[12..].copy_from_slice(&(n as u64).to_be_bytes());
    a
}
fn stress_block(
    s: &CanonicalFixtureStore,
    m: &FixtureManifest,
    keys: &[SigningKey],
    addresses: &[Address],
    start: usize,
    n: usize,
    credit: bool,
) -> NativeBlock {
    let ctx = m.context();
    let mut signed = Vec::new();
    for i in 0..n {
        let k = (start + i) % keys.len();
        let sender = addresses[k];
        signed.push(
            sign(
                UnsignedTransaction {
                    encoding_version: 2,
                    native_rules_version: 1,
                    chain_id: ctx.chain_id(),
                    network_id: ctx.network_id(),
                    kind: 0,
                    sender,
                    nonce: s.snapshot().unwrap().state.account(&sender).nonce,
                    recipient: stress_address(i * 233 % 700000),
                    token_id: 0,
                    value: u128::from(credit),
                    gas_limit: 1001,
                    valid_after_slot: 0,
                },
                &keys[k],
                &ctx,
            )
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        );
    }
    let ids: Vec<_> = signed
        .iter()
        .map(|b| hash_with_domain(ID_DOMAIN, b))
        .collect();
    let pd = ProtocolData {
        missed_proposer: None,
        fees_burned: n as u64 * 10000,
    };
    let mut header = m.anchor().header().clone();
    header.slot = s.snapshot().unwrap().tip.slot + 1;
    header.parent_hash = s.snapshot().unwrap().tip.hash;
    header.transaction_root = ordered_transaction_root(&ids).unwrap();
    header.gas_used = n as u64 * 1000;
    header.protocol_data_root = pd.root();
    NativeBlock::from_parts(header, m.anchor().proposer().into(), pd, signed).unwrap()
}

#[test]
#[ignore = "bounded 703000-account/100000-tx actual-budget append spill+rollback stress, release only"]
fn larger_budget_append_spill_and_failed_restoration_stress() {
    if cfg!(debug_assertions) {
        panic!("release required");
    }
    let policy = CachePolicy::Trial32MiB;
    let ctx = context();
    let keys: Vec<_> = (0..3000).map(stress_key).collect();
    let addresses: Vec<_> = keys
        .iter()
        .map(|k| address_from_public_key(k.verifying_key()))
        .collect();
    let mut accounts = BTreeMap::new();
    for n in 0..700000 {
        accounts.insert(
            stress_address(n),
            TransferAccount {
                balance_quarks: 1_000_000,
                nonce: 0,
            },
        );
    }
    for a in &addresses {
        accounts.insert(
            *a,
            TransferAccount {
                balance_quarks: 20_000_000_000,
                nonce: 0,
            },
        );
    }
    let m = FixtureManifest::new(
        ctx,
        vector("anchor"),
        TransferState::new(accounts, 0, 0),
        "bounded public-toy multi-sender 32MiB append spill stress".into(),
    )
    .unwrap();
    let d = TempDir::new().unwrap();
    let base = d.path().join("base.db");
    let mut s = create(&base, &m, policy);
    for n in 0..100 {
        let b = stress_block(&s, &m, &keys, &addresses, n * 1000, 1000, false);
        let g = FixtureAdmissionGrant::explicit_offline(
            ctx,
            m.anchor().hash(),
            s.snapshot().unwrap().tip,
            b.hash(),
            b.header().slot,
        );
        let st = s.stage_received(&b.wire_bytes(), g).unwrap();
        assert!(matches!(s.commit(st), AppendOutcome::Committed { .. }));
    }
    let expected = s.snapshot().unwrap().clone();
    assert_eq!(expected.transactions.len(), 100000);
    drop(s);
    // Reuse the exact closed base at both actual budgets. The default's older tiny-cache fault
    // regression is separate evidence and cannot substitute for a failure after genuine spills.
    for policy in POLICIES {
        let mut selected_cuts = Vec::new();
        for fail in [false, true] {
            let path = d.path().join(format!("append-{policy:?}-{fail}.db"));
            super::profiling::independent_copy(&base, &path);
            let v = Harness::new();
            let mut s =
                CanonicalFixtureStore::load_with_cache(&path, &m, policy, Some(v.name())).unwrap();
            check_policy(&s, policy);
            let b = stress_block(&s, &m, &keys, &addresses, 0, 3000, true);
            let g = FixtureAdmissionGrant::explicit_offline(
                ctx,
                m.anchor().hash(),
                s.snapshot().unwrap().tip,
                b.hash(),
                b.header().slot,
            );
            let st = s.stage_received(&b.wire_bytes(), g).unwrap();
            let before = cache_spills(&s);
            v.reset();
            if fail {
                let mut arm = v.arm_next_callback("xwrite", ffi::SQLITE_IOERR_WRITE, true);
                s.hook = Some(Box::new(move |p| {
                    if p == "indexes" {
                        arm();
                        Err(invalid(
                            "force restoration after genuine selected-budget append spill",
                        ))
                    } else {
                        Ok(())
                    }
                }));
            }
            let outcome = s.commit(st);
            if !fail && policy == CachePolicy::Trial32MiB {
                let trace = v.events();
                for kind in ["xwrite", "xsync", "xdelete"] {
                    let entry = trace
                        .iter()
                        .enumerate()
                        .find(|(_, e)| {
                            e.kind == kind
                                && (kind == "xdelete"
                                    || !e.path.to_string_lossy().ends_with("-journal"))
                        })
                        .expect("actual stress operation required");
                    selected_cuts.push((kind, entry.0 + 1));
                }
            }
            let spills = cache_spills(&s) - before;
            assert!(
                spills > 0,
                "genuine selected-budget append spills required, not a lowered cache budget"
            );
            assert!(
                v.events()
                    .iter()
                    .any(|e| e.kind == "xwrite" && !e.path.to_string_lossy().ends_with("-journal"))
            );
            if fail {
                assert!(matches!(outcome, AppendOutcome::RecoveryRequired(_)));
                assert!(!s.is_ready());
                s.hook = None;
                v.reset();
                assert_eq!(s.recover().unwrap().attempted_present, Some(false));
                check_policy(&s, policy);
                assert_eq!(s.snapshot().unwrap(), &expected);
            } else {
                assert!(matches!(outcome, AppendOutcome::Committed { .. }));
                let new = s.snapshot().unwrap().clone();
                drop(s);
                let loaded =
                    CanonicalFixtureStore::reopen_with_cache_policy(&path, &m, policy).unwrap();
                assert_eq!(loaded.snapshot().unwrap(), &new);
            }
            println!(
                "cache_append_stress policy={policy:?} accounts=703000 history_txs=100000 body=3000 different_senders=3000 actual_cache_spills={spills} failed_rollback_write={fail}"
            );
        }
        // This large fixture uses selected freshly observed boundaries, not an exhaustive thousands-
        // of-writes sweep. Each cut is in a separate directory so restoring the model never erases base.
        for (kind, cut) in selected_cuts {
            let case = TempDir::new().unwrap();
            let path = case.path().join("power.db");
            super::profiling::independent_copy(&base, &path);
            let v = Harness::new();
            let mut s =
                CanonicalFixtureStore::load_with_cache(&path, &m, policy, Some(v.name())).unwrap();
            let b = stress_block(&s, &m, &keys, &addresses, 0, 3000, true);
            let g = FixtureAdmissionGrant::explicit_offline(
                ctx,
                m.anchor().hash(),
                s.snapshot().unwrap().tip,
                b.hash(),
                b.header().slot,
            );
            let st = s.stage_received(&b.wire_bytes(), g).unwrap();
            v.reset();
            v.power(cut, true);
            let outcome = s.commit(st);
            // A modeled failed persistence boundary cannot authorize an acknowledgement, even if
            // post-cut cleanup makes the volatile real file readable before the stable image is restored.
            assert!(!matches!(outcome, AppendOutcome::Committed { .. }));
            assert_eq!(v.events()[cut - 1].kind, kind);
            match &outcome {
                AppendOutcome::Aborted(_) => assert_eq!(s.snapshot().unwrap(), &expected),
                AppendOutcome::RecoveryRequired(_) => {
                    assert!(!s.is_ready());
                    assert!(s.snapshot().is_err());
                }
                _ => unreachable!(),
            }
            drop(s);
            v.restore_power_image(case.path());
            v.reset();
            let loaded =
                CanonicalFixtureStore::reopen_with_cache_policy(&path, &m, policy).unwrap();
            assert_eq!(loaded.snapshot().unwrap(), &expected);
            println!(
                "cache_stress_power policy={policy:?} freshly_observed_kind={kind} event={cut} sector_prefix=true outcome={outcome:?} recovered_old_complete_prefix=true"
            );
        }
    }
}

#[test]
#[ignore = "isolated release memory observer, invoked by budget comparison"]
fn isolated_memory_child() {
    let Some(path) = std::env::var_os("ETX_CACHE_MEMORY_PATH") else {
        return;
    };
    let policy = if std::env::var("ETX_CACHE_MEMORY_POLICY").as_deref() == Ok("trial32") {
        CachePolicy::Trial32MiB
    } else {
        CachePolicy::ExistingDefault
    };
    let m = bench::fixture(1000);
    let baseline = super::profiling::process_memory();
    let mut s =
        CanonicalFixtureStore::reopen_with_cache_policy(Path::new(&path), &m, policy).unwrap();
    let reopened = super::profiling::process_memory();
    let b = bench::block(&s, &m, 3000, 1000).unwrap();
    let wire = b.wire_bytes();
    let g = bench::grant(&s, &m, &b);
    let begin = Instant::now();
    let st = s.stage_received(&wire, g).unwrap();
    let staged = super::profiling::process_memory();
    assert!(matches!(s.commit(st), AppendOutcome::Committed { .. }));
    let pipeline = begin.elapsed();
    let committed = super::profiling::process_memory();
    let mut bytes = 0i64;
    let mut high = 0i64;
    assert_eq!(
        unsafe {
            ffi::sqlite3_db_status64(
                s.conn().handle(),
                ffi::SQLITE_DBSTATUS_CACHE_USED,
                &mut bytes,
                &mut high,
                0,
            )
        },
        ffi::SQLITE_OK
    );
    println!(
        "{}",
        serde_json::json!({"kind":"cache_compare_isolated_memory","policy":format!("{policy:?}"),"budget_kib":-policy.pragma_value(),"accounts":1000,"history":100000,"body_size":3000,"baseline":baseline,"after_full_reopen":reopened,"during_staged_candidate":staged,"after_commit":committed,"sqlite_cache_bytes":bytes,"pipeline_ms":pipeline.as_secs_f64()*1000.0,"hwm":"fresh-process cumulative, observed independently per budget"})
    );
}
