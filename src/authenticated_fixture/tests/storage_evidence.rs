//! Fresh schema-3 traces and exact evidence oracles; old schema-2 operation counts are not reused.
use super::*;
use crate::durable_fixture::tests::vfs::Harness;
use rusqlite::ffi;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

fn vstore(p: &Path, m: &AuthenticatedFixtureManifest, v: &Harness) -> AuthenticatedFixtureStore {
    AuthenticatedFixtureStore::create_inner(p, m, Some(v.name()), |_| Ok(())).unwrap()
}
fn prefix(s: &mut AuthenticatedFixtureStore, m: &AuthenticatedFixtureManifest) {
    for _ in 0..2 {
        let b = empty(s, "offline-validator");
        append(s, m, &b);
    }
}
fn workload(
    s: &AuthenticatedFixtureStore,
    m: &AuthenticatedFixtureManifest,
    populated: bool,
) -> StagedAuthenticatedBlock {
    let b = if populated {
        let mut h = vector("single").header().clone();
        h.parent_hash = s.snapshot().unwrap().tip.hash;
        h.slot = s.snapshot().unwrap().tip.slot + 1;
        NativeBlock::from_parts(
            h,
            "offline-validator".into(),
            vector("single").protocol_data().clone(),
            vector("single").transactions().to_vec(),
        )
        .unwrap()
    } else {
        empty(s, "offline-validator")
    };
    s.stage_received(&packet(m, &b, 2), grant(m, s.snapshot().unwrap().tip, &b))
        .unwrap()
}

// Max-body process tests use the same independent policy and public sender as the small vectors,
// rather than changing the context or accepting a preauthenticated body across a process boundary.
fn process_workload(
    s: &AuthenticatedFixtureStore,
    m: &AuthenticatedFixtureManifest,
    which: &str,
) -> StagedAuthenticatedBlock {
    if which != "maximum" {
        return workload(s, m, which == "populated");
    }
    use crate::native_transaction::{UnsignedTransaction, address_from_public_key, sign};
    let sender = address_from_public_key(key(1).verifying_key());
    let nonce = s.snapshot().unwrap().state.account(&sender).nonce;
    let input: Vec<_> = (0..MAX_TRANSACTIONS)
        .map(|i| {
            let mut recipient = [0x44; 20];
            recipient[12..].copy_from_slice(&(i as u64 + 1).to_be_bytes());
            sign(
                UnsignedTransaction {
                    encoding_version: 2,
                    native_rules_version: 1,
                    chain_id: m.fixture.context().chain_id(),
                    network_id: m.fixture.context().network_id(),
                    kind: 0,
                    sender,
                    nonce: nonce + i as u64,
                    recipient,
                    token_id: 0,
                    value: 1,
                    gas_limit: 1001,
                    valid_after_slot: 0,
                },
                &key(1),
                &m.fixture.context(),
            )
            .unwrap()
            .canonical_bytes()
            .unwrap()
            .to_vec()
        })
        .collect();
    let prepared = s.prepare_next("offline-validator", 7, &input).unwrap();
    let bytes = packet(m, prepared.block(), 2);
    let g = grant(m, prepared.base_tip(), prepared.block());
    s.seal_prepared(prepared, &bytes, g).unwrap()
}

#[test]
fn schema3_nth_io_traces_initialization_empty_populated_and_recovery() {
    for phase in ["initialization", "empty", "populated", "recovery"] {
        let trace = {
            let d = TempDir::new().unwrap();
            let m = policy(4);
            let v = Harness::new();
            let mut s = vstore(&d.path().join("s.db"), &m, &v);
            if phase != "initialization" {
                prefix(&mut s, &m);
                v.reset();
                if phase == "recovery" {
                    s.recover().unwrap();
                } else {
                    let st = workload(&s, &m, phase == "populated");
                    assert!(matches!(s.commit(st), AppendOutcome::Committed { .. }));
                }
            }
            v.events()
        };
        let mut aborted = 0;
        let mut required = 0;
        let mut cases = 0;
        for (kind, code) in [
            ("xwrite", ffi::SQLITE_FULL),
            ("xwrite", ffi::SQLITE_IOERR_WRITE),
            ("xsync", ffi::SQLITE_IOERR_FSYNC),
            ("xdelete", ffi::SQLITE_IOERR_DELETE),
        ] {
            for nth in 1..=trace.iter().filter(|e| e.kind == kind).count() {
                cases += 1;
                let d = TempDir::new().unwrap();
                let p = d.path().join("s.db");
                let m = policy(4);
                let v = Harness::new();
                if phase == "initialization" {
                    v.fault(kind, nth, code, false);
                    let error =
                        AuthenticatedFixtureStore::create_inner(&p, &m, Some(v.name()), |_| Ok(()))
                            .err()
                            .expect("fault must be reached");
                    if matches!(error, Error::Storage(StoreError::RecoveryRequired(_))) {
                        required += 1;
                    } else {
                        aborted += 1;
                    }
                    v.reset();
                    assert!(matches!(
                        AuthenticatedFixtureStore::load(&p, &m, Some(v.name())),
                        Err(Error::Storage(StoreError::Uninitialized))
                    ));
                    println!(
                        "schema3_io phase={phase} op={kind} nth={nth} code={code} outcome={error:?} recovered=uninitialized"
                    );
                } else {
                    let mut s = vstore(&p, &m, &v);
                    prefix(&mut s, &m);
                    let old = s.snapshot().unwrap().clone();
                    let st = workload(&s, &m, phase == "populated");
                    v.reset();
                    v.fault(kind, nth, code, false);
                    if phase == "recovery" {
                        let e = s.recover().unwrap_err();
                        assert!(!s.is_ready());
                        required += 1;
                        v.reset();
                        s.recover().unwrap();
                        assert_eq!(s.snapshot().unwrap(), &old);
                        println!(
                            "schema3_io phase={phase} op={kind} nth={nth} code={code} outcome={e:?} exact_old_evidence=true"
                        );
                    } else {
                        let outcome = s.commit(st);
                        match outcome {
                            AppendOutcome::Aborted(_) => {
                                aborted += 1;
                                assert_eq!(s.snapshot().unwrap(), &old);
                            }
                            AppendOutcome::RecoveryRequired(_) => {
                                required += 1;
                                assert!(!s.is_ready());
                                assert!(s.export_signed_envelope(1).is_err());
                            }
                            _ => panic!("fault not reached {phase} {kind}:{nth}"),
                        };
                        v.reset();
                        let report = s.recover().unwrap();
                        assert_eq!(s.snapshot().unwrap(), &old);
                        println!(
                            "schema3_io phase={phase} op={kind} nth={nth} code={code} outcome={outcome:?} recovered={report:?} exact_old_evidence=true"
                        );
                    }
                }
            }
        }
        println!(
            "schema3_io_summary phase={phase} newly_enumerated_cases={cases} aborted={aborted} recovery_required={required}"
        );
    }
}

#[test]
fn schema3_power_model_new_traces_and_exact_acknowledged_evidence() {
    for phase in ["initialization", "empty", "populated", "recovery"] {
        let trace = {
            let d = TempDir::new().unwrap();
            let m = policy(4);
            let v = Harness::new();
            let mut s = vstore(&d.path().join("s.db"), &m, &v);
            if phase != "initialization" {
                prefix(&mut s, &m);
                v.reset();
                if phase == "recovery" {
                    s.recover().unwrap();
                } else {
                    let st = workload(&s, &m, phase == "populated");
                    assert!(matches!(s.commit(st), AppendOutcome::Committed { .. }));
                }
            }
            v.events().len()
        };
        for sector in [false, true] {
            let mut old = 0;
            let mut new = 0;
            let mut uninitialized = 0;
            for cut in 1..=trace {
                let d = TempDir::new().unwrap();
                let p = d.path().join("s.db");
                let m = policy(4);
                let v = Harness::new();
                let expected = if phase == "initialization" {
                    v.power(cut, sector);
                    drop(AuthenticatedFixtureStore::create_inner(
                        &p,
                        &m,
                        Some(v.name()),
                        |_| Ok(()),
                    ));
                    None
                } else {
                    let mut s = vstore(&p, &m, &v);
                    prefix(&mut s, &m);
                    let old = s.snapshot().unwrap().clone();
                    let st = workload(&s, &m, phase == "populated");
                    let mut next = old.clone();
                    next.state = st.candidate.clone();
                    next.insert(st.record.clone()).unwrap();
                    v.reset();
                    v.power(cut, sector);
                    if phase == "recovery" {
                        let _ = s.recover();
                    } else {
                        let _ = s.commit(st);
                    }
                    drop(s);
                    Some((old, next))
                };
                v.restore_power_image(d.path());
                v.reset();
                match AuthenticatedFixtureStore::load(&p, &m, Some(v.name())) {
                    Err(Error::Storage(StoreError::Missing | StoreError::Uninitialized))
                        if phase == "initialization" =>
                    {
                        uninitialized += 1
                    }
                    Ok(s) => {
                        if let Some((a, b)) = expected {
                            if s.snapshot().unwrap() == &a {
                                old += 1;
                            } else {
                                assert_eq!(s.snapshot().unwrap(), &b);
                                new += 1;
                            }
                        } else {
                            assert_eq!(s.snapshot().unwrap().state, *m.fixture.initial_state());
                            new += 1;
                        }
                    }
                    Err(e) => panic!("{phase} sector={sector} cut={cut}: {e}"),
                }
            }
            println!(
                "schema3_power phase={phase} sector_prefix={sector} newly_enumerated_cuts={trace} old_complete={old} new_complete={new} uninitialized={uninitialized}"
            );
        }
    }
    for acknowledged in [false, true] {
        let d = TempDir::new().unwrap();
        let m = policy(4);
        let v = Harness::new();
        let p = d.path().join("s.db");
        let mut s = vstore(&p, &m, &v);
        prefix(&mut s, &m);
        let st = workload(&s, &m, true);
        let mut expected = s.snapshot().unwrap().clone();
        expected.state = st.candidate.clone();
        expected.insert(st.record.clone()).unwrap();
        if !acknowledged {
            s.hook = Some(hook("after_commit"));
        }
        let outcome = s.commit(st);
        assert!(if acknowledged {
            matches!(outcome, AppendOutcome::Committed { .. })
        } else {
            matches!(outcome, AppendOutcome::RecoveryRequired(_))
        });
        v.capture_acknowledged();
        drop(s);
        v.restore_power_image(d.path());
        v.reset();
        assert_eq!(
            AuthenticatedFixtureStore::load(&p, &m, Some(v.name()))
                .unwrap()
                .snapshot()
                .unwrap(),
            &expected
        );
        println!("schema3_power acknowledged={acknowledged} exact_accepted_evidence_retained=true");
    }
}

fn handshake(p: &str, target: &str) {
    if p == target {
        println!("SCHEMA3_READY:{p}");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        panic!("parent must kill child");
    }
}
#[test]
#[ignore = "controlled schema-3 child invoked by process parent"]
fn crash_child() {
    let Some(path) = std::env::var_os("ETX_SCHEMA3_PATH") else {
        return;
    };
    let target = std::env::var("ETX_SCHEMA3_POINT").unwrap();
    let which = std::env::var("ETX_SCHEMA3_WORKLOAD").unwrap();
    let m = policy(50000);
    let v = Harness::new();
    let location = target
        .strip_prefix("init_")
        .or_else(|| target.strip_prefix("recovery_"))
        .unwrap_or(&target);
    let event = match location {
        "journal_xwrite" => Some("journal_xwrite"),
        "database_xwrite" => Some("database_xwrite"),
        "journal_xsync" => Some("journal_xsync"),
        "database_xsync" => Some("database_xsync"),
        "xdelete" => Some("xdelete"),
        _ => None,
    };
    if which == "initialization" {
        v.on_event(event, {
            let t = target.clone();
            move |p| handshake(&format!("init_{p}"), &t)
        });
        let _ =
            AuthenticatedFixtureStore::create_inner(Path::new(&path), &m, Some(v.name()), |p| {
                handshake(p, &target);
                Ok(())
            });
    } else {
        let mut s = AuthenticatedFixtureStore::load(Path::new(&path), &m, Some(v.name())).unwrap();
        assert_eq!(s.settings().unwrap().cache_size, -2000);
        let recovering = which == "recovery";
        v.on_event(event, {
            let t = target.clone();
            move |p| {
                if recovering {
                    handshake(&format!("recovery_{p}"), &t)
                } else {
                    handshake(p, &t)
                }
            }
        });
        s.hook = Some(Box::new(move |p| {
            handshake(p, &target);
            Ok(())
        }));
        if recovering {
            let _ = s.recover();
        } else {
            let st = process_workload(&s, &m, &which);
            let _ = s.commit(st);
        }
    }
    panic!("point not reached");
}
fn terminate(p: &Path, point: &str, which: &str) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "authenticated_fixture::tests::storage_evidence::crash_child",
            "--ignored",
            "--nocapture",
        ])
        .env("ETX_SCHEMA3_PATH", p)
        .env("ETX_SCHEMA3_POINT", point)
        .env("ETX_SCHEMA3_WORKLOAD", which)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0, "{which}/{point}");
        if line.starts_with("SCHEMA3_READY:") {
            break;
        }
    }
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
}
#[test]
fn schema3_handshake_process_termination_at_new_initializer_and_evidence_points() {
    let initial = [
        "schema",
        "context",
        "producer_binding",
        "bindings",
        "fixture_account",
        "fixture_accounts",
        "initial_accounting",
        "anchor",
        "anchor_body",
        "initial_tip",
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
    for point in initial {
        let d = TempDir::new().unwrap();
        let p = d.path().join("s.db");
        let m = policy(50000);
        terminate(&p, point, "initialization");
        let result = AuthenticatedFixtureStore::recover_existing(&p, &m);
        if ["init_after_commit", "init_directory_sync"].contains(&point) {
            assert_eq!(
                result.unwrap().snapshot().unwrap().state,
                *m.fixture.initial_state()
            );
        } else {
            assert!(matches!(
                result,
                Err(Error::Storage(StoreError::Uninitialized))
            ));
        }
    }
    let points = [
        "before_begin",
        "accounts",
        "accounting",
        "block_evidence",
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
    for which in ["empty", "populated", "maximum"] {
        for point in points {
            let d = TempDir::new().unwrap();
            let p = d.path().join("s.db");
            let m = policy(50000);
            let mut s = create(&p, &m);
            prefix(&mut s, &m);
            let old = s.snapshot().unwrap().clone();
            let st = process_workload(&s, &m, which);
            let mut next = old.clone();
            next.state = st.candidate.clone();
            next.insert(st.record.clone()).unwrap();
            drop(s);
            terminate(&p, point, which);
            let s = AuthenticatedFixtureStore::recover_existing(&p, &m).unwrap();
            assert_eq!(
                s.snapshot().unwrap(),
                if ["after_commit", "after_install"].contains(&point) {
                    &next
                } else {
                    &old
                },
                "{which}/{point}"
            );
        }
    }
    let recovery_points = [
        "recovery_reopen",
        "recovery_validate",
        "recovery_barrier",
        "recovery_install",
        "recovery_journal_xwrite",
        "recovery_database_xwrite",
        "recovery_journal_xsync",
        "recovery_database_xsync",
        "recovery_xdelete",
    ];
    for point in recovery_points {
        let d = TempDir::new().unwrap();
        let p = d.path().join("s.db");
        let m = policy(50000);
        let mut s = create(&p, &m);
        prefix(&mut s, &m);
        let expected = s.snapshot().unwrap().clone();
        drop(s);
        terminate(&p, point, "recovery");
        let s = AuthenticatedFixtureStore::recover_existing(&p, &m).unwrap();
        assert_eq!(s.snapshot().unwrap(), &expected, "{point}");
    }
    println!(
        "schema3_process initializer_points={} empty_points={} populated_points={} maximum_points={} recovery_points={} kills={} actual_default_cache_preserved=true",
        initial.len(),
        points.len(),
        points.len(),
        points.len(),
        recovery_points.len(),
        initial.len() + 3 * points.len() + recovery_points.len()
    );
}

#[test]
fn schema3_actual_open_and_rollback_faults_stay_poisoned() {
    let d = TempDir::new().unwrap();
    let m = policy(4);
    let v = Harness::new();
    let p = d.path().join("s.db");
    let mut s = vstore(&p, &m, &v);
    let st = workload(&s, &m, true);
    s.hook = Some(hook("after_commit"));
    assert!(matches!(s.commit(st), AppendOutcome::RecoveryRequired(_)));
    s.hook = None;
    v.reset();
    v.fault("xopen", 1, ffi::SQLITE_CANTOPEN, false);
    assert!(s.recover().is_err());
    assert!(s.export_signed_envelope(1).is_err());
    v.reset();
    assert_eq!(s.recover().unwrap().attempted_present, Some(true));
    // A larger seed transaction spills at the unchanged default budget; fail pager truncation.
    let big = policy(50000);
    let v = Harness::new();
    let p = d.path().join("initializer.db");
    let mut arm = v.arm_next_callback("xtruncate", ffi::SQLITE_IOERR_TRUNCATE, true);
    let result = AuthenticatedFixtureStore::create_inner(&p, &big, Some(v.name()), |phase| {
        if phase == "initial_accounting" {
            arm();
            Err(invalid("force real initializer rollback"))
        } else {
            Ok(())
        }
    });
    assert!(matches!(
        result,
        Err(Error::Storage(StoreError::RecoveryRequired(_)))
    ));
    v.reset();
    assert!(matches!(
        AuthenticatedFixtureStore::load(&p, &big, Some(v.name())),
        Err(Error::Storage(StoreError::Uninitialized))
    ));
    println!(
        "schema3_extra_io open=SQLITE_CANTOPEN rollback_truncate=SQLITE_IOERR_TRUNCATE poisoned_until_complete_recovery=true"
    );
}

#[test]
#[ignore = "isolated real SQLite allocation-failure child"]
fn allocation_child() {
    let Some(path) = std::env::var_os("ETX_SCHEMA3_ALLOC_PATH") else {
        return;
    };
    let point = std::env::var("ETX_SCHEMA3_ALLOC_POINT").unwrap();
    let m = policy(4);
    let mut s = create(Path::new(&path), &m);
    let b = vector("single");
    let st = s
        .stage_received(&packet(&m, &b, 2), grant(&m, s.snapshot().unwrap().tip, &b))
        .unwrap();
    let old = s.snapshot().unwrap().clone();
    s.hook = Some(Box::new(move |p| {
        if p == point {
            unsafe {
                // Even a warm tiny fixture must exercise a real new-allocation failure; allowing
                // extra bytes can succeed after SQLite releases pager caches under pressure.
                ffi::sqlite3_hard_heap_limit64(1);
            }
        }
        Ok(())
    }));
    let result = s.commit(st);
    s.hook = None;
    unsafe {
        ffi::sqlite3_hard_heap_limit64(0);
    }
    let text = format!("{result:?}");
    assert!(
        text.contains("OutOfMemory") || text.contains("out of memory"),
        "{text}"
    );
    assert!(!matches!(result, AppendOutcome::Committed { .. }));
    s.recover().unwrap();
    assert_eq!(s.snapshot().unwrap(), &old);
    println!(
        "schema3_allocation outcome={text} exact_old_evidence_effects=true cap=sqlite_hard_heap_1 rust_heap_not_capped=true"
    );
}
#[test]
fn schema3_real_sqlite_allocation_failure_subprocesses() {
    for point in ["before_begin", "block_evidence"] {
        let d = TempDir::new().unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "authenticated_fixture::tests::storage_evidence::allocation_child",
                "--ignored",
                "--nocapture",
            ])
            .env("ETX_SCHEMA3_ALLOC_PATH", d.path().join("s.db"))
            .env("ETX_SCHEMA3_ALLOC_POINT", point)
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
