//! Release-only balanced measurements. No verified-result cache, audit bypass or cache tuning.
use super::*;
use serde_json::json;
use std::fs::{File, OpenOptions};
const CASES: &[(usize, usize, usize)] = &[
    (1000, 100, 0),
    (1000, 100, 100000),
    (10000, 0, 0),
    (1000, 1000, 0),
];
fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}
fn copy(from: &Path, to: &Path) {
    let mut a = File::open(from).unwrap();
    let mut b = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(to)
        .unwrap();
    std::io::copy(&mut a, &mut b).unwrap();
    b.sync_all().unwrap();
    File::open(to.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}
fn memory() -> Value {
    let text = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let get = |key: &str| {
        text.lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u64>().ok())
    };
    json!({"rss_kib":get("VmRSS:"),"cumulative_hwm_kib":get("VmHWM:")})
}
fn old_load(t: canonical::LoadTimings) -> Value {
    json!({"total_ms":ms(t.total),"native_audit_ms":ms(t.audit),"validation_materialization_ms":ms(t.validation_materialization),"barrier_ms":ms(t.barrier),"installation_ms":ms(t.installation)})
}
fn new_load(t: LoadTimings) -> Value {
    let mut v = old_load(t.canonical);
    v["producer_audit_ms"] = json!(ms(t.producer_audit));
    v
}
fn timings(t: canonical::AppendTimings) -> Value {
    json!({"native_stage_ms":ms(t.staging),"durable_ms":ms(t.durable_commit),"cache_preparation_ms":ms(t.cache_preparation),"destruction_ms":ms(t.cache_destruction),"stored_comparison_ms":ms(t.stored_comparison),"sql":t.sql_profile.map(|s|json!({"acquisition_ms":ms(s.acquisition),"metadata_ms":ms(s.metadata_base),"account_comparison_ms":ms(s.account_comparison),"uniqueness_ms":ms(s.uniqueness_probes),"changed_accounts_ms":ms(s.changed_account_writes),"accounting_ms":ms(s.accounting_write),"block_evidence_ms":ms(s.block_insertion),"body_ms":ms(s.body_insertion),"transactions_indexes_ms":ms(s.transaction_index_insertion),"revision_tip_ms":ms(s.revision_tip),"commit_return_ms":ms(s.commit_return)}))})
}
fn equal(new: &Snapshot, old: &canonical::Snapshot) {
    assert_eq!(new.state, old.state);
    assert_eq!(new.tip, old.tip);
    assert_eq!(new.transactions, old.transactions);
    assert_eq!(new.sender_nonces, old.sender_nonces);
    assert_eq!(new.slots, old.slots);
    assert_eq!(new.hashes, old.hashes);
    assert_eq!(new.records.len(), old.blocks.len());
    for (n, o) in new.records.iter().zip(&old.blocks) {
        assert_eq!(n.block(), &o.block);
        assert_eq!(n.outcome(), &o.outcome);
    }
}
fn artifact_pass(artifacts: &[Vec<u8>], m: &AuthenticatedFixtureManifest) -> Duration {
    let begin = Instant::now();
    for bytes in artifacts {
        std::hint::black_box(authenticate(bytes, m, None).unwrap());
    }
    begin.elapsed()
}

// Separate correctness stress on the normally-built large closed base, excluded from sample times.
// Require genuine spills at -2000; fail an actual pager restoration write, not a synthetic flag.
fn spilled_restoration(
    base: &Path,
    m: &AuthenticatedFixtureManifest,
    b: &NativeBlock,
    expected: &Snapshot,
) {
    use crate::durable_fixture::tests::vfs::Harness;
    use rusqlite::ffi;
    let d = tempfile::Builder::new()
        .prefix("schema3-spill-")
        .tempdir_in(base.parent().unwrap())
        .unwrap();
    let path = d.path().join("spill.db");
    copy(base, &path);
    let v = Harness::new();
    let mut s = AuthenticatedFixtureStore::load(&path, m, Some(v.name())).unwrap();
    assert_eq!(s.settings().unwrap().cache_size, -2000);
    let st = s
        .stage_received(&packet(m, b, 2), grant(m, s.snapshot().unwrap().tip, b))
        .unwrap();
    let mut before = 0;
    let mut high = 0;
    assert_eq!(
        unsafe {
            ffi::sqlite3_db_status64(
                s.conn().handle(),
                ffi::SQLITE_DBSTATUS_CACHE_SPILL,
                &mut before,
                &mut high,
                0,
            )
        },
        ffi::SQLITE_OK
    );
    v.reset();
    let mut arm = v.arm_next_callback("xwrite", ffi::SQLITE_IOERR_WRITE, true);
    // Observe the real rollback journal at the stress boundary, outside every performance sample.
    let journal_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let observed_journal = journal_bytes.clone();
    let mut journal_path = path.as_os_str().to_owned();
    journal_path.push("-journal");
    s.hook = Some(Box::new(move |p| {
        if p == "indexes" {
            observed_journal.store(
                std::fs::metadata(&journal_path).unwrap().len(),
                std::sync::atomic::Ordering::SeqCst,
            );
            arm();
            Err(invalid(
                "force restoration after genuine default-budget spill",
            ))
        } else {
            Ok(())
        }
    }));
    let result = s.commit(st);
    let mut after = 0;
    assert_eq!(
        unsafe {
            ffi::sqlite3_db_status64(
                s.conn().handle(),
                ffi::SQLITE_DBSTATUS_CACHE_SPILL,
                &mut after,
                &mut high,
                0,
            )
        },
        ffi::SQLITE_OK
    );
    assert!(after > before);
    assert!(
        v.events()
            .iter()
            .any(|e| e.kind == "xwrite" && !e.path.to_string_lossy().ends_with("-journal"))
    );
    assert!(matches!(result, AppendOutcome::RecoveryRequired(_)));
    s.hook = None;
    v.reset();
    assert_eq!(s.recover().unwrap().attempted_present, Some(false));
    assert_eq!(s.snapshot().unwrap(), expected);
    println!(
        "{}",
        json!({"kind":"schema3_spilled_restoration","history_txs":100000,"body_size":3000,"actual_cache_spills":after-before,"cache_size":-2000,"journal_bytes_at_indexes":journal_bytes.load(std::sync::atomic::Ordering::SeqCst),"real_rollback_write_error":true,"exact_old_evidence_effects":true,"outcome":format!("{result:?}"),"not_a_performance_sample":true})
    );
}

#[test]
#[ignore = "bounded release paired schema-2/schema-3 complete pipeline and authenticated recovery benchmark"]
fn matched_archive_measurements() {
    if cfg!(debug_assertions) {
        panic!("release required");
    }
    let samples: usize = std::env::var("ETX_SCHEMA3_SAMPLES")
        .ok()
        .map(|s| s.parse().unwrap())
        .unwrap_or(8);
    let controls: usize = std::env::var("ETX_SCHEMA3_CONTROLS")
        .ok()
        .map(|s| s.parse().unwrap())
        .unwrap_or(4);
    let only: Option<usize> = std::env::var("ETX_SCHEMA3_CASE")
        .ok()
        .map(|s| s.parse().unwrap());
    let only_body: Option<usize> = std::env::var("ETX_SCHEMA3_BODY")
        .ok()
        .map(|s| s.parse().unwrap());
    assert!(
        samples > 0
            && controls > 0
            && only.is_none_or(|n| n < CASES.len())
            && only_body.is_none_or(|n| [0, 1, 3000].contains(&n))
    );
    let parent = std::env::var_os("ETX_SCHEMA3_PARENT").unwrap_or_else(|| "target".into());
    let dir = tempfile::Builder::new()
        .prefix("schema3-balanced-")
        .tempdir_in(parent)
        .unwrap();
    let whole = Instant::now();
    let mut total = 0;
    println!(
        "{}",
        json!({"kind":"schema3_method","cases":CASES,"phase_pairs":samples,"ordinary_pairs":controls,"selected_case":only,"selected_body":only_body,"order":"23 then 32 on alternating pairs","baseline":"schema2 signed plus local producer self-authentication (adapted count=1)","producer_authentication_count_per_append":[1,1],"native_stage_count_per_append":[1,1],"sqlite_cache_size":-2000,"durability":"DELETE/EXTRA/FK","audits":"all pre/post full","release_test_counters":"thread-local evidence counters compiled in, never consensus inputs","omissions":"no A100000/full Cartesian, cold flush, per-backend isolated peaks, production/live/anti-equivocation guarantees; H1000 max-body optional omitted"})
    );
    for (case, &(a, h, t)) in CASES.iter().enumerate() {
        if only.is_some_and(|n| n != case) {
            continue;
        }
        let f = bench::fixture(a);
        let m = AuthenticatedFixtureManifest::new(
            f.clone(),
            BlockAuthenticationContext::new(f.context(), 2, 1).unwrap(),
            vec![binding("offline-validator", 2)],
        )
        .unwrap();
        let base2 = dir.path().join(format!("schema2-{case}.db"));
        let base3 = dir.path().join(format!("schema3-{case}.db"));
        let start = Instant::now();
        let mut old =
            canonical::CanonicalFixtureStore::create_anchored_fixture(&base2, &f).unwrap();
        let mut new = create(&base3, &m);
        let mut artifacts = Vec::with_capacity(h);
        for _ in 0..h {
            let b = bench::block(&old, &f, t / h, a).unwrap();
            let bytes = packet(&m, &b, 2);
            let g = bench::grant(&old, &f, &b);
            let proof = authenticate(&bytes, &m, None).unwrap();
            let st = old
                .stage_received(&proof.envelope().block().wire_bytes(), g)
                .unwrap();
            assert!(matches!(
                old.commit(st),
                canonical::AppendOutcome::Committed { .. }
            ));
            let st = new.stage_received(&bytes, g).unwrap();
            assert!(matches!(new.commit(st), AppendOutcome::Committed { .. }));
            artifacts.push(bytes);
        }
        equal(new.snapshot().unwrap(), old.snapshot().unwrap());
        let expected2 = old.snapshot().unwrap().clone();
        let expected3 = new.snapshot().unwrap().clone();
        let size2 = std::fs::metadata(&base2).unwrap().len();
        let size3 = std::fs::metadata(&base3).unwrap().len();
        let logical:i64=new.conn().query_row("SELECT coalesce(sum(length(producer_signature)+length(signed_envelope_id)),0) FROM blocks",[],|r|r.get(0)).unwrap();
        assert_eq!(logical, 97 * h as i64);
        assert_eq!(new.settings().unwrap().cache_size, -2000);
        println!(
            "{}",
            json!({"kind":"schema3_fixture","case":case,"accounts":a,"history_blocks":h,"history_txs":t,"construction_ms":ms(start.elapsed()),"schema2_bytes":size2,"schema3_bytes":size3,"evidence_payload_bytes":logical,"separate_schema2_artifact_bytes":artifacts.iter().map(Vec::len).sum::<usize>(),"memory":memory()})
        );
        drop(old);
        drop(new);
        for body in [0, 1, 3000] {
            if only_body.is_some_and(|n| n != body) || (case == 3 && body == 3000) {
                continue;
            }
            let source = canonical::CanonicalFixtureStore::reopen(&base2, &f).unwrap();
            let b = bench::block(&source, &f, body, a).unwrap();
            let input: Vec<_> = b.transactions().iter().map(|b| b.to_vec()).collect();
            let g = bench::grant(&source, &f, &b);
            drop(source);
            let available = packet(&m, &b, 2);
            if case == 1 && body == 3000 {
                spilled_restoration(&base3, &m, &b, &expected3);
            }
            for role in ["producer", "receiver"] {
                for mode in ["phases", "ordinary"] {
                    let count = if mode == "phases" { samples } else { controls };
                    for pair in 0..count {
                        let order = if pair % 2 == 0 { [2, 3] } else { [3, 2] };
                        let mut pair_old = None;
                        let mut pair_new = None;
                        for (position, backend) in order.into_iter().enumerate() {
                            let path = dir
                                .path()
                                .join(format!("c{case}-b{body}-{role}-{mode}-{pair}-{backend}.db"));
                            copy(if backend == 2 { &base2 } else { &base3 }, &path);
                            let mut signing = Duration::ZERO;
                            let attribution: Duration;
                            let mut policy_span = Duration::ZERO;
                            let (
                                pipeline,
                                observations,
                                pre,
                                post,
                                post_ms,
                                ready_recovery,
                                unpublished_recovery,
                                post_artifact_ms,
                            ) = if backend == 2 {
                                let mut s =
                                    canonical::CanonicalFixtureStore::reopen(&path, &f).unwrap();
                                assert_eq!(s.snapshot().unwrap(), &expected2);
                                let pre = old_load(s.load_timings().unwrap());
                                reset();
                                let begin = Instant::now();
                                let (st, outgoing) = if role == "producer" {
                                    let p = s.prepare_next("offline-validator", 7, &input).unwrap();
                                    let now = Instant::now();
                                    let outgoing = packet(&m, p.block(), 2);
                                    signing = now.elapsed();
                                    let now = Instant::now();
                                    authenticate(&outgoing, &m, None).unwrap();
                                    attribution = now.elapsed();
                                    (p.authorize(g).unwrap(), outgoing)
                                } else {
                                    let now = Instant::now();
                                    let proof = authenticate(&available, &m, None).unwrap();
                                    attribution = now.elapsed();
                                    (
                                        s.stage_received(&proof.envelope().block().wire_bytes(), g)
                                            .unwrap(),
                                        available.clone(),
                                    )
                                };
                                let outcome = if mode == "phases" {
                                    s.commit_profiled(st)
                                } else {
                                    s.commit(st)
                                };
                                let elapsed = begin.elapsed();
                                let observed = match outcome {
                                    canonical::AppendOutcome::Committed { timings, .. } => timings,
                                    other => panic!("{other:?}"),
                                };
                                assert_eq!(counters(), (1, 1, (body, body)));
                                let mut local_artifacts = artifacts.clone();
                                local_artifacts.push(outgoing);
                                let finished = s.snapshot().unwrap().clone();
                                pair_old = Some(finished.clone());
                                let mut ready = Value::Null;
                                let mut unpublished = Value::Null;
                                if role == "receiver"
                                    && mode == "ordinary"
                                    && body == if case == 3 { 1 } else { 3000 }
                                {
                                    let now = Instant::now();
                                    s.recover().unwrap();
                                    let native = now.elapsed();
                                    let extra = artifact_pass(&local_artifacts, &m);
                                    ready = json!({"sql_ms":ms(native),"artifact_ms":ms(extra),"combined_nonatomic_ms":ms(native+extra),"load":old_load(s.load_timings().unwrap())});
                                    let p = s.prepare_next("offline-validator", 7, &[]).unwrap();
                                    let bytes = packet(&m, p.block(), 2);
                                    let grant = bench::grant(&s, &f, p.block());
                                    authenticate(&bytes, &m, None).unwrap();
                                    assert!(matches!(
                                        s.commit_unpublished_for_measurement(
                                            p.authorize(grant).unwrap()
                                        ),
                                        canonical::AppendOutcome::RecoveryRequired(_)
                                    ));
                                    local_artifacts.push(bytes);
                                    let now = Instant::now();
                                    assert_eq!(s.recover().unwrap().attempted_present, Some(true));
                                    let native = now.elapsed();
                                    let extra = artifact_pass(&local_artifacts, &m);
                                    unpublished = json!({"sql_ms":ms(native),"artifact_ms":ms(extra),"combined_nonatomic_ms":ms(native+extra),"load":old_load(s.load_timings().unwrap())});
                                }
                                let after = s.snapshot().unwrap().clone();
                                drop(s);
                                let now = Instant::now();
                                let reopened =
                                    canonical::CanonicalFixtureStore::reopen(&path, &f).unwrap();
                                let postms = now.elapsed();
                                assert_eq!(reopened.snapshot().unwrap(), &after);
                                let post = old_load(reopened.load_timings().unwrap());
                                drop(reopened);
                                let extra = artifact_pass(&local_artifacts, &m);
                                (
                                    elapsed,
                                    timings(observed),
                                    pre,
                                    post,
                                    postms,
                                    ready,
                                    unpublished,
                                    extra,
                                )
                            } else {
                                let mut s = AuthenticatedFixtureStore::reopen(&path, &m).unwrap();
                                assert_eq!(s.snapshot().unwrap(), &expected3);
                                let pre = new_load(s.load_timings().unwrap());
                                reset();
                                let begin = Instant::now();
                                let st = if role == "producer" {
                                    let p = s.prepare_next("offline-validator", 7, &input).unwrap();
                                    let now = Instant::now();
                                    let outgoing = packet(&m, p.block(), 2);
                                    signing = now.elapsed();
                                    s.seal_prepared(p, &outgoing, g).unwrap()
                                } else {
                                    s.stage_received(&available, g).unwrap()
                                };
                                let outcome = if mode == "phases" {
                                    s.commit_profiled(st)
                                } else {
                                    s.commit(st)
                                };
                                let elapsed = begin.elapsed();
                                let observed = match outcome {
                                    AppendOutcome::Committed { timings, .. } => timings,
                                    other => panic!("{other:?}"),
                                };
                                assert_eq!(counters(), (1, 1, (body, body)));
                                policy_span = observed.policy_and_prefix;
                                attribution = observed.producer_authentication;
                                let finished = s.snapshot().unwrap().clone();
                                pair_new = Some(finished);
                                let mut ready = Value::Null;
                                let mut unpublished = Value::Null;
                                if role == "receiver"
                                    && mode == "ordinary"
                                    && body == if case == 3 { 1 } else { 3000 }
                                {
                                    let now = Instant::now();
                                    s.recover().unwrap();
                                    ready = json!({"integrated_ms":ms(now.elapsed()),"load":new_load(s.load_timings().unwrap())});
                                    let p = s.prepare_next("offline-validator", 7, &[]).unwrap();
                                    let bytes = packet(&m, p.block(), 2);
                                    let grant = grant(&m, p.base_tip(), p.block());
                                    let st = s.seal_prepared(p, &bytes, grant).unwrap();
                                    s.hook = Some(hook("after_commit"));
                                    assert!(matches!(
                                        s.commit(st),
                                        AppendOutcome::RecoveryRequired(_)
                                    ));
                                    s.hook = None;
                                    let now = Instant::now();
                                    assert_eq!(s.recover().unwrap().attempted_present, Some(true));
                                    unpublished = json!({"integrated_ms":ms(now.elapsed()),"load":new_load(s.load_timings().unwrap())});
                                }
                                let after = s.snapshot().unwrap().clone();
                                drop(s);
                                let now = Instant::now();
                                let reopened =
                                    AuthenticatedFixtureStore::reopen(&path, &m).unwrap();
                                let postms = now.elapsed();
                                assert_eq!(reopened.snapshot().unwrap(), &after);
                                let post = new_load(reopened.load_timings().unwrap());
                                drop(reopened);
                                (
                                    elapsed,
                                    timings(observed.canonical),
                                    pre,
                                    post,
                                    postms,
                                    ready,
                                    unpublished,
                                    Duration::ZERO,
                                )
                            };
                            total += 1;
                            println!(
                                "{}",
                                json!({"kind":"schema3_sample","case":case,"accounts":a,"history_blocks":h,"history_txs":t,"body_size":body,"role":role,"mode":mode,"pair":pair,"order_position":position,"backend":backend,"pipeline_ms":ms(pipeline),"signing_encoding_ms":ms(signing),"attribution_or_signed_staging_ms":ms(attribution),"policy_prefix_ms":ms(policy_span),"observations":observations,"pre_load":pre,"post_load":post,"post_sql_or_integrated_ms":ms(post_ms),"post_external_artifact_ms":ms(post_artifact_ms),"ready_recovery":ready_recovery,"unpublished_recovery":unpublished_recovery,"database_bytes":std::fs::metadata(&path).unwrap().len(),"evidence_payload_bytes":if backend==3{97*(h+1+usize::from(role=="receiver"&&mode=="ordinary"&&body==if case==3{1}else{3000}))}else{0},"memory":memory(),"producer_authentications":1,"native_stages":1})
                            );
                        }
                        equal(pair_new.as_ref().unwrap(), pair_old.as_ref().unwrap());
                    }
                }
            }
        }
    }
    println!(
        "{}",
        json!({"kind":"schema3_complete","samples":total,"failures":0,"outliers":"all retained","elapsed_ms":ms(whole.elapsed()),"default_cache_unchanged":true,"archive_assurance":"attribution under caller policy, not independently pinned signature choice/selection/freshness"})
    );
}
