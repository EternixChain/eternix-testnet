//! Bounded profiling only: unchanged SQL/checks/sync; independent complete history copies per sample.
use super::*;
use serde_json::{Value, json};
use std::fs::{File, OpenOptions};

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}
fn phase_json(p: &SqlProfile) -> Value {
    json!({"acquisition_ms":ms(p.acquisition),"metadata_base_ms":ms(p.metadata_base),"account_comparison_ms":ms(p.account_comparison),
        "uniqueness_probes_ms":ms(p.uniqueness_probes),"changed_account_writes_ms":ms(p.changed_account_writes),"accounting_write_ms":ms(p.accounting_write),
        "block_insertion_ms":ms(p.block_insertion),"body_insertion_ms":ms(p.body_insertion),"transaction_index_insertion_ms":ms(p.transaction_index_insertion),
        "revision_tip_ms":ms(p.revision_tip),"commit_return_ms":ms(p.commit_return),"observed_total_ms":ms(p.observed_total())})
}
fn db_counters(c: &Connection) -> Value {
    let mut result = serde_json::Map::new();
    for (name, op) in [
        ("hits", ffi::SQLITE_DBSTATUS_CACHE_HIT),
        ("misses", ffi::SQLITE_DBSTATUS_CACHE_MISS),
        ("writes", ffi::SQLITE_DBSTATUS_CACHE_WRITE),
        ("spills", ffi::SQLITE_DBSTATUS_CACHE_SPILL),
        ("cache_bytes", ffi::SQLITE_DBSTATUS_CACHE_USED),
    ] {
        let mut current = 0i64;
        let mut high = 0i64;
        // Read-only SQLite diagnostics under this owner's exclusive access. Never reset counters,
        // alter cache limits, or treat diagnostic success as transaction/recovery success.
        let rc = unsafe { ffi::sqlite3_db_status64(c.handle(), op, &mut current, &mut high, 0) };
        result.insert(
            name.into(),
            if rc == ffi::SQLITE_OK {
                json!(current)
            } else {
                Value::Null
            },
        );
    }
    Value::Object(result)
}
fn counter_delta(before: &Value, after: &Value) -> Value {
    json!({"hits":after["hits"].as_i64().unwrap()-before["hits"].as_i64().unwrap(),"misses":after["misses"].as_i64().unwrap()-before["misses"].as_i64().unwrap(),
        "writes":after["writes"].as_i64().unwrap()-before["writes"].as_i64().unwrap(),"spills":after["spills"].as_i64().unwrap()-before["spills"].as_i64().unwrap(),"cache_bytes_after":after["cache_bytes"]})
}
fn plan(c: &Connection, query: &str, parameters: &[&dyn rusqlite::ToSql]) -> Value {
    let mut statement = c.prepare(&format!("EXPLAIN QUERY PLAN {query}")).unwrap();
    json!(
        statement
            .query_map(parameters, |r| r.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    )
}
fn describe(c: &Connection, history: usize) -> Value {
    let id = [0x55u8; 32];
    let sender = sender();
    let nonce = (history as u64).to_be_bytes();
    let revision = 100u64.to_be_bytes();
    let mut statement = c
        .prepare(
            "SELECT name,count(*),sum(pgsize),sum(ncell) FROM dbstat GROUP BY name ORDER BY name",
        )
        .unwrap();
    let pages=statement.query_map([],|r|Ok(json!({"name":r.get::<_,String>(0)?,"pages":r.get::<_,i64>(1)?,"bytes":r.get::<_,i64>(2)?,"cells":r.get::<_,i64>(3)?}))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
    json!({"kind":"sql_layout","retained_transactions":history,"page_count":c.query_row("PRAGMA page_count",[],|r|r.get::<_,i64>(0)).unwrap(),"dbstat":pages,
        "transaction_probe_plan":plan(c,"SELECT EXISTS(SELECT 1 FROM transactions WHERE id=?1 OR (sender=?2 AND nonce=?3))",&[&id.as_slice(),&sender.as_slice(),&nonce.as_slice()]),
        "block_probe_plan":plan(c,"SELECT EXISTS(SELECT 1 FROM blocks WHERE hash=?1 OR slot=?2)",&[&id.as_slice(),&revision.as_slice()]),
        "transaction_insert_plan":plan(c,"INSERT INTO transactions VALUES(?1,?2,?3,?4,?5,?6)",&[&id.as_slice(),&revision.as_slice(),&0u64.to_be_bytes().as_slice(),&sender.as_slice(),&nonce.as_slice(),&[0u8;199].as_slice()])})
}
pub(super) fn independent_copy(from: &Path, to: &Path) {
    // The source is a closed, acknowledged DELETE-mode fixture, with no journal. A new independent
    // dataset keeps every historical row; this is neither pruning nor mutation of an active store.
    let mut source = File::open(from).unwrap();
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(to)
        .unwrap();
    std::io::copy(&mut source, &mut destination).unwrap();
    destination.sync_all().unwrap();
    drop(destination);
    disk::sync_path(to).unwrap();
}
fn clock_cost() -> Value {
    let count = 200_000u32;
    let now = Instant::now();
    for _ in 0..count {
        std::hint::black_box(());
    }
    let control = now.elapsed();
    let now = Instant::now();
    for _ in 0..count {
        let t = Instant::now();
        std::hint::black_box(t.elapsed());
    }
    json!({"kind":"clock_overhead","pairs":count,"control_ns_per_iteration":control.as_nanos() as f64/count as f64,"clock_pair_ns_per_iteration":now.elapsed().as_nanos() as f64/count as f64,
        "phase_instrumentation":"fixed boundary clocks only; no per-row clocks or alternate SQL"})
}

pub(super) fn process_memory() -> Value {
    // Platform measurement only; HWM is process-cumulative, not a per-budget hard memory cap.
    #[cfg(target_os = "linux")]
    if let Ok(text) = std::fs::read_to_string("/proc/self/status") {
        let value = |name: &str| {
            text.lines()
                .find(|l| l.starts_with(name))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
        };
        return json!({"rss_kib":value("VmRSS:"),"process_hwm_kib":value("VmHWM:")});
    }
    Value::Null
}
fn set_io_phases(store: &mut CanonicalFixtureStore, observer: &Harness) {
    let mut phase = observer.phase_controller();
    phase("checks_and_accounts");
    store.hook = Some(Box::new(move |p| {
        match p {
            "before_begin" => phase("checks_and_accounts"),
            "accounts" => phase("accounting"),
            "accounting" => phase("block"),
            "block" => phase("body"),
            "body" => phase("transaction_indexes"),
            "indexes" => phase("revision_tip"),
            "before_commit" => phase("commit"),
            "after_commit" => phase("after_commit"),
            _ => (),
        }
        Ok(())
    }));
}
fn load_json(t: LoadTimings) -> Value {
    json!({"total_ms":ms(t.total),"open_configuration_ms":ms(t.open_configuration),"validation_materialization_ms":ms(t.validation_materialization),"audit_ms":ms(t.audit),"equality_ms":ms(t.equality),"barrier_ms":ms(t.barrier),"installation_ms":ms(t.installation)})
}

#[test]
#[ignore = "balanced optional-cache release experiment; full independent-file audits retained"]
fn cache_budget_comparison() {
    if cfg!(debug_assertions) {
        panic!("release required");
    }
    let parent = PathBuf::from(
        std::env::var_os("ETX_CACHE_COMPARE_PARENT").unwrap_or_else(|| "target".into()),
    );
    let samples: usize = std::env::var("ETX_CACHE_COMPARE_SAMPLES")
        .ok()
        .map(|v| v.parse().unwrap())
        .unwrap_or(8);
    let controls: usize = std::env::var("ETX_CACHE_COMPARE_CONTROLS")
        .ok()
        .map(|v| v.parse().unwrap())
        .unwrap_or(4);
    let passive: usize = std::env::var("ETX_CACHE_COMPARE_PASSIVE")
        .ok()
        .map(|v| v.parse().unwrap())
        .unwrap_or(4);
    let representative: usize = std::env::var("ETX_CACHE_COMPARE_REPRESENTATIVE")
        .ok()
        .map(|v| v.parse().unwrap())
        .unwrap_or(4);
    let only_history: Option<usize> = std::env::var("ETX_CACHE_COMPARE_HISTORY")
        .ok()
        .map(|v| v.parse().unwrap());
    let only_body: Option<usize> = std::env::var("ETX_CACHE_COMPARE_BODY")
        .ok()
        .map(|v| v.parse().unwrap());
    assert!(samples > 0 && controls > 0 && passive > 0 && representative > 0);
    // Reject an empty selection instead of printing a misleading successful experiment summary.
    assert!(
        only_history.is_none_or(|h| [0, 100000].contains(&h))
            && only_body.is_none_or(|n| [0, 1, 3000].contains(&n))
    );
    let dir = tempfile::Builder::new()
        .prefix("stage4-cache-compare-")
        .tempdir_in(parent)
        .unwrap();
    let m = bench::fixture(1000);
    println!("{}", clock_cost());
    println!(
        "{}",
        json!({"kind":"cache_compare_method","accounts":1000,"retained_blocks":100,"retained_transactions":[0,100000],"body_sizes":[0,1,3000],"phase_samples_per_budget":samples,"stock_samples_per_budget":controls,"passive_samples_per_budget":passive,"representative_samples_per_budget":representative,
        "budgets_kib":[2000,32768],"budget_order":"AB for even pair, BA for odd pair; independent complete copied files","history_signing_copy":"outside append timing","audits":"full pre and post for every sample; never bypassed","selected_history":only_history,"selected_body":only_body})
    );
    for history in [0usize, 100_000] {
        if only_history.is_some_and(|h| h != history) {
            continue;
        }
        let base = dir.path().join(format!("base-{history}.db"));
        let now = Instant::now();
        let mut s = CanonicalFixtureStore::create_anchored_fixture(&base, &m).unwrap();
        for _ in 0..100 {
            let b = bench::block(&s, &m, history / 100, 1000).unwrap();
            bench::append(&mut s, &m, &b).unwrap();
        }
        let expected = s.snapshot().unwrap().clone();
        println!("{}", describe(s.conn(), history));
        drop(s);
        println!(
            "{}",
            json!({"kind":"cache_compare_fixture","history":history,"construction_ms":ms(now.elapsed()),"bytes":std::fs::metadata(&base).unwrap().len()})
        );
        for body in [0usize, 1, 3000] {
            if only_body.is_some_and(|n| n != body) {
                continue;
            }
            for mode in ["stock", "phases", "passive"] {
                let n = match mode {
                    "stock" => controls,
                    "phases" => samples,
                    _ => passive,
                };
                for pair in 0..n {
                    let order = if pair % 2 == 0 {
                        [CachePolicy::ExistingDefault, CachePolicy::Trial32MiB]
                    } else {
                        [CachePolicy::Trial32MiB, CachePolicy::ExistingDefault]
                    };
                    let mut results = Vec::new();
                    for (position, policy) in order.into_iter().enumerate() {
                        let path = dir
                            .path()
                            .join(format!("h{history}-n{body}-{mode}-{pair}-{policy:?}.db"));
                        independent_copy(&base, &path);
                        let observer = Harness::new();
                        observer.passive_profile();
                        let before_memory = process_memory();
                        let open = Instant::now();
                        let mut s = if mode == "passive" {
                            CanonicalFixtureStore::load_with_cache(
                                &path,
                                &m,
                                policy,
                                Some(observer.name()),
                            )
                            .unwrap()
                        } else {
                            CanonicalFixtureStore::reopen_with_cache_policy(&path, &m, policy)
                                .unwrap()
                        };
                        let reopen_ms = ms(open.elapsed());
                        let reopen = load_json(s.load_timings().unwrap());
                        assert_eq!(s.snapshot().unwrap(), &expected);
                        let settings = s.settings().unwrap();
                        assert_eq!(settings.cache_size, policy.pragma_value());
                        assert_eq!(settings.synchronous, 3);
                        assert!(settings.foreign_keys);
                        assert_eq!(settings.journal_mode, "delete");
                        let spill: i64 = s
                            .conn()
                            .query_row("PRAGMA cache_spill", [], |r| r.get(0))
                            .unwrap();
                        assert!(spill > 0);
                        let b = bench::block(&s, &m, body, 1000).unwrap();
                        let wire = b.wire_bytes();
                        let g = bench::grant(&s, &m, &b);
                        if mode == "passive" {
                            set_io_phases(&mut s, &observer);
                        }
                        observer.reset();
                        let before = db_counters(s.conn());
                        let start = Instant::now();
                        let st = s.stage_received(&wire, g).unwrap();
                        let result = if mode == "stock" {
                            s.commit(st)
                        } else {
                            s.commit_profiled(st)
                        };
                        let pipeline = ms(start.elapsed());
                        let after = db_counters(s.conn());
                        let times = match result {
                            AppendOutcome::Committed { timings, .. } => timings,
                            other => panic!("budget append: {other:?}"),
                        };
                        let final_snapshot = s.snapshot().unwrap().clone();
                        results.push(final_snapshot.clone());
                        let memory_after = process_memory();
                        println!(
                            "{}",
                            json!({"kind":"cache_compare_sample","history":history,"body_size":body,"mode":mode,"pair":pair,"order_position":position,"policy":format!("{policy:?}"),"budget_kib":-policy.pragma_value(),"pipeline_ms":pipeline,"durable_ms":ms(times.durable_commit),"staging_ms":ms(times.staging),"copy_ms":ms(times.cache_preparation),"drop_ms":ms(times.cache_destruction),"sql":times.sql_profile.map(|p|phase_json(&p)),"phase_residual_ms":times.sql_profile.map(|p|ms(times.durable_commit.saturating_sub(p.observed_total()))),
                            "sqlite_cache":counter_delta(&before,&after),"io":if mode=="passive"{json!(observer.io_profile())}else{Value::Null},"reopen_ms":reopen_ms,"reopen":reopen,"spill_enabled_reported_threshold":spill,"memory_before":before_memory,"memory_after":memory_after})
                        );
                        drop(s);
                        let audited =
                            CanonicalFixtureStore::reopen_with_cache_policy(&path, &m, policy)
                                .unwrap();
                        assert_eq!(audited.snapshot().unwrap(), &final_snapshot);
                        drop(audited);
                    }
                    assert_eq!(
                        results[0], results[1],
                        "complete budget pair state/archive/index/tip equivalence"
                    );
                }
            }
        }
        if history == 100_000 && only_body.is_none_or(|n| n == 3000) {
            for pair in 0..representative {
                let order = if pair % 2 == 0 {
                    [CachePolicy::ExistingDefault, CachePolicy::Trial32MiB]
                } else {
                    [CachePolicy::Trial32MiB, CachePolicy::ExistingDefault]
                };
                let mut snapshots = Vec::new();
                for (position, policy) in order.into_iter().enumerate() {
                    let path = dir
                        .path()
                        .join(format!("representative-{pair}-{policy:?}.db"));
                    independent_copy(&base, &path);
                    let observer = Harness::new();
                    observer.passive_profile();
                    let mut s = CanonicalFixtureStore::load_with_cache(
                        &path,
                        &m,
                        policy,
                        Some(observer.name()),
                    )
                    .unwrap();
                    let b = bench::block(&s, &m, 3000, 1000).unwrap();
                    let input: Vec<_> = b.transactions().iter().map(|b| b.to_vec()).collect();
                    set_io_phases(&mut s, &observer);
                    observer.reset();
                    let before = db_counters(s.conn());
                    let start = Instant::now();
                    let p = s
                        .prepare_next(m.anchor().proposer(), m.anchor().header().ticket_id, &input)
                        .unwrap();
                    assert_eq!(p.block(), &b);
                    let st = p.authorize(bench::grant(&s, &m, &b)).unwrap();
                    let times = match s.commit_profiled(st) {
                        AppendOutcome::Committed { timings, .. } => timings,
                        other => panic!("producer {other:?}"),
                    };
                    let producer = ms(start.elapsed());
                    let after = db_counters(s.conn());
                    let expected = s.snapshot().unwrap().clone();
                    snapshots.push(expected.clone());
                    drop(s);
                    let open = Instant::now();
                    let mut s =
                        CanonicalFixtureStore::reopen_with_cache_policy(&path, &m, policy).unwrap();
                    let reopen = ms(open.elapsed());
                    let reopened = load_json(s.load_timings().unwrap());
                    assert_eq!(s.snapshot().unwrap(), &expected);
                    // A real durable empty commit followed by test-only publication failure poisons
                    // the owner; recovery includes exact-attempt reconciliation and the full audit.
                    let p = s
                        .prepare_next(m.anchor().proposer(), m.anchor().header().ticket_id, &[])
                        .unwrap();
                    let g = bench::grant(&s, &m, p.block());
                    let st = p.authorize(g).unwrap();
                    s.hook = Some(hook_at("after_commit"));
                    assert!(matches!(s.commit(st), AppendOutcome::RecoveryRequired(_)));
                    s.hook = None;
                    let start = Instant::now();
                    let report = s.recover().unwrap();
                    let recover = ms(start.elapsed());
                    assert_eq!(report.attempted_present, Some(true));
                    assert_eq!(s.settings().unwrap().cache_size, policy.pragma_value());
                    println!(
                        "{}",
                        json!({"kind":"cache_compare_representative","pair":pair,"order_position":position,"policy":format!("{policy:?}"),"budget_kib":-policy.pragma_value(),"history":history,"body_size":3000,"producer_pipeline_ms":producer,"producer_sql":times.sql_profile.map(|p|phase_json(&p)),"sqlite_cache":counter_delta(&before,&after),"reopen_total_ms":reopen,"reopen":reopened,"unpublished_recovery_ms":recover,"recovery":load_json(s.load_timings().unwrap()),"attempted_present":report.attempted_present,"memory":process_memory()})
                    );
                }
                assert_eq!(snapshots[0], snapshots[1]);
            }
            for policy in [CachePolicy::ExistingDefault, CachePolicy::Trial32MiB] {
                let path = dir.path().join(format!("isolated-memory-{policy:?}.db"));
                independent_copy(&base, &path);
                let output = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "canonical_fixture::tests::cache_policy::isolated_memory_child",
                        "--ignored",
                        "--nocapture",
                    ])
                    .env("ETX_CACHE_MEMORY_PATH", &path)
                    .env(
                        "ETX_CACHE_MEMORY_POLICY",
                        if policy == CachePolicy::Trial32MiB {
                            "trial32"
                        } else {
                            "default"
                        },
                    )
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "isolated memory process failed: {} {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                print!("{}", String::from_utf8_lossy(&output.stdout));
            }
        }
    }
    println!(
        "{}",
        json!({"kind":"cache_compare_complete","failures":0,"default_changed":false,"spill_policy_assignment":false,"audits":"all retained","outliers":"none discarded"})
    );
}

#[test]
fn profiled_and_ordinary_commit_are_equivalent_and_phases_account_for_time() {
    let d = TempDir::new().unwrap();
    let m = manifest(4);
    let mut a =
        CanonicalFixtureStore::create_anchored_fixture(d.path().join("ordinary.db"), &m).unwrap();
    let mut b =
        CanonicalFixtureStore::create_anchored_fixture(d.path().join("profiled.db"), &m).unwrap();
    let ordinary = stage_next(&a, &[transfer(0, 17, [0x22; 20], 0)]);
    let profiled = stage_next(&b, &[transfer(0, 17, [0x22; 20], 0)]);
    match a.commit(ordinary) {
        AppendOutcome::Committed { timings, .. } => assert!(timings.sql_profile.is_none()),
        other => panic!("{other:?}"),
    }
    match b.commit_profiled(profiled) {
        AppendOutcome::Committed { timings, .. } => {
            let p = timings.sql_profile.expect("explicit profile");
            assert_eq!(p.account_comparison, timings.stored_comparison);
            assert!(p.observed_total() <= timings.durable_commit);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(a.snapshot().unwrap(), b.snapshot().unwrap());
    let old = b.snapshot().unwrap().clone();
    let st = stage_next(&b, &[]);
    b.hook = Some(hook_at("tip"));
    assert!(matches!(b.commit_profiled(st), AppendOutcome::Aborted(_)));
    assert_eq!(b.snapshot().unwrap(), &old);
    b.hook = None;
    let st = stage_next(&b, &[]);
    b.hook = Some(hook_at("after_commit"));
    assert!(matches!(
        b.commit_profiled(st),
        AppendOutcome::RecoveryRequired(_)
    ));
    assert!(b.snapshot().is_err());
    b.hook = None;
    assert_eq!(b.recover().unwrap().attempted_present, Some(true));
}

#[test]
#[ignore = "bounded real-file release SQL profiling; explicitly invoked outside correctness suite"]
fn durable_sql_profile() {
    if cfg!(debug_assertions) {
        panic!("release required");
    }
    let parent = PathBuf::from(
        std::env::var_os("ETX_STAGE4_PROFILE_PARENT").unwrap_or_else(|| "target".into()),
    );
    let phase_samples: usize = std::env::var("ETX_STAGE4_PROFILE_SAMPLES")
        .ok()
        .map(|s| s.parse().unwrap())
        .unwrap_or(12);
    let controls: usize = std::env::var("ETX_STAGE4_PROFILE_CONTROLS")
        .ok()
        .map(|s| s.parse().unwrap())
        .unwrap_or(3);
    let passive: usize = std::env::var("ETX_STAGE4_PROFILE_PASSIVE")
        .ok()
        .map(|s| s.parse().unwrap())
        .unwrap_or(3);
    assert!(phase_samples > 0 && controls > 0 && passive > 0);
    let only_history: Option<usize> = std::env::var("ETX_STAGE4_PROFILE_HISTORY")
        .ok()
        .map(|v| v.parse().unwrap());
    let only_body: Option<usize> = std::env::var("ETX_STAGE4_PROFILE_BODY")
        .ok()
        .map(|v| v.parse().unwrap());
    assert!(
        only_history.is_none_or(|n| [0, 100000].contains(&n))
            && only_body.is_none_or(|n| [0, 1, 3000].contains(&n))
    );
    let dir = tempfile::Builder::new()
        .prefix("stage4-sql-profile-")
        .tempdir_in(&parent)
        .unwrap();
    let m = bench::fixture(1000);
    println!("{}", clock_cost());
    println!(
        "{}",
        json!({"kind":"profile_method","accounts":1000,"retained_blocks":100,"retained_transactions":[0,100000],"body_sizes":[0,1,3000],"phase_samples":phase_samples,"stock_controls":controls,"passive_samples":passive,
        "selected_history":only_history,"selected_body":only_body,"independent_full_history_copy_per_sample":true,"reopen_audit":"full, never bypassed; outside append timer","cache":"warm OS; reopened SQLite owner; no cache flushing", "durability":"verified DELETE/EXTRA/FK; default cache retained"})
    );
    for history in [0usize, 100_000] {
        if only_history.is_some_and(|n| n != history) {
            continue;
        }
        let base = dir.path().join(format!("base-{history}.db"));
        let now = Instant::now();
        let mut source = CanonicalFixtureStore::create_anchored_fixture(&base, &m).unwrap();
        for _ in 0..100 {
            let b = bench::block(&source, &m, history / 100, 1000).unwrap();
            bench::append(&mut source, &m, &b).unwrap();
        }
        let expected = source.snapshot().unwrap().clone();
        let settings = source.settings().unwrap();
        assert_eq!(settings.journal_mode, "delete");
        assert_eq!(settings.synchronous, 3);
        assert!(settings.foreign_keys);
        println!("{}", describe(source.conn(), history));
        println!(
            "{}",
            json!({"kind":"profile_fixture","history":history,"history_construction_ms":ms(now.elapsed()),"bytes":std::fs::metadata(&base).unwrap().len(),"settings":format!("{settings:?}")})
        );
        drop(source);
        for body_size in [0usize, 1, 3000] {
            if only_body.is_some_and(|n| n != body_size) {
                continue;
            }
            for mode in ["stock", "phases", "passive"] {
                let samples = match mode {
                    "stock" => controls,
                    "phases" => phase_samples,
                    _ => passive,
                };
                for sample in 0..samples {
                    let path = dir
                        .path()
                        .join(format!("h-{history}-n-{body_size}-{mode}-{sample}.db"));
                    independent_copy(&base, &path);
                    let observer = Harness::new();
                    observer.passive_profile();
                    let reopen = Instant::now();
                    let mut store = if mode == "passive" {
                        CanonicalFixtureStore::load(&path, &m, Some(observer.name())).unwrap()
                    } else {
                        CanonicalFixtureStore::reopen(&path, &m).unwrap()
                    };
                    let reopen_ms = ms(reopen.elapsed());
                    assert_eq!(store.snapshot().unwrap(), &expected);
                    let block = bench::block(&store, &m, body_size, 1000).unwrap();
                    let wire = block.wire_bytes();
                    let grant = bench::grant(&store, &m, &block);
                    if mode == "passive" {
                        let mut phase = observer.phase_controller();
                        phase("checks_and_accounts");
                        store.hook = Some(Box::new(move |p| {
                            match p {
                                "before_begin" => phase("checks_and_accounts"),
                                "accounts" => phase("accounting"),
                                "accounting" => phase("block"),
                                "block" => phase("body"),
                                "body" => phase("transaction_indexes"),
                                "indexes" => phase("revision_tip"),
                                "before_commit" => phase("commit"),
                                "after_commit" => phase("after_commit"),
                                _ => (),
                            }
                            Ok(())
                        }));
                    }
                    observer.reset();
                    let before = db_counters(store.conn());
                    let begin = Instant::now();
                    let staged = store.stage_received(&wire, grant).unwrap();
                    let result = if mode == "stock" {
                        store.commit(staged)
                    } else {
                        store.commit_profiled(staged)
                    };
                    let pipeline = begin.elapsed();
                    let after = db_counters(store.conn());
                    let (tip, timings) = match result {
                        AppendOutcome::Committed { tip, timings, .. } => (tip, timings),
                        other => panic!("profile append failed: {other:?}"),
                    };
                    assert_eq!(tip.revision, 101);
                    assert_eq!(
                        store.snapshot().unwrap().transactions.len(),
                        history + body_size
                    );
                    if let Some(p) = timings.sql_profile {
                        assert!(p.observed_total() <= timings.durable_commit);
                    }
                    println!(
                        "{}",
                        json!({"kind":"sql_sample","history":history,"body_size":body_size,"mode":mode,"sample":sample,"pipeline_ms":ms(pipeline),"durable_ms":ms(timings.durable_commit),"staging_ms":ms(timings.staging),"copy_ms":ms(timings.cache_preparation),"drop_ms":ms(timings.cache_destruction),"reopen_ms":reopen_ms,
                        "sql":timings.sql_profile.map(|p|phase_json(&p)),"sqlite_cache":counter_delta(&before,&after),"io":if mode=="passive" {json!(observer.io_profile())} else {Value::Null},"phase_residual_ms":timings.sql_profile.map(|p|ms(timings.durable_commit.saturating_sub(p.observed_total())))})
                    );
                    // Complete materialized/archive replay validation after each timed append too.
                    // Observer profiling never substitutes for ordinary no-create reopening/audit.
                    let finished = store.snapshot().unwrap().clone();
                    drop(store);
                    let audited = CanonicalFixtureStore::reopen(&path, &m).unwrap();
                    assert_eq!(audited.snapshot().unwrap(), &finished);
                    drop(audited);
                }
            }
        }
    }
    println!(
        "{}",
        json!({"kind":"profile_complete","failures":0,"outliers":"retained","validation":"full pre/post reopen/audit for every independent sample","optimization_implemented":false})
    );
}
