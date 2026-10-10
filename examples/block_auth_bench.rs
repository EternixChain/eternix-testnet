//! Balanced complete signed/unsigned offline producer/receiver paths, real default-budget SQLite.
//! Each sample copies a closed complete base and retains full pre/post audits. Signature artifacts
//! are separately held/re-authenticated test inputs, never evidence loaded by SQLite recovery.
use eternix_testnet as chain;
// This shared offline owner also exposes replay-only create/close operations, tested separately.
#[allow(dead_code)]
mod block_auth_support;
// Only the existing deterministic fixture/body construction is reused; its older driver is separate.
#[allow(dead_code)]
#[path = "stage4_support/bench.rs"]
mod fixture;
use block_auth_support::{SignedFixtureReceiver, toy_binding, toy_producer_key};
use chain::block_authentication::{BlockAuthenticationContext, authenticate_block, sign_block};
use chain::canonical_fixture::{
    AppendOutcome, AppendTimings, CanonicalFixtureStore, LoadTimings, Snapshot,
};
use serde_json::{Value, json};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const CASES: &[(usize, usize, usize)] = &[(1000, 100, 0), (1000, 100, 100000), (10000, 0, 0)];
fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}
fn load(t: LoadTimings) -> Value {
    json!({"total_ms":ms(t.total),"audit_ms":ms(t.audit),"validation_materialization_ms":ms(t.validation_materialization),"barrier_ms":ms(t.barrier),"configuration_ms":ms(t.open_configuration),"installation_ms":ms(t.installation)})
}
fn phases(t: AppendTimings) -> Value {
    if let Some(s) = t.sql_profile {
        json!({"acquisition_ms":ms(s.acquisition),"metadata_base_ms":ms(s.metadata_base),"account_comparison_ms":ms(s.account_comparison),"uniqueness_probes_ms":ms(s.uniqueness_probes),"changed_accounts_ms":ms(s.changed_account_writes),"accounting_ms":ms(s.accounting_write),"block_ms":ms(s.block_insertion),"body_ms":ms(s.body_insertion),"transaction_indexes_ms":ms(s.transaction_index_insertion),"revision_tip_ms":ms(s.revision_tip),"commit_return_ms":ms(s.commit_return)})
    } else {
        Value::Null
    }
}
fn memory() -> Value {
    // Diagnostic Linux measurements only. Shared-process HWM is cumulative, not per-sample peak.
    let text = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let get = |name: &str| {
        text.lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|n| n.parse::<u64>().ok())
    };
    json!({"rss_kib":get("VmRSS:"),"cumulative_hwm_kib":get("VmHWM:")})
}
fn copy(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut src = File::open(from)?;
    let mut dst = OpenOptions::new().write(true).create_new(true).open(to)?;
    std::io::copy(&mut src, &mut dst)?;
    dst.sync_all()?;
    File::open(to.parent().unwrap())?.sync_all()?;
    Ok(())
}
fn committed(outcome: AppendOutcome) -> Result<AppendTimings, Box<dyn std::error::Error>> {
    match outcome {
        AppendOutcome::Committed { timings, .. } => Ok(timings),
        other => Err(format!("benchmark append {other:?}").into()),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let parent = PathBuf::from(args.first().map(String::as_str).unwrap_or("target"));
    let samples: usize = args.get(1).map(|n| n.parse()).transpose()?.unwrap_or(8);
    let controls: usize = args.get(2).map(|n| n.parse()).transpose()?.unwrap_or(4);
    let selected: Option<usize> = args.get(3).map(|n| n.parse()).transpose()?;
    let body_select: Option<usize> = args.get(4).map(|n| n.parse()).transpose()?;
    if cfg!(debug_assertions)
        || samples == 0
        || controls == 0
        || selected.is_some_and(|n| n >= CASES.len())
        || body_select.is_some_and(|n| ![0, 1, 3000].contains(&n))
    {
        return Err("release, positive samples and valid selections required".into());
    }
    let dir = tempfile::Builder::new()
        .prefix("block-auth-balanced-")
        .tempdir_in(parent)?;
    println!(
        "{}",
        json!({"kind":"block_auth_method","cases":CASES,"phase_pairs":samples,"ordinary_pairs":controls,"selected_case":selected,"selected_body":body_select,"roles":["producer","receiver"],"admission":["unsigned","signed"],"order":"US even pair / SU odd pair, full independent file copies","cache_kib":2000,"durability":"DELETE/EXTRA/FK","audits":"full pre/post every sample","producer_timer":"includes block signing and outgoing unsigned/signed encoding/preallocation; native transaction signing outside","receiver_timer":"available exact wire through one cold producer verification/native stage/commit/install/return","memory":"shared-process cumulative HWM, not per-policy or per-sample peak","omissions":"no full Cartesian matrix, 100000 accounts, cold-cache flushing, host isolation, live economics/transport or authenticated SQL recovery"})
    );
    let mut completed = 0usize;
    for (case, &(accounts, history_blocks, history_txs)) in CASES.iter().enumerate() {
        if selected.is_some_and(|n| n != case) {
            continue;
        }
        let m = fixture::fixture(accounts);
        let context = BlockAuthenticationContext::new(m.context(), 2, 1)?;
        let binding = toy_binding(m.anchor().proposer());
        let producer_key = toy_producer_key();
        let base = dir.path().join(format!("base-{case}.db"));
        let now = Instant::now();
        let mut s = CanonicalFixtureStore::create_anchored_fixture(&base, &m)?;
        let mut historical_artifacts = Vec::with_capacity(history_blocks);
        for _ in 0..history_blocks {
            let b = fixture::block(&s, &m, history_txs / history_blocks, accounts)?;
            let artifact = sign_block(&b, &producer_key, &context, &binding)?.wire_bytes();
            fixture::append(&mut s, &m, &b)?;
            historical_artifacts.push(artifact);
        }
        let expected = s.snapshot()?.clone();
        assert_eq!(expected.transactions.len(), history_txs);
        let settings = s.settings()?;
        assert_eq!(settings.cache_size, -2000);
        assert_eq!(settings.synchronous, 3);
        assert_eq!(settings.journal_mode, "delete");
        assert!(settings.foreign_keys);
        let construction = ms(now.elapsed());
        drop(s);
        println!(
            "{}",
            json!({"kind":"block_auth_fixture","case":case,"accounts":accounts,"history_blocks":history_blocks,"history_txs":history_txs,"construction_ms":construction,"database_bytes":std::fs::metadata(&base)?.len(),"signed_test_artifact_bytes":historical_artifacts.iter().map(Vec::len).sum::<usize>(),"page_size":settings.page_size,"cache_size":settings.cache_size})
        );
        // Entire retained producer-envelope test artifact pass is separately measured; it never
        // replaces SQL's native execution audit or creates evidence rows in the closed base.
        for pair in 0..4 {
            let begin = Instant::now();
            for bytes in &historical_artifacts {
                std::hint::black_box(authenticate_block(bytes, &context, &binding, None)?);
            }
            println!(
                "{}",
                json!({"kind":"block_auth_artifact_audit","case":case,"pair":pair,"envelopes":historical_artifacts.len(),"elapsed_ms":ms(begin.elapsed()),"source":"retained in-memory signed test artifacts, warm OS/CPU; not SQL"})
            );
        }
        for body_size in [0usize, 1, 3000] {
            if body_select.is_some_and(|n| n != body_size) {
                continue;
            }
            // Inputs and grant come from the closed trusted base/controller, not a receiver packet.
            // Close this untimed construction owner before making any independent sample copies.
            let source = CanonicalFixtureStore::reopen(&base, &m)?;
            assert_eq!(source.snapshot()?, &expected);
            let b = fixture::block(&source, &m, body_size, accounts)?;
            let body: Vec<_> = b.transactions().iter().map(|t| t.to_vec()).collect();
            let grant = fixture::grant(&source, &m, &b);
            drop(source);
            for role in ["producer", "receiver"] {
                for mode in ["phases", "ordinary"] {
                    let count = if mode == "phases" { samples } else { controls };
                    for pair in 0..count {
                        let mut states = Vec::<Snapshot>::with_capacity(2);
                        let order = if pair % 2 == 0 {
                            [false, true]
                        } else {
                            [true, false]
                        };
                        for (position, signed) in order.into_iter().enumerate() {
                            let path = dir.path().join(format!(
                                "c{case}-n{body_size}-{role}-{mode}-p{pair}-s{signed}.db"
                            ));
                            copy(&base, &path)?;
                            let reopen_begin = Instant::now();
                            let mut receiver = if role == "receiver" && signed {
                                Some(SignedFixtureReceiver::reopen(
                                    &path,
                                    &m,
                                    context,
                                    binding.clone(),
                                )?)
                            } else {
                                None
                            };
                            let mut store = if receiver.is_none() {
                                Some(CanonicalFixtureStore::reopen(&path, &m)?)
                            } else {
                                None
                            };
                            let reopen = if let Some(s) = &store {
                                assert_eq!(s.snapshot()?, &expected);
                                assert_eq!(s.settings()?.cache_size, -2000);
                                load(s.load_timings()?)
                            } else {
                                let s = receiver.as_ref().unwrap();
                                assert_eq!(s.snapshot()?, &expected);
                                assert_eq!(s.settings()?.cache_size, -2000);
                                load(s.load_timings()?)
                            };
                            let reopen_ms = ms(reopen_begin.elapsed());
                            let mut auth_ms = 0.0;
                            let mut signing_encoding_ms = 0.0;
                            let mut preparation_ms = 0.0;
                            let mut recovery = Value::Null;
                            let (pipeline, timings, finished, wire_len) = if role == "producer" {
                                let store = store.as_mut().unwrap();
                                let begin = Instant::now();
                                let prep_begin = Instant::now();
                                let p = store.prepare_next(binding.producer_id(), 7, &body)?;
                                preparation_ms = ms(prep_begin.elapsed());
                                let sign_begin = Instant::now();
                                let outgoing = if signed {
                                    sign_block(p.block(), &producer_key, &context, &binding)?
                                        .wire_bytes()
                                } else {
                                    p.block().wire_bytes()
                                };
                                signing_encoding_ms = ms(sign_begin.elapsed());
                                let staged = p.authorize(grant)?;
                                let outcome = if mode == "phases" {
                                    store.commit_profiled(staged)
                                } else {
                                    store.commit(staged)
                                };
                                let elapsed = ms(begin.elapsed());
                                let timings = committed(outcome)?;
                                (elapsed, timings, store.snapshot()?.clone(), outgoing.len())
                            } else if signed {
                                // Signing of the already available receiver input is untimed; its
                                // independent cold verification is mandatory inside the receiver timer.
                                let available =
                                    sign_block(&b, &producer_key, &context, &binding)?.wire_bytes();
                                let receiver = receiver.as_mut().unwrap();
                                let begin = Instant::now();
                                let staged = receiver.stage(&available, grant)?;
                                auth_ms = ms(staged.authentication_time());
                                let outcome = if mode == "phases" {
                                    receiver.commit_profiled(staged)
                                } else {
                                    receiver.commit(staged)
                                };
                                let elapsed = ms(begin.elapsed());
                                let timings = committed(outcome)?;
                                let snapshot = receiver.snapshot()?.clone();
                                if mode == "ordinary" && body_size == 3000 {
                                    let begin = Instant::now();
                                    assert_eq!(receiver.recover()?.attempted_present, None);
                                    recovery = json!({"kind":"fixture_ready_refresh","total_ms":ms(begin.elapsed()),"load":load(receiver.load_timings()?)});
                                    assert_eq!(receiver.snapshot()?, &snapshot);
                                }
                                (elapsed, timings, snapshot, available.len())
                            } else {
                                let store = store.as_mut().unwrap();
                                let available = b.wire_bytes();
                                let begin = Instant::now();
                                let staged = store.stage_received(&available, grant)?;
                                let outcome = if mode == "phases" {
                                    store.commit_profiled(staged)
                                } else {
                                    store.commit(staged)
                                };
                                let elapsed = ms(begin.elapsed());
                                let timings = committed(outcome)?;
                                let snapshot = store.snapshot()?.clone();
                                if mode == "ordinary" && body_size == 3000 {
                                    let begin = Instant::now();
                                    assert_eq!(store.recover()?.attempted_present, None);
                                    recovery = json!({"kind":"fixture_ready_refresh","total_ms":ms(begin.elapsed()),"load":load(store.load_timings()?)});
                                    assert_eq!(store.snapshot()?, &snapshot);
                                }
                                (elapsed, timings, snapshot, available.len())
                            };
                            states.push(finished.clone());
                            drop(store);
                            drop(receiver);
                            let post_begin = Instant::now();
                            let audited = CanonicalFixtureStore::reopen(&path, &m)?;
                            let post = load(audited.load_timings()?);
                            let post_ms = ms(post_begin.elapsed());
                            assert_eq!(audited.snapshot()?, &finished);
                            drop(audited);
                            completed += 1;
                            println!(
                                "{}",
                                json!({"kind":"block_auth_sample","case":case,"accounts":accounts,"history_blocks":history_blocks,"history_txs":history_txs,"body_size":body_size,"touched":if body_size==0 {0}else{1+body_size.min(accounts-1)},"role":role,"mode":mode,"pair":pair,"order_position":position,"signed":signed,"wire_bytes":wire_len,"pipeline_ms":pipeline,"native_preparation_ms":preparation_ms,"signing_and_encoding_ms":signing_encoding_ms,"receiver_attribution_ms":auth_ms,"durable_ms":ms(timings.durable_commit),"native_stage_ms":ms(timings.staging),"cache_preparation_ms":ms(timings.cache_preparation),"cache_destruction_ms":ms(timings.cache_destruction),"stored_comparison_ms":ms(timings.stored_comparison),"sql":phases(timings),"pre_reopen_ms":reopen_ms,"pre_reopen":reopen,"post_reopen_ms":post_ms,"post_reopen":post,"recovery":recovery,"memory":memory(),"copied_retained_signed_bytes":199*history_txs,"copied_retained_id_bytes":32*history_txs,"copied_transaction_memberships":2*history_txs,"copied_slot_hash_memberships":2*(history_blocks+1)})
                            );
                        }
                        assert_eq!(
                            states[0], states[1],
                            "complete matched signed/unsigned state/archive/index/tip equality"
                        );
                    }
                }
            }
        }
    }
    println!(
        "{}",
        json!({"kind":"block_auth_complete","samples":completed,"failures":0,"outliers":"all retained","cache_default_changed":false,"sql_producer_evidence":false})
    );
    Ok(())
}
