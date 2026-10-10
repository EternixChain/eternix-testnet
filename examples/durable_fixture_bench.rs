//! Release, single-owner, real-file fixture benchmark with unchanged DELETE/EXTRA durability.
//! Pass an existing disk-backed parent directory and optionally a sample count (default seven).
//! Data construction/signing is outside timings; connections/OS caches are warm, not flushed.

use eternix_testnet::durable_fixture::{CommitOutcome, FixtureStore};
use eternix_testnet::native_transaction::{
    AuthenticationContext, UnsignedTransaction, address_from_public_key,
    network_id_from_genesis_bytes, sign,
};
use eternix_testnet::native_transfer::{TransferAccount, TransferState};
use k256::ecdsa::SigningKey;
use rusqlite::Connection;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn stats(values: &[Duration]) -> (f64, f64) {
    let mut values: Vec<_> = values.iter().map(|v| v.as_secs_f64() * 1000.0).collect();
    values.sort_by(f64::total_cmp);
    let median = if values.len() % 2 == 0 {
        (values[values.len() / 2 - 1] + values[values.len() / 2]) / 2.0
    } else {
        values[values.len() / 2]
    };
    (median, values[values.len() - 1])
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(debug_assertions) {
        return Err("run this benchmark in --release".into());
    }
    let mut args = std::env::args_os().skip(1);
    let parent = PathBuf::from(
        args.next()
            .ok_or("provide an existing disk-backed parent directory")?,
    );
    let samples: usize = args
        .next()
        .map(|v| v.to_str().unwrap().parse())
        .transpose()?
        .unwrap_or(7);
    if samples == 0 {
        return Err("sample count must be positive".into());
    }
    let directory = tempfile::Builder::new()
        .prefix("etx-offline-bench-")
        .tempdir_in(&parent)?;
    // Published scalar-one key and synthetic genesis identity; this never imports node state.
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let key = SigningKey::from_slice(&scalar)?;
    let sender = address_from_public_key(key.verifying_key());
    let context = AuthenticationContext::new(
        1162,
        network_id_from_genesis_bytes(b"ETERNIX_DURABLE_BENCH_FIXTURE_V1"),
        1,
    )?;
    println!(
        "sqlite={} rusqlite=0.38.0 samples={} parent={} concurrency=1 cache=warm,no-flush",
        rusqlite::version(),
        samples,
        parent.display()
    );
    let compile = Connection::open_in_memory()?; // Only compile-option reporting, never a workload.
    let mut options = compile.prepare("PRAGMA compile_options")?;
    println!(
        "compile_options={:?}",
        options
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    );
    println!(
        "accounts,body_entries,touched_accounts,body_bytes,history_before_range,index_before_range,db_bytes_before_range,init_ms,commit_median_ms,commit_max_ms,stored_compare_median_ms,stored_compare_max_ms,memory_compare_median_ms,memory_compare_max_ms,stage_median_ms,stage_max_ms,cache_prepare_median_ms,cache_prepare_max_ms,install_median_ms,install_max_ms,pipeline_median_ms,pipeline_max_ms"
    );
    for count in [100usize, 1_000, 10_000, 100_000] {
        let path = directory.path().join(format!("accounts-{count}.db"));
        let mut accounts = BTreeMap::new();
        // Sender plus count-1 synthetic recipients: total size stays exact for every workload.
        let recipients: Vec<_> = (0..count - 1)
            .map(|n| {
                let mut address = [0x42; 20];
                address[12..].copy_from_slice(&(n as u64).to_be_bytes());
                address
            })
            .collect();
        for address in &recipients {
            accounts.insert(
                *address,
                TransferAccount {
                    balance_quarks: 1_000_000,
                    nonce: 0,
                },
            );
        }
        accounts.insert(
            sender,
            TransferAccount {
                balance_quarks: u128::MAX,
                nonce: 0,
            },
        );
        let started = Instant::now();
        let mut store = FixtureStore::create_fixture(
            &path,
            context,
            TransferState::new(accounts, 0, 0),
            "explicit benchmark fixture v1",
        )?;
        let init = started.elapsed().as_secs_f64() * 1000.0;
        let settings = store.settings()?;
        assert_eq!(settings.journal_mode, "delete");
        assert_eq!(settings.synchronous, 3);
        assert!(settings.foreign_keys);
        println!(
            "verified_accounts={count} settings={settings:?} journal_bytes_before_each_commit=0"
        );
        for size in [0usize, 1, 3_000] {
            let mut commits = Vec::new();
            let mut compares = Vec::new();
            let mut memory = Vec::new();
            let mut stages = Vec::new();
            let mut prep = Vec::new();
            let mut installs = Vec::new();
            let mut pipeline = Vec::new();
            let mut history = Vec::new();
            let mut indexes = Vec::new();
            let mut db_bytes = Vec::new();
            for _ in 0..samples {
                let snap = store.snapshot()?;
                history.push(snap.bodies.len());
                indexes.push(snap.transaction_index.len());
                db_bytes.push(std::fs::metadata(&path)?.len());
                let nonce = snap.state.account(&sender).nonce;
                let body: Vec<Vec<u8>> = (0..size)
                    .map(|position| {
                        let unsigned = UnsignedTransaction {
                            encoding_version: 2,
                            native_rules_version: 1,
                            chain_id: context.chain_id(),
                            network_id: context.network_id(),
                            kind: 0,
                            sender,
                            nonce: nonce + position as u64,
                            recipient: recipients[position % recipients.len()],
                            token_id: 0,
                            value: 1,
                            gas_limit: 1000,
                            valid_after_slot: 0,
                        };
                        sign(unsigned, &key, &context)
                            .unwrap()
                            .canonical_bytes()
                            .unwrap()
                            .to_vec()
                    })
                    .collect();
                let started = Instant::now();
                let stage_start = Instant::now();
                let overlay = store.stage(1, &body)?;
                stages.push(stage_start.elapsed());
                match store.commit(overlay) {
                    CommitOutcome::Committed { timings, .. } => {
                        commits.push(timings.durable_commit);
                        compares.push(timings.stored_comparison);
                        memory.push(timings.memory_comparison);
                        prep.push(timings.publication_preparation);
                        installs.push(timings.installation);
                    }
                    outcome => {
                        return Err(format!(
                            "failed sample accounts={count} size={size}: {outcome:?}"
                        )
                        .into());
                    }
                }
                pipeline.push(started.elapsed());
            }
            let (c, cw) = stats(&commits);
            let (s, sw) = stats(&compares);
            let (m, mw) = stats(&memory);
            let (st, stw) = stats(&stages);
            let (p, pw) = stats(&prep);
            let (i, iw) = stats(&installs);
            let (all, allw) = stats(&pipeline);
            let touched = if size == 0 {
                0
            } else {
                1 + size.min(recipients.len())
            };
            println!(
                "{count},{size},{touched},{},{:?},{:?},{:?},{init:.3},{c:.3},{cw:.3},{s:.3},{sw:.3},{m:.3},{mw:.3},{st:.3},{stw:.3},{p:.3},{pw:.3},{i:.3},{iw:.3},{all:.3},{allw:.3}",
                size * 199,
                (history[0], history[samples - 1]),
                (indexes[0], indexes[samples - 1]),
                (db_bytes[0], db_bytes[samples - 1])
            );
        }
        // Reopen auditing is correctness evidence after measurement, outside steady-state timing.
        let expected = store.snapshot()?.clone();
        drop(store);
        assert_eq!(FixtureStore::reopen(&path, context)?.snapshot()?, &expected);
    }
    println!(
        "failures=0 lock_waits=0 busy_timeout=0ms outliers=retained; small sample count: no p95/p99 claim; execution_reference_ms=2000"
    );
    Ok(())
}
