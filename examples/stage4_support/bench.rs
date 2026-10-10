//! Shared offline benchmark driver, used by a release example and a test-only uncertain-outcome
//! benchmark. History generation/signing is untimed; all append cache copies/destruction are timed.
use super::chain;
use chain::block_commitment::{ProtocolData, hash_with_domain, ordered_transaction_root};
use chain::canonical_fixture::{
    AppendOutcome, CanonicalFixtureStore, Error, FixtureAdmissionGrant, FixtureManifest,
};
use chain::native_block::NativeBlock;
use chain::native_transaction::{
    AuthenticationContext, ID_DOMAIN, UnsignedTransaction, address_from_public_key,
    network_id_from_genesis_bytes, sign,
};
use chain::native_transfer::{TransferAccount, TransferState};
use k256::ecdsa::SigningKey;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

/// Feasible representative points; not a Cartesian product. Large H and large T are independently
/// represented at A=1,000; the costly A=100,000/H=10,000 corner is deliberately omitted/disclosed.
pub const CASES: &[(usize, usize, usize)] = &[
    (100, 0, 0),
    (1_000, 0, 0),
    (10_000, 0, 0),
    (100_000, 0, 0),
    (1_000, 100, 0),
    (1_000, 1_000, 0),
    (1_000, 10_000, 0),
    (1_000, 100, 1_000),
    (1_000, 1_000, 1_000),
    (1_000, 100, 10_000),
    (1_000, 1_000, 10_000),
    (1_000, 100, 100_000),
    (1_000, 1_000, 100_000),
];

fn millis(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}
fn stats(values: &[Duration]) -> serde_json::Value {
    let mut v: Vec<_> = values.iter().copied().map(millis).collect();
    v.sort_by(f64::total_cmp);
    let median = if v.len() % 2 == 0 {
        (v[v.len() / 2 - 1] + v[v.len() / 2]) / 2.0
    } else {
        v[v.len() / 2]
    };
    json!({"median_ms":median,"max_ms":v[v.len()-1],"samples_ms":v})
}
fn key() -> SigningKey {
    let mut b = [0; 32];
    b[31] = 1;
    SigningKey::from_slice(&b).unwrap()
}
pub(super) fn fixture(accounts: usize) -> FixtureManifest {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/stage4_native_blocks.json"
    ))
    .unwrap();
    let context = AuthenticationContext::new(
        1162,
        network_id_from_genesis_bytes(
            &hex::decode(f["canonical_genesis_hex"].as_str().unwrap()).unwrap(),
        ),
        1,
    )
    .unwrap();
    let anchor = NativeBlock::from_wire_bytes(
        &hex::decode(f["vectors"]["anchor"]["wire"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let mut map = BTreeMap::new();
    let sender = address_from_public_key(key().verifying_key());
    for n in 0..accounts - 1 {
        map.insert(
            recipient(n),
            TransferAccount {
                balance_quarks: 1_000_000,
                nonce: 0,
            },
        );
    }
    map.insert(
        sender,
        TransferAccount {
            balance_quarks: u128::MAX,
            nonce: 0,
        },
    );
    FixtureManifest::new(
        context,
        anchor,
        TransferState::new(map, 0, 0),
        format!("explicit-stage4-benchmark-{accounts}-accounts-v1"),
    )
    .unwrap()
}
fn recipient(n: usize) -> [u8; 20] {
    let mut a = [0x42; 20];
    a[12..].copy_from_slice(&(n as u64).to_be_bytes());
    a
}
pub(super) fn block(
    s: &CanonicalFixtureStore,
    m: &FixtureManifest,
    count: usize,
    accounts: usize,
) -> Result<NativeBlock, Box<dyn std::error::Error>> {
    let snapshot = s.snapshot()?;
    let ctx = m.context();
    let sender = address_from_public_key(key().verifying_key());
    let nonce = snapshot.state.account(&sender).nonce;
    let txs: Vec<_> = (0..count)
        .map(|i| {
            sign(
                UnsignedTransaction {
                    encoding_version: 2,
                    native_rules_version: 1,
                    chain_id: ctx.chain_id(),
                    network_id: ctx.network_id(),
                    kind: 0,
                    sender,
                    nonce: nonce + i as u64,
                    recipient: recipient(i % (accounts - 1)),
                    token_id: 0,
                    value: 1,
                    gas_limit: 1001,
                    valid_after_slot: 0,
                },
                &key(),
                &ctx,
            )
            .unwrap()
            .canonical_bytes()
            .unwrap()
        })
        .collect();
    let ids: Vec<_> = txs.iter().map(|b| hash_with_domain(ID_DOMAIN, b)).collect();
    let pd = ProtocolData {
        missed_proposer: None,
        fees_burned: count as u64 * 10_000,
    };
    let mut header = m.anchor().header().clone();
    header.slot = snapshot.tip.slot.checked_add(1).unwrap();
    header.parent_hash = snapshot.tip.hash;
    header.transaction_root = ordered_transaction_root(&ids).unwrap();
    header.gas_used = count as u64 * 1000;
    header.protocol_data_root = pd.root();
    Ok(NativeBlock::from_parts(
        header,
        m.anchor().proposer().into(),
        pd,
        txs,
    )?)
}
pub(super) fn grant(
    s: &CanonicalFixtureStore,
    m: &FixtureManifest,
    b: &NativeBlock,
) -> FixtureAdmissionGrant {
    FixtureAdmissionGrant::explicit_offline(
        m.context(),
        m.anchor().hash(),
        s.snapshot().unwrap().tip,
        b.hash(),
        b.header().slot,
    )
}
pub(super) fn append(
    s: &mut CanonicalFixtureStore,
    m: &FixtureManifest,
    b: &NativeBlock,
) -> Result<(), Box<dyn std::error::Error>> {
    let st = s.stage_received(&b.wire_bytes(), grant(s, m, b))?;
    match s.commit(st) {
        AppendOutcome::Committed { .. } => Ok(()),
        other => Err(format!("benchmark failed append: {other:?}").into()),
    }
}
fn memory() -> serde_json::Value {
    // Linux process metrics, not protocol input. HWM is cumulative for this process, not row-local.
    #[cfg(target_os = "linux")]
    if let Ok(text) = std::fs::read_to_string("/proc/self/status") {
        let get = |name: &str| {
            text.lines()
                .find(|l| l.starts_with(name))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|n| n.parse::<u64>().ok())
        };
        return json!({"rss_kib":get("VmRSS:"),"process_cumulative_hwm_kib":get("VmHWM:")});
    }
    json!({"rss_kib":null,"process_cumulative_hwm_kib":null})
}

/// Runs selected matrix points; recovery preparation is untimed and explicitly labels whether it
/// creates a test-only post-COMMIT/unpublished uncertainty. All recover-to-Ready work is timed.
pub fn run(
    parent: &Path,
    samples: usize,
    only: Option<usize>,
    only_body: Option<usize>,
    mut recovery_preparation: impl FnMut(
        &mut CanonicalFixtureStore,
        &FixtureManifest,
    ) -> Result<bool, Error>,
) -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(debug_assertions) || samples == 0 {
        return Err("release mode and positive samples required".into());
    }
    if only.is_some_and(|n| n >= CASES.len())
        || only_body.is_some_and(|n| ![0, 1, 3000].contains(&n))
    {
        return Err("invalid matrix case/body selection".into());
    }
    let root = tempfile::Builder::new()
        .prefix("stage4-history-bench-")
        .tempdir_in(parent)?;
    let c = rusqlite::Connection::open_in_memory()?; // compile-option reporting only; no workload is in memory
    let mut q = c.prepare("PRAGMA compile_options")?;
    println!(
        "{}",
        json!({"kind":"method","sqlite":rusqlite::version(),"rusqlite":"0.38.0","samples":samples,"concurrency":1,"cache":"warm OS/CPU; fresh SQLite owner on reopen; no cache flushing",
        "matrix":CASES,"selected_case":only,"selected_body":only_body,"omissions":"no full Cartesian product; no A=100000/H=10000; larger H/T omitted; no p95/p99 with small samples", "compile_options":q.query_map([],|r|r.get::<_,String>(0))?.collect::<Result<Vec<_>,_>>()?})
    );
    for (case, &(a, h, t)) in CASES.iter().enumerate() {
        if only.is_some_and(|n| n != case) {
            continue;
        }
        let m = fixture(a);
        for size in [0usize, 1, 3000] {
            if only_body.is_some_and(|n| n != size) {
                continue;
            }
            // Each workload starts at the declared history point, rather than inheriting other
            // workload sizes. Samples then grow naturally; none of the copies/indexes are pruned.
            let path = root.path().join(format!("case-{case}-body-{size}.db"));
            let now = Instant::now();
            let mut s = CanonicalFixtureStore::create_anchored_fixture(&path, &m)?;
            let init = now.elapsed();
            let history_start = Instant::now();
            for n in 0..h {
                let count = t / h + usize::from(n < t % h);
                let b = block(&s, &m, count, a)?;
                append(&mut s, &m, &b)?;
            }
            let history_build = history_start.elapsed();
            assert_eq!(s.snapshot()?.blocks.len() - 1, h);
            assert_eq!(s.snapshot()?.transactions.len(), t);
            let settings = s.settings()?;
            assert_eq!(settings.journal_mode, "delete");
            assert_eq!(settings.synchronous, 3);
            assert!(settings.foreign_keys);
            let mut recv = Vec::new();
            let mut prod = Vec::new();
            let mut commit = Vec::new();
            let mut prep = Vec::new();
            let mut destruction = Vec::new();
            let mut stage = Vec::new();
            let mut stored = Vec::new();
            let mut ram = Vec::new();
            let mut install = Vec::new();
            let mut ranges = Vec::new();
            let mut copied = Vec::new();
            for _ in 0..samples {
                let b = block(&s, &m, size, a)?;
                let body: Vec<_> = b.transactions().iter().map(|b| b.to_vec()).collect();
                let snapshot = s.snapshot()?;
                ranges.push((
                    snapshot.blocks.len() - 1,
                    snapshot.transactions.len(),
                    std::fs::metadata(&path)?.len(),
                ));
                let begin = Instant::now();
                let p =
                    s.prepare_next(m.anchor().proposer(), m.anchor().header().ticket_id, &body)?;
                assert_eq!(p.block(), &b);
                let g = grant(&s, &m, p.block());
                let p = p.authorize(g)?;
                match s.commit(p) {
                    AppendOutcome::Committed { .. } => (),
                    other => return Err(format!("producer sample {other:?}").into()),
                }
                prod.push(begin.elapsed());
                let b = block(&s, &m, size, a)?;
                let bytes = b.wire_bytes();
                let g = grant(&s, &m, &b);
                let snap = s.snapshot()?;
                copied.push(json!({"blocks":snap.blocks.len(),"signed_bytes":199*snap.transactions.len(),"ordered_id_bytes":32*snap.transactions.len(),"transaction_index_entries":2*snap.transactions.len(),"slot_hash_index_entries":2*snap.blocks.len(),"header_bytes":229*snap.blocks.len()}));
                let begin = Instant::now();
                let st = s.stage_received(&bytes, g)?;
                match s.commit(st) {
                    AppendOutcome::Committed { timings, .. } => {
                        commit.push(timings.durable_commit);
                        prep.push(timings.cache_preparation);
                        destruction.push(timings.cache_destruction);
                        stage.push(timings.staging);
                        stored.push(timings.stored_comparison);
                        ram.push(timings.memory_comparison);
                        install.push(timings.installation);
                    }
                    other => return Err(format!("receiver sample {other:?}").into()),
                }
                recv.push(begin.elapsed());
            }
            let expected = s.snapshot()?.clone(); // external correctness oracle, outside timing
            let mut reopened = Vec::new();
            let mut audits = Vec::new();
            let mut rebuilds = Vec::new();
            let mut barriers = Vec::new();
            let mut equalities = Vec::new();
            for _ in 0..samples {
                drop(s);
                let begin = Instant::now();
                s = CanonicalFixtureStore::reopen(&path, &m)?;
                reopened.push(begin.elapsed());
                let load = s.load_timings()?;
                audits.push(load.audit);
                rebuilds.push(load.validation_materialization);
                barriers.push(load.barrier);
                equalities.push(load.equality);
                assert_eq!(s.snapshot()?, &expected);
            }
            let mut recover = Vec::new();
            let mut recover_audit = Vec::new();
            let mut recover_rebuild = Vec::new();
            let mut recover_barrier = Vec::new();
            let mut uncertain = false;
            for _ in 0..samples {
                uncertain = recovery_preparation(&mut s, &m)?;
                let now = Instant::now();
                let report = s.recover()?;
                recover.push(now.elapsed());
                if uncertain {
                    assert_eq!(report.attempted_present, Some(true));
                } else {
                    assert_eq!(report.attempted_present, None);
                }
                let load = s.load_timings()?;
                recover_audit.push(load.audit);
                recover_rebuild.push(load.validation_materialization);
                recover_barrier.push(load.barrier);
            }
            let peak = memory();
            println!(
                "{}",
                json!({"kind":"result","case":case,"accounts":a,"retained_blocks_start":h,"retained_transactions_start":t,"entries":size,"touched":if size==0 {0} else {1+size.min(a-1)},
                "signed_body_bytes":199*size,"wire_bytes":305+203*size,"samples":samples,"initialization_ms":millis(init),"untimed_history_construction_ms":millis(history_build),
                "before_producer_ranges":ranges,"copy_estimates_before_receiver":copied,"journal_before_each_append":"absent; DELETE", "page_size":settings.page_size,"cache_size":settings.cache_size,
                "producer_pipeline":stats(&prod),"receiver_pipeline":stats(&recv),"receiver_stage":stats(&stage),"durable_commit":stats(&commit),"cache_preparation":stats(&prep),"cache_destruction":stats(&destruction),
                "stored_comparison":stats(&stored),"memory_comparison":stats(&ram),"installation":stats(&install),"reopen_total":stats(&reopened),"reopen_audit":stats(&audits),"reopen_validation_rebuild":stats(&rebuilds),"reopen_barrier":stats(&barriers),"reopen_equality":stats(&equalities),
                "recovery_kind":if uncertain {"test_only_post_commit_unpublished"} else {"explicit_ready_refresh"},"recovery_total":stats(&recover),"recovery_audit":stats(&recover_audit),"recovery_validation_rebuild":stats(&recover_rebuild),"recovery_barrier":stats(&recover_barrier),"memory":peak,"execution_reference_ms":2000})
            );
        }
    }
    println!(
        "{}",
        json!({"kind":"complete","failures":0,"lock_waits":0,"busy_timeout_ms":0,"outliers":"retained","timings":"all cache copies and destruction in full path; audit never bypassed"})
    );
    Ok(())
}
