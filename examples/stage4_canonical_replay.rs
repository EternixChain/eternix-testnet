//! Isolated producer/receiver/restart demonstration over separate real SQLite files.
//! Exact archived test bytes and explicit grants are the only inputs; no node/RPC/P2P is started.
mod stage4_support;
use eternix_testnet::canonical_fixture::{AppendOutcome, CanonicalFixtureStore, Error};
use eternix_testnet::native_block::NativeBlock;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let parent = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .unwrap_or_else(|| "target".into()),
    );
    let dir = tempfile::Builder::new()
        .prefix("stage4-offline-replay-")
        .tempdir_in(parent)?;
    let manifest = stage4_support::manifest();
    let body_block = stage4_support::block("sequential");
    let producer_path = dir.path().join("producer.db");
    let receiver_path = dir.path().join("receiver.db");
    let mut producer = CanonicalFixtureStore::create_anchored_fixture(&producer_path, &manifest)?;
    let mut receiver = CanonicalFixtureStore::create_anchored_fixture(&receiver_path, &manifest)?;
    let body: Vec<_> = body_block
        .transactions()
        .iter()
        .map(|b| b.to_vec())
        .collect();
    let mut local_pool = body.clone();
    let unrelated_receiver_pool = [vec![0xff]];
    let producer_pending_nonce = 900u64;
    let receiver_pending_nonce = 42u64; // deliberately not application inputs
    let prepared = producer.prepare_next("offline-validator", 7, &body)?;
    assert_eq!(prepared.block(), &body_block);
    let grant = stage4_support::grant(&manifest, producer.snapshot()?.tip, prepared.block());
    let sealed = prepared.authorize(grant)?;
    match producer.commit(sealed) {
        AppendOutcome::Committed { .. } => local_pool.clear(),
        other => return Err(format!("producer {other:?}").into()),
    }
    let received = receiver.stage_received(&body_block.wire_bytes(), grant)?;
    assert!(matches!(
        receiver.commit(received),
        AppendOutcome::Committed { .. }
    ));
    assert_eq!(producer.snapshot()?, receiver.snapshot()?);
    let tip = producer.snapshot()?.tip;
    let empty = NativeBlock::empty_fixture_anchor(
        &manifest.context(),
        tip.slot.checked_add(1).unwrap(),
        tip.hash,
        "offline-validator".into(),
        7,
    )?;
    for store in [&mut producer, &mut receiver] {
        let grant = stage4_support::grant(&manifest, store.snapshot()?.tip, &empty);
        let staged = store.stage_received(&empty.wire_bytes(), grant)?;
        assert!(matches!(
            store.commit(staged),
            AppendOutcome::Committed { .. }
        ));
    }
    let expected = producer.snapshot()?.clone();
    assert_eq!(&expected, receiver.snapshot()?);
    assert!(matches!(
        receiver.stage_received(&body_block.wire_bytes(), grant),
        Err(Error::AlreadyCommitted(_))
    ));
    drop(producer);
    drop(receiver);
    for path in [&producer_path, &receiver_path] {
        let reopened = CanonicalFixtureStore::reopen(path, &manifest)?;
        assert_eq!(reopened.snapshot()?, &expected);
    }
    assert!(local_pool.is_empty());
    assert_eq!(unrelated_receiver_pool.len(), 1);
    assert_ne!(producer_pending_nonce, receiver_pending_nonce);
    println!(
        "offline_producer_receiver_restart_equal=true blocks_including_anchor={} transactions={} tip_slot={} revision={}",
        expected.blocks.len(),
        expected.transactions.len(),
        expected.tip.slot,
        expected.tip.revision
    );
    println!(
        "gas_total={} burn_total={} exact_bytes_and_indexes_equal=true duplicate_noop=true live_node_started=false",
        expected.state.gas_used_total(),
        expected.state.fees_burned_total()
    );
    Ok(())
}
