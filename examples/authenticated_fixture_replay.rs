//! Fresh schema-3 producer/receiver/restart: exact signed evidence is reconstructed from SQL alone,
//! but attribution still depends on independently supplied policy, not stored key self-authority.
use eternix_testnet as chain;
mod stage4_support;
// Only explicit public toy signing/binding setup is reused, never its unsigned-store wrapper.
#[allow(dead_code)]
mod block_auth_support;
use block_auth_support::{toy_binding, toy_producer_key};
use chain::authenticated_fixture::{
    AppendOutcome, ArchiveRecord, AuthenticatedFixtureManifest, AuthenticatedFixtureStore,
};
use chain::block_authentication::{BlockAuthenticationContext, sign_block};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let parent = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .unwrap_or_else(|| "target".into()),
    );
    let d = tempfile::Builder::new()
        .prefix("schema3-authenticated-replay-")
        .tempdir_in(parent)?;
    let f = stage4_support::manifest();
    let context = BlockAuthenticationContext::new(f.context(), 2, 1)?;
    let binding = toy_binding("offline-validator");
    let m = AuthenticatedFixtureManifest::new(f.clone(), context, vec![binding.clone()])?;
    let p = d.path().join("producer.db");
    let r = d.path().join("receiver.db");
    let mut producer = AuthenticatedFixtureStore::create_authenticated_fixture(&p, &m)?;
    let mut receiver = AuthenticatedFixtureStore::create_authenticated_fixture(&r, &m)?;
    assert!(matches!(
        producer.snapshot()?.records[0],
        ArchiveRecord::TrustedAnchor(_)
    ));
    assert!(producer.export_signed_envelope(0).is_err());
    let b = stage4_support::block("sequential");
    let body: Vec<_> = b.transactions().iter().map(|t| t.to_vec()).collect();
    let mut exact_packets = Vec::with_capacity(2);
    let mut pool = body.clone();
    for input in [&body[..], &[][..]] {
        let prepared = producer.prepare_next(binding.producer_id(), 7, input)?;
        let bytes =
            sign_block(prepared.block(), &toy_producer_key(), &context, &binding)?.wire_bytes();
        let grant = stage4_support::grant(&f, prepared.base_tip(), prepared.block()); // trusted controller, not packet claims
        let producer_stage = producer.seal_prepared(prepared, &bytes, grant)?;
        assert!(matches!(
            producer.commit(producer_stage),
            AppendOutcome::Committed { .. }
        ));
        let receiver_stage = receiver.stage_received(&bytes, grant)?;
        assert!(matches!(
            receiver.commit(receiver_stage),
            AppendOutcome::Committed { .. }
        ));
        assert_eq!(producer.snapshot()?, receiver.snapshot()?);
        pool.clear();
        exact_packets.push(bytes);
    }
    let expected = producer.snapshot()?.clone();
    drop(producer);
    drop(receiver);
    for path in [&p, &r] {
        // No private key/artifact is passed to reopening: exact durable S/E-ID and body rows suffice.
        let mut reopened = AuthenticatedFixtureStore::reopen(path, &m)?;
        assert_eq!(reopened.snapshot()?, &expected);
        for (i, original) in exact_packets.iter().enumerate() {
            assert_eq!(reopened.export_signed_envelope(i as u64 + 1)?, *original);
        }
        assert_eq!(reopened.recover()?.attempted_present, None);
        assert_eq!(reopened.snapshot()?, &expected);
    }
    assert!(pool.is_empty());
    println!(
        "schema3_producer_receiver_restart_equal=true exact_signed_envelopes_reconstructed_from_sql=2 unsigned_anchor_separate=true independent_policy_required=true original_signature_choice_selection_freshness_independently_pinned=false live_node_started=false"
    );
    Ok(())
}
