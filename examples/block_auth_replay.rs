//! Separate real producer/receiver stores with mandatory signed-envelope reception.
//! Retained evidence files are verification artifacts, not part of either SQLite transaction.
use eternix_testnet as chain;
// The same signed owner has benchmark-only SQL profiling/attribution timing methods.
#[allow(dead_code)]
mod block_auth_support;
mod stage4_support;
use block_auth_support::{SignedFixtureReceiver, toy_binding, toy_producer_key};
use chain::block_authentication::{BlockAuthenticationContext, authenticate_block, sign_block};
use chain::canonical_fixture::{AppendOutcome, CanonicalFixtureStore};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let parent = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .unwrap_or_else(|| "target".into()),
    );
    let dir = tempfile::Builder::new()
        .prefix("offline-block-auth-")
        .tempdir_in(parent)?;
    let m = stage4_support::manifest();
    let context = BlockAuthenticationContext::new(m.context(), 2, 1)?;
    let binding = toy_binding("offline-validator");
    for case in ["single", "sequential"] {
        let producer_path = dir.path().join(format!("producer-{case}.db"));
        let receiver_path = dir.path().join(format!("receiver-{case}.db"));
        let mut producer = CanonicalFixtureStore::create_anchored_fixture(&producer_path, &m)?;
        let mut receiver =
            SignedFixtureReceiver::create(&receiver_path, &m, context, binding.clone())?;
        let block = stage4_support::block(case);
        let body: Vec<_> = block.transactions().iter().map(|t| t.to_vec()).collect();
        let mut local_pool = body.clone();
        let unrelated_receiver_pool = [vec![0xff]];
        let mut artifacts = Vec::with_capacity(2); // prepare output ownership before any durable COMMIT
        for selected in [&body[..], &[][..]] {
            let prepared = producer.prepare_next(binding.producer_id(), 7, selected)?;
            if !selected.is_empty() {
                assert_eq!(prepared.block(), &block);
            }
            let signed = sign_block(prepared.block(), &toy_producer_key(), &context, &binding)?;
            let packet = signed.wire_bytes();
            let base = producer.snapshot()?.tip;
            // Trusted local fixture controller supplies both requests' grant, never the receiver.
            let grant = stage4_support::grant(&m, base, prepared.block());
            assert!(matches!(
                producer.commit(prepared.authorize(grant)?),
                AppendOutcome::Committed { .. }
            ));
            let staged = receiver.stage(&packet, grant)?;
            assert!(matches!(
                receiver.commit(staged),
                AppendOutcome::Committed { .. }
            ));
            assert_eq!(producer.snapshot()?, receiver.snapshot()?);
            local_pool.clear();
            artifacts.push(packet);
        }
        let expected = producer.snapshot()?.clone();
        assert_eq!(receiver.recover()?.attempted_present, None);
        assert_eq!(receiver.snapshot()?, &expected);
        let fixture_audit = receiver.load_timings()?.audit;
        assert!(
            receiver
                .stage(
                    &artifacts[0][42..artifacts[0].len() - 65],
                    stage4_support::grant(&m, expected.tip, &block)
                )
                .is_err()
        );
        assert!(matches!(
            receiver.stage(
                &artifacts[0],
                stage4_support::grant(&m, expected.tip, &block)
            ),
            Err(block_auth_support::Error::Fixture(
                chain::canonical_fixture::Error::AlreadyCommitted(_)
            ))
        ));
        drop(producer);
        drop(receiver.into_store());
        for path in [&producer_path, &receiver_path] {
            assert_eq!(
                CanonicalFixtureStore::reopen(path, &m)?.snapshot()?,
                &expected
            );
        }
        for (index, packet) in artifacts.iter().enumerate() {
            // Artifact output is separate from already-confirmed fixture commitment. No SQL evidence
            // retention/atomic two-file publication claim is made by writing or reading this file.
            let path = dir
                .path()
                .join(format!("signed-artifact-{case}-{index}.bin"));
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            f.write_all(packet)?;
            f.sync_all()?;
            drop(f);
            let retained = std::fs::read(path)?;
            let proof = authenticate_block(&retained, &context, &binding, None)?;
            assert_eq!(proof.envelope().wire_bytes(), *packet);
        }
        assert!(local_pool.is_empty());
        assert_eq!(unrelated_receiver_pool.len(), 1);
        println!(
            "case={case} producer_receiver_state_archive_indexes_tip_equal=true fixture_store_reopen_equal=true fixture_ready_refresh_audit_ms={} separate_retained_envelope_reauthentication=2 sql_producer_evidence=false signed_admission_required=true live_node_started=false",
            fixture_audit.as_secs_f64() * 1000.0
        );
    }
    Ok(())
}
