//! Secondary cold rejection costs only, never successful append or live admission throughput.
use eternix_testnet as chain;
// Reuse only original explicit fixtures/bodies, not the older storage benchmark driver.
#[allow(dead_code)]
#[path = "stage4_support/bench.rs"]
mod fixture;
// Static public-key setup shared with the two file-backed offline drivers.
#[allow(dead_code)]
mod block_auth_support;
use block_auth_support::{toy_binding, toy_producer_key};
use chain::block_authentication::{
    BlockAuthenticationContext, Error, ProducerBinding, authenticate_block, sign_block,
};
use chain::canonical_fixture::CanonicalFixtureStore;
use serde_json::json;
use std::hint::black_box;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(debug_assertions) {
        return Err("release required".into());
    }
    let parent = std::env::args().nth(1).unwrap_or_else(|| "target".into());
    let d = tempfile::Builder::new()
        .prefix("block-auth-reject-")
        .tempdir_in(parent)?;
    let m = fixture::fixture(1000);
    let s = CanonicalFixtureStore::create_anchored_fixture(d.path().join("base.db"), &m)?;
    let ctx = BlockAuthenticationContext::new(m.context(), 2, 1)?;
    let binding = toy_binding("offline-validator");
    let other = BlockAuthenticationContext::new(
        chain::native_transaction::AuthenticationContext::new(1162, [0; 32], 1)?,
        2,
        1,
    )?;
    // Published scalar-one sender key is deliberately the *wrong* full producer key; no secret.
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let wrong_key = k256::ecdsa::SigningKey::from_slice(&scalar)?;
    let wrong = ProducerBinding::new(
        "offline-validator",
        wrong_key.verifying_key().to_encoded_point(true).as_bytes(),
    )?;
    for body in [0, 3000] {
        let b = fixture::block(&s, &m, body, 1000)?;
        let packet = sign_block(&b, &toy_producer_key(), &ctx, &binding)?.wire_bytes(); // input/signing untimed
        for kind in ["framing", "network", "canonical_wrong_key"] {
            for sample in 0..4 {
                let begin = Instant::now();
                for _ in 0..100 {
                    let outcome = match kind {
                        // Keep even constant malformed bytes opaque to the optimizer; no cached or
                        // constant-folded authentication result should masquerade as cold validation.
                        "framing" => authenticate_block(
                            black_box(&[]),
                            black_box(&ctx),
                            black_box(&binding),
                            None,
                        ),
                        "network" => authenticate_block(
                            black_box(&packet),
                            black_box(&other),
                            black_box(&binding),
                            None,
                        ),
                        _ => authenticate_block(
                            black_box(&packet),
                            black_box(&ctx),
                            black_box(&wrong),
                            None,
                        ),
                    };
                    let error = outcome.expect_err("rejection benchmark must never accept");
                    match kind {
                        "framing" => assert_eq!(error, Error::Frame("truncation")),
                        "network" => assert_eq!(error, Error::NetworkMismatch),
                        _ => assert_eq!(error, Error::KeyMismatch),
                    }
                    std::hint::black_box(error);
                }
                let elapsed = begin.elapsed().as_secs_f64() * 1000.0;
                println!(
                    "{}",
                    json!({"kind":"block_auth_rejection","body_size":body,"class":kind,"sample":sample,"batch":100,"elapsed_ms":elapsed,"ms_per_rejection":elapsed/100.0,"cache":"no authenticated-result cache; repeated raw bytes, warm OS/CPU","boundary":"pure attribution plus exact-error check; no native execution/SQL append"})
                );
            }
        }
    }
    println!(
        "{}",
        json!({"kind":"block_auth_rejection_complete","batches":24,"rejections":2400,"unexpected_acceptances":0})
    );
    Ok(())
}
