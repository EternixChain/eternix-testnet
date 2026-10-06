//! Standalone test-only cold-authentication measurement; does not start or configure the node.
//! Run with `cargo run --release --example native_auth_bench`.

use std::hint::black_box;
use std::time::Instant;

use eternix_testnet::native_transaction::{
    AuthenticationContext, ENCODING_VERSION, NATIVE_RULES_VERSION, TRANSFER_KIND,
    UnsignedTransaction, address_from_public_key, authenticate, network_id_from_genesis_bytes,
    sign,
};
use k256::ecdsa::SigningKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(debug_assertions) {
        return Err("run this measurement in release mode".into());
    }
    const COUNT: usize = 3000;
    const EXECUTION_BUDGET_MS: f64 = 2000.0;
    // Published scalar-one test key and opaque test genesis, not production allocations/config.
    let mut public_test_scalar = [0; 32];
    public_test_scalar[31] = 1;
    let key = SigningKey::from_slice(&public_test_scalar)?;
    let context = AuthenticationContext::new(
        1162,
        network_id_from_genesis_bytes(b"ETERNIX_NATIVE_AUTH_VECTOR_GENESIS_V1"),
        NATIVE_RULES_VERSION,
    )?;
    let sender = address_from_public_key(key.verifying_key());
    let mut dataset = Vec::with_capacity(COUNT);
    // Generation/signing is outside the timed section. Each payload has a distinct signed nonce;
    // none is preauthenticated, and the module has no verified-result cache or warmup path.
    for index in 0..COUNT {
        let unsigned = UnsignedTransaction {
            encoding_version: ENCODING_VERSION,
            native_rules_version: NATIVE_RULES_VERSION,
            chain_id: 1162,
            network_id: network_id_from_genesis_bytes(b"ETERNIX_NATIVE_AUTH_VECTOR_GENESIS_V1"),
            kind: TRANSFER_KIND,
            sender,
            nonce: index as u64,
            recipient: [0x22; 20],
            token_id: 0,
            value: index as u128 + 1,
            gas_limit: 1000 + index as u64 % 2,
            valid_after_slot: 0,
        };
        dataset.push(sign(unsigned, &key, &context)?.canonical_bytes()?);
    }

    let started = Instant::now();
    let mut checksum = [0_u8; 32];
    for bytes in &dataset {
        let proof = black_box(authenticate(black_box(bytes), black_box(&context), None)?);
        for (accumulator, byte) in checksum.iter_mut().zip(proof.transaction_id()) {
            *accumulator ^= byte;
        }
    }
    let elapsed = started.elapsed();
    black_box(checksum);
    let total_ms = elapsed.as_secs_f64() * 1000.0;
    println!("backend=RustCrypto k256 recover_from_prehash + sha3 Keccak256");
    println!("mode=release, single-threaded, unique objects, no authentication cache");
    println!("transactions={COUNT}");
    println!("total_ms={total_ms:.3}");
    println!("per_transaction_us={:.3}", total_ms * 1000.0 / COUNT as f64);
    println!("execution_budget_ms={EXECUTION_BUDGET_MS:.0}");
    println!(
        "execution_budget_percent={:.2}",
        total_ms / EXECUTION_BUDGET_MS * 100.0
    );
    println!("checksum={}", hex::encode(checksum));
    Ok(())
}
