//! Exact independent bytes, phase precedence and malformed-input/identity regressions.
use super::*;
use crate::block_commitment::{BlockKind, ProtocolData, ordered_transaction_root};
use serde_json::Value;

fn data() -> Value {
    serde_json::from_str(include_str!(
        "../../tests/fixtures/block_authentication.json"
    ))
    .unwrap()
}
fn row(name: &str) -> Value {
    data()["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == name)
        .unwrap()
        .clone()
}
fn bytes(r: &Value, field: &str) -> Vec<u8> {
    if field == "envelope" {
        // Concatenate frozen literal components, never call the Rust encoder for expected bytes.
        let inner = if let Some(name) = r["inner"].as_str() {
            let old: Value = serde_json::from_str(include_str!(
                "../../tests/fixtures/stage4_native_blocks.json"
            ))
            .unwrap();
            old["vectors"][name]["wire"].as_str().unwrap().to_owned()
        } else {
            r["inner"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<String>()
        };
        return hex::decode(format!(
            "{}{}{}",
            r["outer_prefix"].as_str().unwrap(),
            inner,
            r["signature"].as_str().unwrap()
        ))
        .unwrap();
    }
    hex::decode(r[field].as_str().unwrap()).unwrap()
}
fn ctx(r: &Value) -> BlockAuthenticationContext {
    BlockAuthenticationContext::new(
        AuthenticationContext::new(
            r["chain_id"].as_str().unwrap().parse().unwrap(),
            bytes(r, "network_id").try_into().unwrap(),
            1,
        )
        .unwrap(),
        2,
        1,
    )
    .unwrap()
}
fn key(n: u8) -> SigningKey {
    let mut b = [0; 32];
    b[31] = n;
    SigningKey::from_slice(&b).unwrap()
} // published toy integers
fn binding(r: &Value) -> ProducerBinding {
    ProducerBinding::new(
        r["producer"].as_str().unwrap(),
        &bytes(&data(), "compressed_key"),
    )
    .unwrap()
}
fn env(name: &str) -> SignedBlockEnvelope {
    SignedBlockEnvelope::from_wire_bytes(&bytes(&row(name), "envelope")).unwrap()
}
fn authenticate(bytes: &[u8]) -> Result<AuthenticatedProducerBlock, Error> {
    let r = row("empty");
    authenticate_block(bytes, &ctx(&r), &binding(&r), None)
}

#[test]
fn independent_goldens_exact_context_payload_signature_and_envelope() {
    assert_eq!(data()["test_only"], true);
    assert_eq!(hex::encode(SIGNING_DOMAIN), data()["sign_domain"]);
    assert_eq!(
        hex::encode(ENVELOPE_ID_DOMAIN),
        data()["envelope_id_domain"]
    );
    for r in data()["vectors"].as_array().unwrap() {
        let wire = bytes(r, "envelope");
        let e = SignedBlockEnvelope::from_wire_bytes(&wire).unwrap();
        assert_eq!(e.wire_bytes(), wire);
        assert_eq!(hex::encode(e.signing_payload()), r["payload"]);
        assert_eq!(hex::encode(e.signing_preimage()), r["preimage"]);
        assert_eq!(hex::encode(e.signing_digest()), r["digest"]);
        assert_eq!(hex::encode(e.block().hash()), r["block_hash"]);
        assert_eq!(hex::encode(e.envelope_id()), r["envelope_id"]);
        phase_evidence::reset();
        let p = authenticate_block(&wire, &ctx(r), &binding(r), Some(&e.envelope_id())).unwrap();
        assert_eq!(phase_evidence::count(), 1);
        assert_eq!(p.context(), ctx(r));
        assert_eq!(p.producer_binding(), &binding(r));
        assert_eq!(p.block_hash(), e.block().hash());
        assert_eq!(p.signing_digest(), e.signing_digest());
        assert_eq!(p.signature().as_bytes(), e.signature_bytes());
        assert_eq!(p.envelope().block().header().canonical_bytes().len(), 229);
        let signature = Signature::from_slice(&bytes(r, "signature")[..64]).unwrap();
        let raw_s: [u8; 32] = bytes(r, "raw_s").try_into().unwrap();
        let raw = Signature::from_scalars(signature.r().to_bytes(), raw_s).unwrap();
        assert_eq!(
            raw.normalize_s().is_some(),
            r["normalized_low_s"].as_bool().unwrap()
        );
        assert_eq!(
            bytes(r, "signature")[64],
            r["raw_parity"].as_u64().unwrap() as u8 ^ u8::from(raw.normalize_s().is_some())
        );
        if r["deterministic"] == true {
            assert_eq!(
                sign_block(e.block(), &key(2), &ctx(r), &binding(r))
                    .unwrap()
                    .wire_bytes(),
                wire
            );
        }
    }
    assert_eq!(PAYLOAD_LEN, 82);
    assert_eq!(SIGNING_PREIMAGE_LEN, 102);
    assert_eq!(MAX_ENVELOPE_BYTES, 609651);
}

#[test]
fn trusted_policy_and_full_key_bindings_have_no_defaults_or_normalization() {
    let r = row("empty");
    let native = ctx(&r).native_context();
    assert_eq!(
        BlockAuthenticationContext::new(native, 1, 1),
        Err(Error::UnsupportedProfile(1))
    );
    assert_eq!(
        BlockAuthenticationContext::new(native, 2, 0),
        Err(Error::UnsupportedRules(0))
    );
    let good = bytes(&data(), "compressed_key");
    for id in ["", "protocol", &"x".repeat(257)] {
        assert_eq!(
            ProducerBinding::new(id, &good),
            Err(Error::InvalidProducerId)
        );
    }
    for b in [
        vec![],
        vec![0; 33],
        vec![2; 32],
        vec![4; 33],
        bytes(&data(), "uncompressed_key"),
        [vec![2], vec![0xff; 32]].concat(),
    ] {
        assert_eq!(
            ProducerBinding::new("offline-validator", &b),
            Err(Error::InvalidPublicKey)
        );
    }
    let wrong_id = ProducerBinding::new("Offline-validator", &good).unwrap();
    phase_evidence::reset();
    assert_eq!(
        authenticate_block(&env("empty").wire_bytes(), &ctx(&r), &wrong_id, None),
        Err(Error::ProducerMismatch)
    );
    assert_eq!(phase_evidence::count(), 0);
    let wrong_key = ProducerBinding::new(
        "offline-validator",
        key(1).verifying_key().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    assert_eq!(
        authenticate_block(&env("empty").wire_bytes(), &ctx(&r), &wrong_key, None),
        Err(Error::KeyMismatch)
    );
    assert_eq!(phase_evidence::count(), 1);
    assert_eq!(
        sign_block(env("empty").block(), &key(1), &ctx(&r), &binding(&r)),
        Err(Error::KeyMismatch)
    );
}

#[test]
fn exact_framing_truncations_versions_limits_and_no_unsigned_fallback() {
    let wire = env("sequential").wire_bytes();
    for end in 0..wire.len() {
        assert!(
            SignedBlockEnvelope::from_wire_bytes(&wire[..end]).is_err(),
            "{end}"
        );
    }
    for more in [vec![0], vec![0; 65]] {
        assert!(authenticate(&[wire.clone(), more].concat()).is_err());
    }
    for (offset, value, expected) in [
        (0, 2, Error::UnsupportedWire(2)),
        (1, 2, Error::UnsupportedEncoding(2)),
        (5, 2, Error::UnsupportedRules(2)),
    ] {
        let mut bad = wire.clone();
        bad[offset] = value;
        assert_eq!(authenticate(&bad), Err(expected));
    }
    for len in [0u32, 288, 609545, u32::MAX] {
        let mut bad = wire.clone();
        bad[38..42].copy_from_slice(&len.to_be_bytes());
        assert_eq!(authenticate(&bad), Err(Error::Frame("inner length")));
    }
    assert_eq!(
        authenticate(&vec![3; MAX_ENVELOPE_BYTES + 1]),
        Err(Error::Frame("envelope size"))
    );
    assert_eq!(
        authenticate(&env("single").block().wire_bytes()),
        Err(Error::UnsupportedWire(2))
    );
    let mut bad = wire.clone();
    bad[42] = 1;
    assert!(matches!(
        authenticate(&bad),
        Err(Error::Block(BlockError::Frame { .. }))
    ));
    // Inner metadata lengths and UTF-8 remain bounded by the unchanged codec.
    for off in [42 + 262, 42 + 287] {
        let mut bad = wire.clone();
        bad[off..off + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(authenticate(&bad).is_err());
    }
    let mut bad = wire.clone();
    bad[42 + 266] = 0xff;
    assert!(matches!(
        authenticate(&bad),
        Err(Error::Block(BlockError::Frame {
            reason: "proposer UTF-8",
            ..
        }))
    ));
}

#[test]
fn network_preflight_identity_signature_claim_recovery_order_is_fixed() {
    let r = row("empty");
    let mut wire = env("empty").wire_bytes();
    let last = wire.len() - 1;
    wire[last] = 27;
    wire[6] ^= 1;
    phase_evidence::reset();
    assert_eq!(authenticate(&wire), Err(Error::NetworkMismatch));
    assert_eq!(phase_evidence::count(), 0);
    wire[6] ^= 1;
    wire[42 + 33 + 3] = 1;
    assert_eq!(authenticate(&wire), Err(Error::Block(BlockError::Profile)));
    let mut wire = env("empty").wire_bytes();
    wire[last] = 27;
    assert_eq!(
        authenticate(&wire),
        Err(Error::Signature(native::Error::InvalidParity(27)))
    );
    assert_eq!(
        authenticate_block(&wire, &ctx(&r), &binding(&r), Some(&[0; 32])),
        Err(Error::Signature(native::Error::InvalidParity(27)))
    );
    assert_eq!(
        authenticate_block(
            &env("empty").wire_bytes(),
            &ctx(&r),
            &binding(&r),
            Some(&[0; 32])
        ),
        Err(Error::ClaimedEnvelopeIdMismatch)
    );
    assert_eq!(phase_evidence::count(), 0);
    let other = env("empty_other_network");
    assert_eq!(
        authenticate(&other.wire_bytes()),
        Err(Error::NetworkMismatch)
    );
    let replaced = SignedBlockEnvelope::from_parts(
        other.block().clone(),
        ctx(&r).native_context().network_id(),
        *other.signature_bytes(),
    )
    .unwrap();
    assert_eq!(
        authenticate(&replaced.wire_bytes()),
        Err(Error::KeyMismatch)
    );
}

#[test]
fn all_payload_signature_and_header_byte_mutations_fail_attribution() {
    let e = env("single");
    let r = row("single");
    let digest = e.signing_digest();
    let sig = BlockSignature::from_bytes(e.signature_bytes()).unwrap();
    for i in 0..PAYLOAD_LEN {
        let mut payload = e.signing_payload();
        payload[i] ^= 1;
        let hash = hash_with_domain(SIGNING_DOMAIN, &payload);
        assert_ne!(
            sig.recover(&hash)
                .unwrap()
                .to_encoded_point(true)
                .as_bytes(),
            binding(&r).public_key()
        );
    }
    let wire = e.wire_bytes();
    for i in wire.len() - 65..wire.len() {
        let mut bad = wire.clone();
        bad[i] ^= 1;
        assert!(authenticate(&bad).is_err(), "signature byte {i}");
    }
    for i in 0..229 {
        let mut bad = wire.clone();
        bad[42 + 33 + i] ^= 1;
        // Recompute the claimed hash too: changing a header cannot retain producer authorization.
        let h = hash_with_domain(
            crate::block_commitment::BLOCK_HEADER_DOMAIN,
            &bad[42 + 33..42 + 262],
        );
        bad[43..75].copy_from_slice(&h);
        assert!(authenticate(&bad).is_err(), "header byte {i}");
    }
    assert_eq!(sig.recover(&digest).unwrap(), *key(2).verifying_key());
}

#[test]
fn canonical_signature_scalar_parity_recovery_and_domain_rejection() {
    let e = env("empty");
    let s = *e.signature_bytes();
    for parity in 2..=255 {
        let mut bad = s;
        bad[64] = parity;
        assert_eq!(
            BlockSignature::from_bytes(&bad),
            Err(Error::Signature(native::Error::InvalidParity(parity)))
        );
    }
    let n =
        hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap();
    for (start, end) in [(0, 32), (32, 64)] {
        for replacement in [vec![0; 32], n.clone()] {
            let mut bad = s;
            bad[start..end].copy_from_slice(&replacement);
            assert_eq!(
                BlockSignature::from_bytes(&bad),
                Err(Error::Signature(native::Error::InvalidScalar))
            );
        }
    }
    let raw = bytes(&row("empty"), "raw_s");
    let mut high = s;
    high[32..64].copy_from_slice(&raw);
    high[64] ^= 1;
    assert_eq!(
        BlockSignature::from_bytes(&high),
        Err(Error::Signature(native::Error::HighS))
    );
    for bytes in [
        &s[..64],
        &[s.as_slice(), &[0]].concat(),
        &Signature::from_slice(&s[..64]).unwrap().to_der().to_bytes(),
    ] {
        assert!(BlockSignature::from_bytes(bytes).is_err());
    }
    let mut bad = [0; 65];
    bad[31] = 5;
    bad[63] = 1;
    assert_eq!(
        BlockSignature::from_bytes(&bad)
            .unwrap()
            .recover(&e.signing_digest()),
        Err(Error::RecoveryFailed)
    );
    let infinity = key(1).verifying_key().to_encoded_point(false);
    let mut bad = [0; 65];
    bad[..32].copy_from_slice(&infinity.as_bytes()[1..33]);
    bad[63] = 1;
    let mut one = [0; 32];
    one[31] = 1;
    assert_eq!(
        BlockSignature::from_bytes(&bad).unwrap().recover(&one),
        Err(Error::RecoveryFailed)
    );
    for domain in [
        native::SIGNING_DOMAIN.as_slice(),
        b"\x19Ethereum Signed Message:\n82",
        b"BLOCK_SIGN",
    ] {
        let digest = hash_with_domain(domain, &e.signing_payload());
        let (s, id) = key(2).sign_prehash_recoverable(&digest).unwrap();
        let mut sig = [0; 65];
        sig[..64].copy_from_slice(&s.to_bytes());
        sig[64] = id.to_byte();
        let bad = SignedBlockEnvelope::from_parts(e.block().clone(), e.network_id(), sig).unwrap();
        assert_eq!(authenticate(&bad.wire_bytes()), Err(Error::KeyMismatch));
    }
}

#[test]
fn signature_variants_and_conflicting_headers_have_distinct_evidence_not_new_rules() {
    let a = authenticate(&env("empty").wire_bytes()).unwrap();
    let b = authenticate(&env("empty_alternate").wire_bytes()).unwrap();
    assert_eq!(a.block_hash(), b.block_hash());
    assert_ne!(a.envelope_id(), b.envelope_id());
    assert_ne!(a.signature(), b.signature());
    let mut header = a.envelope().block().header().clone();
    header.ticket_id += 1;
    let block = NativeBlock::from_parts(
        header,
        "offline-validator".into(),
        ProtocolData::empty(),
        vec![],
    )
    .unwrap();
    let c = authenticate(
        &sign_block(&block, &key(2), &a.context(), a.producer_binding())
            .unwrap()
            .wire_bytes(),
    )
    .unwrap();
    assert_eq!(
        a.envelope().block().header().slot,
        c.envelope().block().header().slot
    );
    assert_ne!(a.block_hash(), c.block_hash());
    // Both are signature proofs only: no selection, penalty or canonical replacement is inferred.
    for kind in [
        BlockKind::ProtocolMiss,
        BlockKind::ProtocolNoTickets,
        BlockKind::ProtocolCollision,
    ] {
        let mut h = block.header().clone();
        h.block_kind = kind;
        let bad =
            NativeBlock::from_parts(h, "offline-validator".into(), ProtocolData::empty(), vec![])
                .unwrap();
        assert_eq!(
            sign_block(&bad, &key(2), &a.context(), a.producer_binding()),
            Err(Error::Block(BlockError::Kind))
        );
    }
}

#[test]
fn maximum_envelope_is_bounded_and_transaction_authentication_is_not_preflight() {
    let e = env("empty");
    let mut h = e.block().header().clone();
    let txs = vec![[0u8; 199]; 3000];
    let ids: Vec<_> = txs
        .iter()
        .map(|b| hash_with_domain(native::ID_DOMAIN, b))
        .collect();
    let proposer = "x".repeat(256);
    h.proposer_id = proposer_id(&proposer);
    h.transaction_root = ordered_transaction_root(&ids).unwrap();
    let b = NativeBlock::from_parts(h, proposer.clone(), ProtocolData::empty(), txs).unwrap();
    let r = row("empty");
    let binding = ProducerBinding::new(
        &proposer,
        key(2).verifying_key().to_encoded_point(true).as_bytes(),
    )
    .unwrap();
    let signed = sign_block(&b, &key(2), &ctx(&r), &binding).unwrap();
    assert_eq!(signed.wire_bytes().len(), MAX_ENVELOPE_BYTES);
    let p = authenticate_block(&signed.wire_bytes(), &ctx(&r), &binding, None).unwrap();
    assert_eq!(p.envelope().block().transactions().len(), 3000);
    // Opaque invalid user bodies do not become execution-valid merely because a producer signed.
    assert!(
        native::authenticate(
            &p.envelope().block().transactions()[0],
            &ctx(&r).native_context(),
            None
        )
        .is_err()
    );
}

#[test]
fn x_overflow_uses_real_fresh_nonce_retry_not_masked_parity() {
    let digest = env("empty").signing_digest();
    let (sig, _) = key(2).sign_prehash_recoverable(&digest).unwrap();
    let mut calls = vec![];
    let result = sign_with_retry(|retry| {
        calls.push(retry);
        if calls.len() <= 2 {
            Ok((
                sig,
                RecoveryId::from_byte(if calls.len() == 1 { 2 } else { 3 }).unwrap(),
            ))
        } else {
            fresh_candidate(&key(2), &digest, OsRng)
        }
    })
    .unwrap();
    assert_eq!(&calls[..3], &[false, true, true]);
    assert_eq!(result.recover(&digest).unwrap(), *key(2).verifying_key());
    assert_eq!(
        sign_with_retry(|_| Err(Error::SigningFailed)),
        Err(Error::SigningFailed)
    );
}

#[test]
fn scalar_half_order_boundary_and_recomputed_body_protocol_tampering() {
    let half =
        hex::decode("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0").unwrap();
    let mut sig = [0; 65];
    sig[31] = 1;
    sig[32..64].copy_from_slice(&half);
    assert!(BlockSignature::from_bytes(&sig).is_ok());
    sig[63] += 1;
    assert_eq!(
        BlockSignature::from_bytes(&sig),
        Err(Error::Signature(native::Error::HighS))
    );
    let e = env("single");
    for body in [true, false] {
        let mut h = e.block().header().clone();
        let mut pd = e.block().protocol_data().clone();
        let mut txs = e.block().transactions().to_vec();
        if body {
            txs[0][0] ^= 1;
            let ids: Vec<_> = txs
                .iter()
                .map(|t| hash_with_domain(native::ID_DOMAIN, t))
                .collect();
            h.transaction_root = ordered_transaction_root(&ids).unwrap();
        } else {
            pd.fees_burned += 1;
            h.protocol_data_root = pd.root();
        }
        let b = NativeBlock::from_parts(h, e.block().proposer().into(), pd, txs).unwrap();
        let bad = SignedBlockEnvelope::from_parts(b, e.network_id(), *e.signature_bytes()).unwrap();
        assert_eq!(authenticate(&bad.wire_bytes()), Err(Error::KeyMismatch));
    }
}

#[test]
fn retry_entropy_failure_is_explicit_without_infallible_os_rng_calls() {
    use k256::elliptic_curve::rand_core::{CryptoRng, Error as RngError, RngCore};
    struct NoEntropy;
    impl CryptoRng for NoEntropy {}
    impl RngCore for NoEntropy {
        fn next_u32(&mut self) -> u32 {
            panic!("infallible entropy path must not run")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("infallible entropy path must not run")
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("infallible entropy path must not run")
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), RngError> {
            Err(std::num::NonZeroU32::new(RngError::CUSTOM_START)
                .unwrap()
                .into())
        }
    }
    assert_eq!(
        fresh_candidate(&key(2), &env("empty").signing_digest(), NoEntropy),
        Err(Error::SigningFailed)
    );
}
