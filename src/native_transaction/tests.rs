//! Native-only fixtures and regressions. The public scalar-one key and synthetic genesis below
//! are for interoperability testing, never node configuration or production allocations.

use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    test_only: bool,
    test_private_key_hex: String,
    canonical_genesis_hex: String,
    network_id: String,
    encoding_version: u8,
    native_rules_version: u32,
    chain_id: u64,
    kind: u8,
    sender: String,
    recipient: String,
    value: String,
    valid_after_slot: String,
    public_key: String,
    unsigned_bytes: String,
    signing_preimage: String,
    signed_bytes: String,
    high_s_signature: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    nonce: String,
    token_id: String,
    gas_limit: String,
    digest: String,
    signature: String,
    transaction_id: String,
    expected_error: Option<String>,
}

fn fixture() -> Fixture {
    let fixture: Fixture =
        serde_json::from_str(include_str!("../../tests/fixtures/native_auth_v2.json")).unwrap();
    assert!(fixture.test_only);
    fixture
}

fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    hex::decode(hex).unwrap().try_into().unwrap()
}

fn context(f: &Fixture) -> AuthenticationContext {
    AuthenticationContext::new(f.chain_id, bytes(&f.network_id), f.native_rules_version).unwrap()
}

fn key(f: &Fixture) -> SigningKey {
    SigningKey::from_slice(&hex::decode(&f.test_private_key_hex).unwrap()).unwrap()
}

fn unsigned(f: &Fixture, v: &Vector) -> UnsignedTransaction {
    UnsignedTransaction {
        encoding_version: f.encoding_version,
        native_rules_version: f.native_rules_version,
        chain_id: f.chain_id,
        network_id: bytes(&f.network_id),
        kind: f.kind,
        sender: bytes(&f.sender),
        nonce: v.nonce.parse().unwrap(),
        recipient: bytes(&f.recipient),
        token_id: v.token_id.parse().unwrap(),
        value: f.value.parse().unwrap(),
        gas_limit: v.gas_limit.parse().unwrap(),
        valid_after_slot: f.valid_after_slot.parse().unwrap(),
    }
}

#[test]
fn approved_vectors_match_encoding_hashes_signing_and_authentication() {
    let f = fixture();
    let context = context(&f);
    let key = key(&f);
    assert_eq!(
        network_id_from_genesis_bytes(&hex::decode(&f.canonical_genesis_hex).unwrap()),
        bytes::<32>(&f.network_id)
    );
    assert_eq!(
        address_from_public_key(key.verifying_key()),
        bytes::<20>(&f.sender)
    );

    for v in &f.vectors {
        let unsigned = unsigned(&f, v);
        let digest = unsigned.signing_digest().unwrap();
        assert_eq!(digest, bytes::<32>(&v.digest), "{}", v.name);
        let signature = NativeSignature::from_bytes(&hex::decode(&v.signature).unwrap()).unwrap();
        let recovered = signature.recover_public_key(&digest).unwrap();
        assert_eq!(hex::encode(recovered.to_encoded_point(false)), f.public_key);
        assert_eq!(&recovered, key.verifying_key());

        // Reproduce even the cryptographically valid but profile-invalid vectors through k256.
        // Public module signing correctly refuses those profiles instead of fabricating validity.
        let (backend_signature, id) = key.sign_prehash_recoverable(&digest).unwrap();
        assert!(!id.is_x_reduced());
        assert_eq!(
            &backend_signature.to_bytes()[..],
            &signature.as_bytes()[..64]
        );
        assert_eq!(id.to_byte(), signature.as_bytes()[64]);
        let signed = SignedTransaction::from_parts(unsigned.clone(), signature).unwrap();
        let encoded = signed.canonical_bytes().unwrap();
        assert_eq!(
            signed.transaction_id().unwrap(),
            bytes::<32>(&v.transaction_id)
        );
        assert_eq!(
            SignedTransaction::from_canonical_bytes(&encoded).unwrap(),
            signed
        );

        match v.expected_error.as_deref() {
            None => {
                assert_eq!(sign(unsigned, &key, &context).unwrap(), signed);
                let proof =
                    authenticate(&encoded, &context, Some(&bytes(&v.transaction_id))).unwrap();
                assert_eq!(proof.transaction(), &signed);
                assert_eq!(proof.signing_digest(), digest);
                assert_eq!(proof.transaction_id(), signed.transaction_id().unwrap());
                assert_eq!(hex::encode(proof.public_key()), f.public_key);
            }
            Some(error) => {
                let expected = match error {
                    "gas" => Error::GasBelowIntrinsic(999),
                    "token" => Error::UnsupportedToken(1),
                    "nonce" => Error::NonceExhausted,
                    _ => panic!("unknown test-only expected error"),
                };
                assert_eq!(
                    authenticate(&encoded, &context, None),
                    Err(expected.clone())
                );
                assert_eq!(sign(unsigned, &key, &context), Err(expected));
            }
        }
    }
}

#[test]
fn full_golden_bytes_and_lengths_are_frozen() {
    let f = fixture();
    let t = unsigned(&f, &f.vectors[0]);
    assert_eq!(
        t.canonical_bytes().unwrap(),
        bytes::<134>(&f.unsigned_bytes)
    );
    assert_eq!(
        t.signing_preimage().unwrap(),
        bytes::<158>(&f.signing_preimage)
    );
    let signed = sign(t.clone(), &key(&f), &context(&f)).unwrap();
    assert_eq!(
        signed.canonical_bytes().unwrap(),
        bytes::<199>(&f.signed_bytes)
    );
    assert_eq!(
        UnsignedTransaction::from_canonical_bytes(&bytes::<134>(&f.unsigned_bytes)).unwrap(),
        t
    );
    assert_ne!(
        signed.transaction_id().unwrap(),
        t.signing_digest().unwrap()
    );
    assert_eq!(UNSIGNED_LEN, 134);
    assert_eq!(SIGNING_PREIMAGE_LEN, 158);
    assert_eq!(SIGNED_LEN, 199);
    assert_eq!(ID_DOMAIN.len() + SIGNED_LEN, 221);
}

#[test]
fn offsets_and_endianness_cover_all_fields() {
    let f = fixture();
    let mut t = unsigned(&f, &f.vectors[0]);
    t.native_rules_version = 0x01020304;
    t.chain_id = 0x0102030405060708;
    t.network_id = [0xa1; 32];
    t.sender = [0xb2; 20];
    t.nonce = 0x1112131415161718;
    t.recipient = [0xc3; 20];
    t.token_id = 0x2122232425262728;
    t.value = 0x3132333435363738393a3b3c3d3e3f40;
    t.gas_limit = 0x4142434445464748;
    t.valid_after_slot = 0x5152535455565758;
    let b = t.canonical_bytes().unwrap();
    assert_eq!(b[0], 2);
    assert_eq!(&b[1..5], &[1, 2, 3, 4]);
    assert_eq!(&b[5..13], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(&b[13..45], &[0xa1; 32]);
    assert_eq!(b[45], 0);
    assert_eq!(&b[46..66], &[0xb2; 20]);
    assert_eq!(&b[66..74], &hex::decode("1112131415161718").unwrap());
    assert_eq!(&b[74..94], &[0xc3; 20]);
    assert_eq!(&b[94..102], &hex::decode("2122232425262728").unwrap());
    assert_eq!(
        &b[102..118],
        &hex::decode("3132333435363738393a3b3c3d3e3f40").unwrap()
    );
    assert_eq!(&b[118..126], &hex::decode("4142434445464748").unwrap());
    assert_eq!(&b[126..134], &hex::decode("5152535455565758").unwrap());
    assert_eq!(UnsignedTransaction::from_canonical_bytes(&b).unwrap(), t);
}

#[test]
fn exact_decoders_reject_every_truncation_and_trailing_fields() {
    let f = fixture();
    let unsigned = bytes::<134>(&f.unsigned_bytes);
    let signed = bytes::<199>(&f.signed_bytes);
    for length in 0..UNSIGNED_LEN {
        assert_eq!(
            UnsignedTransaction::from_canonical_bytes(&unsigned[..length]),
            Err(Error::InvalidLength {
                expected: 134,
                actual: length
            })
        );
    }
    for length in 0..SIGNED_LEN {
        assert_eq!(
            SignedTransaction::from_canonical_bytes(&signed[..length]),
            Err(Error::InvalidLength {
                expected: 199,
                actual: length
            })
        );
    }
    for extra in [1, 8, 32, 65_507] {
        let mut input = signed.to_vec();
        input.resize(SIGNED_LEN + extra, 0);
        assert_eq!(
            authenticate(&input, &context(&f), None),
            Err(Error::InvalidLength {
                expected: 199,
                actual: SIGNED_LEN + extra
            })
        );
        let mut input = unsigned.to_vec();
        input.resize(UNSIGNED_LEN + extra, 0);
        assert!(UnsignedTransaction::from_canonical_bytes(&input).is_err());
    }
}

#[test]
fn every_unsigned_byte_is_authenticated() {
    let f = fixture();
    let signed = bytes::<199>(&f.signed_bytes);
    for offset in 0..UNSIGNED_LEN {
        let mut mutated = signed;
        mutated[offset] ^= 1;
        assert!(
            authenticate(&mutated, &context(&f), None).is_err(),
            "unsigned offset {offset}"
        );
    }
}

#[test]
fn signature_bytes_change_the_id_and_cannot_reuse_authorization() {
    let f = fixture();
    let signed = bytes::<199>(&f.signed_bytes);
    let expected_id = bytes::<32>(&f.vectors[0].transaction_id);
    for offset in UNSIGNED_LEN..SIGNED_LEN {
        let mut mutated = signed;
        mutated[offset] ^= 1;
        assert!(
            authenticate(&mutated, &context(&f), None).is_err(),
            "signature offset {offset}"
        );
        if let Ok(decoded) = SignedTransaction::from_canonical_bytes(&mutated) {
            assert_ne!(decoded.transaction_id().unwrap(), expected_id);
            assert_eq!(
                decoded.unsigned().signing_digest().unwrap(),
                bytes::<32>(&f.vectors[0].digest)
            );
        }
    }
}

#[test]
fn all_non_parity_recovery_values_are_rejected() {
    let f = fixture();
    for parity in 2..=u8::MAX {
        let mut signed = bytes::<199>(&f.signed_bytes);
        signed[198] = parity;
        assert_eq!(
            authenticate(&signed, &context(&f), None),
            Err(Error::InvalidParity(parity))
        );
    }
}

#[test]
fn both_valid_parities_recover_the_same_intended_sender() {
    let f = fixture();
    let mut seen = [false; 2];
    for v in &f.vectors[..2] {
        let signed = SignedTransaction::from_parts(
            unsigned(&f, v),
            NativeSignature::from_bytes(&hex::decode(&v.signature).unwrap()).unwrap(),
        )
        .unwrap();
        let proof = authenticate(&signed.canonical_bytes().unwrap(), &context(&f), None).unwrap();
        seen[usize::from(signed.signature().as_bytes()[64])] = true;
        assert_eq!(hex::encode(proof.public_key()), f.public_key);
    }
    assert_eq!(seen, [true, true]);
    let mut wrong = bytes::<199>(&f.signed_bytes);
    wrong[198] ^= 1;
    assert_eq!(
        authenticate(&wrong, &context(&f), None),
        Err(Error::SenderMismatch)
    );
}

#[test]
fn high_s_twin_is_rejected_not_normalized() {
    let f = fixture();
    assert_eq!(
        NativeSignature::from_bytes(&hex::decode(&f.high_s_signature).unwrap()),
        Err(Error::HighS)
    );
}

#[test]
fn scalar_and_compact_encoding_boundaries_are_checked() {
    let f = fixture();
    let signature = bytes::<65>(&f.vectors[0].signature);
    let order = bytes::<32>("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    let half_plus_one =
        bytes::<32>("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1");
    for offset in [0, 32] {
        for scalar in [[0; 32], order] {
            let mut invalid = signature;
            invalid[offset..offset + 32].copy_from_slice(&scalar);
            assert_eq!(
                NativeSignature::from_bytes(&invalid),
                Err(Error::InvalidScalar)
            );
        }
    }
    let mut high = signature;
    high[32..64].copy_from_slice(&half_plus_one);
    assert_eq!(NativeSignature::from_bytes(&high), Err(Error::HighS));
    let mut boundary = signature;
    boundary[..32].copy_from_slice(&order);
    boundary[31] -= 1;
    boundary[32..64].copy_from_slice(&half_plus_one);
    boundary[63] -= 1;
    assert!(NativeSignature::from_bytes(&boundary).is_ok());
    for length in [0, 1, 64, 66, 72] {
        assert_eq!(
            NativeSignature::from_bytes(&vec![0; length]),
            Err(Error::InvalidLength {
                expected: 65,
                actual: length
            })
        );
    }
    let der = Signature::from_slice(&signature[..64]).unwrap().to_der();
    assert!(NativeSignature::from_bytes(der.as_bytes()).is_err());
}

#[test]
fn invalid_recovery_point_and_infinite_key_are_rejected() {
    let f = fixture();
    let t = unsigned(&f, &f.vectors[0]);
    let mut bad_point = [0; 65];
    bad_point[31] = 5;
    bad_point[63] = 1;
    let signature = NativeSignature::from_bytes(&bad_point).unwrap();
    assert_eq!(
        signature.recover_public_key(&t.signing_digest().unwrap()),
        Err(Error::RecoveryFailed)
    );

    // R=G and s=z force Q=r^-1(sR-zG)=infinity. Scalars are canonical for this fixed digest.
    let mut infinite = [0; 65];
    infinite[..32].copy_from_slice(&bytes::<32>(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ));
    infinite[32..64].copy_from_slice(&t.signing_digest().unwrap());
    let signature = NativeSignature::from_bytes(&infinite).unwrap();
    assert_eq!(
        signature.recover_public_key(&t.signing_digest().unwrap()),
        Err(Error::RecoveryFailed)
    );
}

#[test]
fn context_and_claim_failures_precede_curve_recovery() {
    let f = fixture();
    let mut signed = bytes::<199>(&f.signed_bytes);
    // A canonical scalar pair with no recovery point detects accidental entry into recovery.
    signed[134..199].fill(0);
    signed[165] = 5;
    signed[197] = 1;
    let wrong_chain = AuthenticationContext::new(f.chain_id + 1, bytes(&f.network_id), 1).unwrap();
    assert_eq!(
        authenticate(&signed, &wrong_chain, None),
        Err(Error::ChainMismatch)
    );
    let wrong_network = AuthenticationContext::new(f.chain_id, [0; 32], 1).unwrap();
    assert_eq!(
        authenticate(&signed, &wrong_network, None),
        Err(Error::NetworkMismatch)
    );
    assert_eq!(
        authenticate(&signed, &context(&f), Some(&[0; 32])),
        Err(Error::ClaimedIdMismatch)
    );
    assert_eq!(
        authenticate(&signed, &context(&f), None),
        Err(Error::RecoveryFailed)
    );
    for rules in [0, 2, u32::MAX] {
        assert_eq!(
            AuthenticationContext::new(f.chain_id, bytes(&f.network_id), rules),
            Err(Error::UnsupportedRules(rules))
        );
        let mut signed = bytes::<199>(&f.signed_bytes);
        signed[1..5].copy_from_slice(&rules.to_be_bytes());
        assert_eq!(
            authenticate(&signed, &context(&f), None),
            Err(Error::RulesMismatch)
        );
    }
}

#[test]
fn encoding_and_undefined_kinds_have_no_fallback() {
    let f = fixture();
    for version in [0, 1, 3, u8::MAX] {
        let mut signed = bytes::<199>(&f.signed_bytes);
        signed[0] = version;
        assert_eq!(
            authenticate(&signed, &context(&f), None),
            Err(Error::UnsupportedEncoding(version))
        );
    }
    for kind in [1, 2, 3, 0x10, 0x11, 0x12, 0x13, 0x14, 0xff] {
        let mut signed = bytes::<199>(&f.signed_bytes);
        signed[45] = kind;
        assert_eq!(
            authenticate(&signed, &context(&f), None),
            Err(Error::UnsupportedKind(kind))
        );
    }
}

#[test]
fn obsolete_price_bearing_layout_is_rejected() {
    let f = fixture();
    let signed = bytes::<199>(&f.signed_bytes);
    let mut obsolete = signed[..126].to_vec();
    obsolete.extend_from_slice(&10_u64.to_be_bytes());
    obsolete.extend_from_slice(&signed[126..]);
    assert_eq!(obsolete.len(), 207);
    assert_eq!(
        authenticate(&obsolete, &context(&f), None),
        Err(Error::InvalidLength {
            expected: 199,
            actual: 207
        })
    );
    assert_eq!(
        UnsignedTransaction::from_canonical_bytes(&obsolete[..142]),
        Err(Error::InvalidLength {
            expected: 134,
            actual: 142
        })
    );
}

#[test]
fn legacy_v1_bytes_are_not_reinterpreted() {
    let f = fixture();
    // Build a representative historical V1 envelope without touching its codec or fixtures.
    let mut legacy = vec![1, 0];
    legacy.extend_from_slice(&f.chain_id.to_be_bytes());
    for (address, nonce_after) in [
        (format!("0x{}", f.sender), true),
        (format!("0x{}", f.recipient), false),
    ] {
        legacy.extend_from_slice(&(address.len() as u32).to_be_bytes());
        legacy.extend_from_slice(address.as_bytes());
        if nonce_after {
            legacy.extend_from_slice(&0_u64.to_be_bytes());
        }
    }
    legacy.extend_from_slice(&0_u64.to_be_bytes());
    legacy.extend_from_slice(&1_u128.to_be_bytes());
    for number in [1000_u64, 10000, 10, 0, 0] {
        legacy.extend_from_slice(&number.to_be_bytes());
    }
    legacy.push(0);
    legacy.extend_from_slice(&0_u32.to_be_bytes());
    legacy.extend_from_slice(&64_u32.to_be_bytes());
    legacy.extend_from_slice(&[0; 64]);
    assert_eq!(
        authenticate(&legacy, &context(&f), None),
        Err(Error::InvalidLength {
            expected: 199,
            actual: legacy.len()
        })
    );
}

#[test]
fn gas_nonce_and_supported_asset_profile_boundaries() {
    let f = fixture();
    for gas in [0, 999] {
        let mut t = unsigned(&f, &f.vectors[0]);
        t.gas_limit = gas;
        assert_eq!(
            sign(t, &key(&f), &context(&f)),
            Err(Error::GasBelowIntrinsic(gas))
        );
    }
    for gas in [1000, 1001, u64::MAX] {
        let mut t = unsigned(&f, &f.vectors[0]);
        t.gas_limit = gas;
        t.nonce = u64::MAX - 1;
        t.valid_after_slot = u64::MAX;
        let signed = sign(t, &key(&f), &context(&f)).unwrap();
        assert!(authenticate(&signed.canonical_bytes().unwrap(), &context(&f), None).is_ok());
    }
    for token in [1, 2, u64::MAX] {
        let mut t = unsigned(&f, &f.vectors[0]);
        t.token_id = token;
        assert_eq!(
            sign(t, &key(&f), &context(&f)),
            Err(Error::UnsupportedToken(token))
        );
    }
    assert_eq!(INTRINSIC_GAS, 1000);
    assert_eq!(GAS_PRICE_QUARKS, 10);
    assert_eq!(TRANSFER_FEE_QUARKS, 10000);
}

#[test]
fn unsigned_integer_extremes_round_trip_without_clipping() {
    let f = fixture();
    let mut t = unsigned(&f, &f.vectors[0]);
    t.native_rules_version = u32::MAX;
    t.chain_id = u64::MAX;
    t.nonce = u64::MAX;
    t.token_id = u64::MAX;
    t.value = u128::MAX;
    t.gas_limit = u64::MAX;
    t.valid_after_slot = u64::MAX;
    let encoded = t.canonical_bytes().unwrap();
    assert_eq!(
        UnsignedTransaction::from_canonical_bytes(&encoded).unwrap(),
        t
    );
    assert_eq!(&encoded[102..118], &[0xff; 16]);
    t.value = 0;
    assert_eq!(&t.canonical_bytes().unwrap()[102..118], &[0; 16]);
}

#[test]
fn authentication_is_not_a_stateful_execution_success() {
    let f = fixture();
    let mut t = unsigned(&f, &f.vectors[0]);
    // Identity remains provable for a representable payload with impossible economic exposure
    // or a future validity slot. A future executor, not this module, must reject it against state.
    t.value = u128::MAX;
    t.valid_after_slot = u64::MAX;
    let signed = sign(t.clone(), &key(&f), &context(&f)).unwrap();
    let proof = authenticate(&signed.canonical_bytes().unwrap(), &context(&f), None).unwrap();
    assert_eq!(proof.transaction().unsigned(), &t);
}

#[test]
fn signing_refuses_sender_spoofing() {
    let f = fixture();
    let mut public_test_scalar_two = [0; 32];
    public_test_scalar_two[31] = 2;
    let wrong = SigningKey::from_slice(&public_test_scalar_two).unwrap();
    assert_eq!(
        sign(unsigned(&f, &f.vectors[0]), &wrong, &context(&f)),
        Err(Error::SenderMismatch)
    );
}

#[test]
fn native_signatures_do_not_accept_other_hash_domains() {
    let f = fixture();
    let t = unsigned(&f, &f.vectors[0]);
    for domain in [
        ID_DOMAIN.as_slice(),
        b"ETERNIX_BLOCK_HEADER_V1",
        b"ETERNIX_TX_V1",
        b"\x19Ethereum Signed Message:\n134",
    ] {
        let mut preimage = domain.to_vec();
        preimage.extend_from_slice(&t.canonical_bytes().unwrap());
        let (signature, id) = key(&f)
            .sign_prehash_recoverable(&keccak(&preimage))
            .unwrap();
        assert!(!id.is_x_reduced());
        let mut raw = [0; 65];
        raw[..64].copy_from_slice(&signature.to_bytes());
        raw[64] = id.to_byte();
        let signed =
            SignedTransaction::from_parts(t.clone(), NativeSignature::from_bytes(&raw).unwrap())
                .unwrap();
        assert_eq!(
            authenticate(&signed.canonical_bytes().unwrap(), &context(&f), None),
            Err(Error::SenderMismatch)
        );
    }
}

#[test]
fn x_overflow_retry_does_not_mask_recovery_id() {
    let f = fixture();
    let digest = unsigned(&f, &f.vectors[0]).signing_digest().unwrap();
    let key = key(&f);
    let (signature, id) = key.sign_prehash_recoverable(&digest).unwrap();
    let mut calls = Vec::new();
    let result = sign_with_retry(|retry| {
        calls.push(retry);
        if calls.len() <= 2 {
            // Synthetic backend overflow IDs exercise the astronomically rare retry branch.
            Ok((
                signature,
                RecoveryId::from_byte(if calls.len() == 1 { 2 } else { 3 }).unwrap(),
            ))
        } else {
            let fresh: Signature = key.sign_prehash_with_rng(&mut OsRng, &digest).unwrap();
            let fresh_id =
                RecoveryId::trial_recovery_from_prehash(key.verifying_key(), &digest, &fresh)
                    .unwrap();
            Ok((fresh, fresh_id))
        }
    })
    .unwrap();
    assert_eq!(&calls[..3], &[false, true, true]);
    assert_eq!(
        result.recover_public_key(&digest).unwrap(),
        *key.verifying_key()
    );
    assert!(!id.is_x_reduced());
    assert_eq!(
        sign_with_retry(|_| Err(Error::SigningFailed)),
        Err(Error::SigningFailed)
    );
}
