//! Codec tests are shared by the example and same-source library test build.
use super::*;
use serde_json::Value;

fn profile() -> Profile {
    Profile::from_bytes(include_bytes!(
        "../../../../tests/fixtures/testnet_fixture_profile.json"
    ))
    .unwrap()
}

#[test]
fn fixed_peer_header_validates_all_context_before_body_allocation() {
    let p = profile();
    let sender = Context::new(1, &p);
    let receiver = Context::new(2, &p);
    let bytes = encode(&sender, Kind::Status, &status(p.anchor_tip())).unwrap();
    let raw: [u8; HEADER_BYTES] = bytes[..HEADER_BYTES].try_into().unwrap();
    let h = header(&raw, &receiver).unwrap();
    assert_eq!(h.length, 48);
    assert_eq!(h.sender, 1);
    assert!(
        matches!(decode(h.kind,&bytes[HEADER_BYTES..]).unwrap(),Message::Status(t) if t==p.anchor_tip())
    );
    for offset in [0, 4, 5, 6, 8, 12, 14, 15, 16, 79, 80, 112] {
        let mut bad = raw;
        bad[offset] ^= 0xff;
        // Changing sender to a different nonzero ID is structurally legal; the network's static
        // routing layer rejects unconfigured IDs before allocation. Zero/self is rejected here.
        if offset != 12 {
            assert!(header(&bad, &receiver).is_err(), "offset {offset}");
        }
    }
    for legacy in [b"HELL".as_slice(), b"STAT", b"HIST", b"BLOC"] {
        assert!(prefix(legacy).is_err());
    }
    let mut oversized = raw;
    oversized[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(header(&oversized, &receiver).is_err());
}

#[test]
fn peer_payload_widths_ranges_and_response_tags_are_exact() {
    let p = profile();
    let ctx = Context::new(1, &p);
    let d = Delivery {
        revision: 1,
        hash: [1; 32],
        submitted: [2; 32],
    };
    let r = reference(false, d, [3; 32]);
    assert!(
        matches!(decode(Kind::Reference,&r).unwrap(),Message::Reference {new_commit:false,delivery,..} if delivery==d)
    );
    let mut bad = r.clone();
    bad[0] = 3;
    assert!(decode(Kind::Reference, &bad).is_err());
    let mut bad = r;
    bad[1] = 1;
    assert!(decode(Kind::Reference, &bad).is_err());
    assert!(decode(Kind::Reference, &reference(true, d, [3; 32])).is_err());
    assert!(decode(Kind::Error, &error(Reject::Unavailable, 0, [0; 32])).is_ok());
    let mut bad = error(Reject::Invalid, 1, [4; 32]);
    bad[0] = 1;
    assert!(decode(Kind::Error, &bad).is_err());
    let raw = committed(1, &vec![0; 396]);
    assert!(decode(Kind::Committed, &raw).is_ok());
    let mut bad = raw.clone();
    bad[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(decode(Kind::Committed, &bad).is_err());
    assert!(decode(Kind::Committed, &committed(201, &vec![0; 396])).is_err());
    assert!(encode(&ctx, Kind::Status, &[0; 49]).is_err());
    assert!(decode(Kind::Status, &[0; 47]).is_err());
    assert_eq!(MAX_FRAME_BYTES, 3800);
}

#[test]
fn independently_frozen_peer_frames_match_exact_encoder_and_payload_bytes() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/testnet_fixture_transport.json"
    ))
    .unwrap();
    let p = profile();
    let e = hex::decode(fixture["envelope"].as_str().unwrap()).unwrap();
    let h: Hash = hex::decode(fixture["block_hash"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let eid: Hash = hex::decode(fixture["envelope_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let d = Delivery {
        revision: 1,
        hash: h,
        submitted: eid,
    };
    for v in fixture["frames"].as_array().unwrap() {
        let kind = Kind::parse(v["kind"].as_u64().unwrap() as u8).unwrap();
        let sender = v["sender"].as_u64().unwrap() as u16;
        let body = match v["name"].as_str().unwrap() {
            "status" => status(p.anchor_tip()),
            "committed" => committed(1, &e),
            "reference_new" => reference(true, d, eid),
            "reference_duplicate" => reference(false, d, eid),
            "error_unavailable" => error(Reject::Unavailable, 0, [0; 32]),
            "error_rejected" => error(Reject::Invalid, 1, eid),
            _ => unreachable!(),
        };
        let encoded = encode(&Context::new(sender, &p), kind, &body).unwrap();
        assert_eq!(hex::encode(&encoded), v["hex"].as_str().unwrap());
        let raw: [u8; HEADER_BYTES] = encoded[..HEADER_BYTES].try_into().unwrap();
        header(&raw, &Context::new(if sender == 1 { 2 } else { 1 }, &p)).unwrap();
        decode(kind, &encoded[HEADER_BYTES..]).unwrap();
    }
}
