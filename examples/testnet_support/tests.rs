//! Golden initialization and framing boundaries; process acceptance runs the actual example binary.
use super::*;

#[test]
fn independently_frozen_profile_bytes_and_strict_loader() {
    let raw = include_bytes!("../../tests/fixtures/testnet_fixture_profile.json");
    let p = Profile::from_bytes(raw).unwrap();
    assert_eq!(
        hex::encode(&p.genesis),
        include_str!("../../tests/fixtures/testnet_fixture_genesis.hex").trim()
    );
    let mut document: Value = serde_json::from_slice(raw).unwrap();
    for (field, value) in [
        ("chain_id", json!(1)),
        ("seed_burn", json!("00")),
        ("max_transactions", json!(3000)),
        ("network_id", json!("00".repeat(32))),
        ("provenance", json!("self-advertised")),
        ("unknown", json!(0)),
    ] {
        let mut bad = document.clone();
        bad[field] = value;
        assert!(
            Profile::from_bytes(&serde_json::to_vec(&bad).unwrap()).is_err(),
            "{field}"
        );
    }
    document["accounts"][1]["address"] = document["accounts"][0]["address"].clone();
    assert!(Profile::from_bytes(&serde_json::to_vec(&document).unwrap()).is_err());
    let duplicate =
        String::from_utf8(raw.to_vec())
            .unwrap()
            .replacen("{", "{\"chain_id\":1162,", 1);
    assert!(Profile::from_bytes(duplicate.as_bytes()).is_err());
    assert!(Profile::from_bytes(&vec![b' '; profile::MAX_PROFILE_BYTES + 1]).is_err());
}

#[test]
fn bounded_framing_exact_eof_and_response_limit() {
    let value = success(json!({"ok":"bounded"}));
    let mut bytes = vec![];
    framing::write_frame(&mut bytes, &value).unwrap();
    let mut input = &bytes[..];
    assert_eq!(
        serde_json::from_slice::<Value>(&framing::read_frame(&mut input).unwrap().unwrap())
            .unwrap(),
        value
    );
    assert!(framing::read_frame(&mut input).unwrap().is_none());
    for bad in [
        vec![0, 0],
        vec![0, 0, 0, 4, b'{'],
        0u32.to_be_bytes().to_vec(),
        ((framing::MAX_COMMAND_BYTES + 1) as u32)
            .to_be_bytes()
            .to_vec(),
    ] {
        assert!(framing::read_frame(&mut &bad[..]).is_err());
    }
    let mut output = vec![];
    assert!(
        framing::write_frame(&mut output, &json!("x".repeat(framing::MAX_RESPONSE_BYTES))).is_err()
    );
    assert!(
        output.is_empty(),
        "oversize responses fail before writing even a frame header"
    );
}

#[test]
fn empty_commands_reject_unexpected_fields_and_duplicate_tags() {
    // Serde unit variants ignore fields even with enum-level deny_unknown_fields. Empty STRUCT
    // variants preserve the strict operator schema for status/recover/stop too.
    for command in ["status", "recover", "stop", "prepare", "propose"] {
        assert!(serde_json::from_value::<Command>(json!({"command":command})).is_ok());
        assert!(
            serde_json::from_value::<Command>(json!({"command":command,"extra":true})).is_err()
        );
    }
    assert!(serde_json::from_str::<Command>(r#"{"command":"status","command":"stop"}"#).is_err());
}
