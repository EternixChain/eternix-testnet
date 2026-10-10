//! Explicit public-vector fixtures shared only by offline examples, never node startup configuration.
use eternix_testnet::canonical_fixture::{FixtureAdmissionGrant, FixtureManifest, Tip};
use eternix_testnet::native_block::NativeBlock;
use eternix_testnet::native_transaction::{AuthenticationContext, network_id_from_genesis_bytes};
use eternix_testnet::native_transfer::{TransferAccount, TransferState};
use serde_json::Value;
use std::collections::BTreeMap;

pub fn data() -> Value {
    serde_json::from_str(include_str!(
        "../../tests/fixtures/stage4_native_blocks.json"
    ))
    .expect("frozen JSON")
}
pub fn block(name: &str) -> NativeBlock {
    NativeBlock::from_wire_bytes(
        &hex::decode(
            data()["vectors"][name]["wire"]
                .as_str()
                .expect("named fixture"),
        )
        .expect("frozen hex"),
    )
    .expect("frozen envelope")
}
pub fn manifest() -> FixtureManifest {
    let f = data();
    assert_eq!(f["test_only"], true);
    let genesis = hex::decode(f["canonical_genesis_hex"].as_str().unwrap()).unwrap();
    let network = network_id_from_genesis_bytes(&genesis);
    assert_eq!(hex::encode(network), f["network_id"].as_str().unwrap());
    let ctx = AuthenticationContext::new(
        f["chain_id"].as_u64().unwrap(),
        network,
        f["native_rules"].as_u64().unwrap() as u32,
    )
    .unwrap();
    let mut accounts = BTreeMap::new();
    for a in f["post_anchor_state"]["accounts"].as_array().unwrap() {
        let address = hex::decode(a["address"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        accounts.insert(
            address,
            TransferAccount {
                balance_quarks: a["balance"].as_str().unwrap().parse().unwrap(),
                nonce: a["nonce"].as_str().unwrap().parse().unwrap(),
            },
        );
    }
    let initial = TransferState::new(
        accounts,
        f["post_anchor_state"]["gas"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
        f["post_anchor_state"]["burn"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
    );
    FixtureManifest::new(
        ctx,
        block("anchor"),
        initial,
        f["provenance"].as_str().unwrap().to_owned(),
    )
    .unwrap()
}
pub fn grant(m: &FixtureManifest, base: Tip, block: &NativeBlock) -> FixtureAdmissionGrant {
    // This binder belongs to trusted fixture generation, not to the receiver or a live authorizer.
    FixtureAdmissionGrant::explicit_offline(
        m.context(),
        m.anchor().hash(),
        base,
        block.hash(),
        block.header().slot,
    )
}
