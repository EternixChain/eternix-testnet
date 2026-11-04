//! Same-source worker orchestration measured with actual native/producer function-entry counters.
use super::*;
use crate::native_transaction as native;
#[allow(dead_code, clippy::duplicate_mod)] // The actual example, not a rewritten orchestration model.
#[path = "../../../examples/testnet_support/mod.rs"]
pub(super) mod worker;
use serde_json::json;
use worker::producer::Producer;
use worker::profile::{Approvals, Profile};

pub(super) fn profile() -> Profile {
    Profile::from_bytes(include_bytes!(
        "../../../tests/fixtures/testnet_fixture_profile.json"
    ))
    .unwrap()
}
pub(super) fn build(store: AuthenticatedFixtureStore) -> worker::Worker {
    let p = profile();
    let approvals = Approvals::load(
        Path::new("tests/fixtures/testnet_fixture_approvals_empty.json"),
        &p,
    )
    .unwrap();
    let producer = Producer::new(key(2), &p).unwrap();
    worker::Worker::new(store, p, approvals, Some(producer)).unwrap()
}
pub(super) fn inputs(count: usize) -> Vec<Value> {
    let p = profile();
    (0..count).map(|nonce| {
        let signed=native::sign(native::UnsignedTransaction {encoding_version:2,native_rules_version:1,
            chain_id:1162,network_id:p.network,kind:0,sender:native::address_from_public_key(key(1).verifying_key()),
            nonce:nonce as u64,recipient:native::address_from_public_key(key(3).verifying_key()),token_id:0,value:0,
            gas_limit:1001,valid_after_slot:0},&key(1),&p.manifest.fixture().context()).unwrap();
        json!({"command":"submit_native","transaction":hex::encode(signed.canonical_bytes().unwrap())})
    }).collect()
}
pub(super) fn reset_all() {
    reset();
    native::phase_evidence::reset();
}
pub(super) fn evidence() -> (usize, usize, usize, (usize, usize)) {
    let (p, s, n) = counters();
    (native::phase_evidence::count(), p, s, n)
}
pub(super) fn approve(w: &mut worker::Worker, d: &TempDir, proposal: &Value) {
    let p = profile();
    let document = json!({"format":"eternix-fixture-approvals-v1","network_id":hex::encode(p.network),
        "anchor_hash":hex::encode(p.anchor_tip().hash),"producer_id":"P","ticket_id":1,
        "steps":[{"base":proposal["base"],"slot":1,"block_hash":proposal["block_hash"],"envelope_id":proposal["envelope_id"]}]});
    let path = d.path().join("approvals.json");
    std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
    assert_eq!(
        w.test_command(json!({"command":"extend_approvals","path":path}))["ok"],
        true
    );
}
pub(super) fn prepare_proposal(w: &mut worker::Worker) -> Value {
    assert_eq!(w.test_command(json!({"command":"prepare"}))["ok"], true);
    let proposal = w.test_command(json!({"command":"propose"}));
    assert_eq!(proposal["ok"], true);
    proposal["result"].clone()
}

#[test]
fn actual_worker_success_counts_admission_and_once_only_empty_populated_inclusion_separately() {
    for n in [0, 2] {
        let d = TempDir::new().unwrap();
        let p = profile();
        let store = AuthenticatedFixtureStore::create_authenticated_fixture(
            d.path().join("store.db"),
            &p.manifest,
        )
        .unwrap();
        let mut w = build(store);
        reset_all();
        for input in inputs(n) {
            assert_eq!(w.test_command(input)["ok"], true);
        }
        assert_eq!(
            evidence(),
            (n, 0, 0, (0, 0)),
            "admission is authenticated but is not body staging"
        );
        let proposal = prepare_proposal(&mut w);
        assert_eq!(auth::phase_evidence::signing_count(), 1);
        assert_eq!(evidence(), (2 * n, 0, 1, (n, n)));
        assert_eq!(
            w.test_command(json!({"command":"propose"}))["result"],
            proposal
        );
        assert_eq!(
            w.test_command(json!({"command":"prepare"}))["result"]["outcome"],
            "already_prepared"
        );
        assert_eq!(
            evidence(),
            (2 * n, 0, 1, (n, n)),
            "no restage/recovery for repeated private proposal"
        );
        assert_eq!(
            auth::phase_evidence::signing_count(),
            1,
            "a cached proposal never re-signs"
        );
        assert_eq!(
            w.test_command(json!({"command":"commit_prepared","selection":1}))["ok"],
            false
        );
        approve(&mut w, &d, &proposal);
        let committed = w.test_command(json!({"command":"commit_prepared","selection":1}));
        assert_eq!(committed["result"]["new_commit"], true);
        assert_eq!(committed["result"]["envelope"], proposal["envelope"]);
        assert_eq!(
            evidence(),
            (2 * n, 1, 1, (n, n)),
            "seal authenticates producer once; commit repeats neither phase"
        );
        assert_eq!(auth::phase_evidence::signing_count(), 1);
        assert_eq!(
            w.test_command(json!({"command":"pool","offset":0,"limit":16}))["result"]["count"],
            0
        );
    }
}

#[test]
fn worker_refresh_invalidates_preparation_and_only_original_selected_request_can_be_replayed() {
    let d = TempDir::new().unwrap();
    let p = profile();
    let mut w = build(
        AuthenticatedFixtureStore::create_authenticated_fixture(d.path().join("s.db"), &p.manifest)
            .unwrap(),
    );
    for input in inputs(1) {
        assert_eq!(w.test_command(input)["ok"], true);
    }
    let original = prepare_proposal(&mut w);
    approve(&mut w, &d, &original);
    assert_eq!(w.test_command(json!({"command":"recover"}))["ok"], true);
    reset_all();
    for c in [
        json!({"command":"prepare"}),
        json!({"command":"propose"}),
        json!({"command":"commit_prepared","selection":1}),
    ] {
        assert_eq!(w.test_command(c)["ok"], false);
    }
    assert_eq!(
        evidence(),
        (0, 0, 0, (0, 0)),
        "selected unresolved request never triggers automatic re-sign/stage"
    );
    assert_eq!(auth::phase_evidence::signing_count(), 0);
    let replay =
        w.test_command(json!({"command":"apply","selection":1,"envelope":original["envelope"]}));
    assert_eq!(replay["result"]["new_commit"], true);
    assert_eq!(
        evidence(),
        (1, 1, 1, (1, 1)),
        "new explicit replay attempt uses one received-body stage"
    );
}

#[test]
fn selected_original_cannot_trigger_new_signing_of_an_unsigned_preparation() {
    let d = TempDir::new().unwrap();
    let p = profile();
    let mut w = build(
        AuthenticatedFixtureStore::create_authenticated_fixture(d.path().join("s.db"), &p.manifest)
            .unwrap(),
    );
    assert_eq!(w.test_command(json!({"command":"prepare"}))["ok"], true);
    // The independent test controller already holds an original signed empty request; the worker
    // must not reproduce it by signing again, even if ordinary RFC6979 would return identical bytes.
    let b = NativeBlock::empty_fixture_anchor(
        &p.manifest.fixture().context(),
        1,
        p.anchor_tip().hash,
        "P".into(),
        1,
    )
    .unwrap();
    let e = auth::sign_block(
        &b,
        &key(2),
        &p.manifest.context(),
        p.manifest.binding("P").unwrap(),
    )
    .unwrap();
    let proposal = json!({"base":{"hash":hex::encode(p.anchor_tip().hash),"slot":0,"revision":0},
        "block_hash":hex::encode(b.hash()),"envelope_id":hex::encode(e.envelope_id())});
    approve(&mut w, &d, &proposal);
    reset_all();
    assert_eq!(w.test_command(json!({"command":"propose"}))["ok"], false);
    assert_eq!(auth::phase_evidence::signing_count(), 0);
    assert_eq!(evidence(), (0, 0, 0, (0, 0)));
    assert_eq!(w.test_command(json!({"command":"recover"}))["ok"], true);
    let result = w.test_command(
        json!({"command":"apply","selection":1,"envelope":hex::encode(e.wire_bytes())}),
    );
    assert_eq!(result["result"]["new_commit"], true);
    assert_eq!(auth::phase_evidence::signing_count(), 0);
}

#[test]
fn actual_peer_dispatch_authenticates_duplicates_without_native_restage_or_relay_permission() {
    let d = TempDir::new().unwrap();
    let p = profile();
    let reference = AuthenticatedFixtureStore::create_authenticated_fixture(
        d.path().join("reference.db"),
        &p.manifest,
    )
    .unwrap();
    let body: Vec<_> = inputs(2)
        .iter()
        .map(|v| hex::decode(v["transaction"].as_str().unwrap()).unwrap())
        .collect();
    let prepared = reference.prepare_next("P", 1, &body).unwrap();
    let envelope = auth::sign_block(
        prepared.block(),
        &key(2),
        &p.manifest.context(),
        p.manifest.binding("P").unwrap(),
    )
    .unwrap();
    let original = envelope.wire_bytes();
    let proposal = json!({"base":{"hash":hex::encode(p.anchor_tip().hash),"slot":0,"revision":0},
        "block_hash":hex::encode(envelope.block().hash()),"envelope_id":hex::encode(envelope.envelope_id())});
    let store = AuthenticatedFixtureStore::create_authenticated_fixture(
        d.path().join("receiver.db"),
        &p.manifest,
    )
    .unwrap();
    let approvals = Approvals::load(
        Path::new("tests/fixtures/testnet_fixture_approvals_empty.json"),
        &p,
    )
    .unwrap();
    let mut w = worker::Worker::new(store, p, approvals, None).unwrap();
    approve(&mut w, &d, &proposal);
    reset_all();
    let committed = worker::transport::receive(&mut w, 1, &original);
    assert_eq!(committed.new_commit, Some(1));
    assert!(!committed.duplicate);
    assert_eq!(evidence(), (2, 1, 1, (2, 2)));
    let duplicate = worker::transport::receive(&mut w, 1, &original);
    assert_eq!(duplicate.new_commit, None);
    assert!(duplicate.duplicate);
    assert_eq!(
        evidence(),
        (2, 2, 1, (2, 2)),
        "duplicate is cold producer-authenticated but never reapplied"
    );
    let mut bad = original;
    *bad.last_mut().unwrap() = 27;
    let rejected = worker::transport::receive(&mut w, 1, &bad);
    assert_eq!(rejected.new_commit, None);
    assert!(!rejected.duplicate);
    assert_eq!(evidence(), (2, 2, 1, (2, 2)));
    assert_eq!(auth::phase_evidence::signing_count(), 0);
}

#[test]
fn uncertain_worker_has_no_cleanup_output_or_new_signing_until_explicit_audited_recovery() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let d = TempDir::new().unwrap();
    let p = profile();
    let blocked = Arc::new(AtomicBool::new(true));
    let hook_blocked = blocked.clone();
    let mut store =
        AuthenticatedFixtureStore::create_authenticated_fixture(d.path().join("s.db"), &p.manifest)
            .unwrap();
    store.hook = Some(Box::new(move |point| {
        if point == "after_commit"
            || (point == "recovery_barrier" && hook_blocked.load(Ordering::SeqCst))
        {
            Err(invalid("controlled S2 publication/recovery failure"))
        } else {
            Ok(())
        }
    }));
    let mut w = build(store);
    for input in inputs(1) {
        assert_eq!(w.test_command(input)["ok"], true);
    }
    let original = prepare_proposal(&mut w);
    approve(&mut w, &d, &original);
    let failed = w.test_command(json!({"command":"commit_prepared","selection":1}));
    assert_eq!(failed["error"]["kind"], "recovery_required");
    assert!(failed.get("result").is_none());
    let assert_blocked = |w: &mut worker::Worker| {
        let before = evidence();
        let before_signing = auth::phase_evidence::signing_count();
        for c in [
            json!({"command":"prepare"}),
            json!({"command":"propose"}),
            inputs(1).remove(0),
            json!({"command":"commit_prepared","selection":1}),
            json!({"command":"export","revision":1}),
            json!({"command":"pool","offset":0,"limit":16}),
        ] {
            assert_eq!(w.test_command(c)["error"]["kind"], "unavailable");
        }
        assert_eq!(
            before,
            evidence(),
            "poison gate precedes signing/authentication/staging/output"
        );
        assert_eq!(before_signing, auth::phase_evidence::signing_count());
    };
    assert_blocked(&mut w);
    assert_eq!(w.test_command(json!({"command":"recover"}))["ok"], false);
    assert_blocked(&mut w);
    blocked.store(false, Ordering::SeqCst);
    let recovered = w.test_command(json!({"command":"recover"}));
    assert_eq!(recovered["result"]["attempted_present"], true);
    assert_eq!(recovered["result"]["new_commit"], false);
    assert_eq!(
        w.test_command(json!({"command":"pool","offset":0,"limit":16}))["result"]["count"],
        0
    );
    assert_eq!(
        w.test_command(json!({"command":"export","revision":1}))["result"]["envelope"],
        original["envelope"]
    );
    assert_eq!(w.test_command(json!({"command":"propose"}))["ok"], false);
}
