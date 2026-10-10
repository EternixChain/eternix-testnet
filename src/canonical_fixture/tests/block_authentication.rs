//! New signed route composition: signature proof is separate from grant/native/SQL authority.
use super::*;
use crate as chain;
use crate::block_authentication::{self as auth, BlockAuthenticationContext, sign_block};
#[path = "../../../examples/block_auth_support/mod.rs"]
mod support;
use support::{SignedFixtureReceiver, toy_binding, toy_producer_key};

fn context_for(m: &FixtureManifest) -> BlockAuthenticationContext {
    BlockAuthenticationContext::new(m.context(), 2, 1).unwrap()
}
fn receiver(path: &Path, m: &FixtureManifest) -> SignedFixtureReceiver {
    SignedFixtureReceiver::create(path, m, context_for(m), toy_binding("offline-validator"))
        .unwrap()
}
fn packet(b: &NativeBlock, m: &FixtureManifest) -> Vec<u8> {
    sign_block(
        b,
        &toy_producer_key(),
        &context_for(m),
        &toy_binding("offline-validator"),
    )
    .unwrap()
    .wire_bytes()
}
fn reset() {
    auth::phase_evidence::reset();
    phase_evidence::reset();
}
fn counts() -> (usize, (usize, usize)) {
    (auth::phase_evidence::count(), phase_evidence::counts())
}

#[test]
fn signed_producer_receiver_once_only_and_reopen_evidence_are_separate() {
    let d = TempDir::new().unwrap();
    let m = manifest(4);
    let p = d.path().join("p.db");
    let r = d.path().join("r.db");
    let mut producer = CanonicalFixtureStore::create_anchored_fixture(&p, &m).unwrap();
    let mut receiver = receiver(&r, &m);
    let b = vector("sequential");
    let body: Vec<_> = b.transactions().iter().map(|b| b.to_vec()).collect();
    reset();
    let prepared = producer
        .prepare_next("offline-validator", 7, &body)
        .unwrap();
    assert_eq!(counts(), (0, (3, 3)));
    let signed = packet(prepared.block(), &m);
    let g = grant(producer.snapshot().unwrap().tip, &b);
    assert!(matches!(
        producer.commit(prepared.authorize(g).unwrap()),
        AppendOutcome::Committed { .. }
    ));
    assert_eq!(counts(), (0, (3, 3)));
    reset();
    let staged = receiver.stage(&signed, g).unwrap();
    assert_eq!(counts(), (1, (3, 3)));
    assert!(matches!(
        receiver.commit(staged),
        AppendOutcome::Committed { .. }
    ));
    assert_eq!(counts(), (1, (3, 3)));
    assert_eq!(producer.snapshot().unwrap(), receiver.snapshot().unwrap());
    let next = next_empty(&producer);
    let empty = packet(&next, &m);
    let g = grant(producer.snapshot().unwrap().tip, &next);
    append(&mut producer, &next);
    reset();
    let st = receiver.stage(&empty, g).unwrap();
    assert_eq!(counts(), (1, (0, 0)));
    assert!(matches!(
        receiver.commit(st),
        AppendOutcome::Committed { .. }
    ));
    assert_eq!(counts(), (1, (0, 0)));
    let expected = producer.snapshot().unwrap().clone();
    drop(producer);
    drop(receiver.into_store());
    reset();
    assert_eq!(
        CanonicalFixtureStore::reopen(&r, &m)
            .unwrap()
            .snapshot()
            .unwrap(),
        &expected
    );
    assert_eq!(counts(), (0, (3, 3)));
    auth::authenticate_block(
        &signed,
        &context_for(&m),
        &toy_binding("offline-validator"),
        None,
    )
    .unwrap();
    assert_eq!(counts(), (1, (3, 3)));
}

#[test]
fn mandatory_signature_independent_grant_and_known_hash_order() {
    let d = TempDir::new().unwrap();
    let m = manifest(2);
    let mut r = receiver(&d.path().join("r.db"), &m);
    let b = vector("single");
    let original = r.snapshot().unwrap().clone();
    let g = grant(original.tip, &b);
    let signed = packet(&b, &m);
    reset();
    assert!(matches!(
        r.stage(&b.wire_bytes(), g),
        Err(support::Error::Authentication(
            auth::Error::UnsupportedWire(2)
        ))
    ));
    assert_eq!(counts(), (0, (0, 0)));
    let wrong = FixtureAdmissionGrant::explicit_offline(
        m.context(),
        m.anchor().hash(),
        original.tip,
        [0; 32],
        43,
    );
    assert!(matches!(
        r.stage(&signed, wrong),
        Err(support::Error::Fixture(Error::Grant))
    ));
    assert_eq!(counts(), (1, (0, 0)));
    assert_eq!(r.snapshot().unwrap(), &original);
    let st = r.stage(&signed, g).unwrap();
    assert!(matches!(r.commit(st), AppendOutcome::Committed { .. }));
    reset();
    let mut bad = signed.clone();
    *bad.last_mut().unwrap() = 27;
    assert!(matches!(
        r.stage(&bad, g),
        Err(support::Error::Authentication(auth::Error::Signature(
            native_transaction::Error::InvalidParity(27)
        )))
    ));
    assert_eq!(counts(), (0, (0, 0)));
    assert!(matches!(
        r.stage(&signed, g),
        Err(support::Error::Fixture(Error::AlreadyCommitted(_)))
    ));
    assert_eq!(counts(), (1, (0, 0)));
}

#[test]
fn compound_producer_and_native_phase_failures_have_exact_precedence() {
    let d = TempDir::new().unwrap();
    let m = manifest(2);
    let r = receiver(&d.path().join("r.db"), &m);
    let original = r.snapshot().unwrap().clone();
    let nonce = transfer(1, 1, [0x22; 20], 0);
    let mut bad_signature = transfer(0, 1, [0x22; 20], 0);
    bad_signature[198] = 27;
    let b = untrusted_body(original.tip, vec![nonce, bad_signature], 0, 0);
    let mut bytes = packet(&b, &m);
    let g = grant(original.tip, &b);
    *bytes.last_mut().unwrap() = 27;
    reset();
    assert!(matches!(
        r.stage(&bytes, g),
        Err(support::Error::Authentication(_))
    ));
    assert_eq!(counts(), (0, (0, 0)));
    reset();
    assert!(matches!(
        r.stage(&packet(&b, &m), g),
        Err(support::Error::Fixture(Error::Body(BodyError {
            transaction_index: 1,
            ..
        })))
    ));
    assert_eq!(counts(), (1, (2, 0)));
    assert_eq!(r.snapshot().unwrap(), &original);
    let b = untrusted_body(original.tip, vec![transfer(1, 1, [0x22; 20], 0)], 0, 0);
    reset();
    assert!(matches!(
        r.stage(&packet(&b, &m), grant(original.tip, &b)),
        Err(support::Error::Fixture(Error::Body(BodyError {
            transaction_index: 0,
            cause: TransferError::NonceMismatch { .. }
        })))
    ));
    assert_eq!(counts(), (1, (1, 1)));
}

#[test]
fn authentic_producer_does_not_prove_parent_slot_actual_gas_burn_or_funding() {
    let d = TempDir::new().unwrap();
    let m = manifest(2);
    let r = receiver(&d.path().join("r.db"), &m);
    let original = r.snapshot().unwrap().clone();
    for error in ["parent", "slot", "gas", "burn", "funding"] {
        let mut b = if error == "funding" {
            untrusted_body(
                original.tip,
                vec![transfer(0, 20_000_000_000, [0x22; 20], 0)],
                1000,
                10000,
            )
        } else {
            vector("single")
        };
        let mut h = b.header().clone();
        let mut pd = b.protocol_data().clone();
        match error {
            "parent" => h.parent_hash = [0; 32],
            "slot" => h.slot += 1,
            "gas" => h.gas_used += 1,
            "burn" => {
                pd.fees_burned += 1;
                h.protocol_data_root = pd.root();
            }
            _ => (),
        }
        b = NativeBlock::from_parts(h, b.proposer().into(), pd, b.transactions().to_vec()).unwrap();
        reset();
        let result = r.stage(&packet(&b, &m), grant(original.tip, &b));
        assert!(result.is_err());
        assert_eq!(auth::phase_evidence::count(), 1);
        match error {
            "parent" => assert!(matches!(
                result,
                Err(support::Error::Fixture(Error::Parent))
            )),
            "slot" => assert!(matches!(result, Err(support::Error::Fixture(Error::Slot)))),
            "gas" => assert!(matches!(
                result,
                Err(support::Error::Fixture(Error::Block(BlockError::ActualGas)))
            )),
            "burn" => assert!(matches!(
                result,
                Err(support::Error::Fixture(Error::Block(
                    BlockError::ActualBurn
                )))
            )),
            _ => assert!(matches!(
                result,
                Err(support::Error::Fixture(Error::Body(_)))
            )),
        }
        assert_eq!(r.snapshot().unwrap(), &original);
    }
}

#[test]
fn alternate_low_s_duplicate_and_signed_conflict_cannot_reapply_or_replace() {
    let d = TempDir::new().unwrap();
    let m = manifest(2);
    let mut r = receiver(&d.path().join("r.db"), &m);
    for name in ["single", "empty"] {
        let b = vector(name);
        let g = grant(r.snapshot().unwrap().tip, &b);
        let st = r.stage(&packet(&b, &m), g).unwrap();
        assert!(matches!(r.commit(st), AppendOutcome::Committed { .. }));
    }
    let expected = r.snapshot().unwrap().clone();
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/block_authentication.json"
    ))
    .unwrap();
    let row = f["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "empty_alternate")
        .unwrap();
    let wire = hex::decode(format!(
        "{}{}{}",
        row["outer_prefix"].as_str().unwrap(),
        vectors()["vectors"]["empty"]["wire"].as_str().unwrap(),
        row["signature"].as_str().unwrap()
    ))
    .unwrap();
    reset();
    assert!(matches!(
        r.stage(&wire, grant(expected.tip, &vector("empty"))),
        Err(support::Error::Fixture(Error::AlreadyCommitted(_)))
    ));
    assert_eq!(counts(), (1, (0, 0)));
    let b = vector("empty");
    let mut h = b.header().clone();
    h.ticket_id += 1;
    let different =
        NativeBlock::from_parts(h, b.proposer().into(), b.protocol_data().clone(), vec![]).unwrap();
    assert!(matches!(
        r.stage(&packet(&different, &m), grant(expected.tip, &different)),
        Err(support::Error::Fixture(Error::SlotConflict))
    ));
    assert_eq!(r.snapshot().unwrap(), &expected);
}

#[test]
fn signed_owner_rollback_poison_recovery_and_old_overlay_invalidation() {
    let d = TempDir::new().unwrap();
    let m = manifest(2);
    let mut r = receiver(&d.path().join("r.db"), &m);
    let original = r.snapshot().unwrap().clone();
    let b = vector("single");
    let g = grant(original.tip, &b);
    let signed = packet(&b, &m);
    let old = r.stage(&signed, g).unwrap();
    let current = r.stage(&signed, g).unwrap();
    r.store_mut_for_test().hook = Some(hook_at("tip"));
    assert!(matches!(r.commit(current), AppendOutcome::Aborted(_)));
    assert_eq!(r.snapshot().unwrap(), &original);
    r.store_mut_for_test().hook = None;
    let current = r.stage(&signed, g).unwrap();
    r.store_mut_for_test().hook = Some(hook_at("after_commit"));
    assert!(matches!(
        r.commit(current),
        AppendOutcome::RecoveryRequired(_)
    ));
    reset();
    assert!(matches!(
        r.stage(&[0], g),
        Err(support::Error::Fixture(Error::Blocked))
    ));
    assert_eq!(counts(), (0, (0, 0)));
    for p in [
        "recovery_reopen",
        "recovery_validate",
        "recovery_barrier",
        "recovery_install",
    ] {
        r.store_mut_for_test().hook = Some(hook_at(p));
        assert!(r.recover().is_err());
        assert!(r.snapshot().is_err());
    }
    r.store_mut_for_test().hook = None;
    reset();
    assert_eq!(r.recover().unwrap().attempted_present, Some(true));
    assert_eq!(counts(), (0, (1, 1)));
    assert!(matches!(
        r.commit(old),
        AppendOutcome::Aborted(Error::Stale)
    ));
    assert!(r.load_timings().unwrap().audit > Duration::ZERO);
}

#[test]
fn maximum_valid_body_uses_one_recovery_and_one_native_stage() {
    let d = TempDir::new().unwrap();
    let m = bench::fixture(1000);
    let mut p = CanonicalFixtureStore::create_anchored_fixture(d.path().join("p.db"), &m).unwrap();
    let mut r = receiver(&d.path().join("r.db"), &m);
    let b = bench::block(&p, &m, 3000, 1000).unwrap();
    let wire = packet(&b, &m);
    let g = bench::grant(&p, &m, &b);
    reset();
    let st = r.stage(&wire, g).unwrap();
    assert_eq!(counts(), (1, (3000, 3000)));
    assert!(matches!(r.commit(st), AppendOutcome::Committed { .. }));
    assert_eq!(counts(), (1, (3000, 3000)));
    bench::append(&mut p, &m, &b).unwrap();
    assert_eq!(p.snapshot().unwrap(), r.snapshot().unwrap());
    assert_eq!(wire.len(), 609412);
}

#[test]
fn failed_signing_and_context_mismatch_publish_nothing() {
    let d = TempDir::new().unwrap();
    let m = manifest(2);
    let p = CanonicalFixtureStore::create_anchored_fixture(d.path().join("p.db"), &m).unwrap();
    let original = p.snapshot().unwrap().clone();
    let prepared = p.prepare_next("offline-validator", 7, &[]).unwrap();
    assert_eq!(
        sign_block(
            prepared.block(),
            &key(),
            &context_for(&m),
            &toy_binding("offline-validator")
        ),
        Err(auth::Error::KeyMismatch)
    );
    drop(prepared);
    assert_eq!(p.snapshot().unwrap(), &original);
    let bad = BlockAuthenticationContext::new(
        AuthenticationContext::new(1162, [0; 32], 1).unwrap(),
        2,
        1,
    )
    .unwrap();
    let path = d.path().join("wrong-context.db");
    assert!(matches!(
        SignedFixtureReceiver::create(&path, &m, bad, toy_binding("offline-validator")),
        Err(support::Error::Context)
    ));
    assert!(!path.exists());
}

#[test]
fn profiled_and_ordinary_signed_owners_match_and_reopen_stays_signature_required() {
    let d = TempDir::new().unwrap();
    let m = manifest(2);
    let b = vector("single");
    let wire = packet(&b, &m);
    let mut states = vec![];
    for profiled in [false, true] {
        let path = d.path().join(format!("profile-{profiled}.db"));
        let mut r = receiver(&path, &m);
        let g = grant(r.snapshot().unwrap().tip, &b);
        reset();
        let stage = r.stage(&wire, g).unwrap();
        std::hint::black_box(stage.authentication_time());
        let outcome = if profiled {
            r.commit_profiled(stage)
        } else {
            r.commit(stage)
        };
        match outcome {
            AppendOutcome::Committed { timings, .. } => {
                assert_eq!(timings.sql_profile.is_some(), profiled)
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(counts(), (1, (1, 1)));
        states.push(r.snapshot().unwrap().clone());
        drop(r.into_store());
        reset();
        let reopened = SignedFixtureReceiver::reopen(
            &path,
            &m,
            context_for(&m),
            toy_binding("offline-validator"),
        )
        .unwrap();
        assert_eq!(reopened.snapshot().unwrap(), states.last().unwrap());
        assert_eq!(reopened.settings().unwrap().cache_size, -2000);
        assert_eq!(counts(), (0, (1, 1)));
        assert!(matches!(
            reopened.stage(&b.wire_bytes(), g),
            Err(support::Error::Authentication(
                auth::Error::UnsupportedWire(2)
            ))
        ));
    }
    assert_eq!(states[0], states[1]);
}
