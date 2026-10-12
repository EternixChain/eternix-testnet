//! Independent existing wire goldens plus actual schema-3 ownership/evidence regression tests.
use super::*;
use crate as chain;
use crate::native_transaction::{AuthenticationContext, network_id_from_genesis_bytes};
use crate::native_transfer::{TransferAccount, phase_evidence};
use k256::ecdsa::SigningKey;
use serde_json::Value;
#[allow(dead_code)]
// Reuse the unchanged baseline's fixture algorithms; this is not a second native validator.
#[allow(clippy::duplicate_mod)]
#[path = "../../examples/stage4_support/bench.rs"]
mod bench;
use tempfile::TempDir;

fn key(n: u8) -> SigningKey {
    let mut b = [0; 32];
    b[31] = n;
    SigningKey::from_slice(&b).unwrap()
} // public toy integers only
fn binding(id: &str, n: u8) -> ProducerBinding {
    ProducerBinding::new(id, key(n).verifying_key().to_encoded_point(true).as_bytes()).unwrap()
}
fn vector(name: &str) -> NativeBlock {
    let f: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/stage4_native_blocks.json"
    ))
    .unwrap();
    NativeBlock::from_wire_bytes(
        &hex::decode(f["vectors"][name]["wire"].as_str().unwrap()).unwrap(),
    )
    .unwrap()
}
fn context() -> crate::native_transaction::AuthenticationContext {
    AuthenticationContext::new(
        1162,
        network_id_from_genesis_bytes(b"ETERNIX_NATIVE_AUTH_VECTOR_GENESIS_V1"),
        1,
    )
    .unwrap()
}
fn policy(accounts: usize) -> AuthenticatedFixtureManifest {
    let mut map = BTreeMap::new();
    for n in 1..accounts {
        let mut a = [0x44; 20];
        a[12..].copy_from_slice(&(n as u64).to_be_bytes());
        map.insert(
            a,
            TransferAccount {
                balance_quarks: 1_000_000,
                nonce: 0,
            },
        );
    }
    map.insert(
        crate::native_transaction::address_from_public_key(key(1).verifying_key()),
        TransferAccount {
            balance_quarks: 20_000_000_000,
            nonce: 0,
        },
    );
    let f = FixtureManifest::new(
        context(),
        vector("anchor"),
        TransferState::new(map, 7, 13),
        "schema3-public-toy-anchor-42".into(),
    )
    .unwrap();
    AuthenticatedFixtureManifest::new(
        f,
        BlockAuthenticationContext::new(context(), 2, 1).unwrap(),
        vec![
            binding("offline-validator", 2),
            binding("second-offline-producer", 3),
        ],
    )
    .unwrap()
}
fn create(p: &Path, m: &AuthenticatedFixtureManifest) -> AuthenticatedFixtureStore {
    AuthenticatedFixtureStore::create_authenticated_fixture(p, m).unwrap()
}
fn grant(m: &AuthenticatedFixtureManifest, base: Tip, b: &NativeBlock) -> FixtureAdmissionGrant {
    FixtureAdmissionGrant::explicit_offline(
        m.fixture.context(),
        m.fixture.anchor().hash(),
        base,
        b.hash(),
        b.header().slot,
    )
}
fn packet(m: &AuthenticatedFixtureManifest, b: &NativeBlock, n: u8) -> Vec<u8> {
    auth::sign_block(b, &key(n), &m.context, m.binding(b.proposer()).unwrap())
        .unwrap()
        .wire_bytes()
}
fn append(s: &mut AuthenticatedFixtureStore, m: &AuthenticatedFixtureManifest, b: &NativeBlock) {
    let st = s
        .stage_received(&packet(m, b, 2), grant(m, s.snapshot().unwrap().tip, b))
        .unwrap();
    assert!(matches!(s.commit(st), AppendOutcome::Committed { .. }));
}
fn empty(s: &AuthenticatedFixtureStore, id: &str) -> NativeBlock {
    s.prepare_next(id, 7, &[]).unwrap().block().clone()
}
fn reset() {
    auth::phase_evidence::reset();
    phase_evidence::reset();
}
fn counters() -> (usize, usize, (usize, usize)) {
    (
        auth::phase_evidence::count(),
        phase_evidence::stages(),
        phase_evidence::counts(),
    )
}
fn hook(point: &'static str) -> Hook {
    Box::new(move |p| {
        if p == point {
            Err(invalid(point))
        } else {
            Ok(())
        }
    })
}

#[test]
fn atomic_unsigned_anchor_signed_producer_receiver_and_authenticated_restart() {
    let d = TempDir::new().unwrap();
    let m = policy(4);
    let p = d.path().join("producer.db");
    let r = d.path().join("receiver.db");
    let mut producer = create(&p, &m);
    let mut receiver = create(&r, &m);
    assert!(matches!(
        producer.snapshot().unwrap().records[0],
        ArchiveRecord::TrustedAnchor(_)
    ));
    assert!(matches!(
        producer.export_signed_envelope(0),
        Err(Error::TrustedAnchorReference(_))
    ));
    let b = vector("sequential");
    let input: Vec<_> = b.transactions().iter().map(|b| b.to_vec()).collect();
    reset();
    let prep = producer
        .prepare_next("offline-validator", 7, &input)
        .unwrap();
    assert_eq!(counters(), (0, 1, (3, 3)));
    let wire = packet(&m, prep.block(), 2);
    let g = grant(&m, prep.base_tip(), prep.block());
    let st = producer.seal_prepared(prep, &wire, g).unwrap();
    assert_eq!(counters(), (1, 1, (3, 3)));
    assert!(matches!(
        producer.commit(st),
        AppendOutcome::Committed { .. }
    ));
    assert_eq!(counters(), (1, 1, (3, 3)));
    reset();
    let st = receiver.stage_received(&wire, g).unwrap();
    assert_eq!(counters(), (1, 1, (3, 3)));
    assert!(matches!(
        receiver.commit_profiled(st),
        AppendOutcome::Committed { .. }
    ));
    assert_eq!(counters(), (1, 1, (3, 3)));
    assert_eq!(producer.snapshot().unwrap(), receiver.snapshot().unwrap());
    assert_eq!(producer.export_signed_envelope(1).unwrap(), wire);
    for id in ["offline-validator", "second-offline-producer"] {
        let n = if id == "offline-validator" { 2 } else { 3 };
        let b = empty(&producer, id);
        let bytes = packet(&m, &b, n);
        let g = grant(&m, producer.snapshot().unwrap().tip, &b);
        for s in [&mut producer, &mut receiver] {
            reset();
            let st = s.stage_received(&bytes, g).unwrap();
            assert_eq!(counters(), (1, 1, (0, 0)));
            assert!(matches!(s.commit(st), AppendOutcome::Committed { .. }));
            assert_eq!(counters(), (1, 1, (0, 0)));
        }
    }
    let expected = producer.snapshot().unwrap().clone();
    drop(producer);
    drop(receiver);
    reset();
    let loaded = AuthenticatedFixtureStore::reopen(&r, &m).unwrap();
    assert_eq!(loaded.snapshot().unwrap(), &expected);
    assert_eq!(counters(), (3, 3, (3, 3)));
    assert_eq!(loaded.export_signed_envelope(1).unwrap(), wire);
    assert_eq!(loaded.settings().unwrap().cache_size, -2000);
}

#[test]
fn duplicates_retain_first_evidence_and_anchor_stays_unsigned() {
    let d = TempDir::new().unwrap();
    let m = policy(2);
    let mut s = create(&d.path().join("s.db"), &m);
    append(&mut s, &m, &vector("single"));
    append(&mut s, &m, &vector("empty"));
    let old = s.snapshot().unwrap().clone();
    let f: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/block_authentication.json"
    ))
    .unwrap();
    let v = f["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "empty_alternate")
        .unwrap();
    let bytes = hex::decode(format!(
        "{}{}{}",
        v["outer_prefix"].as_str().unwrap(),
        hex::encode(vector("empty").wire_bytes()),
        v["signature"].as_str().unwrap()
    ))
    .unwrap();
    reset();
    let result = s.stage_received(&bytes, grant(&m, old.tip, &vector("empty")));
    assert!(
        matches!(result,Err(Error::AlreadyCommitted{retained_envelope_id,submitted_envelope_id,..})if retained_envelope_id!=submitted_envelope_id)
    );
    assert_eq!(counters(), (1, 0, (0, 0)));
    assert_eq!(s.snapshot().unwrap(), &old);
    assert_ne!(s.export_signed_envelope(2).unwrap(), bytes);
    let anchor = packet(&m, m.fixture.anchor(), 2);
    assert!(matches!(
        s.stage_received(&anchor, grant(&m, old.tip, m.fixture.anchor())),
        Err(Error::TrustedAnchorReference(_))
    ));
    let mut malformed = s.export_signed_envelope(2).unwrap();
    *malformed.last_mut().unwrap() = 27;
    assert!(matches!(
        s.stage_received(&malformed, grant(&m, old.tip, &vector("empty"))),
        Err(Error::Authentication(auth::Error::Signature(_)))
    ));
}

#[test]
fn rollback_poison_and_exact_request_recovery_hide_all_publication() {
    let d = TempDir::new().unwrap();
    let m = policy(2);
    let mut s = create(&d.path().join("s.db"), &m);
    let b = vector("single");
    let bytes = packet(&m, &b, 2);
    let g = grant(&m, s.snapshot().unwrap().tip, &b);
    let old = s.snapshot().unwrap().clone();
    for point in [
        "accounts",
        "accounting",
        "block_evidence",
        "body",
        "indexes",
        "revision",
        "tip",
        "before_commit",
    ] {
        let st = s.stage_received(&bytes, g).unwrap();
        s.hook = Some(hook(point));
        assert!(matches!(s.commit(st), AppendOutcome::Aborted(_)), "{point}");
        assert_eq!(s.snapshot().unwrap(), &old);
        s.hook = None;
    }
    let stale = s.stage_received(&bytes, g).unwrap();
    let st = s.stage_received(&bytes, g).unwrap();
    s.hook = Some(hook("after_commit"));
    assert!(matches!(s.commit(st), AppendOutcome::RecoveryRequired(_)));
    reset();
    assert_eq!(s.stage_received(&[], g).err(), Some(Error::Blocked));
    assert!(s.export_signed_envelope(1).is_err());
    assert!(s.snapshot().is_err());
    assert!(s.settings().is_err());
    assert_eq!(counters(), (0, 0, (0, 0)));
    for point in [
        "recovery_reopen",
        "recovery_validate",
        "recovery_barrier",
        "recovery_install",
    ] {
        s.hook = Some(hook(point));
        assert!(s.recover().is_err());
        assert!(!s.is_ready());
    }
    s.hook = None;
    assert_eq!(s.recover().unwrap().attempted_present, Some(true));
    assert_eq!(s.export_signed_envelope(1).unwrap(), bytes);
    assert!(matches!(
        s.commit(stale),
        AppendOutcome::Aborted(Error::Stale)
    ));
}

#[test]
fn policies_schemas_and_missing_paths_are_independent_authority() {
    let d = TempDir::new().unwrap();
    let m = policy(2);
    let p = d.path().join("s.db");
    assert!(matches!(
        AuthenticatedFixtureStore::reopen(&p, &m),
        Err(Error::Storage(StoreError::Missing))
    ));
    assert!(!p.exists());
    drop(create(&p, &m));
    assert!(matches!(
        AuthenticatedFixtureStore::create_authenticated_fixture(&p, &m),
        Err(Error::Storage(StoreError::AlreadyExists))
    ));
    assert!(canonical::CanonicalFixtureStore::reopen(&p, &m.fixture).is_err());
    let p2 = d.path().join("schema2.db");
    drop(canonical::CanonicalFixtureStore::create_anchored_fixture(&p2, &m.fixture).unwrap());
    assert!(AuthenticatedFixtureStore::reopen(&p2, &m).is_err());
    let p1 = d.path().join("schema1.db");
    drop(
        disk::FixtureStore::create_fixture(
            &p1,
            m.fixture.context(),
            m.fixture.initial_state().clone(),
            "old schema",
        )
        .unwrap(),
    );
    assert!(AuthenticatedFixtureStore::reopen(&p1, &m).is_err());
    assert!(disk::FixtureStore::reopen(&p, m.fixture.context()).is_err());
    let wrong = AuthenticatedFixtureManifest::new(
        m.fixture.clone(),
        m.context,
        vec![
            binding("offline-validator", 4),
            binding("second-offline-producer", 3),
        ],
    )
    .unwrap();
    assert!(AuthenticatedFixtureStore::reopen(&p, &wrong).is_err());
    assert_eq!(
        AuthenticatedFixtureManifest::new(m.fixture.clone(), m.context, vec![]),
        Err(Error::Policy)
    );
    assert_eq!(
        AuthenticatedFixtureManifest::new(
            m.fixture.clone(),
            m.context,
            vec![binding("one", 2), binding("two", 2)]
        ),
        Err(Error::Policy)
    );
    let mut s = AuthenticatedFixtureStore::reopen(&p, &m).unwrap();
    let b = empty(&s, "offline-validator");
    assert!(matches!(
        s.stage_received(&b.wire_bytes(), grant(&m, s.snapshot().unwrap().tip, &b)),
        Err(Error::Authentication(auth::Error::UnsupportedWire(2)))
    ));
    let g = grant(&m, s.snapshot().unwrap().tip, &b);
    let st = s.stage_received(&packet(&m, &b, 2), g).unwrap();
    assert!(matches!(s.commit(st), AppendOutcome::Committed { .. }));
}

// Deliberately bypass the application immutability guards, then restore exact schema definitions.
// A corruption oracle must not fail merely because the test forgot to recreate a required trigger.
fn corrupt(c: &Connection, statement: &str) {
    c.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
    for (name, _) in schema::triggers() {
        c.execute_batch(&format!("DROP TRIGGER {name}")).unwrap();
    }
    c.execute_batch("PRAGMA ignore_check_constraints=ON")
        .unwrap();
    c.execute_batch(statement).unwrap();
    c.execute_batch("PRAGMA ignore_check_constraints=OFF")
        .unwrap();
    for (_, ddl) in schema::triggers() {
        c.execute_batch(&ddl).unwrap();
    }
}
fn alternate() -> ([u8; 65], Hash) {
    let f: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/block_authentication.json"
    ))
    .unwrap();
    let v = f["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "empty_alternate")
        .unwrap();
    (
        hex::decode(v["signature"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        hex::decode(v["envelope_id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

#[test]
fn missing_tampered_swapped_policy_evidence_and_canonical_fields_fail_full_reopen() {
    for sql in [
        "UPDATE blocks SET producer_signature=NULL WHERE revision=x'0000000000000001'",
        "UPDATE blocks SET producer_signature=zeroblob(64) WHERE revision=x'0000000000000001'",
        "UPDATE blocks SET producer_signature=zeroblob(66) WHERE revision=x'0000000000000001'",
        "UPDATE blocks SET producer_signature=zeroblob(65) WHERE revision=x'0000000000000001'",
        "UPDATE blocks SET producer_signature=substr(producer_signature,1,64)||x'1b' WHERE revision=x'0000000000000001'",
        "UPDATE blocks SET signed_envelope_id=zeroblob(32) WHERE revision=x'0000000000000001'",
        "UPDATE blocks SET signed_envelope_id=zeroblob(31) WHERE revision=x'0000000000000001'",
        "UPDATE blocks SET signed_envelope_id=zeroblob(33) WHERE revision=x'0000000000000001'",
        "UPDATE blocks SET signed_envelope_id=CAST(signed_envelope_id AS TEXT) WHERE revision=x'0000000000000001'",
        "UPDATE blocks SET signed_envelope_id=NULL WHERE revision=x'0000000000000001'",
        "UPDATE blocks SET producer_signature=zeroblob(65),signed_envelope_id=zeroblob(32) WHERE is_anchor=1",
        "UPDATE blocks SET producer_signature=(SELECT producer_signature FROM blocks WHERE revision=x'0000000000000002') WHERE revision=x'0000000000000001'",
        "UPDATE blocks SET header=zeroblob(229) WHERE revision=x'0000000000000001'",
        "UPDATE blocks SET proposer=x'66616b65' WHERE revision=x'0000000000000001'",
        "UPDATE blocks SET protocol_data=zeroblob(10) WHERE revision=x'0000000000000001'",
        "UPDATE transactions SET signed=zeroblob(199) WHERE position=x'0000000000000000'",
        "UPDATE transactions SET position=x'0000000000000002' WHERE position=x'0000000000000000'",
        "UPDATE canonical_tip SET hash=zeroblob(32)",
        "UPDATE seed_accounts SET nonce=x'0000000000000001'",
        "UPDATE accounts SET balance=zeroblob(16)",
        "UPDATE metadata SET network=zeroblob(32)",
        "UPDATE metadata SET provenance='self advertised different fixture'",
        "UPDATE producer_bindings SET public_key=zeroblob(33) WHERE producer=x'6f66666c696e652d76616c696461746f72'",
        "DELETE FROM producer_bindings WHERE producer=x'7365636f6e642d6f66666c696e652d70726f6475636572'",
        "DELETE FROM bodies WHERE revision=x'0000000000000002'",
    ] {
        let d = TempDir::new().unwrap();
        let m = policy(2);
        let p = d.path().join("s.db");
        let mut s = create(&p, &m);
        append(&mut s, &m, &vector("single"));
        append(&mut s, &m, &vector("empty"));
        drop(s);
        let c = Connection::open(&p).unwrap();
        corrupt(&c, sql);
        drop(c);
        assert!(AuthenticatedFixtureStore::reopen(&p, &m).is_err(), "{sql}");
    }
}

#[test]
fn exact_attempt_differs_from_attribution_after_consistent_valid_signature_replacement() {
    let d = TempDir::new().unwrap();
    let m = policy(2);
    let p = d.path().join("s.db");
    let mut s = create(&p, &m);
    append(&mut s, &m, &vector("single"));
    let b = vector("empty");
    let bytes = packet(&m, &b, 2);
    let st = s
        .stage_received(&bytes, grant(&m, s.snapshot().unwrap().tip, &b))
        .unwrap();
    s.hook = Some(hook("after_commit"));
    assert!(matches!(s.commit(st), AppendOutcome::RecoveryRequired(_)));
    s.hook = None;
    s.connection.take();
    let c = Connection::open(&p).unwrap();
    let (sig, id) = alternate();
    corrupt(
        &c,
        &format!(
            "UPDATE blocks SET producer_signature=x'{}' WHERE revision=x'0000000000000002'",
            hex::encode(sig)
        ),
    );
    drop(c);
    assert!(AuthenticatedFixtureStore::reopen(&p, &m).is_err()); // original E-ID is an integrity check
    let c = Connection::open(&p).unwrap();
    corrupt(
        &c,
        &format!(
            "UPDATE blocks SET signed_envelope_id=x'{}' WHERE revision=x'0000000000000002'",
            hex::encode(id)
        ),
    );
    drop(c);
    // §8: the new unpinned owner establishes correct attribution, not original signature choice.
    let other = AuthenticatedFixtureStore::reopen(&p, &m).unwrap();
    assert_eq!(other.snapshot().unwrap().tip.hash, b.hash());
    assert_ne!(other.export_signed_envelope(2).unwrap(), bytes);
    drop(other);
    assert!(s.recover().is_err());
    assert!(!s.is_ready());
    assert!(s.snapshot().is_err());
}

#[test]
fn exact_absent_attempt_and_exact_present_with_valid_descendants_reconcile_without_guessing() {
    for present in [false, true] {
        let d = TempDir::new().unwrap();
        let m = policy(2);
        let p = d.path().join("s.db");
        let mut s = create(&p, &m);
        let b = vector("single");
        let bytes = packet(&m, &b, 2);
        let g = grant(&m, s.snapshot().unwrap().tip, &b);
        let st = s.stage_received(&bytes, g).unwrap();
        s.hook = Some(if present {
            hook("after_commit")
        } else {
            Box::new(|p| {
                if ["accounts", "rollback"].contains(&p) {
                    Err(invalid(p))
                } else {
                    Ok(())
                }
            })
        });
        assert!(matches!(s.commit(st), AppendOutcome::RecoveryRequired(_)));
        s.hook = None;
        if present {
            s.connection.take();
            let mut other = AuthenticatedFixtureStore::reopen(&p, &m).unwrap();
            let b = empty(&other, "offline-validator");
            append(&mut other, &m, &b);
            drop(other);
        }
        assert_eq!(s.recover().unwrap().attempted_present, Some(present));
        assert_eq!(
            s.snapshot().unwrap().tip.revision,
            if present { 2 } else { 0 }
        );
    }
}

#[test]
fn schema_guards_reject_evidence_replacement_policy_mutation_and_unsigned_fill_in() {
    let d = TempDir::new().unwrap();
    let m = policy(2);
    let mut s = create(&d.path().join("s.db"), &m);
    append(&mut s, &m, &vector("single"));
    for sql in [
        "UPDATE blocks SET producer_signature=producer_signature WHERE is_anchor=0",
        "DELETE FROM blocks WHERE is_anchor=0",
        "UPDATE producer_bindings SET public_key=public_key",
        "DELETE FROM producer_bindings",
        "UPDATE seed_accounts SET nonce=nonce",
        "UPDATE metadata SET network=zeroblob(32)",
        "DELETE FROM metadata",
        "INSERT OR REPLACE INTO blocks SELECT * FROM blocks WHERE is_anchor=0",
    ] {
        assert!(s.conn().execute_batch(sql).is_err(), "{sql}");
    }
    assert_eq!(s.snapshot().unwrap().tip.revision, 1);
}

#[test]
fn signing_preparation_matching_and_native_error_order_cannot_borrow_unsigned_effects() {
    let d = TempDir::new().unwrap();
    let m = policy(2);
    let mut s = create(&d.path().join("s.db"), &m);
    let old = s.snapshot().unwrap().clone();
    let p = s.prepare_next("offline-validator", 7, &[]).unwrap();
    let b = empty(&s, "second-offline-producer");
    let bytes = packet(&m, &b, 3);
    reset();
    assert_eq!(
        s.seal_prepared(p, &bytes, grant(&m, old.tip, &b)).err(),
        Some(Error::PreparedIdentity)
    );
    assert_eq!(counters(), (1, 0, (0, 0)));
    assert_eq!(s.snapshot().unwrap(), &old);
    let p = s.prepare_next("offline-validator", 7, &[]).unwrap();
    let b = p.block().clone();
    append(&mut s, &m, &b);
    reset();
    assert_eq!(
        s.seal_prepared(p, &[], grant(&m, old.tip, &b)).err(),
        Some(Error::Stale)
    );
    assert_eq!(counters(), (0, 0, (0, 0)));
    // Authentic producer on invalid opaque user bytes still fails the shared native stage.
    let mut h = vector("single").header().clone();
    h.slot = s.snapshot().unwrap().tip.slot + 1;
    h.parent_hash = s.snapshot().unwrap().tip.hash;
    let tx = [0; 199];
    h.transaction_root =
        crate::block_commitment::ordered_transaction_root(&[hash_with_domain(ID_DOMAIN, &tx)])
            .unwrap();
    let b = NativeBlock::from_parts(
        h,
        "offline-validator".into(),
        vector("single").protocol_data().clone(),
        vec![tx],
    )
    .unwrap();
    reset();
    assert!(matches!(
        s.stage_received(&packet(&m, &b, 2), grant(&m, s.snapshot().unwrap().tip, &b)),
        Err(Error::Body(BodyError {
            transaction_index: 0,
            ..
        }))
    ));
    assert_eq!(counters(), (1, 1, (1, 0)));
}

#[test]
fn full_width_anchor_state_and_empty_successor_commit_and_reopen() {
    let d = TempDir::new().unwrap();
    let ctx = AuthenticationContext::new(u64::MAX, context().network_id(), 1).unwrap();
    let anchor = NativeBlock::empty_fixture_anchor(
        &ctx,
        u64::MAX - 1,
        vector("anchor").hash(),
        "offline-validator".into(),
        u64::MAX,
    )
    .unwrap();
    let initial = TransferState::new(
        BTreeMap::from([(
            [0x55; 20],
            TransferAccount {
                balance_quarks: u128::MAX,
                nonce: u64::MAX,
            },
        )]),
        u64::MAX,
        u128::MAX,
    );
    let f = FixtureManifest::new(ctx, anchor, initial, "explicit unsigned maxima".into()).unwrap();
    let m = AuthenticatedFixtureManifest::new(
        f,
        BlockAuthenticationContext::new(ctx, 2, 1).unwrap(),
        vec![binding("offline-validator", 2)],
    )
    .unwrap();
    let path = d.path().join("max.db");
    let mut s = create(&path, &m);
    let p = s.prepare_next("offline-validator", u64::MAX, &[]).unwrap();
    let bytes = packet(&m, p.block(), 2);
    let g = grant(&m, p.base_tip(), p.block());
    let st = s.seal_prepared(p, &bytes, g).unwrap();
    assert!(matches!(s.commit(st), AppendOutcome::Committed { .. }));
    assert_eq!(
        s.prepare_next("offline-validator", 1, &[]).err(),
        Some(Error::Overflow)
    );
    let expected = s.snapshot().unwrap().clone();
    drop(s);
    assert_eq!(
        AuthenticatedFixtureStore::reopen(&path, &m)
            .unwrap()
            .snapshot()
            .unwrap(),
        &expected
    );
}

mod measurements;
mod storage_evidence;

#[test]
fn independently_changed_context_anchor_seed_and_binding_declarations_never_self_authorize() {
    let d = TempDir::new().unwrap();
    let m = policy(2);
    let p = d.path().join("s.db");
    let mut s = create(&p, &m);
    append(&mut s, &m, &vector("single"));
    let expected = s.snapshot().unwrap().clone();
    drop(s);
    for change in ["network", "seeds", "provenance", "anchor", "bindings"] {
        let native = if change == "network" {
            AuthenticationContext::new(1162, [0; 32], 1).unwrap()
        } else {
            context()
        };
        let mut anchor = m.fixture.anchor().clone();
        if change == "anchor" {
            anchor = NativeBlock::empty_fixture_anchor(
                &native,
                42,
                vector("single").hash(),
                "offline-validator".into(),
                7,
            )
            .unwrap();
        }
        let mut seeds = m.fixture.initial_state().clone();
        if change == "seeds" {
            seeds = TransferState::new(seeds.accounts().clone(), 8, 13);
        }
        let f = FixtureManifest::new(
            native,
            anchor,
            seeds,
            if change == "provenance" {
                "different authority".into()
            } else {
                m.fixture.provenance().into()
            },
        )
        .unwrap();
        let keys = if change == "bindings" {
            vec![
                binding("offline-validator", 4),
                binding("second-offline-producer", 3),
            ]
        } else {
            m.bindings().cloned().collect()
        };
        let wrong = AuthenticatedFixtureManifest::new(
            f,
            BlockAuthenticationContext::new(native, 2, 1).unwrap(),
            keys,
        )
        .unwrap();
        assert!(
            AuthenticatedFixtureStore::reopen(&p, &wrong).is_err(),
            "{change}"
        );
    }
    let c = Connection::open(&p).unwrap();
    let evil = binding("offline-validator", 4);
    corrupt(
        &c,
        &format!(
            "UPDATE producer_bindings SET public_key=x'{}' WHERE producer=x'{}'",
            hex::encode(evil.public_key()),
            hex::encode("offline-validator")
        ),
    );
    let b = vector("single");
    let forged = auth::sign_block(&b, &key(4), &m.context, &evil).unwrap();
    corrupt(
        &c,
        &format!(
            "UPDATE blocks SET producer_signature=x'{}',signed_envelope_id=x'{}' WHERE revision=x'0000000000000001'",
            hex::encode(forged.signature_bytes()),
            hex::encode(forged.envelope_id())
        ),
    );
    drop(c);
    assert!(AuthenticatedFixtureStore::reopen(&p, &m).is_err());
    assert_eq!(expected.tip.revision, 1);
}

#[test]
fn maximum_valid_body_is_attributed_staged_and_committed_once_then_exported_exactly() {
    let d = TempDir::new().unwrap();
    let f = bench::fixture(1000);
    let m = AuthenticatedFixtureManifest::new(
        f.clone(),
        BlockAuthenticationContext::new(f.context(), 2, 1).unwrap(),
        vec![binding("offline-validator", 2)],
    )
    .unwrap();
    let mut reference =
        canonical::CanonicalFixtureStore::create_anchored_fixture(d.path().join("ref.db"), &f)
            .unwrap();
    let b = bench::block(&reference, &f, 3000, 1000).unwrap();
    let mut s = create(&d.path().join("s.db"), &m);
    let bytes = packet(&m, &b, 2);
    reset();
    let st = s
        .stage_received(&bytes, grant(&m, s.snapshot().unwrap().tip, &b))
        .unwrap();
    assert_eq!(counters(), (1, 1, (3000, 3000)));
    assert!(matches!(s.commit(st), AppendOutcome::Committed { .. }));
    assert_eq!(counters(), (1, 1, (3000, 3000)));
    assert_eq!(s.export_signed_envelope(1).unwrap(), bytes);
    bench::append(&mut reference, &f, &b).unwrap();
    assert_eq!(
        s.snapshot().unwrap().state,
        reference.snapshot().unwrap().state
    );
}

#[test]
fn reserved_prefix_wildcards_cannot_hide_extra_schema_objects() {
    let d = TempDir::new().unwrap();
    let m = policy(2);
    let p = d.path().join("s.db");
    drop(create(&p, &m));
    let c = Connection::open(&p).unwrap();
    c.execute_batch("CREATE TABLE sqliteXnot_internal (id INTEGER)")
        .unwrap();
    drop(c);
    assert!(AuthenticatedFixtureStore::reopen(&p, &m).is_err());
}

#[test]
fn independent_existing_signed_goldens_reconstruct_from_compact_sql_evidence() {
    let d = TempDir::new().unwrap();
    let m = policy(2);
    let p = d.path().join("s.db");
    let mut s = create(&p, &m);
    let f: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/block_authentication.json"
    ))
    .unwrap();
    let mut expected = vec![];
    for name in ["single", "empty"] {
        let v = f["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap();
        let b = vector(name);
        let bytes = hex::decode(format!(
            "{}{}{}",
            v["outer_prefix"].as_str().unwrap(),
            hex::encode(b.wire_bytes()),
            v["signature"].as_str().unwrap()
        ))
        .unwrap();
        let st = s
            .stage_received(&bytes, grant(&m, s.snapshot().unwrap().tip, &b))
            .unwrap();
        assert!(matches!(s.commit(st), AppendOutcome::Committed { .. }));
        expected.push(bytes);
    }
    let rows = s
        .conn()
        .query_row(
            "SELECT sum(length(producer_signature)+length(signed_envelope_id)) FROM blocks",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(rows, 194);
    drop(s);
    let loaded = AuthenticatedFixtureStore::reopen(&p, &m).unwrap();
    for (i, e) in expected.iter().enumerate() {
        assert_eq!(loaded.export_signed_envelope(i as u64 + 1).unwrap(), *e);
    }
}

#[test]
fn ready_refresh_preserves_known_evidence_pin_without_an_uncertain_attempt() {
    let d = TempDir::new().unwrap();
    let m = policy(2);
    let p = d.path().join("s.db");
    let mut s = create(&p, &m);
    append(&mut s, &m, &vector("single"));
    append(&mut s, &m, &vector("empty"));
    let original = s.export_signed_envelope(2).unwrap();
    assert!(s.attempt.is_none());
    s.connection.take();
    let c = Connection::open(&p).unwrap();
    let (signature, id) = alternate();
    corrupt(
        &c,
        &format!(
            "UPDATE blocks SET producer_signature=x'{}',signed_envelope_id=x'{}' WHERE revision=x'0000000000000002'",
            hex::encode(signature),
            hex::encode(id)
        ),
    );
    drop(c);
    // Consistent alternate evidence remains attributed on a fresh unpinned load, not a known refresh.
    let fresh = AuthenticatedFixtureStore::reopen(&p, &m).unwrap();
    assert_ne!(fresh.export_signed_envelope(2).unwrap(), original);
    drop(fresh);
    assert!(s.recover().is_err());
    assert!(!s.is_ready());
    assert!(s.snapshot().is_err());
    assert!(s.export_signed_envelope(2).is_err());
}

#[test]
fn external_revision_change_is_stale_before_any_candidate_write() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let d = TempDir::new().unwrap();
    let m = policy(2);
    let p = d.path().join("s.db");
    let mut s = create(&p, &m);
    let b = vector("single");
    let st = s
        .stage_received(&packet(&m, &b, 2), grant(&m, s.snapshot().unwrap().tip, &b))
        .unwrap();
    let wrote = Arc::new(AtomicBool::new(false));
    let observed = wrote.clone();
    s.hook = Some(Box::new(move |point| {
        if point == "accounts" {
            observed.store(true, Ordering::SeqCst);
        }
        Ok(())
    }));
    let c = Connection::open(&p).unwrap();
    c.execute_batch("UPDATE metadata SET revision=x'0000000000000001'")
        .unwrap();
    assert!(matches!(s.commit(st), AppendOutcome::Aborted(Error::Stale)));
    assert!(!wrote.load(Ordering::SeqCst));
    assert!(!s.is_ready());
    assert!(s.attempt.is_none());
    assert_eq!(disk::read_state(&c).unwrap(), *m.fixture.initial_state());
    assert_eq!(count(&c, "blocks").unwrap(), 1);
    // Test-only repair of the corrupt external metadata restores the original complete prefix.
    c.execute_batch("UPDATE metadata SET revision=x'0000000000000000'")
        .unwrap();
    drop(c);
    s.hook = None;
    assert_eq!(s.recover().unwrap().attempted_present, None);
}

#[test]
fn external_valid_append_requires_refresh_and_wrong_owner_stages_never_install() {
    let d = TempDir::new().unwrap();
    let m = policy(2);
    let p = d.path().join("s.db");
    let mut s = create(&p, &m);
    let mut other = AuthenticatedFixtureStore::reopen(&p, &m).unwrap();
    let b = empty(&s, "offline-validator");
    let bytes = packet(&m, &b, 2);
    let g = grant(&m, s.snapshot().unwrap().tip, &b);
    let foreign = s.stage_received(&bytes, g).unwrap();
    assert!(matches!(
        other.commit(foreign),
        AppendOutcome::Aborted(Error::Stale)
    ));
    let st = s.stage_received(&bytes, g).unwrap();
    append(&mut other, &m, &b);
    assert!(matches!(s.commit(st), AppendOutcome::Aborted(Error::Stale)));
    assert!(!s.is_ready());
    let expected = other.snapshot().unwrap().clone();
    drop(other);
    assert_eq!(s.recover().unwrap().attempted_present, None);
    assert_eq!(s.snapshot().unwrap(), &expected);
}

#[test]
fn different_valid_content_at_uncertain_revision_remains_unresolved() {
    let d = TempDir::new().unwrap();
    let m = policy(2);
    let p = d.path().join("s.db");
    let mut s = create(&p, &m);
    let b = empty(&s, "offline-validator");
    let st = s
        .stage_received(&packet(&m, &b, 2), grant(&m, s.snapshot().unwrap().tip, &b))
        .unwrap();
    s.hook = Some(Box::new(|point| {
        if ["accounts", "rollback"].contains(&point) {
            Err(invalid(point))
        } else {
            Ok(())
        }
    }));
    assert!(matches!(s.commit(st), AppendOutcome::RecoveryRequired(_)));
    s.connection.take();
    s.hook = None;
    let mut other = AuthenticatedFixtureStore::reopen(&p, &m).unwrap();
    let different = other
        .prepare_next("offline-validator", 8, &[])
        .unwrap()
        .block()
        .clone();
    assert_ne!(different.hash(), b.hash());
    append(&mut other, &m, &different);
    drop(other);
    assert!(s.recover().is_err());
    assert!(!s.is_ready());
}
