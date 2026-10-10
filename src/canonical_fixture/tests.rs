//! Independent bytes, native phase ordering, complete prefix/initialization and real storage evidence.
use super::*;
use crate::block_commitment::{BlockKind, ordered_transaction_root};
use crate::durable_fixture::tests::vfs::Harness;
use crate::native_transaction::{
    self, UnsignedTransaction, address_from_public_key, network_id_from_genesis_bytes, sign,
};
use crate::native_transfer::{ArithmeticField, TransferAccount, TransferError, phase_evidence};
use k256::ecdsa::SigningKey;
use rusqlite::ffi;
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../tests/fixtures/stage4_native_blocks.json"
    ))
    .unwrap()
}
fn vector(name: &str) -> NativeBlock {
    NativeBlock::from_wire_bytes(
        &hex::decode(vectors()["vectors"][name]["wire"].as_str().unwrap()).unwrap(),
    )
    .unwrap()
}
fn context() -> AuthenticationContext {
    AuthenticationContext::new(
        1162,
        network_id_from_genesis_bytes(b"ETERNIX_NATIVE_AUTH_VECTOR_GENESIS_V1"),
        1,
    )
    .unwrap()
}
fn key() -> SigningKey {
    let mut b = [0; 32];
    b[31] = 1;
    SigningKey::from_slice(&b).unwrap()
} // published toy scalar only
fn sender() -> Address {
    address_from_public_key(key().verifying_key())
}
fn manifest(accounts: usize) -> FixtureManifest {
    let mut map = BTreeMap::new();
    for n in 1..accounts {
        let mut a = [0x44; 20];
        a[12..].copy_from_slice(&(n as u64).to_be_bytes());
        map.insert(
            a,
            TransferAccount {
                balance_quarks: u128::MAX,
                nonce: u64::MAX,
            },
        );
    }
    map.insert(
        sender(),
        TransferAccount {
            balance_quarks: 20_000_000_000,
            nonce: 0,
        },
    );
    FixtureManifest::new(
        context(),
        vector("anchor"),
        TransferState::new(map, 7, 13),
        "stage4-public-toy-anchor-42-v1".into(),
    )
    .unwrap()
}
fn grant(base: Tip, block: &NativeBlock) -> FixtureAdmissionGrant {
    FixtureAdmissionGrant::explicit_offline(
        context(),
        vector("anchor").hash(),
        base,
        block.hash(),
        block.header().slot,
    )
}
fn append(store: &mut CanonicalFixtureStore, block: &NativeBlock) {
    let base = store.snapshot().unwrap().tip;
    let staged = store
        .stage_received(&block.wire_bytes(), grant(base, block))
        .unwrap();
    assert!(matches!(
        store.commit(staged),
        AppendOutcome::Committed { .. }
    ));
}
fn next_empty(store: &CanonicalFixtureStore) -> NativeBlock {
    let p = store.prepare_next("offline-validator", 7, &[]).unwrap();
    p.block().clone()
}
fn transfer(nonce: u64, value: u128, target: Address, maturity: u64) -> Vec<u8> {
    sign(
        UnsignedTransaction {
            encoding_version: 2,
            native_rules_version: 1,
            chain_id: 1162,
            network_id: context().network_id(),
            kind: 0,
            sender: sender(),
            nonce,
            recipient: target,
            token_id: 0,
            value,
            gas_limit: 1001,
            valid_after_slot: maturity,
        },
        &key(),
        &context(),
    )
    .unwrap()
    .canonical_bytes()
    .unwrap()
    .to_vec()
}
// Construct opaque invalid fixtures with recomputed commitments, reaching the intended body phase.
fn untrusted_body(base: Tip, bytes: Vec<Vec<u8>>, gas: u64, burn: u64) -> NativeBlock {
    let txs: Vec<[u8; SIGNED_LEN]> = bytes.into_iter().map(|b| b.try_into().unwrap()).collect();
    let ids: Vec<_> = txs.iter().map(|b| hash_with_domain(ID_DOMAIN, b)).collect();
    let pd = ProtocolData {
        missed_proposer: None,
        fees_burned: burn,
    };
    let mut header = vector("single").header().clone();
    header.slot = base.slot + 1;
    header.parent_hash = base.hash;
    header.transaction_root = ordered_transaction_root(&ids).unwrap();
    header.protocol_data_root = pd.root();
    header.gas_used = gas;
    NativeBlock::from_parts(header, "offline-validator".into(), pd, txs).unwrap()
}

#[test]
fn independent_goldens_and_prefix_match_shared_codec() {
    let f = vectors();
    assert_eq!(f["test_only"], true);
    for name in ["anchor", "single", "empty", "sequential"] {
        let b = vector(name);
        let v = &f["vectors"][name];
        assert_eq!(hex::encode(b.wire_bytes()), v["wire"].as_str().unwrap());
        assert_eq!(
            hex::encode(b.header().canonical_bytes()),
            v["header"].as_str().unwrap()
        );
        assert_eq!(hex::encode(b.hash()), v["hash"].as_str().unwrap());
        assert_eq!(b.header().canonical_bytes().len(), 229);
        let ids = b.preflight(&context()).unwrap();
        assert_eq!(
            ids.iter().map(hex::encode).collect::<Vec<_>>(),
            v["ids"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        );
    }
    let mut parent = [0; 32];
    for slot in 0..43 {
        let b = NativeBlock::empty_fixture_anchor(
            &context(),
            slot,
            parent,
            "offline-validator".into(),
            7,
        )
        .unwrap();
        assert_eq!(hex::encode(b.hash()), f["prefix_hashes"][slot as usize]);
        parent = b.hash();
    }
    assert_eq!(parent, vector("anchor").hash());
}

#[test]
fn codec_all_truncations_bounds_and_structural_error_order() {
    let bytes = vector("sequential").wire_bytes();
    for end in 0..bytes.len() {
        assert!(
            NativeBlock::from_wire_bytes(&bytes[..end]).is_err(),
            "{end}"
        );
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(NativeBlock::from_wire_bytes(&extra).is_err());
    for offset in [0, 1, 33, 45, 53, 126, 158, 190, 222] {
        let mut changed = bytes.clone();
        changed[offset] ^= 0x80;
        assert!(
            NativeBlock::from_wire_bytes(&changed)
                .and_then(|b| b.preflight(&context()))
                .is_err(),
            "offset {offset}"
        );
    }
    let b = vector("single");
    let mut h = b.header().clone();
    for (kind, expected) in [
        (BlockKind::ProtocolMiss, BlockError::Kind),
        (BlockKind::ProtocolNoTickets, BlockError::Kind),
        (BlockKind::ProtocolCollision, BlockError::Kind),
    ] {
        h.block_kind = kind;
        let bad = NativeBlock::from_parts(
            h.clone(),
            b.proposer().into(),
            b.protocol_data().clone(),
            b.transactions().to_vec(),
        )
        .unwrap();
        assert_eq!(bad.preflight(&context()), Err(expected));
    }
    let mut h = b.header().clone();
    h.protocol_version = 1;
    h.state_root = [9; 32];
    assert_eq!(
        NativeBlock::from_parts(
            h,
            b.proposer().into(),
            b.protocol_data().clone(),
            b.transactions().to_vec()
        )
        .unwrap()
        .preflight(&context()),
        Err(BlockError::Profile)
    );
    assert!(
        NativeBlock::from_parts(
            b.header().clone(),
            "a".repeat(257),
            b.protocol_data().clone(),
            vec![]
        )
        .is_err()
    );
    assert!(
        NativeBlock::from_parts(
            b.header().clone(),
            b.proposer().into(),
            b.protocol_data().clone(),
            vec![[0; 199]; 3001]
        )
        .is_err()
    );
    let mut count = vector("anchor").wire_bytes();
    let end = count.len();
    count[end - 8..].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(NativeBlock::from_wire_bytes(&count).is_err());
}

#[test]
fn producer_receiver_reopen_and_one_execution_match_exact_prefix() {
    let dir = TempDir::new().unwrap();
    let m = manifest(1);
    let mut producer =
        CanonicalFixtureStore::create_anchored_fixture(dir.path().join("producer.db"), &m).unwrap();
    let mut receiver =
        CanonicalFixtureStore::create_anchored_fixture(dir.path().join("receiver.db"), &m).unwrap();
    for name in ["single", "empty"] {
        let exact = vector(name);
        let body: Vec<_> = exact.transactions().iter().map(|b| b.to_vec()).collect();
        phase_evidence::reset();
        let prepared = producer
            .prepare_next("offline-validator", 7, &body)
            .unwrap();
        assert_eq!(prepared.block(), &exact);
        assert_eq!(phase_evidence::counts(), (body.len(), body.len()));
        let authorized = prepared
            .authorize(grant(producer.snapshot().unwrap().tip, &exact))
            .unwrap();
        phase_evidence::reset();
        assert!(matches!(
            producer.commit(authorized),
            AppendOutcome::Committed { .. }
        ));
        assert_eq!(phase_evidence::counts(), (0, 0));
        append(&mut receiver, &exact);
        assert_eq!(producer.snapshot().unwrap(), receiver.snapshot().unwrap());
    }
    let expected = producer.snapshot().unwrap().clone();
    assert_eq!(
        expected.state.account(&sender()),
        TransferAccount {
            balance_quarks: 9_999_990_000,
            nonce: 1
        }
    );
    assert_eq!(
        (
            expected.state.gas_used_total(),
            expected.state.fees_burned_total()
        ),
        (1007, 10013)
    );
    assert!(matches!(
        receiver.stage_received(
            &vector("single").wire_bytes(),
            grant(expected.tip, &vector("single"))
        ),
        Err(Error::AlreadyCommitted(_))
    ));
    drop(producer);
    drop(receiver);
    for file in ["producer.db", "receiver.db"] {
        let loaded = CanonicalFixtureStore::reopen(dir.path().join(file), &m).unwrap();
        assert_eq!(loaded.snapshot().unwrap(), &expected);
    }
}

#[test]
fn compound_phase_precedence_and_no_candidate_publication() {
    let dir = TempDir::new().unwrap();
    let m = manifest(1);
    let store =
        CanonicalFixtureStore::create_anchored_fixture(dir.path().join("s.db"), &m).unwrap();
    let old = store.snapshot().unwrap().clone();
    let bad_nonce = transfer(1, 1, [0x22; 20], 0);
    let mut bad_signature = transfer(0, 1, [0x22; 20], 0);
    bad_signature[198] = 2;
    let b = untrusted_body(
        old.tip,
        vec![bad_nonce.clone(), bad_signature.clone()],
        999,
        1,
    );
    phase_evidence::reset();
    assert!(matches!(
        store.stage_received(&b.wire_bytes(), grant(old.tip, &b)),
        Err(Error::Body(BodyError {
            transaction_index: 1,
            cause: TransferError::Authentication(native_transaction::Error::InvalidParity(2))
        }))
    ));
    assert_eq!(phase_evidence::counts(), (2, 0));
    let b = untrusted_body(old.tip, vec![bad_signature.clone(), bad_signature], 0, 0);
    assert!(matches!(
        store.stage_received(&b.wire_bytes(), grant(old.tip, &b)),
        Err(Error::Body(BodyError {
            transaction_index: 0,
            ..
        }))
    ));
    let b = untrusted_body(
        old.tip,
        vec![bad_nonce, transfer(2, 1, [0x22; 20], 0)],
        0,
        0,
    );
    phase_evidence::reset();
    assert!(matches!(
        store.stage_received(&b.wire_bytes(), grant(old.tip, &b)),
        Err(Error::Body(BodyError {
            transaction_index: 0,
            cause: TransferError::NonceMismatch { .. }
        }))
    ));
    assert_eq!(phase_evidence::counts(), (2, 1));
    let b = untrusted_body(old.tip, vec![transfer(0, 1, [0x22; 20], 0)], 0, 1);
    assert!(matches!(
        store.stage_received(&b.wire_bytes(), grant(old.tip, &b)),
        Err(Error::Block(BlockError::ActualGas))
    ));
    let b = untrusted_body(old.tip, vec![transfer(0, 1, [0x22; 20], 0)], 1000, 1);
    assert!(matches!(
        store.stage_received(&b.wire_bytes(), grant(old.tip, &b)),
        Err(Error::Block(BlockError::ActualBurn))
    ));
    assert_eq!(store.snapshot().unwrap(), &old);
}

#[test]
fn parent_slot_grant_stale_and_duplicate_nonce_rejection() {
    let dir = TempDir::new().unwrap();
    let m = manifest(1);
    let mut s =
        CanonicalFixtureStore::create_anchored_fixture(dir.path().join("s.db"), &m).unwrap();
    let base = s.snapshot().unwrap().tip;
    let b = vector("single");
    let mut h = b.header().clone();
    h.slot += 1;
    h.parent_hash = [0; 32];
    let wrong = NativeBlock::from_parts(
        h,
        b.proposer().into(),
        b.protocol_data().clone(),
        b.transactions().to_vec(),
    )
    .unwrap();
    assert!(matches!(
        s.stage_received(&wrong.wire_bytes(), grant(base, &wrong)),
        Err(Error::Slot)
    ));
    let mut h = b.header().clone();
    h.parent_hash = [0; 32];
    let wrong = NativeBlock::from_parts(
        h,
        b.proposer().into(),
        b.protocol_data().clone(),
        b.transactions().to_vec(),
    )
    .unwrap();
    assert!(matches!(
        s.stage_received(&wrong.wire_bytes(), grant(base, &wrong)),
        Err(Error::Parent)
    ));
    assert!(matches!(
        s.stage_received(
            &b.wire_bytes(),
            FixtureAdmissionGrant::explicit_offline(context(), [0; 32], base, b.hash(), 43)
        ),
        Err(Error::Grant)
    ));
    let old = s.stage_received(&b.wire_bytes(), grant(base, &b)).unwrap();
    let e = next_empty(&s);
    append(&mut s, &e);
    assert!(matches!(
        s.commit(old),
        AppendOutcome::Aborted(Error::Stale)
    ));
    let stale = s.prepare_next("offline-validator", 7, &[]).unwrap();
    let sb = stale.block().clone();
    let stale = stale
        .authorize(grant(s.snapshot().unwrap().tip, &sb))
        .unwrap();
    s.recover().unwrap();
    assert!(matches!(
        s.commit(stale),
        AppendOutcome::Aborted(Error::Stale)
    ));
    let duplicate = transfer(0, 1, [0x22; 20], 0);
    let b = untrusted_body(
        s.snapshot().unwrap().tip,
        vec![duplicate.clone(), duplicate],
        2000,
        20000,
    );
    assert!(matches!(
        s.stage_received(&b.wire_bytes(), grant(s.snapshot().unwrap().tip, &b)),
        Err(Error::Body(BodyError {
            transaction_index: 1,
            cause: TransferError::NonceMismatch { .. }
        }))
    ));
}

#[test]
fn strict_creation_schema_separation_and_unsigned_limits() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("s.db");
    let m = manifest(1);
    assert!(matches!(
        CanonicalFixtureStore::reopen(&path, &m),
        Err(Error::Storage(StoreError::Missing))
    ));
    assert!(!path.exists());
    std::fs::File::create(&path).unwrap();
    assert!(matches!(
        CanonicalFixtureStore::reopen(&path, &m),
        Err(Error::Storage(StoreError::Uninitialized))
    ));
    assert!(matches!(
        CanonicalFixtureStore::create_anchored_fixture(&path, &m),
        Err(Error::Storage(StoreError::AlreadyExists))
    ));
    let one = dir.path().join("one.db");
    drop(disk::FixtureStore::create_fixture(&one, context(), m.initial.clone(), "one").unwrap());
    assert!(CanonicalFixtureStore::reopen(&one, &m).is_err());
    let two = dir.path().join("two.db");
    drop(CanonicalFixtureStore::create_anchored_fixture(&two, &m).unwrap());
    assert!(disk::FixtureStore::reopen(&two, context()).is_err());
    let max = NativeBlock::empty_fixture_anchor(
        &context(),
        u64::MAX,
        vector("anchor").hash(),
        "offline-validator".into(),
        u64::MAX,
    )
    .unwrap();
    let maxstate = TransferState::new(
        BTreeMap::from([(
            sender(),
            TransferAccount {
                balance_quarks: u128::MAX,
                nonce: u64::MAX,
            },
        )]),
        u64::MAX,
        u128::MAX,
    );
    let mm = FixtureManifest::new(context(), max, maxstate, "max fixture".into()).unwrap();
    let maxpath = dir.path().join("max.db");
    let s = CanonicalFixtureStore::create_anchored_fixture(&maxpath, &mm).unwrap();
    assert!(matches!(
        s.prepare_next("offline-validator", 7, &[]),
        Err(Error::Overflow)
    ));
    drop(s);
    assert_eq!(
        CanonicalFixtureStore::reopen(maxpath, &mm)
            .unwrap()
            .snapshot()
            .unwrap()
            .state,
        mm.initial
    );
}

#[test]
fn full_unsigned_chain_slot_nonce_balance_and_accounting_commit_roundtrip() {
    let d = TempDir::new().unwrap();
    let path = d.path().join("unsigned.db");
    let c = AuthenticationContext::new(u64::MAX, context().network_id(), 1).unwrap();
    let anchor = NativeBlock::empty_fixture_anchor(
        &c,
        u64::MAX - 1,
        vector("anchor").hash(),
        "unsigned-offline-fixture".into(),
        u64::MAX,
    )
    .unwrap();
    let initial = TransferState::new(
        BTreeMap::from([(
            sender(),
            TransferAccount {
                balance_quarks: u128::MAX,
                nonce: u64::MAX - 1,
            },
        )]),
        u64::MAX - 1000,
        u128::MAX - 10_000,
    );
    let m = FixtureManifest::new(
        c,
        anchor,
        initial,
        "unsigned maxima, explicit post-anchor authority".into(),
    )
    .unwrap();
    let mut s = CanonicalFixtureStore::create_anchored_fixture(&path, &m).unwrap();
    let signed = sign(
        UnsignedTransaction {
            encoding_version: 2,
            native_rules_version: 1,
            chain_id: u64::MAX,
            network_id: c.network_id(),
            kind: 0,
            sender: sender(),
            nonce: u64::MAX - 1,
            recipient: [0x22; 20],
            token_id: 0,
            value: 1,
            gas_limit: u64::MAX,
            valid_after_slot: u64::MAX,
        },
        &key(),
        &c,
    )
    .unwrap()
    .canonical_bytes()
    .unwrap()
    .to_vec();
    let p = s
        .prepare_next("unsigned-offline-fixture", u64::MAX, &[signed])
        .unwrap();
    let g = FixtureAdmissionGrant::explicit_offline(
        c,
        m.anchor().hash(),
        s.snapshot().unwrap().tip,
        p.block().hash(),
        u64::MAX,
    );
    assert!(matches!(
        s.commit(p.authorize(g).unwrap()),
        AppendOutcome::Committed { .. }
    ));
    let expected = s.snapshot().unwrap().clone();
    assert_eq!(expected.tip.slot, u64::MAX);
    assert_eq!(expected.tip.revision, 1);
    assert_eq!(expected.state.account(&sender()).nonce, u64::MAX);
    assert_eq!(
        expected.state.account(&sender()).balance_quarks,
        u128::MAX - 10_001
    );
    assert_eq!(
        (
            expected.state.gas_used_total(),
            expected.state.fees_burned_total()
        ),
        (u64::MAX, u128::MAX)
    );
    assert!(matches!(
        s.prepare_next("unsigned-offline-fixture", 1, &[]),
        Err(Error::Overflow)
    ));
    drop(s);
    assert_eq!(
        CanonicalFixtureStore::reopen(path, &m)
            .unwrap()
            .snapshot()
            .unwrap(),
        &expected
    );
}

fn hook_at(point: &'static str) -> Hook {
    Box::new(move |p| {
        if p == point {
            Err(invalid(format!("application failpoint {p}")))
        } else {
            Ok(())
        }
    })
}
fn stage_next(s: &CanonicalFixtureStore, body: &[Vec<u8>]) -> StagedNativeBlock {
    let p = s.prepare_next("offline-validator", 7, body).unwrap();
    let g = grant(s.snapshot().unwrap().tip, p.block());
    p.authorize(g).unwrap()
}

#[test]
fn atomic_anchored_initialization_every_phase_and_no_reseeding() {
    for point in [
        "schema",
        "context",
        "fixture_account",
        "fixture_accounts",
        "initial_accounting",
        "anchor",
        "anchor_body",
        "initial_tip",
        "provenance",
        "marker",
        "init_before_commit",
        "init_after_commit",
        "init_directory_sync",
    ] {
        let d = TempDir::new().unwrap();
        let path = d.path().join("s.db");
        let m = manifest(4);
        let result = CanonicalFixtureStore::create_inner(&path, &m, None, |p| {
            if p == point { Err(invalid(p)) } else { Ok(()) }
        });
        assert!(result.is_err(), "{point}");
        if ["init_after_commit", "init_directory_sync"].contains(&point) {
            assert!(matches!(
                result,
                Err(Error::Storage(StoreError::RecoveryRequired(_)))
            ));
            let recovered = CanonicalFixtureStore::recover_existing(&path, &m).unwrap();
            assert_eq!(recovered.snapshot().unwrap().state, m.initial);
            assert_eq!(recovered.snapshot().unwrap().tip, Tip::at(m.anchor(), 0));
        } else {
            assert!(
                matches!(
                    CanonicalFixtureStore::reopen(&path, &m),
                    Err(Error::Storage(StoreError::Uninitialized))
                ),
                "{point}"
            );
        }
        assert!(matches!(
            CanonicalFixtureStore::create_anchored_fixture(&path, &m),
            Err(Error::Storage(StoreError::AlreadyExists))
        ));
    }
}

#[test]
fn rollback_all_sql_phases_and_real_index_tip_constraints() {
    for point in [
        "accounts",
        "accounting",
        "block",
        "body",
        "indexes",
        "revision",
        "tip",
        "before_commit",
        "index_constraint",
        "tip_constraint",
    ] {
        let d = TempDir::new().unwrap();
        let path = d.path().join("s.db");
        let m = manifest(4);
        let mut s = CanonicalFixtureStore::create_anchored_fixture(&path, &m).unwrap();
        for _ in 0..2 {
            let e = next_empty(&s);
            append(&mut s, &e);
        }
        let old = s.snapshot().unwrap().clone();
        let staged = stage_next(&s, &[transfer(0, 17, [0x22; 20], 0)]);
        if point == "index_constraint" {
            s.conn().execute_batch("CREATE TRIGGER reject_index BEFORE INSERT ON transactions BEGIN SELECT RAISE(ABORT,'offline index fault'); END").unwrap();
        } else if point == "tip_constraint" {
            s.conn().execute_batch("CREATE TRIGGER reject_tip BEFORE UPDATE ON canonical_tip BEGIN SELECT RAISE(ABORT,'offline tip fault'); END").unwrap();
        } else {
            s.hook = Some(hook_at(point));
        }
        assert!(
            matches!(s.commit(staged), AppendOutcome::Aborted(_)),
            "{point}"
        );
        assert_eq!(s.snapshot().unwrap(), &old);
        s.hook = None;
        if point == "index_constraint" {
            s.conn().execute_batch("DROP TRIGGER reject_index").unwrap();
        }
        if point == "tip_constraint" {
            s.conn().execute_batch("DROP TRIGGER reject_tip").unwrap();
        }
        drop(s);
        assert_eq!(
            CanonicalFixtureStore::reopen(&path, &m)
                .unwrap()
                .snapshot()
                .unwrap(),
            &old
        );
    }
}

#[test]
fn poison_gate_failed_recovery_and_exact_old_new_reconciliation() {
    for new in [false, true] {
        let d = TempDir::new().unwrap();
        let path = d.path().join("s.db");
        let m = manifest(2);
        let mut s = CanonicalFixtureStore::create_anchored_fixture(&path, &m).unwrap();
        let old = stage_next(&s, &[]);
        let candidate = stage_next(&s, &[transfer(0, 17, [0x22; 20], 0)]);
        s.hook = Some(Box::new(move |p| {
            if p == if new { "after_commit" } else { "accounts" } || (!new && p == "rollback") {
                Err(invalid(p))
            } else {
                Ok(())
            }
        }));
        assert!(matches!(
            s.commit(candidate),
            AppendOutcome::RecoveryRequired(_)
        ));
        assert!(!s.is_ready());
        assert!(s.snapshot().is_err());
        assert!(s.settings().is_err());
        assert!(s.prepare_next("offline-validator", 7, &[]).is_err());
        let blocked = s.commit(old);
        assert!(matches!(blocked, AppendOutcome::Aborted(Error::Blocked)));
        for p in [
            "recovery_reopen",
            "recovery_validate",
            "recovery_barrier",
            "recovery_install",
        ] {
            s.hook = Some(hook_at(p));
            assert!(s.recover().is_err());
            assert!(!s.is_ready());
        }
        s.hook = None;
        let report = s.recover().unwrap();
        assert_eq!(report.attempted_present, Some(new));
        assert_eq!(report.tip.revision, u64::from(new));
        let e = next_empty(&s);
        append(&mut s, &e);
    }
    let d = TempDir::new().unwrap();
    let m = manifest(1);
    let mut s = CanonicalFixtureStore::create_anchored_fixture(d.path().join("s.db"), &m).unwrap();
    let old = stage_next(&s, &[]);
    let now = stage_next(&s, &[]);
    s.hook = Some(hook_at("after_commit"));
    assert!(matches!(s.commit(now), AppendOutcome::RecoveryRequired(_)));
    s.hook = None;
    s.recover().unwrap();
    assert!(matches!(
        s.commit(old),
        AppendOutcome::Aborted(Error::Stale)
    ));
}

#[test]
fn recovery_never_infers_attempt_identity_from_revision() {
    let d = TempDir::new().unwrap();
    let path = d.path().join("s.db");
    let m = manifest(1);
    let mut s = CanonicalFixtureStore::create_anchored_fixture(&path, &m).unwrap();
    let attempted = stage_next(&s, &[]);
    s.hook = Some(Box::new(|p| {
        if ["accounts", "rollback"].contains(&p) {
            Err(invalid(p))
        } else {
            Ok(())
        }
    }));
    assert!(matches!(
        s.commit(attempted),
        AppendOutcome::RecoveryRequired(_)
    ));
    s.connection.take();
    s.hook = None;
    // A different legitimate offline request occupies exactly the attempted revision, but its
    // header hash is different. Revision >= attempted cannot resolve the first owner's uncertainty.
    let mut second = CanonicalFixtureStore::reopen(&path, &m).unwrap();
    let p = second
        .prepare_next("different-fixture-proposer", 8, &[])
        .unwrap();
    let g = grant(second.snapshot().unwrap().tip, p.block());
    assert!(matches!(
        second.commit(p.authorize(g).unwrap()),
        AppendOutcome::Committed { .. }
    ));
    drop(second);
    assert!(matches!(
        s.recover(),
        Err(Error::Storage(StoreError::RecoveryRequired(_)))
    ));
    assert!(!s.is_ready());
}

#[test]
fn sql_base_change_blocks_cache_until_explicit_refresh() {
    let d = TempDir::new().unwrap();
    let path = d.path().join("s.db");
    let m = manifest(1);
    let mut a = CanonicalFixtureStore::create_anchored_fixture(&path, &m).unwrap();
    let candidate = stage_next(&a, &[]);
    let mut b = CanonicalFixtureStore::reopen(&path, &m).unwrap();
    let e = next_empty(&b);
    append(&mut b, &e);
    drop(b);
    assert!(matches!(
        a.commit(candidate),
        AppendOutcome::Aborted(Error::Stale)
    ));
    assert!(a.snapshot().is_err());
    assert_eq!(a.recover().unwrap().tip.revision, 1);
    assert!(a.is_ready());
}

#[test]
fn corrupt_authority_headers_bodies_tips_indexes_and_widths_fail_without_repair() {
    for fault in [
        "schema", "marker", "context", "seed", "header", "parent", "body", "tip", "index", "width",
        "damaged",
    ] {
        let d = TempDir::new().unwrap();
        let path = d.path().join("s.db");
        let m = manifest(2);
        let mut s = CanonicalFixtureStore::create_anchored_fixture(&path, &m).unwrap();
        append(&mut s, &vector("single"));
        drop(s);
        if fault == "damaged" {
            std::fs::write(&path, b"not a SQLite database").unwrap();
        } else {
            let c = Connection::open(&path).unwrap();
            c.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON")
                .unwrap();
            let text = match fault {
                "schema" => "UPDATE metadata SET schema_version=x'00000003'",
                "marker" => "UPDATE metadata SET initialized=0",
                "context" => "UPDATE metadata SET network=zeroblob(32)",
                "seed" => "UPDATE seed_accounts SET balance=zeroblob(16)",
                "header" => {
                    "UPDATE blocks SET header=zeroblob(229) WHERE revision=x'0000000000000001'"
                }
                "parent" => {
                    "UPDATE blocks SET parent=zeroblob(32) WHERE revision=x'0000000000000001'"
                }
                "body" => "DELETE FROM bodies WHERE revision=x'0000000000000001'",
                "tip" => "UPDATE canonical_tip SET hash=zeroblob(32)",
                "index" => "UPDATE transactions SET position=x'0000000000000001'",
                "width" => "UPDATE accounts SET nonce=x'00'",
                _ => unreachable!(),
            };
            c.execute_batch(text).unwrap();
        }
        let before = std::fs::read(&path).unwrap();
        assert!(CanonicalFixtureStore::reopen(&path, &m).is_err(), "{fault}");
        assert!(
            CanonicalFixtureStore::recover_existing(&path, &m).is_err(),
            "{fault}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

#[test]
fn later_transfer_and_accounting_failures_preserve_full_prefix() {
    let d = TempDir::new().unwrap();
    let m = manifest(1);
    let s = CanonicalFixtureStore::create_anchored_fixture(d.path().join("s.db"), &m).unwrap();
    let old = s.snapshot().unwrap().clone();
    let b = untrusted_body(
        old.tip,
        vec![
            transfer(0, 1, [0x22; 20], 0),
            transfer(1, 1, [0x22; 20], 44),
        ],
        2000,
        20000,
    );
    assert!(matches!(
        s.stage_received(&b.wire_bytes(), grant(old.tip, &b)),
        Err(Error::Body(BodyError {
            transaction_index: 1,
            cause: TransferError::NotMature { .. }
        }))
    ));
    assert_eq!(s.snapshot().unwrap(), &old);
    let mm = FixtureManifest::new(
        context(),
        vector("anchor"),
        TransferState::new(m.initial.accounts().clone(), u64::MAX, 13),
        "overflow fixture".into(),
    )
    .unwrap();
    let ss =
        CanonicalFixtureStore::create_anchored_fixture(d.path().join("overflow.db"), &mm).unwrap();
    assert!(matches!(
        ss.prepare_next("offline-validator", 7, &[transfer(0, 1, [0x22; 20], 0)]),
        Err(Error::Body(BodyError {
            cause: TransferError::Overflow(ArithmeticField::TotalGas),
            ..
        }))
    ));
}

fn with_vfs(path: &Path, m: &FixtureManifest, v: &Harness) -> CanonicalFixtureStore {
    with_vfs_policy(path, m, v, CachePolicy::ExistingDefault)
}
fn with_vfs_policy(
    path: &Path,
    m: &FixtureManifest,
    v: &Harness,
    policy: CachePolicy,
) -> CanonicalFixtureStore {
    CanonicalFixtureStore::create_inner_with_cache(path, m, policy, Some(v.name()), |_| Ok(()))
        .unwrap()
}
fn ack_prefix(s: &mut CanonicalFixtureStore) {
    for _ in 0..2 {
        let e = next_empty(s);
        append(s, &e);
    }
}
fn stage_workload(s: &CanonicalFixtureStore, populated: bool) -> StagedNativeBlock {
    stage_next(
        s,
        &if populated {
            vec![transfer(0, 17, [0x22; 20], 0)]
        } else {
            vec![]
        },
    )
}

#[test]
fn sqlite_io_fault_sweeps_initialization_empty_transfer_and_recovery() {
    io_sweeps(CachePolicy::ExistingDefault);
}
fn io_sweeps(policy: CachePolicy) {
    for phase in ["initialization", "empty", "transfer", "recovery"] {
        let trace = {
            let d = TempDir::new().unwrap();
            let p = d.path().join("s.db");
            let m = manifest(4);
            let v = Harness::new();
            let mut s = with_vfs_policy(&p, &m, &v, policy);
            if phase != "initialization" {
                ack_prefix(&mut s);
                v.reset();
                if phase == "recovery" {
                    s.recover().unwrap();
                } else {
                    let st = stage_workload(&s, phase == "transfer");
                    assert!(matches!(s.commit(st), AppendOutcome::Committed { .. }));
                }
            }
            v.events()
        };
        let mut cases = 0;
        let mut aborted = 0;
        let mut required = 0;
        for (kind, code) in [
            ("xwrite", ffi::SQLITE_FULL),
            ("xwrite", ffi::SQLITE_IOERR_WRITE),
            ("xsync", ffi::SQLITE_IOERR_FSYNC),
            ("xdelete", ffi::SQLITE_IOERR_DELETE),
        ] {
            for nth in 1..=trace.iter().filter(|e| e.kind == kind).count() {
                let d = TempDir::new().unwrap();
                let p = d.path().join("s.db");
                let m = manifest(4);
                let v = Harness::new();
                cases += 1;
                if phase == "initialization" {
                    v.fault(kind, nth, code, false);
                    let result = CanonicalFixtureStore::create_inner_with_cache(
                        &p,
                        &m,
                        policy,
                        Some(v.name()),
                        |_| Ok(()),
                    );
                    assert!(result.is_err(), "{phase} {kind}:{nth}");
                    let error = result.err().unwrap();
                    if matches!(error, Error::Storage(StoreError::RecoveryRequired(_))) {
                        required += 1;
                    } else {
                        aborted += 1;
                    }
                    v.reset();
                    let recovered =
                        CanonicalFixtureStore::load_with_cache(&p, &m, policy, Some(v.name()));
                    let observed = match recovered {
                        Ok(s) => {
                            assert_eq!(s.snapshot().unwrap().tip.revision, 0);
                            assert_eq!(s.snapshot().unwrap().state, m.initial);
                            "complete anchor"
                        }
                        Err(Error::Storage(StoreError::Uninitialized)) => "uninitialized",
                        Err(e) => panic!("{phase} {kind}:{nth} recovery {e}"),
                    };
                    println!(
                        "stage4_io phase={phase} op={kind} nth={nth} injected={code} observed={error:?} recovered={observed}"
                    );
                } else {
                    let mut s = with_vfs_policy(&p, &m, &v, policy);
                    ack_prefix(&mut s);
                    let old = s.snapshot().unwrap().clone();
                    let st = stage_workload(&s, phase == "transfer");
                    v.reset();
                    v.fault(kind, nth, code, false);
                    if phase == "recovery" {
                        let error = s.recover().unwrap_err();
                        assert!(!s.is_ready());
                        assert!(s.snapshot().is_err());
                        required += 1;
                        v.reset();
                        s.recover().unwrap();
                        assert_eq!(s.snapshot().unwrap(), &old);
                        println!(
                            "stage4_io phase={phase} op={kind} nth={nth} injected={code} observed={error:?} recovered_tip={:?}",
                            s.snapshot().unwrap().tip
                        );
                    } else {
                        let outcome = s.commit(st);
                        let was_abort = matches!(outcome, AppendOutcome::Aborted(_));
                        match &outcome {
                            AppendOutcome::Aborted(_) => {
                                aborted += 1;
                                assert_eq!(s.snapshot().unwrap(), &old);
                            }
                            AppendOutcome::RecoveryRequired(_) => {
                                required += 1;
                                assert!(!s.is_ready());
                                assert!(s.snapshot().is_err());
                                assert!(s.prepare_next("offline-validator", 7, &[]).is_err());
                            }
                            _ => panic!("fault not reached {phase} {kind}:{nth}"),
                        }
                        v.reset();
                        let report = s.recover().unwrap();
                        assert!((2..=3).contains(&report.tip.revision));
                        if was_abort {
                            assert_eq!(s.snapshot().unwrap(), &old);
                        }
                        println!(
                            "stage4_io phase={phase} op={kind} nth={nth} injected={code} observed={outcome:?} recovered_tip={:?} exact_attempt={:?}",
                            report.tip, report.attempted_present
                        );
                    }
                }
            }
        }
        println!(
            "stage4_io_summary cache_policy={policy:?} phase={phase} cases={cases} aborted={aborted} recovery_required={required}"
        );
    }
}

#[test]
fn real_spilled_page_rollback_and_initialization_truncate_faults_poison() {
    let d = TempDir::new().unwrap();
    let p = d.path().join("s.db");
    let m = manifest(4);
    let v = Harness::new();
    let mut s = with_vfs(&p, &m, &v);
    ack_prefix(&mut s);
    s.conn().execute_batch("PRAGMA cache_size=1").unwrap();
    let bytes: Vec<_> = (0..2048u64)
        .map(|n| {
            let mut a = [0x55; 20];
            a[12..].copy_from_slice(&n.to_be_bytes());
            transfer(n, 1, a, 0)
        })
        .collect();
    let staged = stage_next(&s, &bytes);
    let old = s.snapshot().unwrap().clone();
    v.reset();
    let mut arm = v.arm_next_callback("xwrite", ffi::SQLITE_IOERR_WRITE, true);
    s.hook = Some(Box::new(move |p| {
        if p == "accounting" {
            arm();
            Err(invalid("force rollback after real page spill"))
        } else {
            Ok(())
        }
    }));
    assert!(matches!(
        s.commit(staged),
        AppendOutcome::RecoveryRequired(_)
    ));
    assert!(
        v.events()
            .iter()
            .any(|e| e.kind == "xwrite" && !e.path.to_string_lossy().ends_with("-journal"))
    );
    assert!(!s.is_ready());
    s.hook = None;
    v.reset();
    assert_eq!(s.recover().unwrap().attempted_present, Some(false));
    assert_eq!(s.snapshot().unwrap(), &old);
    drop(s);
    let p2 = d.path().join("init.db");
    let big = manifest(50_000);
    let v2 = Harness::new();
    let mut arm = v2.arm_next_callback("xtruncate", ffi::SQLITE_IOERR_TRUNCATE, true);
    let result = CanonicalFixtureStore::create_inner(&p2, &big, Some(v2.name()), move |p| {
        if p == "initial_accounting" {
            arm();
            Err(invalid("force initialization rollback"))
        } else {
            Ok(())
        }
    });
    assert!(matches!(
        result,
        Err(Error::Storage(StoreError::RecoveryRequired(_)))
    ));
    v2.reset();
    assert!(matches!(
        CanonicalFixtureStore::load(&p2, &big, Some(v2.name())),
        Err(Error::Storage(StoreError::Uninitialized))
    ));
}

#[test]
fn actual_vfs_reopen_error_keeps_poison_and_old_overlay_blocked() {
    // Reopening failures must leave ownership blocked independently of the connection's budget.
    for policy in [CachePolicy::ExistingDefault, CachePolicy::Trial32MiB] {
        reopen_fault(policy);
    }
}
fn reopen_fault(policy: CachePolicy) {
    let d = TempDir::new().unwrap();
    let p = d.path().join("s.db");
    let m = manifest(4);
    let v = Harness::new();
    let mut s = with_vfs_policy(&p, &m, &v, policy);
    let stale = stage_next(&s, &[]);
    let current = stage_next(&s, &[]);
    s.hook = Some(hook_at("after_commit"));
    assert!(matches!(
        s.commit(current),
        AppendOutcome::RecoveryRequired(_)
    ));
    s.hook = None;
    v.reset();
    v.fault("xopen", 1, ffi::SQLITE_CANTOPEN, false);
    let error = s.recover().unwrap_err();
    assert!(!s.is_ready());
    assert!(s.snapshot().is_err());
    assert!(s.prepare_next("offline-validator", 7, &[]).is_err());
    println!(
        "stage4_io cache_policy={policy:?} reopen_op=xopen injected={} observed={error:?} poisoned=true",
        ffi::SQLITE_CANTOPEN
    );
    v.reset();
    assert_eq!(s.recover().unwrap().attempted_present, Some(true));
    assert_eq!(s.settings().unwrap().cache_size, policy.pragma_value());
    assert!(matches!(
        s.commit(stale),
        AppendOutcome::Aborted(Error::Stale)
    ));
}

#[test]
fn declared_power_loss_model_anchor_blocks_and_recovery_valid_prefixes() {
    power_loss_sweep(CachePolicy::ExistingDefault);
}
fn power_loss_sweep(policy: CachePolicy) {
    for phase in ["initialization", "empty", "transfer", "recovery"] {
        let trace = {
            let d = TempDir::new().unwrap();
            let p = d.path().join("s.db");
            let m = manifest(4);
            let v = Harness::new();
            let mut s = with_vfs_policy(&p, &m, &v, policy);
            if phase != "initialization" {
                ack_prefix(&mut s);
                if phase == "recovery" {
                    let st = stage_workload(&s, true);
                    assert!(matches!(s.commit(st), AppendOutcome::Committed { .. }));
                }
                v.reset();
                if phase == "recovery" {
                    s.recover().unwrap();
                } else {
                    let st = stage_workload(&s, phase == "transfer");
                    assert!(matches!(s.commit(st), AppendOutcome::Committed { .. }));
                }
            }
            v.events().len()
        };
        for torn in [false, true] {
            let mut complete = 0;
            let mut uninitialized = 0;
            let mut old = 0;
            let mut new = 0;
            for cut in 1..=trace {
                let d = TempDir::new().unwrap();
                let p = d.path().join("s.db");
                let m = manifest(4);
                let v = Harness::new();
                if phase == "initialization" {
                    v.power(cut, torn);
                    drop(CanonicalFixtureStore::create_inner_with_cache(
                        &p,
                        &m,
                        policy,
                        Some(v.name()),
                        |_| Ok(()),
                    ));
                } else {
                    let mut s = with_vfs_policy(&p, &m, &v, policy);
                    ack_prefix(&mut s);
                    if phase == "recovery" {
                        let st = stage_workload(&s, true);
                        assert!(matches!(s.commit(st), AppendOutcome::Committed { .. }));
                    }
                    v.reset();
                    v.power(cut, torn);
                    if phase == "recovery" {
                        let _ = s.recover();
                    } else {
                        let st = stage_workload(&s, phase == "transfer");
                        let _ = s.commit(st);
                    }
                    drop(s);
                }
                v.restore_power_image(d.path());
                v.reset();
                match CanonicalFixtureStore::load_with_cache(&p, &m, policy, Some(v.name())) {
                    Ok(s) if phase == "initialization" => {
                        complete += 1;
                        assert_eq!(s.snapshot().unwrap().state, m.initial);
                        assert_eq!(s.snapshot().unwrap().tip.revision, 0);
                    }
                    Err(Error::Storage(StoreError::Uninitialized | StoreError::Missing))
                        if phase == "initialization" =>
                    {
                        uninitialized += 1
                    }
                    Ok(s) => {
                        let snap = s.snapshot().unwrap();
                        let r = snap.tip.revision;
                        if phase == "recovery" {
                            assert_eq!(r, 3);
                            assert_eq!(snap.transactions.len(), 1);
                            new += 1;
                        } else {
                            assert!((2..=3).contains(&r));
                            if r == 2 {
                                old += 1;
                                assert_eq!(snap.state, m.initial);
                            } else {
                                new += 1;
                            }
                        }
                        assert_eq!(snap.blocks.len(), r as usize + 1);
                        assert_eq!(snap.blocks[0].block, m.anchor); // entire audit already checked every field/index
                    }
                    Err(e) => panic!("power phase={phase} sector={torn} cut={cut}: {e}"),
                }
            }
            println!(
                "stage4_power cache_policy={policy:?} phase={phase} sector_prefix={torn} cuts={trace} complete_init={complete} uninitialized={uninitialized} old={old} new={new}"
            );
        }
    }
    // Stable-image loss after both acknowledged success and durable-but-unacknowledged COMMIT.
    // The latter verifies the new prefix survives without using an acknowledgement as authority.
    for acknowledged in [false, true] {
        let d = TempDir::new().unwrap();
        let p = d.path().join("s.db");
        let m = manifest(4);
        let v = Harness::new();
        let mut s = with_vfs_policy(&p, &m, &v, policy);
        ack_prefix(&mut s);
        let st = stage_workload(&s, true);
        let mut expected = s.snapshot().unwrap().clone();
        expected.state = st.prepared.candidate.clone();
        expected.insert_record(st.prepared.record.clone()).unwrap();
        if !acknowledged {
            s.hook = Some(hook_at("after_commit"));
        }
        let outcome = s.commit(st);
        assert!(if acknowledged {
            matches!(outcome, AppendOutcome::Committed { .. })
        } else {
            matches!(outcome, AppendOutcome::RecoveryRequired(_))
        });
        v.capture_acknowledged();
        drop(s);
        v.restore_power_image(d.path());
        v.reset();
        assert_eq!(
            CanonicalFixtureStore::load_with_cache(&p, &m, policy, Some(v.name()))
                .unwrap()
                .snapshot()
                .unwrap(),
            &expected
        );
        println!(
            "stage4_power cache_policy={policy:?} post_commit acknowledged={acknowledged} new_complete_prefix_retained=true"
        );
    }
}

fn handshake(point: &str, target: &str) {
    if point == target {
        println!("STAGE4_READY:{point}");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        panic!("parent must kill child");
    }
}
#[test]
#[ignore = "controlled process entry invoked by stage4_process_termination"]
fn crash_child() {
    let Some(path) = std::env::var_os("ETX_STAGE4_PATH") else {
        return;
    };
    let p = PathBuf::from(path);
    let target = std::env::var("ETX_STAGE4_POINT").unwrap();
    let workload = std::env::var("ETX_STAGE4_WORKLOAD").unwrap();
    let policy = if std::env::var("ETX_STAGE4_CACHE_POLICY").as_deref() == Ok("trial32") {
        CachePolicy::Trial32MiB
    } else {
        CachePolicy::ExistingDefault
    };
    let m = manifest(50_000);
    let v = Harness::new();
    let location = target.strip_prefix("init_").unwrap_or(&target);
    let vfs_point = match location {
        "journal_xwrite" => Some("journal_xwrite"),
        "database_xwrite" => Some("database_xwrite"),
        "journal_xsync" => Some("journal_xsync"),
        "database_xsync" => Some("database_xsync"),
        "xdelete" => Some("xdelete"),
        _ => None,
    };
    if workload == "initialization" {
        v.on_event(vfs_point, {
            let target = target.clone();
            move |p| handshake(&format!("init_{p}"), &target)
        });
        let _ =
            CanonicalFixtureStore::create_inner_with_cache(&p, &m, policy, Some(v.name()), |p| {
                handshake(p, &target);
                Ok(())
            });
    } else {
        let mut s = CanonicalFixtureStore::load_with_cache(&p, &m, policy, Some(v.name())).unwrap();
        if std::env::var_os("ETX_STAGE4_PRESERVE_BUDGET").is_none() {
            s.conn().execute_batch("PRAGMA cache_size=8").unwrap();
        } else {
            assert_eq!(s.settings().unwrap().cache_size, policy.pragma_value());
        }
        // Arm storage callbacks only after reopen's own synchronized barrier has completed.
        v.on_event(vfs_point, {
            let target = target.clone();
            move |p| handshake(p, &target)
        });
        s.hook = Some(Box::new(move |p| {
            handshake(p, &target);
            Ok(())
        }));
        let st = stage_workload(&s, workload == "transfer");
        let _ = s.commit(st);
    }
    panic!("controlled failpoint not reached");
}
fn terminate(path: &Path, point: &str, workload: &str) {
    terminate_policy(path, point, workload, CachePolicy::ExistingDefault, false);
}
fn terminate_policy(
    path: &Path,
    point: &str,
    workload: &str,
    policy: CachePolicy,
    preserve_budget: bool,
) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "canonical_fixture::tests::crash_child",
            "--ignored",
            "--nocapture",
        ])
        .env("ETX_STAGE4_PATH", path)
        .env("ETX_STAGE4_POINT", point)
        .env("ETX_STAGE4_WORKLOAD", workload)
        .env(
            "ETX_STAGE4_CACHE_POLICY",
            if policy == CachePolicy::Trial32MiB {
                "trial32"
            } else {
                "default"
            },
        )
        .envs(if preserve_budget {
            vec![("ETX_STAGE4_PRESERVE_BUDGET", "1")]
        } else {
            vec![]
        })
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(
            reader.read_line(&mut line).unwrap(),
            0,
            "child exited before {workload}/{point}"
        );
        if line.starts_with("STAGE4_READY:") {
            break;
        }
    }
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
    if point.contains("database_xsync") {
        assert!(
            std::fs::metadata(format!("{}-journal", path.display()))
                .unwrap()
                .len()
                >= 512
        );
    }
}
#[test]
fn stage4_process_termination_anchor_and_empty_populated_append() {
    let initial = [
        "schema",
        "context",
        "fixture_account",
        "fixture_accounts",
        "initial_accounting",
        "anchor",
        "anchor_body",
        "initial_tip",
        "provenance",
        "marker",
        "init_before_commit",
        "init_journal_xwrite",
        "init_database_xwrite",
        "init_journal_xsync",
        "init_database_xsync",
        "init_xdelete",
        "init_after_commit",
        "init_directory_sync",
    ];
    for point in initial {
        let d = TempDir::new().unwrap();
        let p = d.path().join("s.db");
        let m = manifest(50_000);
        terminate(&p, point, "initialization");
        let result = CanonicalFixtureStore::recover_existing(&p, &m);
        if ["init_after_commit", "init_directory_sync"].contains(&point) {
            let s = result.unwrap();
            assert_eq!(s.snapshot().unwrap().state, m.initial);
            assert_eq!(s.snapshot().unwrap().tip.revision, 0);
        } else {
            assert!(
                matches!(result, Err(Error::Storage(StoreError::Uninitialized))),
                "{point}"
            );
        }
    }
    let app = [
        "before_begin",
        "accounts",
        "accounting",
        "block",
        "body",
        "indexes",
        "revision",
        "tip",
        "before_commit",
        "journal_xwrite",
        "database_xwrite",
        "journal_xsync",
        "database_xsync",
        "xdelete",
        "after_commit",
        "after_install",
    ];
    for workload in ["empty", "transfer"] {
        for point in app {
            let d = TempDir::new().unwrap();
            let p = d.path().join("s.db");
            let m = manifest(50_000);
            let mut s = CanonicalFixtureStore::create_anchored_fixture(&p, &m).unwrap();
            ack_prefix(&mut s);
            drop(s);
            terminate(&p, point, workload);
            let loaded = CanonicalFixtureStore::recover_existing(&p, &m).unwrap();
            let new = ["after_commit", "after_install"].contains(&point);
            let snap = loaded.snapshot().unwrap();
            assert_eq!(snap.tip.revision, 2 + u64::from(new), "{workload}/{point}");
            assert_eq!(snap.blocks.len(), snap.tip.revision as usize + 1);
            assert_eq!(
                snap.transactions.len(),
                usize::from(new && workload == "transfer")
            );
        }
    }
    println!(
        "stage4_process initial_locations={} empty_locations={} transfer_locations={} total_kills={}",
        initial.len(),
        app.len(),
        app.len(),
        initial.len() + 2 * app.len()
    );
}

use crate as chain;
#[path = "../../examples/stage4_support/bench.rs"]
mod bench;
mod block_authentication;
mod cache_policy;
mod profiling;
#[test]
#[ignore = "release retained-history benchmark, explicitly invoked outside correctness suite"]
fn uncertain_history_benchmark() {
    let parent = PathBuf::from(
        std::env::var_os("ETX_STAGE4_BENCH_PARENT").unwrap_or_else(|| "target".into()),
    );
    let samples = std::env::var("ETX_STAGE4_BENCH_SAMPLES")
        .ok()
        .map(|s| s.parse().unwrap())
        .unwrap_or(3);
    let case = std::env::var("ETX_STAGE4_BENCH_CASE")
        .ok()
        .map(|s| s.parse().unwrap());
    let body = std::env::var("ETX_STAGE4_BENCH_BODY")
        .ok()
        .map(|s| s.parse().unwrap());
    bench::run(&parent, samples, case, body, |s, m| {
        let prepared = s.prepare_next(m.anchor().proposer(), m.anchor().header().ticket_id, &[])?;
        let grant = FixtureAdmissionGrant::explicit_offline(
            m.context(),
            m.anchor().hash(),
            s.snapshot()?.tip,
            prepared.block().hash(),
            prepared.block().header().slot,
        );
        let st = prepared.authorize(grant)?;
        s.hook = Some(hook_at("after_commit"));
        let outcome = s.commit(st);
        s.hook = None;
        if !matches!(outcome, AppendOutcome::RecoveryRequired(_)) {
            return Err(invalid("benchmark uncertainty hook did not block"));
        }
        Ok(true)
    })
    .unwrap();
}
