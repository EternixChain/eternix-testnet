//! Actual C1 owner/codec/compound/replay checks; signatures below use published toy inputs only.
use super::*;
use crate::block_commitment::{
    ProtocolData, hash_with_domain, keccak256, ordered_transaction_root, proposer_id,
};
use crate::native_transaction::{self as native, UnsignedTransaction, address_from_public_key};
use crate::native_transfer::{self as transfer, ArithmeticField, TransferError};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, signature::hazmat::RandomizedPrehashSigner};
use rand::{SeedableRng, rngs::StdRng};
use serde_json::Value;
use tempfile::TempDir;
mod faults;

fn key(n: u8) -> SigningKey {
    let mut b = [0; 32];
    b[31] = n;
    SigningKey::from_slice(&b).unwrap()
}
fn genesis() -> Genesis {
    let v: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/native_poash_eligibility.json"
    ))
    .unwrap();
    let bytes = v["genesis"]["hex_parts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect::<String>();
    Genesis::from_bytes(&hex::decode(bytes).unwrap()).unwrap()
}
fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/native_poash_application.json"
    ))
    .unwrap()
}
fn create(p: &Path, g: &Genesis) -> PoashTrialStore {
    PoashTrialStore::create(p, g).unwrap()
}
fn signature(block: &Block, g: &Genesis, alternate: bool) -> [u8; 65] {
    let n = if block.claim().producer() == "trial-A" {
        2
    } else {
        5
    };
    let k = key(n);
    let digest = block.claim().signing_digest(g.network_id());
    let (s, id) = if alternate {
        let s: Signature = k
            .sign_prehash_with_rng(&mut StdRng::seed_from_u64(91237), &digest)
            .unwrap();
        let id = RecoveryId::trial_recovery_from_prehash(k.verifying_key(), &digest, &s).unwrap();
        (s, id)
    } else {
        k.sign_prehash_recoverable(&digest).unwrap()
    };
    assert!(!id.is_x_reduced());
    let mut bytes = [0; 65];
    bytes[..64].copy_from_slice(&s.to_bytes());
    bytes[64] = id.to_byte();
    bytes
}
fn packet(block: &Block, g: &Genesis) -> Vec<u8> {
    Envelope::from_parts(block.clone(), g.network_id(), signature(block, g, false)).wire_bytes()
}
fn unsigned(
    g: &Genesis,
    n: u8,
    recipient: Address,
    value: u128,
    nonce: u64,
) -> UnsignedTransaction {
    UnsignedTransaction {
        encoding_version: 2,
        native_rules_version: 1,
        chain_id: CHAIN_ID,
        network_id: g.network_id(),
        kind: 0,
        sender: address_from_public_key(key(n).verifying_key()),
        nonce,
        recipient,
        token_id: 0,
        value,
        gas_limit: 1001,
        valid_after_slot: 0,
    }
}
fn signed(g: &Genesis, n: u8, tx: UnsignedTransaction) -> Vec<u8> {
    native::sign(tx, &key(n), &app::native_context(g))
        .unwrap()
        .canonical_bytes()
        .unwrap()
        .to_vec()
}
fn tx(g: &Genesis, n: u8, to: u8, value: u128, nonce: u64) -> Vec<u8> {
    signed(
        g,
        n,
        unsigned(
            g,
            n,
            address_from_public_key(key(to).verifying_key()),
            value,
            nonce,
        ),
    )
}
fn workload(g: &Genesis, slot: u64) -> Vec<Vec<u8>> {
    match slot {
        2 => vec![
            tx(g, 1, 3, 1000000, 0),
            tx(g, 3, 4, 20000, 0),
            tx(g, 1, 1, 123, 1),
            signed(g, 1, unsigned(g, 1, [0x77; 20], 0, 2)),
        ],
        3 => vec![tx(g, 3, 4, 0, 1)],
        4 => vec![tx(g, 4, 4, 5000, 0)],
        _ => vec![],
    }
}
fn preparation(s: &PoashTrialStore, body: &[Vec<u8>]) -> PreparedBlock {
    let selection = s.slot_start().unwrap().select().unwrap();
    s.prepare_next(selection.producer(), selection.ticket_id(), body)
        .unwrap()
}
fn empty(s: &PoashTrialStore) -> Block {
    preparation(s, &[]).block().clone()
}
fn append(s: &mut PoashTrialStore, g: &Genesis, body: &[Vec<u8>]) -> Vec<u8> {
    let prep = preparation(s, body);
    let wire = packet(prep.block(), g);
    let st = s.seal_prepared(prep, &wire).unwrap();
    assert!(matches!(s.commit(st), AppendOutcome::Committed { .. }));
    wire
}
fn receive(s: &mut PoashTrialStore, wire: &[u8]) {
    let st = s.stage_received(wire).unwrap();
    assert!(matches!(s.commit(st), AppendOutcome::Committed { .. }));
}
fn reset() {
    app::phase_evidence::reset();
    transfer::phase_evidence::reset();
}
fn counts() -> (usize, usize, (usize, usize)) {
    (
        app::phase_evidence::count(),
        transfer::phase_evidence::stages(),
        transfer::phase_evidence::counts(),
    )
}
fn hook(target: &'static str) -> Hook {
    Box::new(move |p| {
        if p == target {
            Err(invalid(target))
        } else {
            Ok(())
        }
    })
}
fn block_for(s: &PoashTrialStore, producer: &str, ticket: u64, body: Vec<Vec<u8>>) -> Block {
    let ids: Vec<_> = body
        .iter()
        .map(|b| hash_with_domain(native::ID_DOMAIN, b))
        .collect();
    let mut h = empty(s).claim().header().clone();
    h.proposer_id = proposer_id(producer);
    h.ticket_id = ticket;
    h.transaction_root = ordered_transaction_root(&ids).unwrap();
    h.gas_used = body.len() as u64 * 1000;
    let protocol = ProtocolData {
        fees_burned: body.len() as u64 * 10000,
        missed_proposer: None,
    };
    h.protocol_data_root = protocol.root();
    Block::from_parts(
        h,
        producer.into(),
        protocol,
        body.iter()
            .map(|b| b.as_slice().try_into().unwrap())
            .collect(),
    )
    .unwrap()
}

#[test]
fn independent_codec_signature_transition_and_complete_three_owner_restart_equivalence() {
    let d = TempDir::new().unwrap();
    let g = genesis();
    let golden = vectors();
    let mut p = create(&d.path().join("p.db"), &g);
    let mut r = create(&d.path().join("r.db"), &g);
    for slot in 1..=65 {
        let reference = p.slot_start().unwrap().reference();
        let body = workload(&g, slot);
        reset();
        let prep = preparation(&p, &body);
        let block = prep.block().clone();
        assert_eq!(counts(), (0, 1, (body.len(), body.len())));
        let bytes = packet(&block, &g);
        let st = p.seal_prepared(prep, &bytes).unwrap();
        assert_eq!(counts(), (1, 1, (body.len(), body.len())));
        assert!(matches!(p.commit(st), AppendOutcome::Committed { .. }));
        assert_eq!(counts(), (1, 1, (body.len(), body.len())));
        reset();
        receive(&mut r, &bytes);
        assert_eq!(counts(), (1, 1, (body.len(), body.len())));
        assert_eq!(p.snapshot().unwrap(), r.snapshot().unwrap());
        if let Some(v) = golden["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["slot"] == slot)
        {
            assert_eq!(hex::encode(reference), v["reference"]);
            assert_eq!(hex::encode(block.hash()), v["hash"]);
            assert_eq!(block.claim().producer(), v["producer"]);
            assert_eq!(block.claim().header().ticket_id, v["ticket"]);
            assert_eq!(block.wire_bytes().len() as u64, v["inner_bytes"]);
            assert_eq!(
                hex::encode(keccak256(&block.wire_bytes())),
                v["inner_keccak"]
            );
            assert_eq!(
                hex::encode(block.claim().signing_digest(g.network_id())),
                v["signing_digest"]
            );
            let e = Envelope::from_wire_bytes(&bytes).unwrap();
            assert_eq!(e.wire_bytes(), bytes);
            assert_eq!(hex::encode(e.signature_bytes()), v["signature"]);
            assert_eq!(hex::encode(e.id()), v["envelope_id"]);
            if slot == 1 {
                assert_eq!(hex::encode(block.wire_bytes()), v["empty_inner"]);
            }
            let s = &p.snapshot().unwrap().state;
            let a = s.input();
            assert_eq!(s.canonical_bytes().len() as u64, v["state_bytes"]);
            assert_eq!(hex::encode(s.id()), v["state_id"]);
            assert_eq!(a.gas_used, v["gas"]);
            assert_eq!(a.fees_burned, v["fees"].as_u64().unwrap() as u128);
            assert_eq!(a.base_issuance, v["issuance"].as_u64().unwrap() as u128);
            let supply: u128 = a.accounts.iter().map(|a| a.balance).sum::<u128>()
                + a.validators.iter().map(|a| a.vault).sum::<u128>();
            assert_eq!(supply, v["supply"].as_u64().unwrap() as u128);
            assert_eq!(a.accounts.len(), v["accounts"].as_array().unwrap().len());
            for (a, expected) in a.accounts.iter().zip(v["accounts"].as_array().unwrap()) {
                assert_eq!(hex::encode(a.address), expected["address"]);
                assert_eq!(a.balance, expected["balance"].as_u64().unwrap() as u128);
                assert_eq!(a.nonce, expected["nonce"]);
            }
            for validator in &a.validators {
                assert_eq!(validator.produced, v["counts"][&validator.id]);
                assert_eq!(
                    validator.locked,
                    validator.produced as u128 * g.year_zero().reward
                );
                assert_eq!(validator.vault, INITIAL_VAULT + validator.locked);
            }
            let last = p.snapshot().unwrap().records.last().unwrap();
            assert_eq!(
                last.outcome
                    .transaction_ids
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>(),
                v["transaction_ids"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap())
                    .collect::<Vec<_>>()
            );
        }
    }
    let expected = p.snapshot().unwrap().clone();
    let current_supply =
        INITIAL_SUPPLY + expected.state.input().base_issuance - expected.state.input().fees_burned;
    // This prefix is long enough that a forbidden recalculation from today's supply would change
    // the whole-quark reward. Reopen must still retain and audit the original boundary record.
    assert_ne!(
        current_supply * 3 / (50 * YEAR_SLOTS as u128),
        g.year_zero().reward
    );
    drop(p);
    drop(r);
    reset();
    let reopened = PoashTrialStore::reopen(d.path().join("p.db"), &g).unwrap();
    assert_eq!(counts(), (65, 65, (6, 6)));
    assert_eq!(reopened.snapshot().unwrap(), &expected);
    let mut fresh = create(&d.path().join("fresh.db"), &g);
    for slot in 1..=65 {
        receive(&mut fresh, &reopened.export_envelope(slot).unwrap());
    }
    assert_eq!(fresh.snapshot().unwrap(), &expected);
    let settings = fresh.settings().unwrap();
    assert_eq!(
        (
            settings.journal_mode.as_str(),
            settings.synchronous,
            settings.foreign_keys,
            settings.cache_size
        ),
        ("delete", 3, true, -2000)
    );
    assert!(fresh.export_envelope(0).is_err());
}

#[test]
fn codecs_reject_old_profiles_truncations_tails_bad_lengths_commitments_and_signatures() {
    let d = TempDir::new().unwrap();
    let g = genesis();
    let mut s = create(&d.path().join("s.db"), &g);
    let b = empty(&s);
    let wire = packet(&b, &g);
    let old = s.snapshot().unwrap().clone();
    for n in 0..wire.len() {
        assert!(
            Envelope::from_wire_bytes(&wire[..n]).is_err(),
            "truncation {n}"
        );
    }
    let mut tail = wire.clone();
    tail.push(0);
    assert!(Envelope::from_wire_bytes(&tail).is_err());
    for offset in [0, 1, 2, 5, 38, 41, 42, 43, 74, 78, 304, 312, 324] {
        let mut bad = wire.clone();
        bad[offset] ^= 0x7f;
        assert!(s.stage_received(&bad).is_err(), "mutation {offset}");
        assert_eq!(s.snapshot().unwrap(), &old);
    }
    for offset in [0, 1, 5] {
        let mut bad = wire.clone();
        bad[offset] = if offset == 0 { 3 } else { 0 };
        assert!(s.stage_received(&bad).is_err());
    }
    assert!(crate::block_authentication::SignedBlockEnvelope::from_wire_bytes(&wire).is_err());
    assert!(crate::native_block::NativeBlock::from_wire_bytes(&b.wire_bytes()).is_err());
    let mut inner = b.wire_bytes();
    inner[0] = 2;
    assert!(Block::from_wire_bytes(&inner).is_err());
    let mut bad = wire.clone();
    *bad.last_mut().unwrap() = 27;
    assert!(s.stage_received(&bad).is_err());
    let mut bad = wire.clone();
    bad[6] ^= 1;
    assert!(matches!(
        s.stage_received(&bad),
        Err(Error::Protocol(super::super::Error::Context(_)))
    ));
    for field in ["profile", "chain", "kind", "state", "receipt", "gas"] {
        let mut h = b.claim().header().clone();
        match field {
            "profile" => h.protocol_version = 2,
            "chain" => h.chain_id += 1,
            "kind" => h.block_kind = crate::block_commitment::BlockKind::ProtocolNoTickets,
            "state" => h.state_root = [1; 32],
            "receipt" => h.receipts_root = [0; 32],
            _ => h.gas_used = 1000,
        }
        assert!(
            Block::from_parts(h, "trial-A".into(), ProtocolData::empty(), vec![]).is_err(),
            "{field}"
        );
    }
    // Width/count corruption is rejected before allocation; producer signatures stay opaque until
    // authentication, so syntax alone never turns this envelope into a canonical reference.
    let mut inner = b.wire_bytes();
    let count = inner.len() - 8;
    inner[count..].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(Block::from_wire_bytes(&inner).is_err());
}

#[test]
fn historical_admission_rejects_nonselected_wrong_ticket_parent_context_and_selected_conflicts_halt()
 {
    let d = TempDir::new().unwrap();
    let g = genesis();
    let mut s = create(&d.path().join("s.db"), &g);
    let old = s.snapshot().unwrap().clone();
    let selected = s.slot_start().unwrap().select().unwrap();
    let other = if selected.producer() == "trial-A" {
        "trial-B"
    } else {
        "trial-A"
    };
    let ticket = if other == "trial-A" { 1 } else { 255 };
    let b = block_for(&s, other, ticket, vec![]);
    let bytes = packet(&b, &g);
    assert!(
        Envelope::from_wire_bytes(&bytes)
            .unwrap()
            .authenticate(&g)
            .is_ok()
    );
    reset();
    assert_eq!(
        s.stage_received(&bytes).err(),
        Some(super::super::Error::NotSelected.into())
    );
    assert_eq!(counts(), (1, 0, (0, 0)));
    assert_eq!(s.snapshot().unwrap(), &old);
    assert!(!s.is_halted());
    let b = block_for(
        &s,
        selected.producer(),
        if selected.ticket_id() == 1 { 255 } else { 1 },
        vec![],
    );
    assert_eq!(
        s.stage_received(&packet(&b, &g)).err(),
        Some(super::super::Error::NotSelected.into())
    );
    let good = empty(&s);
    let mut h = good.claim().header().clone();
    h.parent_hash = [7; 32];
    let b =
        Block::from_parts(h, selected.producer().into(), ProtocolData::empty(), vec![]).unwrap();
    assert!(matches!(
        s.stage_received(&packet(&b, &g)),
        Err(Error::Protocol(super::super::Error::Context(_)))
    ));
    let accepted = append(&mut s, &g, &[]);
    assert_eq!(s.snapshot().unwrap().tip().hash, good.hash());
    let mut h = good.claim().header().clone();
    h.proposer_id = proposer_id(other);
    h.ticket_id = ticket;
    let b = Block::from_parts(h, other.into(), ProtocolData::empty(), vec![]).unwrap();
    assert_eq!(
        s.stage_received(&packet(&b, &g)).err(),
        Some(super::super::Error::NotSelected.into())
    );
    assert!(!s.is_halted());
    // A correctly selected-key, exact-parent alternate H halts before native body work. This is a
    // diagnostic statement, not adjudication that its opaque transaction body is historically valid.
    let mut h = good.claim().header().clone();
    let opaque = [0; 199];
    h.gas_used = 1000;
    h.transaction_root =
        ordered_transaction_root(&[hash_with_domain(native::ID_DOMAIN, &opaque)]).unwrap();
    let pd = ProtocolData {
        fees_burned: 10000,
        missed_proposer: None,
    };
    h.protocol_data_root = pd.root();
    let conflict = Block::from_parts(h, selected.producer().into(), pd, vec![opaque]).unwrap();
    reset();
    assert_eq!(
        s.stage_received(&packet(&conflict, &g)).err(),
        Some(Error::ConflictHalt)
    );
    assert_eq!(counts(), (1, 0, (0, 0)));
    assert!(s.is_halted());
    assert!(s.slot_start().is_err());
    assert_eq!(s.export_envelope(1).unwrap(), accepted);
    s.recover().unwrap();
    assert!(s.is_halted());
    assert!(s.prepare_next("trial-A", 1, &[]).is_err());
}

#[test]
fn later_invalid_native_entries_discard_every_native_reward_count_and_supply_effect() {
    let d = TempDir::new().unwrap();
    let g = genesis();
    let mut s = create(&d.path().join("s.db"), &g);
    let old = s.snapshot().unwrap().clone();
    let sel = s.slot_start().unwrap().select().unwrap();
    for which in [
        "signature",
        "nonce",
        "maturity",
        "funding",
        "overflow",
        "kind",
        "asset",
    ] {
        let first = tx(&g, 1, 3, 1, 0);
        let mut bad = unsigned(&g, 1, address_from_public_key(key(3).verifying_key()), 0, 1);
        match which {
            "nonce" => bad.nonce = 2,
            "maturity" => bad.valid_after_slot = 2,
            "funding" => bad.value = INITIAL_SUPPLY,
            "overflow" => bad.value = u128::MAX,
            _ => {}
        }
        let mut second = signed(&g, 1, bad);
        match which {
            "signature" => second[198] = 27,
            "kind" => second[45] = 1,
            "asset" => second[101] = 1,
            _ => {}
        }
        let b = block_for(&s, sel.producer(), sel.ticket_id(), vec![first, second]);
        reset();
        let error = s.stage_received(&packet(&b, &g)).unwrap_err();
        assert!(
            matches!(
                error,
                Error::Body(transfer::BodyError {
                    transaction_index: 1,
                    ..
                })
            ),
            "{which}: {error}"
        );
        if which == "overflow" {
            assert!(matches!(
                error,
                Error::Body(transfer::BodyError {
                    cause: TransferError::Overflow(ArithmeticField::CombinedDebit),
                    ..
                })
            ));
        }
        assert_eq!(counts().0, 1);
        assert_eq!(counts().1, 1);
        assert_eq!(
            counts().2,
            if ["signature", "kind", "asset"].contains(&which) {
                (2, 0)
            } else {
                (2, 2)
            }
        );
        assert_eq!(s.snapshot().unwrap(), &old);
        sql::verify(s.conn(), &g, &old).unwrap();
    }
    // A producer preparation is subject to the same body contract; it cannot retain the earlier
    // partial effects or earn a reward when a later entry fails.
    assert!(
        s.prepare_next(
            sel.producer(),
            sel.ticket_id(),
            &[tx(&g, 1, 3, 1, 0), tx(&g, 1, 3, 0, 2)]
        )
        .is_err()
    );
}

#[test]
fn duplicates_authenticate_before_reference_retain_original_evidence_and_apply_nothing_twice() {
    let d = TempDir::new().unwrap();
    let g = genesis();
    let p = d.path().join("s.db");
    let mut s = create(&p, &g);
    let wire = append(&mut s, &g, &[tx(&g, 1, 3, 1, 0)]);
    let original = Envelope::from_wire_bytes(&wire).unwrap();
    append(&mut s, &g, &[]);
    let old = s.snapshot().unwrap().clone();
    let alternate = Envelope::from_parts(
        original.block().clone(),
        g.network_id(),
        signature(original.block(), &g, true),
    );
    assert_ne!(alternate.id(), original.id());
    for e in [&original, &alternate] {
        reset();
        assert!(
            matches!(s.stage_received(&e.wire_bytes()),Err(Error::AlreadyCommitted{retained_envelope_id,submitted_envelope_id,..}) if retained_envelope_id==original.id() && submitted_envelope_id==e.id())
        );
        assert_eq!(counts(), (1, 0, (0, 0)));
        assert_eq!(s.snapshot().unwrap(), &old);
        assert_eq!(s.export_envelope(1).unwrap(), wire);
    }
    let mut bad = wire.clone();
    *bad.last_mut().unwrap() = 27;
    assert!(matches!(
        s.stage_received(&bad),
        Err(Error::Protocol(super::super::Error::Signature(_)))
    ));
    drop(s);
    assert_eq!(
        PoashTrialStore::reopen(&p, &g).unwrap().snapshot().unwrap(),
        &old
    );
}

#[test]
fn foreign_stale_recovery_invalidated_and_mismatched_producer_preparations_never_install() {
    let d = TempDir::new().unwrap();
    let g = genesis();
    let p = d.path().join("a.db");
    let mut a = create(&p, &g);
    let mut b = create(&d.path().join("b.db"), &g);
    let prep = preparation(&a, &[]);
    let wire = packet(prep.block(), &g);
    reset();
    assert_eq!(b.seal_prepared(prep, &wire).err(), Some(Error::Stale));
    assert_eq!(counts(), (0, 0, (0, 0)));
    let staged = a.stage_received(&wire).unwrap();
    assert!(matches!(
        b.commit(staged),
        AppendOutcome::Aborted(Error::Stale)
    ));
    let prep = preparation(&a, &[]);
    let staged = a.stage_received(&wire).unwrap();
    a.recover().unwrap();
    reset();
    assert_eq!(a.seal_prepared(prep, &wire).err(), Some(Error::Stale));
    assert!(matches!(
        a.commit(staged),
        AppendOutcome::Aborted(Error::Stale)
    ));
    assert_eq!(counts(), (0, 0, (0, 0)));
    let prep = preparation(&a, &[]);
    let selection = a.slot_start().unwrap().select().unwrap();
    let other = block_for(
        &a,
        selection.producer(),
        selection.ticket_id(),
        vec![tx(&g, 1, 3, 1, 0)],
    );
    reset();
    assert_eq!(
        a.seal_prepared(prep, &packet(&other, &g)).err(),
        Some(Error::PreparedIdentity)
    );
    assert_eq!(counts(), (1, 0, (0, 0)));
    let prep = preparation(&a, &[]);
    let st = a.stage_received(&wire).unwrap();
    receive(&mut a, &wire);
    reset();
    assert_eq!(a.seal_prepared(prep, &wire).err(), Some(Error::Stale));
    assert!(matches!(a.commit(st), AppendOutcome::Aborted(Error::Stale)));
    assert_eq!(counts(), (0, 0, (0, 0)));
    // Another valid SQL writer advances the file while this owner retains its old audited RAM.
    let mut second = PoashTrialStore::reopen(&p, &g).unwrap();
    let st = a.stage_received(&packet(&empty(&a), &g)).unwrap();
    append(&mut second, &g, &[]);
    assert!(matches!(a.commit(st), AppendOutcome::Aborted(Error::Stale)));
    assert!(!a.is_ready());
    a.recover().unwrap();
    assert_eq!(a.snapshot().unwrap(), second.snapshot().unwrap());
}

#[test]
fn rollback_poison_recovery_failures_exact_present_absent_and_stale_tokens() {
    for present in [false, true] {
        let d = TempDir::new().unwrap();
        let g = genesis();
        let mut s = create(&d.path().join("s.db"), &g);
        append(&mut s, &g, &[]);
        let wire = packet(preparation(&s, &[tx(&g, 1, 3, 1, 0)]).block(), &g);
        let old = s.snapshot().unwrap().clone();
        for target in [
            "accounts",
            "accounting",
            "block_evidence",
            "body",
            "indexes",
            "reward",
            "state",
            "revision",
            "tip",
            "before_commit",
        ] {
            let st = s.stage_received(&wire).unwrap();
            s.hook = Some(hook(target));
            assert!(
                matches!(s.commit(st), AppendOutcome::Aborted(_)),
                "{target}"
            );
            s.hook = None;
            assert_eq!(s.snapshot().unwrap(), &old);
            sql::verify(s.conn(), &g, &old).unwrap();
        }
        let stale = s.stage_received(&wire).unwrap();
        let st = s.stage_received(&wire).unwrap();
        let mut next = old.clone();
        next.insert(st.record.clone()).unwrap();
        s.hook = Some(if present {
            hook("after_commit")
        } else {
            Box::new(|p| {
                if ["reward", "rollback"].contains(&p) {
                    Err(invalid(p))
                } else {
                    Ok(())
                }
            })
        });
        assert!(matches!(s.commit(st), AppendOutcome::RecoveryRequired(_)));
        reset();
        assert!(s.snapshot().is_err());
        assert!(s.settings().is_err());
        assert!(s.export_envelope(1).is_err());
        assert!(s.slot_start().is_err());
        assert_eq!(s.stage_received(&[]).err(), Some(Error::Blocked));
        assert_eq!(counts(), (0, 0, (0, 0)));
        for target in [
            "recovery_reopen",
            "recovery_validate",
            "recovery_barrier",
            "recovery_install",
        ] {
            s.hook = Some(hook(target));
            assert!(s.recover().is_err());
            assert!(!s.is_ready());
        }
        s.hook = None;
        assert_eq!(s.recover().unwrap().attempted_present, Some(present));
        assert_eq!(s.snapshot().unwrap(), if present { &next } else { &old });
        assert!(matches!(
            s.commit(stale),
            AppendOutcome::Aborted(Error::Stale)
        ));
    }
}

// Corruption deliberately bypasses guards and then restores the EXACT schema. These are audit
// adversaries, not a repair API or an assertion that the OS/SQLite naturally makes these edits.
fn corrupt(c: &Connection, statement: &str) {
    c.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
    for (name, _) in sql::triggers() {
        c.execute_batch(&format!("DROP TRIGGER {name}")).unwrap();
    }
    c.execute_batch(statement).unwrap();
    for (_, ddl) in sql::triggers() {
        c.execute_batch(&ddl).unwrap();
    }
}

#[test]
fn full_replay_rejects_changed_state_year_reward_metadata_body_index_evidence_and_history() {
    for statement in [
        "UPDATE accounts SET balance=zeroblob(16) WHERE nonce<>zeroblob(8)",
        "UPDATE accounting SET issuance=zeroblob(16)",
        "UPDATE accounting SET supply=zeroblob(16)",
        "UPDATE accounting SET eligible_fee_burn=zeroblob(16)",
        "UPDATE year_zero SET record=zeroblob(120)",
        "UPDATE rewards SET amount=zeroblob(16)",
        "UPDATE rewards SET hold_epochs=x'0000000000000003'",
        "UPDATE states SET payload=zeroblob(length(payload)) WHERE slot=x'0000000000000002'",
        "UPDATE states SET state_id=zeroblob(32) WHERE slot=x'0000000000000001'",
        "UPDATE transactions SET nonce=x'0000000000000001'",
        "UPDATE transactions SET position=x'0000000000000001'",
        "UPDATE bodies SET gas=zeroblob(8) WHERE slot=x'0000000000000002'",
        "UPDATE blocks SET signature=zeroblob(65) WHERE slot=x'0000000000000002'",
        "UPDATE blocks SET envelope_id=zeroblob(32) WHERE slot=x'0000000000000002'",
        "DELETE FROM blocks WHERE slot=x'0000000000000001'",
        "UPDATE metadata SET genesis=zeroblob(length(genesis))",
        "CREATE TABLE sqliteXhidden (id INTEGER)",
    ] {
        let d = TempDir::new().unwrap();
        let g = genesis();
        let p = d.path().join("s.db");
        let mut s = create(&p, &g);
        append(&mut s, &g, &[]);
        append(&mut s, &g, &[tx(&g, 1, 3, 1, 0)]);
        drop(s);
        let c = Connection::open(&p).unwrap();
        corrupt(&c, statement);
        drop(c);
        assert!(PoashTrialStore::reopen(&p, &g).is_err(), "{statement}");
    }
}

#[test]
fn exact_sql_base_checks_all_state_evidence_and_indexes_before_any_candidate_write() {
    for statement in [
        "UPDATE accounts SET balance=zeroblob(16) WHERE nonce<>zeroblob(8)",
        "UPDATE rewards SET amount=zeroblob(16)",
        "UPDATE year_zero SET record=zeroblob(120)",
        "UPDATE transactions SET nonce=x'0000000000000002'",
        "UPDATE metadata SET revision=x'0000000000000002'",
        "UPDATE blocks SET envelope_id=zeroblob(32)",
    ] {
        let d = TempDir::new().unwrap();
        let g = genesis();
        let p = d.path().join("s.db");
        let mut s = create(&p, &g);
        append(&mut s, &g, &[tx(&g, 1, 3, 1, 0)]);
        let st = s.stage_received(&packet(&empty(&s), &g)).unwrap();
        let wrote = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = wrote.clone();
        s.hook = Some(Box::new(move |p| {
            if p == "accounts" {
                observed.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(())
        }));
        let c = Connection::open(&p).unwrap();
        corrupt(&c, statement);
        drop(c);
        reset();
        assert!(
            matches!(s.commit(st), AppendOutcome::Aborted(Error::Stale)),
            "{statement}"
        );
        assert!(!wrote.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(counts(), (0, 0, (0, 0)));
        assert!(!s.is_ready());
        assert!(s.recover().is_err());
    }
}

#[test]
fn uncertain_exact_original_choice_and_full_attempt_are_not_replaced_by_valid_alternates() {
    for attempted in [false, true] {
        let d = TempDir::new().unwrap();
        let g = genesis();
        let p = d.path().join("s.db");
        let mut s = create(&p, &g);
        let wire = packet(&empty(&s), &g);
        if attempted {
            let st = s.stage_received(&wire).unwrap();
            s.hook = Some(hook("after_commit"));
            assert!(matches!(s.commit(st), AppendOutcome::RecoveryRequired(_)));
        } else {
            receive(&mut s, &wire);
        }
        s.hook = None;
        s.connection.take();
        let e = Envelope::from_wire_bytes(&wire).unwrap();
        let alternate = Envelope::from_parts(
            e.block().clone(),
            g.network_id(),
            signature(e.block(), &g, true),
        );
        let c = Connection::open(&p).unwrap();
        corrupt(
            &c,
            &format!(
                "UPDATE blocks SET signature=x'{}',envelope_id=x'{}'",
                hex::encode(alternate.signature_bytes()),
                hex::encode(alternate.id())
            ),
        );
        drop(c);
        let fresh = PoashTrialStore::reopen(&p, &g).unwrap();
        assert_eq!(fresh.export_envelope(1).unwrap(), alternate.wire_bytes());
        drop(fresh);
        assert!(s.recover().is_err());
        assert!(!s.is_ready());
    }
}

#[test]
fn exact_present_attempt_can_have_audited_descendants_but_different_valid_attempt_cannot_reconcile()
{
    for different in [false, true] {
        let d = TempDir::new().unwrap();
        let g = genesis();
        let p = d.path().join("s.db");
        let mut s = create(&p, &g);
        let st = s.stage_received(&packet(&empty(&s), &g)).unwrap();
        s.hook = Some(if different {
            Box::new(|p| {
                if ["reward", "rollback"].contains(&p) {
                    Err(invalid(p))
                } else {
                    Ok(())
                }
            })
        } else {
            hook("after_commit")
        });
        assert!(matches!(s.commit(st), AppendOutcome::RecoveryRequired(_)));
        s.connection.take();
        s.hook = None;
        let mut other = PoashTrialStore::reopen(&p, &g).unwrap();
        append(&mut other, &g, &[tx(&g, 1, 3, 1, 0)]);
        let expected = other.snapshot().unwrap().clone();
        drop(other);
        if different {
            assert!(s.recover().is_err());
            assert!(!s.is_ready());
        } else {
            assert_eq!(s.recover().unwrap().attempted_present, Some(true));
            assert_eq!(s.snapshot().unwrap(), &expected);
        }
    }
}

#[test]
fn initialization_no_create_policy_schema_guards_and_supported_domain_stop() {
    let d = TempDir::new().unwrap();
    let g = genesis();
    let p = d.path().join("s.db");
    assert!(matches!(
        PoashTrialStore::reopen(&p, &g),
        Err(Error::Storage(StoreError::Missing))
    ));
    assert!(!p.exists());
    let mut s = create(&p, &g);
    assert!(matches!(
        PoashTrialStore::create(&p, &g),
        Err(Error::Storage(StoreError::AlreadyExists))
    ));
    let mut bytes = g.canonical_bytes().to_vec();
    bytes[31] = b'X';
    let wrong = Genesis::from_bytes(&bytes).unwrap();
    assert!(PoashTrialStore::reopen(&p, &wrong).is_err());
    assert!(disk::FixtureStore::reopen(&p, app::native_context(&g)).is_err());
    let old = d.path().join("schema1.db");
    drop(
        disk::FixtureStore::create_fixture(
            &old,
            app::native_context(&g),
            app::native_state(g.initial_state()),
            "old fixture",
        )
        .unwrap(),
    );
    assert!(PoashTrialStore::reopen(&old, &g).is_err());
    append(&mut s, &g, &[]);
    for statement in [
        "UPDATE blocks SET signature=signature",
        "DELETE FROM rewards",
        "UPDATE states SET payload=payload",
        "INSERT OR REPLACE INTO blocks SELECT * FROM blocks",
        "UPDATE metadata SET genesis=zeroblob(1)",
        "DELETE FROM year_zero",
    ] {
        assert!(s.conn().execute_batch(statement).is_err(), "{statement}");
    }
    for _ in 2..=MAX_SLOTS {
        append(&mut s, &g, &[]);
    }
    assert_eq!(s.snapshot().unwrap().tip().slot, 200);
    assert_eq!(
        s.snapshot().unwrap().state.input().base_issuance,
        200 * g.year_zero().reward
    );
    assert_eq!(
        s.slot_start().err(),
        Some(super::super::Error::ExperimentLimit.into())
    );
    assert!(s.prepare_next("trial-A", 1, &[]).is_err());
    let expected = s.snapshot().unwrap().clone();
    drop(s);
    assert_eq!(
        PoashTrialStore::reopen(&p, &g).unwrap().snapshot().unwrap(),
        &expected
    );
}

#[test]
fn private_compound_arithmetic_and_unsupported_state_guards_fail_closed() {
    let d = TempDir::new().unwrap();
    let g = genesis();
    let s = create(&d.path().join("s.db"), &g);
    let b = empty(&s);
    // Forced impossible internal values test checked reward arithmetic only. They are NOT accepted
    // snapshots or live checkpoint imports: the public constructor rejects this inconsistent state.
    let mut view = s.slot_start().unwrap();
    let winner = view.select().unwrap().producer().to_owned();
    let prefix = std::sync::Arc::make_mut(&mut view.prefix);
    prefix
        .state
        .data
        .validators
        .iter_mut()
        .find(|v| v.id == winner)
        .unwrap()
        .vault = u128::MAX;
    assert_eq!(
        app::compound(
            &view,
            &b,
            app::native_state(g.initial_state()),
            &BodyOutcome::default()
        )
        .err(),
        Some(super::super::Error::Overflow.into())
    );
    let mut input = g.initial_state().input().clone();
    input.validators[0].misses = 1;
    let state = ClosedState::from_trusted_snapshot(&g, input).unwrap();
    assert!(app::supported(&state).is_err());
    assert!(ClosedState::from_trusted_snapshot(&g, view.state().input().clone()).is_err());
}

#[test]
fn c1_sixteen_entry_limit_new_accounts_and_native_fee_totals_survive_replay() {
    let d = TempDir::new().unwrap();
    let g = genesis();
    let p = d.path().join("s.db");
    let mut s = create(&p, &g);
    let body: Vec<_> = (0..16)
        .map(|i| {
            let mut address = [0x88; 20];
            address[19] = i;
            signed(&g, 1, unsigned(&g, 1, address, 1, i as u64))
        })
        .collect();
    let mut too_many = body.clone();
    too_many.push(tx(&g, 1, 3, 1, 16));
    reset();
    let winner = s.slot_start().unwrap().select().unwrap();
    assert!(
        s.prepare_next(winner.producer(), winner.ticket_id(), &too_many)
            .is_err()
    );
    assert_eq!(counts(), (0, 0, (0, 0)));
    reset();
    let prep = preparation(&s, &body);
    let wire = packet(prep.block(), &g);
    assert_eq!(prep.block().wire_bytes().len(), app::MAX_BLOCK_BYTES);
    assert_eq!(wire.len(), app::MAX_ENVELOPE_BYTES);
    let stage = s.seal_prepared(prep, &wire).unwrap();
    assert!(matches!(s.commit(stage), AppendOutcome::Committed { .. }));
    assert_eq!(counts(), (1, 1, (16, 16)));
    let snapshot = s.snapshot().unwrap().clone();
    let state = snapshot.state.input();
    assert_eq!(state.accounts.len(), 19);
    assert_eq!(state.gas_used, 16000);
    assert_eq!(state.fees_burned, 160000);
    assert_eq!(state.base_issuance, 10000000);
    assert_eq!(snapshot.transactions.len(), 16);
    assert_eq!(snapshot.sender_nonces.len(), 16);
    assert_eq!(
        state.accounts.iter().map(|a| a.balance).sum::<u128>()
            + state.validators.iter().map(|v| v.vault).sum::<u128>(),
        INITIAL_SUPPLY + 10000000 - 160000
    );
    drop(s);
    assert_eq!(
        PoashTrialStore::reopen(&p, &g).unwrap().snapshot().unwrap(),
        &snapshot
    );
}

#[test]
fn authoritative_missing_archive_rows_block_reopen_without_fallback_or_repair() {
    let d = TempDir::new().unwrap();
    let g = genesis();
    let p = d.path().join("s.db");
    let mut s = create(&p, &g);
    for _ in 1..=33 {
        append(&mut s, &g, &[]);
    }
    let expected = s.snapshot().unwrap().clone();
    // Internal hole injection proves the actual owner constructs/validates its own view before
    // body staging. Such an inconsistent RAM value is not constructible through the public API.
    let removed = s.snapshot.records.remove(31);
    reset();
    assert_eq!(
        s.slot_start().err(),
        Some(super::super::Error::MissingHistory(32).into())
    );
    assert_eq!(counts(), (0, 0, (0, 0)));
    s.snapshot.records.insert(31, removed);
    assert_eq!(s.snapshot().unwrap(), &expected);
    drop(s);
    let c = Connection::open(&p).unwrap();
    corrupt(&c, "DELETE FROM blocks WHERE slot=x'0000000000000020'");
    drop(c);
    assert!(PoashTrialStore::reopen(&p, &g).is_err());
    let c = Connection::open(&p).unwrap();
    let n: i64 = c
        .query_row("SELECT count(*) FROM blocks", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 32);
}

#[test]
fn schema_two_three_remain_separate_and_c1_cannot_promote_their_anchors() {
    use crate::authenticated_fixture::{AuthenticatedFixtureManifest, AuthenticatedFixtureStore};
    use crate::block_authentication::{BlockAuthenticationContext, ProducerBinding};
    use crate::canonical_fixture::{CanonicalFixtureStore, FixtureManifest};
    let d = TempDir::new().unwrap();
    let g = genesis();
    let context = app::native_context(&g);
    let anchor = crate::native_block::NativeBlock::empty_fixture_anchor(
        &context,
        0,
        [0; 32],
        "trial-A".into(),
        1,
    )
    .unwrap();
    let manifest = FixtureManifest::new(
        context,
        anchor,
        app::native_state(g.initial_state()),
        "independent old fixture".into(),
    )
    .unwrap();
    let auth = AuthenticatedFixtureManifest::new(
        manifest.clone(),
        BlockAuthenticationContext::new(context, 2, 1).unwrap(),
        g.validators()
            .iter()
            .map(|v| ProducerBinding::new(&v.id, &v.public_key).unwrap())
            .collect(),
    )
    .unwrap();
    let p2 = d.path().join("two.db");
    let p3 = d.path().join("three.db");
    let p4 = d.path().join("four.db");
    drop(CanonicalFixtureStore::create_anchored_fixture(&p2, &manifest).unwrap());
    drop(AuthenticatedFixtureStore::create_authenticated_fixture(&p3, &auth).unwrap());
    drop(create(&p4, &g));
    assert!(PoashTrialStore::reopen(&p2, &g).is_err());
    assert!(PoashTrialStore::reopen(&p3, &g).is_err());
    assert!(CanonicalFixtureStore::reopen(&p4, &manifest).is_err());
    assert!(AuthenticatedFixtureStore::reopen(&p4, &auth).is_err());
}
