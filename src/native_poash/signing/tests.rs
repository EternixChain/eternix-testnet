//! Actual protected signing and cross-file C1 reconciliation, with public small-integer toy keys.
use super::*;
use crate::native_transaction::{self as native, UnsignedTransaction, address_from_public_key};
use crate::native_transfer::phase_evidence as native_phases;
use serde_json::Value;
use tempfile::TempDir;
mod faults;
fn key(n: u8) -> SigningKey {
    let mut b = [0; 32];
    b[31] = n;
    SigningKey::from_slice(&b).unwrap()
}
fn genesis() -> Genesis {
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/native_poash_eligibility.json"
    ))
    .unwrap();
    Genesis::from_bytes(
        &hex::decode(
            f["genesis"]["hex_parts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap())
                .collect::<String>(),
        )
        .unwrap(),
    )
    .unwrap()
}
fn owner(path: &Path, g: &Genesis) -> PoashTrialStore {
    PoashTrialStore::create(path, g).unwrap()
}
fn prepare(o: &PoashTrialStore, body: &[Vec<u8>]) -> PreparedBlock {
    let s = o.slot_start().unwrap().select().unwrap();
    o.prepare_next(s.producer(), s.ticket_id(), body).unwrap()
}
fn body(g: &Genesis) -> Vec<Vec<u8>> {
    vec![
        native::sign(
            UnsignedTransaction {
                encoding_version: 2,
                native_rules_version: 1,
                chain_id: CHAIN_ID,
                network_id: g.network_id(),
                kind: 0,
                sender: address_from_public_key(key(1).verifying_key()),
                nonce: 0,
                recipient: address_from_public_key(key(3).verifying_key()),
                token_id: 0,
                value: 1,
                gas_limit: 1001,
                valid_after_slot: 0,
            },
            &key(1),
            &app::native_context(g),
        )
        .unwrap()
        .canonical_bytes()
        .unwrap()
        .to_vec(),
    ]
}
fn authority(root: &Path, g: &Genesis, o: &PoashTrialStore) -> SigningAuthority {
    SigningAuthority::create(root, g, "trial-A", key(2), o).unwrap()
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

#[test]
fn durable_original_precedes_response_repeats_and_once_only_canonical_installation() {
    let d = TempDir::new().unwrap();
    let root = TempDir::new().unwrap();
    let g = genesis();
    let p = d.path().join("owner.db");
    let mut o = owner(&p, &g);
    let mut a = authority(root.path(), &g, &o);
    phase_evidence::reset();
    native_phases::reset();
    app::phase_evidence::reset();
    let prep = prepare(&o, &body(&g));
    assert_eq!(native_phases::stages(), 1);
    let original = a.sign_prepared(&o, &prep).unwrap();
    assert_eq!(phase_evidence::count(), 1);
    assert_eq!(app::phase_evidence::count(), 0);
    let bytes = original.bytes().to_vec();
    let repeated = a.sign_prepared(&o, &prep).unwrap();
    assert_eq!(repeated.bytes(), bytes);
    assert_eq!(phase_evidence::count(), 1);
    assert_eq!(native_phases::stages(), 1);
    assert!(repeated.timings().signature.is_zero());
    let st = o.seal_prepared(prep, &bytes).unwrap();
    a.check_application(&o, 1, &st).unwrap();
    assert_eq!(app::phase_evidence::count(), 1);
    assert!(matches!(o.commit(st), AppendOutcome::Committed { .. }));
    assert_eq!(native_phases::stages(), 1);
    assert_eq!(app::phase_evidence::count(), 1);
    assert_eq!(a.original(&o, 1).unwrap().bytes(), bytes);
    assert_eq!(phase_evidence::count(), 1);
    let expected = o.snapshot().unwrap().clone();
    drop(a);
    drop(o);
    let o = PoashTrialStore::reopen(&p, &g).unwrap();
    let mut a = SigningAuthority::reopen(root.path(), &g, "trial-A", key(2), &o).unwrap();
    assert_eq!(a.status(&o).unwrap().committed, vec![1]);
    assert_eq!(a.original(&o, 1).unwrap().bytes(), bytes);
    assert_eq!(o.snapshot().unwrap(), &expected);
}
#[test]
fn incomplete_reservations_remain_fenced_even_when_canonical_sql_is_absent() {
    for target in [
        "after_reservation_sync",
        "before_signature",
        "after_signature",
        "original_written",
        "before_original_commit",
    ] {
        let d = TempDir::new().unwrap();
        let root = TempDir::new().unwrap();
        let g = genesis();
        let o = owner(&d.path().join("o.db"), &g);
        let mut a = authority(root.path(), &g, &o);
        let prep = prepare(&o, &[]);
        a.hook = Some(hook(target));
        assert!(a.sign_prepared(&o, &prep).is_err());
        assert!(!a.is_ready());
        assert!(a.original(&o, 1).is_err());
        a.hook = None;
        assert_eq!(a.recover(&o).unwrap().incomplete, vec![1]);
        assert_eq!(o.snapshot().unwrap().tip().slot, 0);
        phase_evidence::reset();
        assert!(matches!(
            a.sign_prepared(&o, &prep),
            Err(Error::Incomplete(1))
        ));
        let different = prepare(&o, &body(&g));
        assert!(matches!(
            a.sign_prepared(&o, &different),
            Err(Error::Conflict(1))
        ));
        assert_eq!(phase_evidence::count(), 0);
        drop(a);
        let mut a = SigningAuthority::reopen(root.path(), &g, "trial-A", key(2), &o).unwrap();
        assert_eq!(a.status(&o).unwrap().incomplete, vec![1]);
        assert!(a.sign_prepared(&o, &different).is_err());
        assert_eq!(phase_evidence::count(), 0);
    }
}
#[test]
fn synchronized_original_lost_response_and_pending_replay_never_sign_again() {
    for target in [
        "after_original_commit",
        "after_original_sync",
        "before_response",
    ] {
        let d = TempDir::new().unwrap();
        let root = TempDir::new().unwrap();
        let g = genesis();
        let mut o = owner(&d.path().join("o.db"), &g);
        let mut a = authority(root.path(), &g, &o);
        let prep = prepare(&o, &[]);
        a.hook = Some(hook(target));
        phase_evidence::reset();
        assert!(a.sign_prepared(&o, &prep).is_err());
        assert_eq!(phase_evidence::count(), 1);
        a.hook = None;
        let report = a.recover(&o).unwrap();
        assert_eq!(report.pending, vec![1]);
        assert!(report.incomplete.is_empty());
        let original = a.original(&o, 1).unwrap();
        let expected = original.bytes().to_vec();
        let st = o.seal_prepared(prep, original.bytes()).unwrap();
        a.check_application(&o, 1, &st).unwrap();
        assert!(matches!(o.commit(st), AppendOutcome::Committed { .. }));
        assert_eq!(a.original(&o, 1).unwrap().bytes(), expected);
        assert_eq!(phase_evidence::count(), 1);
        assert!(matches!(
            o.stage_received(&expected),
            Err(app::Error::AlreadyCommitted { .. })
        ));
    }
}
#[test]
fn fence_is_per_network_key_across_archive_directories_and_held_while_poisoned() {
    let d = TempDir::new().unwrap();
    let root = TempDir::new().unwrap();
    let g = genesis();
    let a = owner(&d.path().join("a.db"), &g);
    let b = owner(&d.path().join("b.db"), &g);
    let mut signer = authority(root.path(), &g, &a);
    assert!(matches!(
        SigningAuthority::reopen(root.path(), &g, "trial-A", key(2), &b),
        Err(Error::Owned)
    ));
    assert!(matches!(
        SigningAuthority::create(root.path(), &g, "trial-A", key(2), &b),
        Err(Error::Owned)
    ));
    // The distinct configured key can coexist under the SAME protection root.
    let other = SigningAuthority::create(root.path(), &g, "trial-B", key(5), &b).unwrap();
    drop(other);
    signer.hook = Some(hook("after_reservation_sync"));
    let p = prepare(&a, &[]);
    assert!(signer.sign_prepared(&a, &p).is_err());
    assert!(matches!(
        SigningAuthority::reopen(root.path(), &g, "trial-A", key(2), &b),
        Err(Error::Owned)
    ));
    drop(signer);
    assert_eq!(
        SigningAuthority::reopen(root.path(), &g, "trial-A", key(2), &b)
            .unwrap()
            .status(&b)
            .unwrap()
            .incomplete,
        vec![1]
    );
}
#[test]
fn foreign_preparations_changed_generations_and_context_never_reach_reservation_or_signing() {
    let d = TempDir::new().unwrap();
    let root = TempDir::new().unwrap();
    let g = genesis();
    let mut a = owner(&d.path().join("a.db"), &g);
    let b = owner(&d.path().join("b.db"), &g);
    let mut s = authority(root.path(), &g, &a);
    phase_evidence::reset();
    let foreign = prepare(&b, &[]);
    assert!(s.sign_prepared(&a, &foreign).is_err());
    assert_eq!(phase_evidence::count(), 0);
    assert!(s.intents.is_empty());
    let prep = prepare(&a, &[]);
    a.recover().unwrap();
    assert!(matches!(s.sign_prepared(&a, &prep), Err(Error::Blocked)));
    s.recover(&a).unwrap();
    assert!(s.sign_prepared(&a, &prep).is_err());
    assert_eq!(phase_evidence::count(), 0);
    assert!(s.intents.is_empty());
    let root2 = TempDir::new().unwrap();
    let mut raw = g.canonical_bytes().to_vec();
    raw[31] = b'Z';
    let other = Genesis::from_bytes(&raw).unwrap();
    assert!(SigningAuthority::create(root2.path(), &other, "trial-A", key(2), &a).is_err());
    assert!(SigningAuthority::create(root2.path(), &g, "trial-A", key(5), &a).is_err());
}
#[test]
fn canonical_abort_uncertainty_and_recovery_do_not_release_original_or_auto_apply() {
    for target in ["before_begin", "reward", "after_commit", "after_install"] {
        let d = TempDir::new().unwrap();
        let root = TempDir::new().unwrap();
        let g = genesis();
        let mut o = owner(&d.path().join("o.db"), &g);
        let mut a = authority(root.path(), &g, &o);
        let prep = prepare(&o, &body(&g));
        let bytes = a.sign_prepared(&o, &prep).unwrap().bytes().to_vec();
        let st = o.seal_prepared(prep, &bytes).unwrap();
        o.signing_test_hook(Some(Box::new(move |p| {
            if p == target {
                Err(app::invalid(target))
            } else {
                Ok(())
            }
        })));
        let outcome = o.commit(st);
        assert!(!matches!(outcome, AppendOutcome::Committed { .. }));
        o.signing_test_hook(None);
        o.recover().unwrap();
        assert!(a.original(&o, 1).is_err());
        let report = a.recover(&o).unwrap();
        let present = ["after_commit", "after_install"].contains(&target);
        assert_eq!(
            o.snapshot().unwrap().tip().slot,
            if present { 1 } else { 0 }
        );
        assert_eq!(report.committed, if present { vec![1] } else { vec![] });
        assert_eq!(report.pending, if present { vec![] } else { vec![1] });
        phase_evidence::reset();
        let original = a.original(&o, 1).unwrap();
        assert_eq!(original.bytes(), bytes);
        if !present {
            let st = o.stage_received(original.bytes()).unwrap();
            a.check_application(&o, 1, &st).unwrap();
            assert!(matches!(o.commit(st), AppendOutcome::Committed { .. }));
        }
        assert_eq!(phase_evidence::count(), 0);
        assert_eq!(
            o.snapshot().unwrap().state.input().base_issuance,
            10_000_000
        );
    }
}
#[test]
fn signer_recovery_failures_hide_originals_and_never_repair_or_initialize_missing_protection() {
    let d = TempDir::new().unwrap();
    let root = TempDir::new().unwrap();
    let g = genesis();
    let o = owner(&d.path().join("o.db"), &g);
    assert!(matches!(
        SigningAuthority::reopen(root.path(), &g, "trial-A", key(2), &o),
        Err(Error::Missing)
    ));
    let mut a = authority(root.path(), &g, &o);
    let prep = prepare(&o, &[]);
    let bytes = a.sign_prepared(&o, &prep).unwrap().bytes().to_vec();
    for target in [
        "recovery_reopen",
        "recovery_audit",
        "recovery_barrier",
        "recovery_install",
    ] {
        a.hook = Some(hook(target));
        assert!(a.recover(&o).is_err());
        assert!(!a.is_ready());
        assert!(a.original(&o, 1).is_err());
        assert!(a.sign_prepared(&o, &prep).is_err());
    }
    a.hook = None;
    a.recover(&o).unwrap();
    assert_eq!(a.original(&o, 1).unwrap().bytes(), bytes);
    drop(a);
    assert!(matches!(
        SigningAuthority::create(root.path(), &g, "trial-A", key(2), &o),
        Err(Error::Exists)
    ));
}

#[test]
fn independently_packed_authority_reservation_and_base_ids_match_actual_durable_rows() {
    let d = TempDir::new().unwrap();
    let root = TempDir::new().unwrap();
    let g = genesis();
    let o = owner(&d.path().join("o.db"), &g);
    let mut a = authority(root.path(), &g, &o);
    let prepared = prepare(&o, &[]);
    let v: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/native_poash_signing.json"
    ))
    .unwrap();
    let expected = hex::decode(
        v["reservation_parts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect::<String>(),
    )
    .unwrap();
    a.sign_prepared(&o, &prepared).unwrap();
    assert_eq!(a.intents[&1].reservation, expected);
    let identity: Vec<u8> = a
        .conn()
        .query_row("SELECT identity FROM metadata WHERE id=1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(hex::encode(identity), v["authority_identity"]);
    assert_eq!(
        hex::encode(crate::block_commitment::keccak256(&expected)),
        v["reservation_keccak"]
    );
    for n in 0..expected.len() {
        assert!(
            journal::decode_reservation(&expected[..n], &g, "trial-A", a.public_key).is_err(),
            "truncated {n}"
        );
    }
    for offset in [
        0, 28, 31, 32, 64, 68, 72, 73, 74, 75, 79, 112, 114, 121, 129, 161, 353,
    ] {
        let mut bad = expected.clone();
        bad[offset] ^= 0x80;
        assert!(
            journal::decode_reservation(&bad, &g, "trial-A", a.public_key).is_err(),
            "reservation mutation {offset}"
        );
    }
    // Opaque base IDs are checked against the independently audited owner, not accepted by syntax.
    let old = a.intents.clone();
    a.intents.get_mut(&1).unwrap().reservation[193] ^= 1;
    assert!(a.status(&o).is_err());
    a.intents = old;
}
