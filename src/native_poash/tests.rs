//! Tests invoke actual C1 constructors/planner; no owner, SQL or economic application is modeled.
use super::*;
use crate::block_commitment::{
    BlockHeader, BlockKind, EMPTY_RECEIPTS_ROOT, EMPTY_TX_ROOT, ProtocolData, proposer_id,
};
use k256::ecdsa::SigningKey;

fn addr(s: &str) -> Address {
    hex::decode(s).unwrap().try_into().unwrap()
}
fn key(n: u8) -> SigningKey {
    let mut b = [0; 32];
    b[31] = n;
    SigningKey::from_slice(&b).unwrap()
} // published toy inputs only
fn input() -> GenesisInput {
    let a = addr("7e5f4552091a69125d5dfcb7b8c2659029395bdf");
    let b = addr("6813eb9362372eef6200f3b1dbc3f819671cba69");
    GenesisInput {
        run_id: "c1-eligibility-golden-2026".into(),
        accounts: vec![
            Account {
                address: a,
                balance: 1_600_000_000_000_000,
                nonce: 0,
            },
            Account {
                address: b,
                balance: 32_000_000_000_000,
                nonce: 0,
            },
            Account {
                address: addr("1eff47bc3a10a45d4b230b5d10e37751fe6aa718"),
                balance: 0,
                nonce: 0,
            },
        ],
        validators: [("trial-A", 2, a), ("trial-B", 5, b)]
            .into_iter()
            .map(|(id, n, owner)| ValidatorConfig {
                id: id.into(),
                public_key: key(n)
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                owner,
                reward: owner,
                initial_vault: INITIAL_VAULT,
            })
            .collect(),
        tickets: vec![Ticket::active(1, "trial-A"), Ticket::active(255, "trial-B")],
    }
}
fn genesis() -> Genesis {
    Genesis::new(input()).unwrap()
}
fn header(g: &Genesis, slot: u64, parent: Hash, producer: &str, ticket: u64) -> BlockHeader {
    let _ = g;
    BlockHeader {
        protocol_version: HEADER_PROFILE,
        chain_id: CHAIN_ID,
        slot,
        block_kind: BlockKind::Validator,
        parent_hash: parent,
        proposer_id: proposer_id(producer),
        ticket_id: ticket,
        transaction_root: *EMPTY_TX_ROOT,
        state_root: [0; 32],
        receipts_root: *EMPTY_RECEIPTS_ROOT,
        gas_used: 0,
        protocol_data_root: ProtocolData::empty().root(),
    }
}
fn sign(g: &Genesis, claim: &HeaderClaim, n: u8) -> AuthenticatedHeader {
    let (s, id) = key(n)
        .sign_prehash_recoverable(&claim.signing_digest(g.network_id()))
        .unwrap();
    assert!(!id.is_x_reduced());
    let mut b = s.to_bytes().to_vec();
    b.push(id.to_byte());
    claim.authenticate(g, g.network_id(), &b).unwrap()
}
// Synthetic header history is generated from the actual selector and exact empty header recipe.
// Reward metadata is explicit test input, not a production application/transition helper.
fn history(g: &Genesis, end: u64) -> (Vec<HistoricalHeader>, SnapshotInput) {
    let mut headers = vec![HistoricalHeader::new(g.anchor().clone(), g.anchor().hash()).unwrap()];
    let mut s = g.initial_state().input().clone();
    let r = g.year_zero().reward;
    for slot in 1..=end {
        let reference = if slot < 32 {
            g.network_id()
        } else {
            headers[(slot - 32) as usize].hash()
        };
        let selection =
            selection::select_inputs(reference, slot, &s.validators, &s.tickets).unwrap();
        let h = header(
            g,
            slot,
            headers.last().unwrap().hash(),
            selection.producer(),
            selection.ticket_id(),
        );
        let hash = h.hash();
        headers.push(HistoricalHeader::new(h, hash).unwrap());
        let v = s
            .validators
            .iter_mut()
            .find(|v| v.id == selection.producer())
            .unwrap();
        v.produced += 1;
        v.vault += r;
        v.locked += r;
        s.credits.push(RewardCredit {
            slot,
            validator: selection.producer().into(),
            amount: r,
        });
        s.base_issuance += r;
        s.position = Position { slot, hash };
    }
    (headers, s)
}
fn context(g: &Genesis, end: u64) -> PrefixContext {
    let (h, s) = history(g, end);
    PrefixContext::from_trusted_history(g, h, ClosedState::from_trusted_snapshot(g, s).unwrap())
        .unwrap()
}

#[test]
fn closed_genesis_exact_roundtrip_rejects_every_truncation_and_parameter_mutation() {
    let g = genesis();
    assert_eq!(Genesis::from_bytes(g.canonical_bytes()).unwrap(), g);
    assert_ne!(g.network_id(), g.anchor().hash());
    assert_eq!(g.year_zero().reward, 10_000_000);
    for n in 0..g.canonical_bytes().len() {
        assert!(
            Genesis::from_bytes(&g.canonical_bytes()[..n]).is_err(),
            "truncation {n}"
        );
    }
    // The run label is intentionally variable; fixed parameter/anchor/state bytes are not.
    let start = GENESIS_DESCRIPTOR.len() + 4 + 2 + g.run_id().len();
    for i in start..g.canonical_bytes().len() {
        let mut b = g.canonical_bytes().to_vec();
        b[i] ^= 1;
        assert!(Genesis::from_bytes(&b).is_err(), "fixed byte {i}");
    }
    let mut tail = g.canonical_bytes().to_vec();
    tail.push(0);
    assert!(Genesis::from_bytes(&tail).is_err());
    let mut reset = input();
    reset.run_id.push('x');
    assert_ne!(Genesis::new(reset).unwrap().network_id(), g.network_id());
    let mut bad = input();
    bad.validators[1].public_key = bad.validators[0].public_key;
    assert!(Genesis::new(bad).is_err());
    let mut bad = input();
    bad.tickets[1].id = 1;
    assert!(Genesis::new(bad).is_err());
    let mut bad = input();
    bad.accounts[0].balance += 1;
    assert!(Genesis::new(bad).is_err());
}

#[test]
fn canonical_input_permutations_do_not_select_different_bytes_or_permission() {
    let g = genesis();
    let mut p = input();
    p.accounts.reverse();
    p.validators.reverse();
    p.tickets.reverse();
    assert_eq!(Genesis::new(p).unwrap(), g);
    let (h, mut s) = history(&g, 63);
    let original = ClosedState::from_trusted_snapshot(&g, s.clone()).unwrap();
    s.accounts.reverse();
    s.validators.reverse();
    s.tickets.reverse();
    s.credits.reverse();
    let reordered = ClosedState::from_trusted_snapshot(&g, s).unwrap();
    assert_eq!(original, reordered);
    let a = PrefixContext::from_trusted_history(&g, h.clone(), original)
        .unwrap()
        .slot_start()
        .unwrap();
    let b = PrefixContext::from_trusted_history(&g, h, reordered)
        .unwrap()
        .slot_start()
        .unwrap();
    assert_eq!(a.id(), b.id());
    assert_eq!(a.select(), b.select());
}

#[test]
fn lookback_31_32_33_64_uses_explicit_prefix_and_distinct_post_parent_state() {
    let g = genesis();
    for slot in [31, 32, 33, 64] {
        let c = context(&g, slot - 1);
        let view = c.slot_start().unwrap();
        assert_eq!(view.state().position().slot, slot - 1);
        let expected = if slot < 32 {
            g.network_id()
        } else {
            c.historical_hash(slot - 32).unwrap()
        };
        assert_eq!(view.reference(), expected);
        assert_eq!(view.select().unwrap().reference(), expected);
    }
    let (h, s) = history(&g, 63);
    let state = ClosedState::from_trusted_snapshot(&g, s).unwrap();
    for missing in [0, 1, 32, 63] {
        let mut bad = h.clone();
        bad.remove(missing);
        assert_eq!(
            PrefixContext::from_trusted_history(&g, bad, state.clone()).unwrap_err(),
            Error::MissingHistory(missing as u64)
        );
    }
    assert_eq!(
        context(&g, 200).slot_start().unwrap_err(),
        Error::ExperimentLimit
    );
    assert_eq!(
        context(&g, 63).historical_hash(64),
        Err(Error::MissingHistory(64))
    );
}

#[test]
fn malformed_duplicate_and_undercollateralized_state_fail_before_lottery() {
    let g = genesis();
    let (_, base) = history(&g, 2);
    for kind in 0..11 {
        let mut s = base.clone();
        match kind {
            0 => s.accounts[1] = s.accounts[0].clone(),
            1 => s.validators[1].id = s.validators[0].id.clone(),
            2 => s.tickets[1].id = s.tickets[0].id,
            3 => s.tickets[0].owner = "unknown".into(),
            4 => s.tickets[0].bucket = 0,
            5 => s.validators[0].vault = 5 * TICKET_COST,
            6 => s.validators[0].locked = s.validators[0].vault + 1,
            7 => s.credits.pop().map(|_| ()).unwrap(),
            8 => s.base_issuance += 1,
            9 => s.accounts[0].nonce = u64::MAX,
            _ => s.tickets[0].retire_start = Some(0),
        };
        assert!(
            ClosedState::from_trusted_snapshot(&g, s).is_err(),
            "case {kind}"
        );
    }
    let (h, mut s) = history(&g, 2);
    s.position.hash = [0; 32];
    let s = ClosedState::from_trusted_snapshot(&g, s).unwrap();
    assert!(PrefixContext::from_trusted_history(&g, h, s).is_err());
    let mut fake = g.anchor().clone();
    fake.parent_hash = [4; 32];
    let hash = fake.hash();
    let state = g.initial_state().clone();
    assert!(
        PrefixContext::from_trusted_history(
            &g,
            vec![HistoricalHeader::new(fake, hash).unwrap()],
            state
        )
        .is_err()
    );
}

#[test]
fn correctly_authenticated_non_selected_is_rejected_without_native_staging() {
    let g = genesis();
    let view = context(&g, 63).slot_start().unwrap();
    let selected = view.select().unwrap();
    crate::native_transfer::phase_evidence::reset();
    crate::native_transaction::phase_evidence::reset();
    for (id, ticket, n) in [("trial-A", 1, 2), ("trial-B", 255, 5)] {
        let claim =
            HeaderClaim::new(header(&g, 64, view.parent().hash, id, ticket), id.into(), 0).unwrap();
        let proof = sign(&g, &claim, n);
        assert_eq!(
            proof.public_key(),
            &g.validators()
                .iter()
                .find(|v| v.id == id)
                .unwrap()
                .public_key
        );
        if id == selected.producer() {
            let plan = view.plan(&proof).unwrap();
            assert!(plan.check(&view, &proof).is_ok());
        } else {
            assert_eq!(view.plan(&proof).unwrap_err(), Error::NotSelected);
        }
        assert!(
            claim
                .authenticate(&g, [0; 32], proof.signature_bytes())
                .is_err()
        );
        let mut bad = *proof.signature_bytes();
        bad[64] = 27;
        assert!(claim.authenticate(&g, g.network_id(), &bad).is_err());
    }
    assert_eq!(crate::native_transfer::phase_evidence::stages(), 0);
    assert_eq!(crate::native_transfer::phase_evidence::counts(), (0, 0));
    assert_eq!(crate::native_transaction::phase_evidence::count(), 0);
}

#[test]
fn plan_captures_entire_state_parent_prefix_network_and_exact_claim() {
    let g = genesis();
    let c = context(&g, 32);
    let view = c.slot_start().unwrap();
    let s = view.select().unwrap();
    let n = if s.producer() == "trial-A" { 2 } else { 5 };
    let claim = HeaderClaim::new(
        header(&g, 33, view.parent().hash, s.producer(), s.ticket_id()),
        s.producer().into(),
        0,
    )
    .unwrap();
    let proof = sign(&g, &claim, n);
    let plan = view.plan(&proof).unwrap();
    // A different, still-conserved supplied account allocation at the SAME header changes the
    // exact state identity. It cannot borrow permission from a signature/parent-only check.
    let (h, mut raw) = history(&g, 32);
    raw.accounts[0].balance += 1;
    raw.accounts[1].balance -= 1;
    let changed = PrefixContext::from_trusted_history(
        &g,
        h,
        ClosedState::from_trusted_snapshot(&g, raw).unwrap(),
    )
    .unwrap()
    .slot_start()
    .unwrap();
    assert_eq!(view.parent(), changed.parent());
    assert_ne!(view.id(), changed.id());
    assert_eq!(plan.check(&changed, &proof), Err(Error::PlanMismatch));
    let mut wrong = claim.header().clone();
    wrong.parent_hash = [7; 32];
    let wrong = HeaderClaim::new(wrong, s.producer().into(), 0).unwrap();
    assert!(view.plan(&sign(&g, &wrong, n)).is_err());
    let other = context(&g, 33).slot_start().unwrap();
    assert_eq!(plan.check(&other, &proof), Err(Error::PlanMismatch));
    let mut old = claim.header().clone();
    old.protocol_version = 2;
    assert!(HeaderClaim::new(old, s.producer().into(), 0).is_err());
}

#[test]
fn historical_snapshot_is_not_replaced_by_later_eligibility_or_missing_history() {
    let g = genesis();
    let (h, raw) = history(&g, 63);
    let original = ClosedState::from_trusted_snapshot(&g, raw.clone()).unwrap();
    let old = PrefixContext::from_trusted_history(&g, h.clone(), original)
        .unwrap()
        .slot_start()
        .unwrap();
    let winner = old.select().unwrap();
    let mut later = raw;
    later
        .validators
        .iter_mut()
        .find(|v| v.id == winner.producer())
        .unwrap()
        .status = ValidatorStatus::Inactive;
    for t in &mut later.tickets {
        if t.owner == winner.producer() {
            t.status = TicketStatus::Muted;
            t.bucket = 1;
        }
    }
    let later = ClosedState::from_trusted_snapshot(&g, later).unwrap();
    let new = PrefixContext::from_trusted_history(&g, h.clone(), later.clone())
        .unwrap()
        .slot_start()
        .unwrap();
    assert_ne!(new.select().unwrap().producer(), winner.producer());
    assert_eq!(old.select().unwrap(), winner);
    let mut none = later.input().clone();
    for v in &mut none.validators {
        v.status = ValidatorStatus::Inactive;
    }
    for t in &mut none.tickets {
        t.status = TicketStatus::Muted;
        t.bucket = 1;
    }
    let none = ClosedState::from_trusted_snapshot(&g, none).unwrap();
    let mut gap = h.clone();
    gap.remove(32);
    assert_eq!(
        PrefixContext::from_trusted_history(&g, gap, none.clone()).unwrap_err(),
        Error::MissingHistory(32)
    );
    let none = PrefixContext::from_trusted_history(&g, h, none)
        .unwrap()
        .slot_start()
        .unwrap();
    assert_eq!(none.select(), Err(Error::NoEligibleTickets));
}

#[test]
fn exact_selector_multibucket_unequal_weights_ties_rejection_and_permutations() {
    let g = genesis();
    let vs = &g.initial_state().input().validators;
    // Checked synthetic kernel input, NOT a permitted C1 ticket-creation transition or new genesis.
    let ts = vec![
        Ticket::active(254, "trial-A"),
        Ticket::active(1, "trial-A"),
        Ticket::active(255, "trial-B"),
        Ticket::active(253, "trial-B"),
    ];
    let s = selection::select_inputs([0x44; 32], 42, vs, &ts).unwrap();
    assert_eq!(s.total_tickets(), 4);
    assert_eq!(s.bucket(), 2);
    assert_eq!(s.ticket_id(), 254);
    let mut ts2 = ts.clone();
    ts2.reverse();
    assert_eq!(
        selection::select_inputs([0x44; 32], 42, vs, &ts2).unwrap(),
        s
    );
    assert_eq!(
        selection::draw_with(3, |i| if i == 0 { 0 } else { 1 }).unwrap(),
        (1, 1, 1)
    );
    let score = [4; 32];
    assert_eq!(
        selection::best([(score, 255, "trial-B"), (score, 1, "trial-A")].into_iter())
            .unwrap()
            .1,
        1
    );
    let mut dup = ts;
    dup.push(dup[0].clone());
    assert!(selection::select_inputs([0; 32], 42, vs, &dup).is_err());
}

fn hash_value(v: &serde_json::Value) -> Hash {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}
fn check_selection(s: &Selection, v: &serde_json::Value) {
    assert_eq!(s.slot(), v["slot"].as_u64().unwrap());
    assert_eq!(s.reference(), hash_value(&v["reference"]));
    assert_eq!(s.seed(), hash_value(&v["seed"]));
    assert_eq!(s.total_tickets(), v["total"].as_u64().unwrap());
    assert_eq!(s.bucket() as u64, v["bucket"].as_u64().unwrap());
    assert_eq!(s.retry(), v["retry"].as_u64().unwrap());
    assert_eq!(s.raw(), v["raw"].as_u64().unwrap());
    assert_eq!(s.offset(), v["offset"].as_u64().unwrap());
    assert_eq!(s.producer(), v["producer"].as_str().unwrap());
    assert_eq!(s.ticket_id(), v["ticket"].as_u64().unwrap());
    assert_eq!(s.score(), hash_value(&v["score"]));
}

#[test]
fn independent_genesis_prefix_state_selector_and_authenticated_header_goldens_match() {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/native_poash_eligibility.json"
    ))
    .unwrap();
    let g = genesis();
    let hex_parts = f["genesis"]["hex_parts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect::<String>();
    assert_eq!(g.canonical_bytes(), hex::decode(hex_parts).unwrap());
    assert_eq!(
        g.canonical_bytes().len() as u64,
        f["genesis"]["bytes"].as_u64().unwrap()
    );
    assert_eq!(g.network_id(), hash_value(&f["genesis"]["network_id"]));
    assert_eq!(g.anchor().hash(), hash_value(&f["genesis"]["anchor_hash"]));
    assert_eq!(
        hex::encode(g.anchor().canonical_bytes()),
        f["genesis"]["anchor_header"]
    );
    assert_eq!(
        g.initial_state().id(),
        hash_value(&f["genesis"]["initial_state_id"])
    );
    let (headers, _) = history(&g, 64);
    for (h, v) in headers.iter().zip(f["history_hashes"].as_array().unwrap()) {
        assert_eq!(h.hash(), hash_value(v));
    }
    assert_eq!(headers.len(), f["history_hashes"].as_array().unwrap().len());
    for v in f["cases"].as_array().unwrap() {
        let slot = v["slot"].as_u64().unwrap();
        let c = context(&g, slot - 1);
        let view = c.slot_start().unwrap();
        assert_eq!(view.parent().hash, hash_value(&v["parent"]));
        assert_eq!(
            view.state().canonical_bytes().len() as u64,
            v["state_bytes"].as_u64().unwrap()
        );
        assert_eq!(view.state().id(), hash_value(&v["state_id"]));
        assert_eq!(c.id(), hash_value(&v["prefix_id"]));
        assert_eq!(view.id(), hash_value(&v["view_id"]));
        check_selection(&view.select().unwrap(), &v["selection"]);
        for p in v["proofs"].as_array().unwrap() {
            let h = BlockHeader::from_canonical_bytes(
                &hex::decode(p["header"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
            let claim = HeaderClaim::new(h, p["producer"].as_str().unwrap().into(), 0).unwrap();
            assert_eq!(claim.hash(), hash_value(&p["hash"]));
            assert_eq!(
                hex::encode(claim.signing_preimage(g.network_id())),
                p["preimage"]
            );
            assert_eq!(
                claim.signing_digest(g.network_id()),
                hash_value(&p["digest"])
            );
            let proof = claim
                .authenticate(
                    &g,
                    g.network_id(),
                    &hex::decode(p["signature"].as_str().unwrap()).unwrap(),
                )
                .unwrap();
            assert_eq!(hex::encode(proof.public_key()), p["public_key"]);
            assert_eq!(proof.signing_digest(), hash_value(&p["digest"]));
            if p["selected"] == true {
                view.plan(&proof).unwrap();
            } else {
                assert_eq!(view.plan(&proof).unwrap_err(), Error::NotSelected);
            }
        }
    }
    for v in f["kernels"].as_array().unwrap() {
        let ts: Vec<_> = v["tickets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| Ticket::active(t["id"].as_u64().unwrap(), t["owner"].as_str().unwrap()))
            .collect();
        let s = &v["selection"];
        let selected = selection::select_inputs(
            hash_value(&s["reference"]),
            s["slot"].as_u64().unwrap(),
            &g.initial_state().input().validators,
            &ts,
        )
        .unwrap();
        check_selection(&selected, s);
        for t in ts.iter().filter(|t| t.bucket == selected.bucket()) {
            let mut pre = Vec::from(selected.seed());
            pre.extend_from_slice(&t.id.to_be_bytes());
            assert_eq!(
                crate::block_commitment::hash_with_domain(b"eternix:ticket-selection:v1", &pre),
                hash_value(&s["scores"][t.id.to_string()])
            );
        }
    }
}

#[test]
fn c1_profile_is_separate_and_bad_signature_context_or_header_never_creates_a_plan() {
    let g = genesis();
    let view = context(&g, 30).slot_start().unwrap();
    let choice = view.select().unwrap();
    let n = if choice.producer() == "trial-A" { 2 } else { 5 };
    let claim = HeaderClaim::new(
        header(
            &g,
            31,
            view.parent().hash,
            choice.producer(),
            choice.ticket_id(),
        ),
        choice.producer().into(),
        0,
    )
    .unwrap();
    let proof = sign(&g, &claim, n);
    let mut wrong_pre = claim.signing_preimage(g.network_id());
    wrong_pre[20] = 3;
    wrong_pre[22..26].copy_from_slice(&1u32.to_be_bytes());
    let (sig, id) = key(n)
        .sign_prehash_recoverable(&crate::block_commitment::keccak256(&wrong_pre))
        .unwrap();
    let mut sig = sig.to_bytes().to_vec();
    sig.push(id.to_byte());
    assert_eq!(
        claim.authenticate(&g, g.network_id(), &sig),
        Err(Error::KeyMismatch)
    );
    let mut other = input();
    other.run_id.push('x');
    let other = Genesis::new(other).unwrap();
    assert_eq!(
        claim.authenticate(&other, other.network_id(), proof.signature_bytes()),
        Err(Error::KeyMismatch)
    );
    let ctx =
        crate::native_transaction::AuthenticationContext::new(CHAIN_ID, g.network_id(), 1).unwrap();
    assert!(
        crate::block_authentication::BlockAuthenticationContext::new(
            ctx,
            HEADER_PROFILE,
            AUTH_RULES
        )
        .is_err()
    );
    assert!(
        Genesis::from_bytes(
            &hex::decode(include_str!("../../tests/fixtures/testnet_fixture_genesis.hex").trim())
                .unwrap()
        )
        .is_err()
    );
    for kind in 0..7 {
        let mut h = claim.header().clone();
        let mut count = 0;
        match kind {
            0 => h.block_kind = BlockKind::ProtocolMiss,
            1 => h.state_root = [1; 32],
            2 => h.receipts_root = [2; 32],
            3 => h.gas_used = 1,
            4 => h.transaction_root = [3; 32],
            5 => count = 17,
            _ => h.ticket_id = 0,
        };
        assert!(HeaderClaim::new(h, choice.producer().into(), count).is_err());
    }
    // Populated claims remain plainly incomplete: count/gas/burn commitments can be checked here,
    // but neither these fields nor producer authentication proves a transaction body exists.
    let mut h = claim.header().clone();
    h.gas_used = 16000;
    h.transaction_root = [0x55; 32];
    h.protocol_data_root = (ProtocolData {
        missed_proposer: None,
        fees_burned: 160000,
    })
    .root();
    assert_eq!(
        HeaderClaim::new(h, choice.producer().into(), 16)
            .unwrap()
            .transaction_count(),
        16
    );
}

#[test]
fn prefix_hash_identity_links_order_network_and_ticket_associations_fail_closed() {
    let g = genesis();
    let (h, s) = history(&g, 32);
    let state = ClosedState::from_trusted_snapshot(&g, s).unwrap();
    let mut raw = h[10].header().clone();
    raw.parent_hash = [8; 32];
    let hash = raw.hash();
    let mut broken = h.clone();
    broken[10] = HistoricalHeader::new(raw, hash).unwrap();
    assert_eq!(
        PrefixContext::from_trusted_history(&g, broken, state.clone()).unwrap_err(),
        Error::Context("historical parent link")
    );
    assert!(HistoricalHeader::new(h[10].header().clone(), [0; 32]).is_err());
    let mut order = h.clone();
    order.swap(9, 10);
    assert_eq!(
        PrefixContext::from_trusted_history(&g, order, state.clone()).unwrap_err(),
        Error::MissingHistory(9)
    );
    let mut duplicate = h.clone();
    duplicate[10] = duplicate[9].clone();
    assert_eq!(
        PrefixContext::from_trusted_history(&g, duplicate, state.clone()).unwrap_err(),
        Error::MissingHistory(10)
    );
    let mut extra = h.clone();
    extra.push(h[32].clone());
    assert!(PrefixContext::from_trusted_history(&g, extra, state.clone()).is_err());
    let mut bad = input();
    bad.run_id.push('x');
    let other = Genesis::new(bad).unwrap();
    assert!(PrefixContext::from_trusted_history(&other, h.clone(), state.clone()).is_err());
    let mut raw = h[1].header().clone();
    raw.ticket_id = 99;
    let hash = raw.hash();
    let mut wrong = h;
    wrong[1] = HistoricalHeader::new(raw, hash).unwrap();
    assert!(PrefixContext::from_trusted_history(&g, wrong, state).is_err());
    let mut s = g.initial_state().input().clone();
    s.tickets[0].status = TicketStatus::Dead;
    s.tickets[0].bucket = 0;
    assert_eq!(
        ClosedState::from_trusted_snapshot(&g, s).unwrap_err(),
        Error::State("ACTIVE validator without active ticket")
    );
}
