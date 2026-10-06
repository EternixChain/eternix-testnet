//! Offline synthetic snapshots and published toy keys only; no live node, genesis allocation,
//! mempool admission, or prototype nonce-tracker conversion is used by these regressions.

use super::*;
use crate::native_transaction::{
    ENCODING_VERSION, NATIVE_RULES_VERSION, NativeSignature, SignedTransaction,
    UnsignedTransaction, address_from_public_key, network_id_from_genesis_bytes, sign,
};
use k256::ecdsa::SigningKey;

fn context() -> AuthenticationContext {
    AuthenticationContext::new(
        1162,
        network_id_from_genesis_bytes(b"ETERNIX_NATIVE_AUTH_VECTOR_GENESIS_V1"),
        NATIVE_RULES_VERSION,
    )
    .unwrap()
}

fn public_test_key(scalar: u8) -> SigningKey {
    let mut bytes = [0; 32];
    bytes[31] = scalar;
    SigningKey::from_slice(&bytes).unwrap()
}

fn alice() -> Address {
    address_from_public_key(public_test_key(1).verifying_key())
}

fn bob() -> Address {
    address_from_public_key(public_test_key(2).verifying_key())
}

fn carol() -> Address {
    [0x33; 20]
}

fn state(balance: u128, nonce: u64) -> TransferState {
    TransferState::new(
        BTreeMap::from([(
            alice(),
            TransferAccount {
                balance_quarks: balance,
                nonce,
            },
        )]),
        0,
        0,
    )
}

fn transaction(
    key: &SigningKey,
    recipient: Address,
    nonce: u64,
    value: u128,
    gas_limit: u64,
    valid_after_slot: u64,
) -> Vec<u8> {
    let unsigned = UnsignedTransaction {
        encoding_version: ENCODING_VERSION,
        native_rules_version: NATIVE_RULES_VERSION,
        chain_id: 1162,
        network_id: network_id_from_genesis_bytes(b"ETERNIX_NATIVE_AUTH_VECTOR_GENESIS_V1"),
        kind: TRANSFER_KIND,
        sender: address_from_public_key(key.verifying_key()),
        nonce,
        recipient,
        token_id: ETX_TOKEN_ID,
        value,
        gas_limit,
        valid_after_slot,
    };
    sign(unsigned, key, &context())
        .unwrap()
        .canonical_bytes()
        .unwrap()
        .to_vec()
}

fn body() -> Vec<Vec<u8>> {
    vec![
        transaction(&public_test_key(1), bob(), 0, 30_000, 1000, 12),
        transaction(&public_test_key(2), carol(), 0, 5000, 1001, 13),
        transaction(&public_test_key(1), alice(), 1, 20_000, u64::MAX, 14),
        transaction(&public_test_key(1), carol(), 2, 0, 1000, 15),
    ]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoreError {
    Injected,
    WrongBase,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "offline test store error: {self:?}")
    }
}

impl std::error::Error for StoreError {}

struct TestStore {
    state: TransferState,
    records: Vec<AppliedBody>,
    calls: usize,
    fail_next: bool,
}

impl TestStore {
    fn new(initial: &TransferState) -> Self {
        Self {
            state: initial.clone(),
            records: Vec::new(),
            calls: 0,
            fail_next: false,
        }
    }
}

impl AtomicBodyStore for TestStore {
    type Error = StoreError;

    fn persist(
        &mut self,
        expected_base: &TransferState,
        candidate: &TransferState,
        record: &AppliedBody,
    ) -> Result<(), Self::Error> {
        self.calls += 1;
        if self.state != *expected_base {
            return Err(StoreError::WrongBase);
        }
        // Fully prepare the pending storage update before the injected commit-point failure.
        // Neither the committed snapshot nor body records are modified on Err.
        let next_state = candidate.clone();
        let mut next_records = self.records.clone();
        next_records.push(record.clone());
        if std::mem::take(&mut self.fail_next) {
            return Err(StoreError::Injected);
        }
        self.state = next_state;
        self.records = next_records;
        Ok(())
    }
}

fn expected_transaction_error(index: usize, cause: TransferError) -> ApplyError<StoreError> {
    ApplyError::Body(BodyError {
        transaction_index: index,
        cause,
    })
}

#[test]
fn producer_and_keyless_replay_match_state_outcomes_and_exact_body() {
    let initial = state(100_000, 0);
    let signed_body = body();
    let mut producer = initial.clone();
    let mut receiver = initial.clone();
    let mut producer_store = TestStore::new(&initial);
    let mut receiver_store = TestStore::new(&initial);
    // Deliberately unrelated local caches are not inputs to shared application or canonical nonces.
    let producer_pending = BTreeMap::from([(alice(), 900_u64)]);
    let receiver_pending = BTreeMap::from([(alice(), 42_u64)]);
    let mut producer_pool = signed_body.clone();
    let receiver_pool = vec![vec![0xff], signed_body[0].clone()];
    assert_ne!(producer_pool, receiver_pool);
    assert_ne!(producer_pending, receiver_pending);

    // Producer preparation executes on an overlay, never canonically before the shared commit.
    let staged = stage_body(&producer, &context(), 15, &signed_body).unwrap();
    assert_eq!(producer, initial);
    let producer_outcome = staged.commit(&mut producer, &mut producer_store).unwrap();
    producer_pool.retain(|queued| !signed_body.contains(queued));
    let receiver_outcome = apply_body(
        &mut receiver,
        &context(),
        15,
        &signed_body,
        &mut receiver_store,
    )
    .unwrap();

    assert_eq!(producer, receiver);
    assert_eq!(producer_outcome, receiver_outcome);
    assert_eq!(producer_store.state, producer);
    assert_eq!(receiver_store.state, receiver);
    assert_eq!(producer_store.records, receiver_store.records);
    assert_eq!(
        producer_store.records[0].transactions,
        signed_body
            .iter()
            .map(|bytes| bytes.as_slice().try_into().unwrap())
            .collect::<Vec<[u8; 199]>>()
    );
    assert_eq!(
        producer.account(&alice()),
        TransferAccount {
            balance_quarks: 40_000,
            nonce: 3
        }
    );
    assert_eq!(
        producer.account(&bob()),
        TransferAccount {
            balance_quarks: 15_000,
            nonce: 1
        }
    );
    assert_eq!(
        producer.account(&carol()),
        TransferAccount {
            balance_quarks: 5000,
            nonce: 0
        }
    );
    assert_eq!(producer.gas_used_total(), 4000);
    assert_eq!(producer.fees_burned_total(), 40_000);
    assert_eq!(producer_outcome.gas_used, 4000);
    assert_eq!(producer_outcome.fees_burned, 40_000);
    assert_eq!(producer_outcome.transaction_ids.len(), 4);
    assert!(producer_pool.is_empty());
    assert_eq!(receiver_pool.len(), 2);
    assert_eq!(producer_pending[&alice()], 900);
    assert_eq!(receiver_pending[&alice()], 42);
}

#[test]
fn body_order_is_required_for_funding_and_same_sender_nonces() {
    let initial = state(100_000, 0);
    let mut reversed = body();
    reversed.swap(0, 1); // Bob cannot spend before Alice's preceding funding transfer.
    let mut live = initial.clone();
    let mut store = TestStore::new(&initial);
    assert_eq!(
        apply_body(&mut live, &context(), 15, &reversed, &mut store),
        Err(expected_transaction_error(
            0,
            TransferError::InsufficientCombinedFunds {
                available: 0,
                required: 15_000
            }
        ))
    );
    assert_eq!(live, initial);
    assert_eq!(store.calls, 0);

    let mut wrong_nonce_order = body();
    wrong_nonce_order.swap(2, 3);
    assert_eq!(
        apply_body(&mut live, &context(), 15, &wrong_nonce_order, &mut store),
        Err(expected_transaction_error(
            2,
            TransferError::NonceMismatch {
                expected: 1,
                actual: 2
            }
        ))
    );
    assert_eq!(live, initial);
    assert_eq!(store.calls, 0);
}

#[test]
fn self_transfer_uses_one_record_and_still_requires_full_combined_funding() {
    let initial = state(40_000, 7);
    let mut live = initial.clone();
    let mut store = TestStore::new(&initial);
    let signed = vec![transaction(
        &public_test_key(1),
        alice(),
        7,
        30_000,
        u64::MAX,
        0,
    )];
    let outcome = apply_body(&mut live, &context(), 0, &signed, &mut store).unwrap();
    assert_eq!(
        live.account(&alice()),
        TransferAccount {
            balance_quarks: 30_000,
            nonce: 8
        }
    );
    assert_eq!(live.accounts().len(), 1);
    assert_eq!((outcome.gas_used, outcome.fees_burned), (1000, 10_000));

    let initial = state(10_000, 0);
    let mut live = initial.clone();
    let mut store = TestStore::new(&initial);
    let signed = vec![transaction(&public_test_key(1), alice(), 0, 1, 1000, 0)];
    assert_eq!(
        apply_body(&mut live, &context(), 0, &signed, &mut store),
        Err(expected_transaction_error(
            0,
            TransferError::InsufficientCombinedFunds {
                available: 10_000,
                required: 10_001
            }
        ))
    );
    assert_eq!(live, initial);
    assert_eq!(store.calls, 0);
}

#[test]
fn zero_value_charges_the_fixed_fee_and_preserves_recipient_state() {
    for recipient in [alice(), bob()] {
        let initial = state(10_000, 0);
        let mut live = initial.clone();
        let mut store = TestStore::new(&initial);
        let signed = vec![transaction(&public_test_key(1), recipient, 0, 0, 1001, 0)];
        apply_body(&mut live, &context(), 0, &signed, &mut store).unwrap();
        assert_eq!(
            live.account(&alice()),
            TransferAccount {
                balance_quarks: 0,
                nonce: 1
            }
        );
        assert_eq!(live.accounts().len(), 1);
        assert_eq!(live.gas_used_total(), 1000);
        assert_eq!(live.fees_burned_total(), 10_000);
    }
}

#[test]
fn maturity_is_inclusive_and_uses_only_the_supplied_slot() {
    let initial = state(10_000, 0);
    for slot in [9, 10, 11, u64::MAX] {
        let mut live = initial.clone();
        let mut store = TestStore::new(&initial);
        let signed = vec![transaction(&public_test_key(1), bob(), 0, 0, 1000, 10)];
        let result = apply_body(&mut live, &context(), slot, &signed, &mut store);
        if slot < 10 {
            assert_eq!(
                result,
                Err(expected_transaction_error(
                    0,
                    TransferError::NotMature {
                        slot,
                        valid_after_slot: 10
                    }
                ))
            );
            assert_eq!(live, initial);
            assert_eq!(store.calls, 0);
        } else {
            assert!(result.is_ok());
            assert_eq!(live.account(&alice()).nonce, 1);
        }
    }
}

#[test]
fn stale_and_future_nonces_are_not_includable() {
    let initial = state(100_000, 3);
    for nonce in [2, 4] {
        let mut live = initial.clone();
        let mut store = TestStore::new(&initial);
        let signed = vec![transaction(&public_test_key(1), bob(), nonce, 0, 1000, 0)];
        assert_eq!(
            apply_body(&mut live, &context(), 0, &signed, &mut store),
            Err(expected_transaction_error(
                0,
                TransferError::NonceMismatch {
                    expected: 3,
                    actual: nonce
                }
            ))
        );
        assert_eq!(live, initial);
        assert_eq!(store.calls, 0);
    }
}

#[test]
fn insufficient_combined_funds_and_missing_sender_have_no_effects() {
    for initial in [state(10_000, 0), TransferState::default()] {
        let mut live = initial.clone();
        let mut store = TestStore::new(&initial);
        let signed = vec![transaction(&public_test_key(1), bob(), 0, 100, 1000, 0)];
        assert_eq!(
            apply_body(&mut live, &context(), 0, &signed, &mut store),
            Err(expected_transaction_error(
                0,
                TransferError::InsufficientCombinedFunds {
                    available: initial.account(&alice()).balance_quarks,
                    required: 10_100
                }
            ))
        );
        assert_eq!(live, initial);
        assert_eq!(store.calls, 0);
    }
}

#[test]
fn later_invalid_transaction_discards_all_earlier_staged_effects() {
    let initial = state(100_000, 0);
    let mut bad_body = body();
    bad_body.push(transaction(&public_test_key(1), bob(), 3, 40_000, 1000, 15));
    let mut live = initial.clone();
    let mut store = TestStore::new(&initial);
    assert_eq!(
        apply_body(&mut live, &context(), 15, &bad_body, &mut store),
        Err(expected_transaction_error(
            4,
            TransferError::InsufficientCombinedFunds {
                available: 40_000,
                required: 50_000
            }
        ))
    );
    assert_eq!(live, initial);
    assert_eq!(store.state, initial);
    assert!(store.records.is_empty());
    assert_eq!(store.calls, 0);
}

#[test]
fn later_maturity_failure_discards_successful_predecessors() {
    let initial = state(100_000, 0);
    let mut live = initial.clone();
    let mut store = TestStore::new(&initial);
    assert_eq!(
        apply_body(&mut live, &context(), 14, &body(), &mut store),
        Err(expected_transaction_error(
            3,
            TransferError::NotMature {
                slot: 14,
                valid_after_slot: 15
            }
        ))
    );
    assert_eq!(live, initial);
    assert_eq!(store.calls, 0);
}

#[test]
fn persistence_failure_discards_complete_execution_and_retry_applies_once() {
    let initial = state(100_000, 0);
    let signed_body = body();
    let mut live = initial.clone();
    let mut store = TestStore::new(&initial);
    let staged = stage_body(&live, &context(), 15, &signed_body).unwrap();
    assert_eq!(staged.candidate().account(&alice()).nonce, 3);
    assert_eq!(staged.candidate().fees_burned_total(), 40_000);
    assert_eq!(live, initial);
    store.fail_next = true;
    assert_eq!(
        staged.commit(&mut live, &mut store),
        Err(ApplyError::Persistence(StoreError::Injected))
    );
    assert_eq!(live, initial);
    assert_eq!(store.state, initial);
    assert!(store.records.is_empty());
    assert_eq!(store.calls, 1);

    apply_body(&mut live, &context(), 15, &signed_body, &mut store).unwrap();
    assert_eq!(live.account(&alice()).nonce, 3);
    assert_eq!(live.fees_burned_total(), 40_000);
    assert_eq!(live.gas_used_total(), 4000);
    assert_eq!(store.state, live);
    assert_eq!(store.records.len(), 1);
}

#[test]
fn duplicate_body_and_duplicate_entry_cannot_charge_again() {
    let initial = state(100_000, 0);
    let signed_body = body();
    let mut live = initial.clone();
    let mut store = TestStore::new(&initial);
    apply_body(&mut live, &context(), 15, &signed_body, &mut store).unwrap();
    let before = live.clone();
    let records = store.records.clone();
    assert_eq!(
        apply_body(&mut live, &context(), 16, &signed_body, &mut store),
        Err(expected_transaction_error(
            0,
            TransferError::NonceMismatch {
                expected: 3,
                actual: 0
            }
        ))
    );
    assert_eq!(live, before);
    assert_eq!(store.records, records);
    assert_eq!(store.calls, 1);

    let mut live = initial.clone();
    let mut store = TestStore::new(&initial);
    let duplicated = vec![signed_body[0].clone(), signed_body[0].clone()];
    assert_eq!(
        apply_body(&mut live, &context(), 15, &duplicated, &mut store),
        Err(expected_transaction_error(
            1,
            TransferError::NonceMismatch {
                expected: 1,
                actual: 0
            }
        ))
    );
    assert_eq!(live, initial);
    assert!(store.records.is_empty());
}

#[test]
fn stale_prepared_overlay_cannot_overwrite_intervening_commit() {
    let initial = state(100_000, 0);
    let signed = vec![transaction(&public_test_key(1), bob(), 0, 1, 1000, 0)];
    let staged = stage_body(&initial, &context(), 0, &signed).unwrap();
    let mut live = initial.clone();
    let mut store = TestStore::new(&initial);
    apply_body(&mut live, &context(), 0, &signed, &mut store).unwrap();
    let before = live.clone();
    assert_eq!(
        staged.commit(&mut live, &mut store),
        Err(ApplyError::StaleBase)
    );
    assert_eq!(live, before);
    assert_eq!(store.calls, 1);
}

#[test]
fn combined_debit_and_recipient_overflow_roll_back() {
    let initial = state(u128::MAX, 0);
    let mut live = initial.clone();
    let mut store = TestStore::new(&initial);
    let signed = vec![transaction(
        &public_test_key(1),
        bob(),
        0,
        u128::MAX,
        1000,
        0,
    )];
    assert_eq!(
        apply_body(&mut live, &context(), 0, &signed, &mut store),
        Err(expected_transaction_error(
            0,
            TransferError::Overflow(ArithmeticField::CombinedDebit)
        ))
    );
    assert_eq!(live, initial);

    let mut accounts = state(100_000, 0).accounts().clone();
    accounts.insert(
        bob(),
        TransferAccount {
            balance_quarks: u128::MAX,
            nonce: 41,
        },
    );
    let initial = TransferState::new(accounts, 0, 0);
    let mut live = initial.clone();
    let mut store = TestStore::new(&initial);
    let signed = vec![transaction(&public_test_key(1), bob(), 0, 1, 1000, 0)];
    assert_eq!(
        apply_body(&mut live, &context(), 0, &signed, &mut store),
        Err(expected_transaction_error(
            0,
            TransferError::Overflow(ArithmeticField::RecipientBalance)
        ))
    );
    assert_eq!(live, initial);
    assert_eq!(store.calls, 0);
}

#[test]
fn self_transfer_at_max_balance_does_not_credit_a_stale_copy() {
    let initial = state(u128::MAX, 0);
    let mut live = initial.clone();
    let mut store = TestStore::new(&initial);
    let signed = vec![transaction(
        &public_test_key(1),
        alice(),
        0,
        u128::MAX - 10_000,
        1000,
        0,
    )];
    apply_body(&mut live, &context(), 0, &signed, &mut store).unwrap();
    assert_eq!(
        live.account(&alice()),
        TransferAccount {
            balance_quarks: u128::MAX - 10_000,
            nonce: 1
        }
    );
}

#[test]
fn cumulative_accounting_overflow_discards_prior_entries() {
    for (gas, burn, field) in [
        (u64::MAX - 1000, 0, ArithmeticField::TotalGas),
        (0, u128::MAX - 10_000, ArithmeticField::TotalBurn),
    ] {
        let initial = TransferState::new(state(20_000, 0).accounts().clone(), gas, burn);
        let mut live = initial.clone();
        let mut store = TestStore::new(&initial);
        let signed = vec![
            transaction(&public_test_key(1), bob(), 0, 0, 1000, 0),
            transaction(&public_test_key(1), bob(), 1, 0, 1000, 0),
        ];
        assert_eq!(
            apply_body(&mut live, &context(), 0, &signed, &mut store),
            Err(expected_transaction_error(
                1,
                TransferError::Overflow(field)
            ))
        );
        assert_eq!(live, initial);
        assert_eq!(store.state, initial);
        assert_eq!(store.calls, 0);
    }
}

fn negative_fixture_body(vector_index: usize) -> Vec<u8> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/native_auth_v2.json")).unwrap();
    assert_eq!(fixture["test_only"], true);
    let vector = &fixture["vectors"][vector_index];
    let mut unsigned = UnsignedTransaction::from_canonical_bytes(
        &hex::decode(fixture["unsigned_bytes"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    unsigned.nonce = vector["nonce"].as_str().unwrap().parse().unwrap();
    unsigned.token_id = vector["token_id"].as_str().unwrap().parse().unwrap();
    unsigned.gas_limit = vector["gas_limit"].as_str().unwrap().parse().unwrap();
    let signature =
        NativeSignature::from_bytes(&hex::decode(vector["signature"].as_str().unwrap()).unwrap())
            .unwrap();
    SignedTransaction::from_parts(unsigned, signature)
        .unwrap()
        .canonical_bytes()
        .unwrap()
        .to_vec()
}

#[test]
fn nonce_exhaustion_never_wraps_or_resets_the_account() {
    let initial = state(10_000, u64::MAX - 1);
    let mut live = initial.clone();
    let mut store = TestStore::new(&initial);
    let signed = vec![transaction(
        &public_test_key(1),
        bob(),
        u64::MAX - 1,
        0,
        1000,
        0,
    )];
    apply_body(&mut live, &context(), 0, &signed, &mut store).unwrap();
    assert_eq!(live.account(&alice()).nonce, u64::MAX);
    let before = live.clone();
    let exhausted = vec![negative_fixture_body(4)];
    assert_eq!(
        apply_body(&mut live, &context(), 0, &exhausted, &mut store),
        Err(expected_transaction_error(
            0,
            TransferError::Authentication(native_transaction::Error::NonceExhausted)
        ))
    );
    assert_eq!(live, before);
    assert_eq!(store.calls, 1);
}

#[test]
fn unsupported_asset_gas_and_kind_are_explicitly_rejected() {
    for (index, error) in [
        (2, native_transaction::Error::GasBelowIntrinsic(999)),
        (3, native_transaction::Error::UnsupportedToken(1)),
    ] {
        let initial = state(100_000, 0);
        let mut live = initial.clone();
        let mut store = TestStore::new(&initial);
        assert_eq!(
            apply_body(
                &mut live,
                &context(),
                0,
                &[negative_fixture_body(index)],
                &mut store
            ),
            Err(expected_transaction_error(
                0,
                TransferError::Authentication(error)
            ))
        );
        assert_eq!(live, initial);
        assert_eq!(store.calls, 0);
    }
    for kind in [1, 2, 3, 0x10, 0x11, 0x12, 0x13, 0x14, 0xff] {
        let initial = state(100_000, 0);
        let mut live = initial.clone();
        let mut store = TestStore::new(&initial);
        let mut signed = body()[0].clone();
        signed[45] = kind;
        assert_eq!(
            apply_body(&mut live, &context(), 15, &[signed], &mut store),
            Err(expected_transaction_error(
                0,
                TransferError::Authentication(native_transaction::Error::UnsupportedKind(kind))
            ))
        );
        assert_eq!(live, initial);
        assert_eq!(store.calls, 0);
    }
}

#[test]
fn later_tampered_bytes_are_rejected_before_any_execution_or_persistence() {
    let initial = state(100_000, 0);
    let mut live = initial.clone();
    let mut store = TestStore::new(&initial);
    let mut signed = body();
    signed[3][117] ^= 1; // Modify signed value, retaining the original signature.
    assert_eq!(
        apply_body(&mut live, &context(), 15, &signed, &mut store),
        Err(expected_transaction_error(
            3,
            TransferError::Authentication(native_transaction::Error::SenderMismatch)
        ))
    );
    assert_eq!(live, initial);
    assert_eq!(store.calls, 0);

    signed[3] = vec![0; 198];
    assert_eq!(
        apply_body(&mut live, &context(), 15, &signed, &mut store),
        Err(expected_transaction_error(
            3,
            TransferError::Authentication(native_transaction::Error::InvalidLength {
                expected: 199,
                actual: 198
            })
        ))
    );
    assert_eq!(live, initial);
}

#[test]
fn replay_from_archived_bytes_and_initial_snapshot_needs_no_wallet() {
    let initial = state(100_000, 0);
    let mut producer = initial.clone();
    let mut producer_store = TestStore::new(&initial);
    apply_body(&mut producer, &context(), 15, &body(), &mut producer_store).unwrap();
    let archive = producer_store.records.clone();
    let mut restarted = initial.clone();
    let mut restarted_store = TestStore::new(&initial);
    for record in &archive {
        let exact_body = record
            .transactions
            .iter()
            .map(|bytes| bytes.to_vec())
            .collect::<Vec<_>>();
        let outcome = apply_body(
            &mut restarted,
            &record.context,
            record.slot,
            &exact_body,
            &mut restarted_store,
        )
        .unwrap();
        assert_eq!(outcome, record.outcome);
    }
    assert_eq!(restarted, producer);
    assert_eq!(restarted_store.records, archive);
}

#[test]
fn empty_body_has_no_canonical_account_or_accounting_effects() {
    let initial = state(100_000, 7);
    let mut live = initial.clone();
    let mut store = TestStore::new(&initial);
    let outcome = apply_body(&mut live, &context(), 42, &[], &mut store).unwrap();
    assert_eq!(outcome, BodyOutcome::default());
    assert_eq!(live, initial);
    assert_eq!(store.state, initial);
}

#[test]
fn different_signed_ids_cannot_bypass_the_same_canonical_nonce() {
    let initial = state(100_000, 0);
    let first = transaction(&public_test_key(1), bob(), 0, 1, 1000, 0);
    let second = transaction(&public_test_key(1), bob(), 0, 2, 1001, 0);
    assert_ne!(
        SignedTransaction::from_canonical_bytes(&first)
            .unwrap()
            .transaction_id()
            .unwrap(),
        SignedTransaction::from_canonical_bytes(&second)
            .unwrap()
            .transaction_id()
            .unwrap()
    );
    let mut live = initial.clone();
    let mut store = TestStore::new(&initial);
    assert_eq!(
        apply_body(&mut live, &context(), 0, &[first, second], &mut store),
        Err(expected_transaction_error(
            1,
            TransferError::NonceMismatch {
                expected: 1,
                actual: 0
            }
        ))
    );
    assert_eq!(live, initial);
    assert_eq!(store.calls, 0);
}

#[test]
fn recipient_credit_preserves_its_committed_nonce() {
    let mut accounts = state(100_000, 0).accounts().clone();
    accounts.insert(
        bob(),
        TransferAccount {
            balance_quarks: 5,
            nonce: 37,
        },
    );
    let initial = TransferState::new(accounts, 0, 0);
    let mut live = initial.clone();
    let mut store = TestStore::new(&initial);
    let signed = vec![transaction(&public_test_key(1), bob(), 0, 100, 1000, 0)];
    apply_body(&mut live, &context(), 0, &signed, &mut store).unwrap();
    assert_eq!(
        live.account(&bob()),
        TransferAccount {
            balance_quarks: 105,
            nonce: 37
        }
    );
    assert_eq!(
        live.account(&alice()),
        TransferAccount {
            balance_quarks: 89_900,
            nonce: 1
        }
    );
}

#[test]
fn persistence_failure_preserves_existing_committed_history() {
    let initial = state(100_000, 0);
    let mut live = initial.clone();
    let mut store = TestStore::new(&initial);
    apply_body(&mut live, &context(), 15, &body(), &mut store).unwrap();
    let before = live.clone();
    let records = store.records.clone();
    store.fail_next = true;
    let next = vec![transaction(&public_test_key(1), bob(), 3, 0, 1000, 0)];
    assert_eq!(
        apply_body(&mut live, &context(), 16, &next, &mut store),
        Err(ApplyError::Persistence(StoreError::Injected))
    );
    assert_eq!(live, before);
    assert_eq!(store.state, before);
    assert_eq!(store.records, records);
}
