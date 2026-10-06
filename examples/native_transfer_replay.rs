//! Offline producer/replay demonstration with published toy keys and synthetic input state.
//! It does not start the node, define production genesis, or import any prototype nonce tracker.

use std::collections::BTreeMap;
use std::fmt;

use eternix_testnet::native_transaction::{
    Address, AuthenticationContext, ENCODING_VERSION, NATIVE_RULES_VERSION, TRANSFER_KIND,
    UnsignedTransaction, address_from_public_key, network_id_from_genesis_bytes, sign,
};
use eternix_testnet::native_transfer::{
    AppliedBody, ApplyError, AtomicBodyStore, TransferAccount, TransferState, apply_body,
    stage_body,
};
use k256::ecdsa::SigningKey;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoreError {
    InjectedFailure,
    StaleStoredBase,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "offline memory-store error: {self:?}")
    }
}

impl std::error::Error for StoreError {}

struct MemoryStore {
    snapshot: TransferState,
    records: Vec<AppliedBody>,
    fail_next: bool,
}

impl MemoryStore {
    fn new(initial: &TransferState) -> Self {
        Self {
            snapshot: initial.clone(),
            records: Vec::new(),
            fail_next: false,
        }
    }
}

impl AtomicBodyStore for MemoryStore {
    type Error = StoreError;

    fn persist(
        &mut self,
        expected_base: &TransferState,
        candidate: &TransferState,
        record: &AppliedBody,
    ) -> Result<(), Self::Error> {
        if self.snapshot != *expected_base {
            return Err(StoreError::StaleStoredBase);
        }
        // Prepare both changes first; inject failure before the in-memory atomic commit point.
        // This is an offline transactional sink, not a production disk/database implementation.
        let snapshot = candidate.clone();
        let mut records = self.records.clone();
        records.push(record.clone());
        if std::mem::take(&mut self.fail_next) {
            return Err(StoreError::InjectedFailure);
        }
        self.snapshot = snapshot;
        self.records = records;
        Ok(())
    }
}

fn public_test_key(scalar: u8) -> SigningKey {
    let mut bytes = [0; 32];
    bytes[31] = scalar;
    SigningKey::from_slice(&bytes).expect("published nonzero toy scalar")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let network_id = network_id_from_genesis_bytes(b"ETERNIX_NATIVE_AUTH_VECTOR_GENESIS_V1");
    let context = AuthenticationContext::new(1162, network_id, NATIVE_RULES_VERSION)?;
    let alice_key = public_test_key(1);
    let bob_key = public_test_key(2);
    let alice = address_from_public_key(alice_key.verifying_key());
    let bob = address_from_public_key(bob_key.verifying_key());
    let carol: Address = [0x33; 20];
    // Synthetic trusted input snapshot, not an allocation inferred from the opaque test genesis.
    let initial = TransferState::new(
        BTreeMap::from([(
            alice,
            TransferAccount {
                balance_quarks: 100_000,
                nonce: 0,
            },
        )]),
        0,
        0,
    );
    let mut body = Vec::new();
    for (key, recipient, nonce, value, gas_limit, valid_after_slot) in [
        (&alice_key, bob, 0, 30_000, 1000, 12),
        (&bob_key, carol, 0, 5000, 1001, 13),
        (&alice_key, alice, 1, 20_000, u64::MAX, 14),
        (&alice_key, carol, 2, 0, 1000, 15),
    ] {
        let unsigned = UnsignedTransaction {
            encoding_version: ENCODING_VERSION,
            native_rules_version: NATIVE_RULES_VERSION,
            chain_id: 1162,
            network_id,
            kind: TRANSFER_KIND,
            sender: address_from_public_key(key.verifying_key()),
            nonce,
            recipient,
            token_id: 0,
            value,
            gas_limit,
            valid_after_slot,
        };
        body.push(sign(unsigned, key, &context)?.canonical_bytes()?.to_vec());
    }
    // Neither application actor needs a wallet once the exact signed bytes are available.
    drop(alice_key);
    drop(bob_key);
    let mut producer = initial.clone();
    let mut receiver = initial.clone();
    let mut producer_store = MemoryStore::new(&initial);
    let mut receiver_store = MemoryStore::new(&initial);
    let mut producer_mempool = body.clone();
    let receiver_mempool = [vec![0xff], body[0].clone()];
    let producer_pending_nonces = BTreeMap::from([(alice, 900_u64)]);
    let receiver_pending_nonces = BTreeMap::from([(alice, 42_u64)]);

    let staged = stage_body(&producer, &context, 15, &body)?;
    assert_eq!(producer, initial);
    let produced = staged.commit(&mut producer, &mut producer_store)?;
    // Pool bookkeeping is local and only runs after successful commit; canonical nonce is separate.
    producer_mempool.retain(|queued| !body.contains(queued));
    let replayed = apply_body(&mut receiver, &context, 15, &body, &mut receiver_store)?;
    assert_eq!(producer, receiver);
    assert_eq!(produced, replayed);
    assert_eq!(producer_store.records, receiver_store.records);
    assert_eq!(
        producer.account(&alice),
        TransferAccount {
            balance_quarks: 40_000,
            nonce: 3
        }
    );
    assert_eq!(
        producer.account(&bob),
        TransferAccount {
            balance_quarks: 15_000,
            nonce: 1
        }
    );
    assert_eq!(
        producer.account(&carol),
        TransferAccount {
            balance_quarks: 5000,
            nonce: 0
        }
    );
    assert_eq!((produced.gas_used, produced.fees_burned), (4000, 40_000));
    assert!(producer_mempool.is_empty());
    assert_eq!(receiver_mempool.len(), 2);
    assert_eq!(producer_pending_nonces[&alice], 900);
    assert_eq!(receiver_pending_nonces[&alice], 42);

    // A later maturity failure would follow three successful staged entries, but publishes none.
    let mut invalid_receiver = initial.clone();
    let mut invalid_store = MemoryStore::new(&initial);
    assert!(matches!(
        apply_body(
            &mut invalid_receiver,
            &context,
            14,
            &body,
            &mut invalid_store
        ),
        Err(ApplyError::Body(_))
    ));
    assert_eq!(invalid_receiver, initial);
    assert_eq!(invalid_store.snapshot, initial);
    assert!(invalid_store.records.is_empty());

    let mut failed_receiver = initial.clone();
    let mut failed_store = MemoryStore::new(&initial);
    failed_store.fail_next = true;
    assert!(matches!(
        apply_body(&mut failed_receiver, &context, 15, &body, &mut failed_store),
        Err(ApplyError::Persistence(StoreError::InjectedFailure))
    ));
    assert_eq!(failed_receiver, initial);
    assert_eq!(failed_store.snapshot, initial);
    assert!(failed_store.records.is_empty());

    let before_duplicate = receiver.clone();
    assert!(apply_body(&mut receiver, &context, 16, &body, &mut receiver_store).is_err());
    assert_eq!(receiver, before_duplicate);
    assert_eq!(receiver_store.records.len(), 1);

    println!("offline_producer_replay_state_equal=true");
    println!("signed_body_bytes_equal=true");
    println!("gas_used={}", produced.gas_used);
    println!("fees_burned_quarks={}", produced.fees_burned);
    println!(
        "canonical_nonces=alice:{},bob:{}",
        producer.account(&alice).nonce,
        producer.account(&bob).nonce
    );
    println!("wallet_and_mempool_independent=true");
    println!("later_invalid_transaction_rollback=true");
    println!("persistence_failure_rollback=true");
    println!("duplicate_application_rejected=true");
    Ok(())
}
