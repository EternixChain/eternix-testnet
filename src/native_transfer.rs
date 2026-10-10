//! Shared native V2 primitive-transfer application for offline producer/replay only.
//!
//! This is an ETX account/accounting projection, not the prototype ProtocolState or an activated
//! production state/storage format. No wallet key, pending nonce tracker, mempool, wall clock,
//! validator operation, V1 transaction, block identity, state root, or reorg rule enters application.

use std::collections::BTreeMap;
use std::fmt;

// Test-only phase evidence: count calls, not inferred flags, without changing execution/profile
// decisions. Thread-local counters isolate parallel tests and are absent from production builds.
#[cfg(test)]
pub(crate) mod phase_evidence {
    use std::cell::Cell;
    thread_local! { static COUNTS: Cell<(usize, usize)> = const { Cell::new((0, 0)) }; }
    pub(crate) fn reset() {
        COUNTS.set((0, 0));
    }
    pub(crate) fn counts() -> (usize, usize) {
        COUNTS.get()
    }
    pub(super) fn authentication() {
        let (a, e) = COUNTS.get();
        COUNTS.set((a + 1, e));
    }
    pub(super) fn execution() {
        let (a, e) = COUNTS.get();
        COUNTS.set((a, e + 1));
    }
}

use crate::native_transaction::{
    self, Address, AuthenticatedTransaction, AuthenticationContext, ETX_TOKEN_ID, Hash,
    INTRINSIC_GAS, SIGNED_LEN, TRANSFER_FEE_QUARKS, TRANSFER_KIND, authenticate,
};

/// Canonical ETX account fields only; absence reads as zero balance and initial nonce zero.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransferAccount {
    /// Spendable ETX in quarks, not a fee bid, floating-point display amount, or validator vault.
    pub balance_quarks: u128,
    /// Committed account nonce, never a pending/admission reservation.
    pub nonce: u64,
}

/// Owned offline canonical account projection with committed accounting totals.
///
/// These Rust values have no newly prescribed wire/storage encoding or state-root hash. BTreeMap
/// makes snapshots and diagnostics deterministic; execution uses lookup and exact body order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TransferState {
    accounts: BTreeMap<Address, TransferAccount>,
    gas_used_total: u64,
    fees_burned_total: u128,
}

impl TransferState {
    /// Accepts an explicit trusted input snapshot, without reading genesis or converting V1 state.
    pub fn new(
        accounts: BTreeMap<Address, TransferAccount>,
        gas_used_total: u64,
        fees_burned_total: u128,
    ) -> Self {
        Self {
            accounts,
            gas_used_total,
            fees_burned_total,
        }
    }

    /// Reads an existing account or its specified zero/default value without materializing it.
    pub fn account(&self, address: &Address) -> TransferAccount {
        self.accounts.get(address).copied().unwrap_or_default()
    }

    /// Read-only ordered account snapshot; no wallet or pending-nonce metadata is present.
    pub fn accounts(&self) -> &BTreeMap<Address, TransferAccount> {
        &self.accounts
    }

    /// Committed gas accounted by this offline projection, not the sum of declared gas limits.
    pub fn gas_used_total(&self) -> u64 {
        self.gas_used_total
    }

    /// Committed ETX fee burns; this does not include issuance or ticket/validator operations.
    pub fn fees_burned_total(&self) -> u128 {
        self.fees_burned_total
    }
}

/// Complete successful body effects, returned only after atomic installation by apply_body.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BodyOutcome {
    /// Content-derived native IDs in exact body order, without a new block/receipt hash scheme.
    pub transaction_ids: Vec<Hash>,
    /// Actual gas, exactly 1,000 per successful primitive transfer.
    pub gas_used: u64,
    /// ETX burned, exactly 10,000 quarks per successful primitive transfer.
    pub fees_burned: u64,
}

/// Checked-arithmetic locations distinguish malformed exposure from accounting/credit overflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArithmeticField {
    /// Full value-plus-fee exposure must be representable, including for self-transfers.
    CombinedDebit,
    /// Destination balance must not wrap; self-credit uses the already-debited record.
    RecipientBalance,
    /// Canonical nonce must never wrap back to zero.
    Nonce,
    /// Offline committed gas accounting must not clip or wrap.
    TotalGas,
    /// Committed ETX burn accounting must not clip or wrap.
    TotalBurn,
    /// Body actual gas is represented as u64 for later explicit block integration.
    BodyGas,
    /// Body burns are represented as u64, matching the existing protocol-data field width.
    BodyBurn,
}

/// A single invalid entry invalidates the entire body; there is no skip/revert/partial acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransferError {
    /// Exact bytes failed native authentication or its supported stateless profile.
    Authentication(native_transaction::Error),
    /// No non-transfer operation can inherit primitive-transfer execution.
    UnsupportedKind(u8),
    /// No FCT, reserved, or unknown asset semantics are implemented here.
    UnsupportedAsset(u64),
    /// This executor supports rules 1 only, independently of future authentication extensions.
    UnsupportedRules(u32),
    /// A minimum intrinsic gas budget is required even though actual gas is constant.
    GasBelowIntrinsic(u64),
    /// The declared nonce must match state produced by all preceding body entries exactly.
    NonceMismatch { expected: u64, actual: u64 },
    /// Validity is compared to the explicit inclusion slot, never the host clock.
    NotMature { slot: u64, valid_after_slot: u64 },
    /// Paying value and fee separately is insufficient; the complete debit must be funded.
    InsufficientCombinedFunds { available: u128, required: u128 },
    /// Explicit checked failure, identical in debug and release builds.
    Overflow(ArithmeticField),
}

impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication(error) => write!(f, "native authentication failed: {error}"),
            Self::UnsupportedKind(kind) => write!(f, "unsupported transfer kind {kind}"),
            Self::UnsupportedAsset(asset) => write!(f, "unsupported transfer asset {asset}"),
            Self::UnsupportedRules(rules) => write!(f, "unsupported transfer rules {rules}"),
            Self::GasBelowIntrinsic(gas) => write!(f, "gas limit {gas} is below intrinsic gas"),
            Self::NonceMismatch { expected, actual } => write!(
                f,
                "canonical nonce mismatch: expected {expected}, got {actual}"
            ),
            Self::NotMature {
                slot,
                valid_after_slot,
            } => write!(
                f,
                "slot {slot} precedes valid-after slot {valid_after_slot}"
            ),
            Self::InsufficientCombinedFunds {
                available,
                required,
            } => write!(
                f,
                "insufficient combined funds: available {available}, required {required}"
            ),
            Self::Overflow(field) => write!(f, "checked native transfer overflow: {field:?}"),
        }
    }
}

impl std::error::Error for TransferError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authentication(error) => Some(error),
            _ => None,
        }
    }
}

/// Deterministic body position and cause; phase order is authentication, then ordered execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyError {
    /// Zero-based failing body position, not mempool position.
    pub transaction_index: usize,
    /// The failure which caused the entire staged body to be discarded.
    pub cause: TransferError,
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "native body transaction {} rejected: {}",
            self.transaction_index, self.cause
        )
    }
}

impl std::error::Error for BodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

/// In-memory offline commit record, not a native block, receipt encoding, or database schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedBody {
    /// Trusted context used to authenticate these exact bytes.
    pub context: AuthenticationContext,
    /// Explicit slot used for maturity checks; no slot/tip/reorg policy is introduced here.
    pub slot: u64,
    /// Exact authenticated signed V2 bytes, preserved without mutation or V1 reinterpretation.
    pub transactions: Vec<[u8; SIGNED_LEN]>,
    /// Gas, burns, and ordered native identities derived by the shared application path.
    pub outcome: BodyOutcome,
}

/// Fallible all-or-nothing persistence boundary required before installing canonical state.
///
/// Implementations must atomically persist both the candidate state and body record, using the
/// expected base when relevant. Err MUST leave committed storage unchanged. A backend reporting
/// an error after partial/indeterminate commitment does not satisfy this contract; production
/// database transaction and recovery semantics remain a separate integration requirement.
pub trait AtomicBodyStore {
    /// Backend failures are surfaced rather than hidden behind an always-successful default.
    type Error: std::error::Error + 'static;

    /// Persists a completely validated candidate; these immutable snapshots have no wallet keys.
    fn persist(
        &mut self,
        expected_base: &TransferState,
        candidate: &TransferState,
        body: &AppliedBody,
    ) -> Result<(), Self::Error>;
}

/// Body validation, stale-overlay, or persistence failure; all preserve the live input state.
#[derive(Debug, Eq, PartialEq)]
pub enum ApplyError<E> {
    /// An authentication or stateful entry failure discarded the complete candidate.
    Body(BodyError),
    /// A prepared overlay may not overwrite intervening committed account/accounting changes.
    StaleBase,
    /// The store rejected the candidate before its atomic commit point.
    Persistence(E),
}

impl<E: fmt::Display> fmt::Display for ApplyError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Body(error) => error.fmt(f),
            Self::StaleBase => f.write_str("native transfer overlay has a stale canonical base"),
            Self::Persistence(error) => write!(f, "native transfer persistence failed: {error}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ApplyError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Body(error) => Some(error),
            Self::StaleBase => None,
            Self::Persistence(error) => Some(error),
        }
    }
}

/// Owned, non-cloneable application overlay. Construction never mutates the canonical base.
#[derive(Debug)]
pub struct StagedBody {
    base: TransferState,
    candidate: TransferState,
    record: AppliedBody,
}

impl StagedBody {
    /// Moves a validated overlay into the isolated durable coordinator without re-execution.
    /// Kept crate-private so only the coordinator can install after its richer commit contract.
    pub(crate) fn into_parts(self) -> (TransferState, TransferState, AppliedBody) {
        (self.base, self.candidate, self.record)
    }

    /// Read-only candidate for producer inspection; it is not installed or committed yet.
    pub fn candidate(&self) -> &TransferState {
        &self.candidate
    }

    /// Read-only exact body and derived outcomes; no caller can modify the staged result.
    pub fn record(&self) -> &AppliedBody {
        &self.record
    }

    /// Consumes an already-executed overlay exactly once, without re-executing its transfers.
    pub fn commit<S: AtomicBodyStore>(
        self,
        live: &mut TransferState,
        store: &mut S,
    ) -> Result<BodyOutcome, ApplyError<S::Error>> {
        if *live != self.base {
            return Err(ApplyError::StaleBase);
        }
        store
            .persist(&self.base, &self.candidate, &self.record)
            .map_err(ApplyError::Persistence)?;
        // All fallible work and allocations precede installation. Move plain owned state once;
        // canonical nonce increments, balances, accounting, and persisted body become visible together.
        *live = self.candidate;
        Ok(self.record.outcome)
    }
}

/// Authenticates exact signed bytes, then applies every entry in body order to owned staged state.
///
/// No keys, mempool, pending nonces, wall clock, or producer-specific execution path is an input.
/// Authentication of the complete body precedes state execution. Any later state failure drops all
/// earlier staged effects. No block identity, body-limit policy, or state-root format is defined here.
pub fn stage_body(
    base: &TransferState,
    context: &AuthenticationContext,
    slot: u64,
    body: &[Vec<u8>],
) -> Result<StagedBody, BodyError> {
    let proofs: Vec<AuthenticatedTransaction> = body
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            #[cfg(test)]
            phase_evidence::authentication();
            authenticate(bytes, context, None).map_err(|error| BodyError {
                transaction_index: index,
                cause: TransferError::Authentication(error),
            })
        })
        .collect::<Result<_, _>>()?;

    let mut candidate = base.clone();
    let mut outcome = BodyOutcome::default();
    for (index, proof) in proofs.iter().enumerate() {
        #[cfg(test)]
        phase_evidence::execution();
        apply_transfer(&mut candidate, &mut outcome, proof, slot).map_err(|cause| BodyError {
            transaction_index: index,
            cause,
        })?;
    }
    let transactions = body
        .iter()
        .map(|bytes| {
            // authenticate's exact decoder has already established every input is exactly 199 bytes.
            bytes
                .as_slice()
                .try_into()
                .expect("authenticated native signed length")
        })
        .collect();
    Ok(StagedBody {
        base: base.clone(),
        candidate,
        record: AppliedBody {
            context: *context,
            slot,
            transactions,
            outcome,
        },
    })
}

/// Shared synchronous stage/persist/install path for both offline producers and receivers.
pub fn apply_body<S: AtomicBodyStore>(
    live: &mut TransferState,
    context: &AuthenticationContext,
    slot: u64,
    body: &[Vec<u8>],
    store: &mut S,
) -> Result<BodyOutcome, ApplyError<S::Error>> {
    stage_body(live, context, slot, body)
        .map_err(ApplyError::Body)?
        .commit(live, store)
}

fn apply_transfer(
    state: &mut TransferState,
    outcome: &mut BodyOutcome,
    proof: &AuthenticatedTransaction,
    slot: u64,
) -> Result<(), TransferError> {
    let transaction = proof.transaction().unsigned();
    // The proof came only from authenticate above. Keep the execution profile explicit so future
    // authentication extensions cannot silently give new kinds, rules, or assets transfer semantics.
    if transaction.native_rules_version != 1 {
        return Err(TransferError::UnsupportedRules(
            transaction.native_rules_version,
        ));
    }
    if transaction.kind != TRANSFER_KIND {
        return Err(TransferError::UnsupportedKind(transaction.kind));
    }
    if transaction.token_id != ETX_TOKEN_ID {
        return Err(TransferError::UnsupportedAsset(transaction.token_id));
    }
    if transaction.gas_limit < INTRINSIC_GAS {
        return Err(TransferError::GasBelowIntrinsic(transaction.gas_limit));
    }
    let sender = state.account(&transaction.sender);
    if transaction.nonce != sender.nonce {
        return Err(TransferError::NonceMismatch {
            expected: sender.nonce,
            actual: transaction.nonce,
        });
    }
    if slot < transaction.valid_after_slot {
        return Err(TransferError::NotMature {
            slot,
            valid_after_slot: transaction.valid_after_slot,
        });
    }

    // Even a self-transfer must fund the full value-plus-fee exposure before its value returns.
    let debit = transaction
        .value
        .checked_add(u128::from(TRANSFER_FEE_QUARKS))
        .ok_or(TransferError::Overflow(ArithmeticField::CombinedDebit))?;
    let debited_balance = sender.balance_quarks.checked_sub(debit).ok_or(
        TransferError::InsufficientCombinedFunds {
            available: sender.balance_quarks,
            required: debit,
        },
    )?;
    let next_nonce = sender
        .nonce
        .checked_add(1)
        .ok_or(TransferError::Overflow(ArithmeticField::Nonce))?;
    let mut next_sender = TransferAccount {
        balance_quarks: debited_balance,
        nonce: next_nonce,
    };
    let mut next_recipient = None;
    if transaction.sender == transaction.recipient {
        // One staged account record holds both debit and credit. Never overwrite its new nonce or
        // compute self-credit against a stale copy of the original sender/recipient balance.
        next_sender.balance_quarks = next_sender
            .balance_quarks
            .checked_add(transaction.value)
            .ok_or(TransferError::Overflow(ArithmeticField::RecipientBalance))?;
    } else if transaction.value != 0 {
        let recipient = state.account(&transaction.recipient);
        next_recipient = Some(TransferAccount {
            balance_quarks: recipient
                .balance_quarks
                .checked_add(transaction.value)
                .ok_or(TransferError::Overflow(ArithmeticField::RecipientBalance))?,
            nonce: recipient.nonce,
        });
    }
    // Zero credit changes no recipient record, including an absent/default one. This sparse
    // offline projection prescribes no production account-pruning or state-commitment encoding.
    let total_gas = state
        .gas_used_total
        .checked_add(INTRINSIC_GAS)
        .ok_or(TransferError::Overflow(ArithmeticField::TotalGas))?;
    let total_burn = state
        .fees_burned_total
        .checked_add(u128::from(TRANSFER_FEE_QUARKS))
        .ok_or(TransferError::Overflow(ArithmeticField::TotalBurn))?;
    let body_gas = outcome
        .gas_used
        .checked_add(INTRINSIC_GAS)
        .ok_or(TransferError::Overflow(ArithmeticField::BodyGas))?;
    let body_burn = outcome
        .fees_burned
        .checked_add(TRANSFER_FEE_QUARKS)
        .ok_or(TransferError::Overflow(ArithmeticField::BodyBurn))?;

    // All account and accounting checks finish before mutating even this temporary candidate.
    state.accounts.insert(transaction.sender, next_sender);
    if let Some(recipient) = next_recipient {
        state.accounts.insert(transaction.recipient, recipient);
    }
    state.gas_used_total = total_gas;
    state.fees_burned_total = total_burn;
    outcome.gas_used = body_gas;
    outcome.fees_burned = body_burn;
    outcome.transaction_ids.push(proof.transaction_id());
    Ok(())
}

#[cfg(test)]
mod tests;
