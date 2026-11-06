//! Explicit C1 wire4/profile3/auth2 objects and compound transition internals.
//!
//! Attribution is public and deliberately weaker than admission. Only the durable owner supplies
//! the audited prefix to the private transition; neither a packet nor a public P2.1 plan is authority.
use super::*;
use crate::block_commitment::{
    BlockHeader, BlockKind, EMPTY_RECEIPTS_ROOT, ProtocolData, hash_with_domain,
    ordered_transaction_root, proposer_id,
};
use crate::durable_fixture::StoreError;
use crate::native_transaction::{AuthenticationContext, ID_DOMAIN, SIGNED_LEN};
use crate::native_transfer::{BodyError, BodyOutcome, TransferAccount, TransferState, stage_body};
use std::collections::BTreeMap;
use std::fmt;

/// Both closed producer names have seven ASCII bytes. Allocation bounds precede all decoding.
pub const MAX_BLOCK_BYTES: usize = 288 + 7 + 203 * MAX_ENTRIES as usize;
/// Outer prefix42 plus signature65; no optional witness, key declaration or verified tail.
pub const MAX_ENVELOPE_BYTES: usize = MAX_BLOCK_BYTES + 107;

/// Explicit C1 application/storage failures; no variant authorizes a fallback protocol result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Existing pure genesis/view/selection/signature contract rejected the input.
    Protocol(super::Error),
    /// Exact C1 framing or content commitment is invalid.
    Codec(&'static str),
    /// Shared all-authentication-before-execution native failure, retaining body position.
    Body(BodyError),
    /// Filesystem/SQLite outcome, never silently retried.
    Storage(StoreError),
    /// Canonical queries and new work are hidden until explicit successful recovery.
    Blocked,
    /// Foreign owner, invalidated generation or changed exact prefix/base.
    Stale,
    /// Authenticated existing content, retaining the first committed original evidence.
    AlreadyCommitted {
        /// Existing canonical position.
        position: Position,
        /// First committed original signature-bearing identity.
        retained_envelope_id: Hash,
        /// Authenticated submitted identity, possibly an alternative signature.
        submitted_envelope_id: Hash,
    },
    /// Selected-key conflicting statement: diagnostic halt, not adjudication/slashing/reorganization.
    ConflictHalt,
    /// Finalized unsigned content differs from the owned producer preparation.
    PreparedIdentity,
    /// Checked native membership collision at the original body position.
    DuplicateTransaction(usize),
    /// Persistent schema/state/evidence or unsupported transition inconsistency; never repaired.
    Invalid(String),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "C1 application: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<super::Error> for Error {
    fn from(e: super::Error) -> Self {
        Self::Protocol(e)
    }
}
impl From<StoreError> for Error {
    fn from(e: StoreError) -> Self {
        Self::Storage(e)
    }
}
pub(super) fn invalid(e: impl fmt::Display) -> Error {
    Error::Invalid(e.to_string())
}
pub(super) fn overflow() -> Error {
    super::Error::Overflow.into()
}

/// Immutable complete unsigned C1 block. Native signatures remain opaque until inclusion staging.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    claim: HeaderClaim,
    protocol: ProtocolData,
    transactions: Vec<[u8; SIGNED_LEN]>,
}
impl Block {
    /// Validate all structural commitments without executing or authenticating any user entry.
    pub fn from_parts(
        header: BlockHeader,
        producer: String,
        protocol: ProtocolData,
        transactions: Vec<[u8; SIGNED_LEN]>,
    ) -> Result<Self, Error> {
        if transactions.len() > MAX_ENTRIES as usize {
            return Err(Error::Codec("body bound"));
        }
        let claim = HeaderClaim::new(header, producer, transactions.len() as u16)?;
        let ids: Vec<_> = transactions
            .iter()
            .map(|b| hash_with_domain(ID_DOMAIN, b))
            .collect();
        if protocol.missed_proposer.is_some()
            || protocol.root() != claim.header().protocol_data_root
            || Some(claim.header().transaction_root) != ordered_transaction_root(&ids)
        {
            return Err(Error::Codec("protocol/body commitment"));
        }
        Ok(Self {
            claim,
            protocol,
            transactions,
        })
    }
    pub(super) fn build(
        view: &SlotStartView,
        selection: &Selection,
        transactions: Vec<[u8; SIGNED_LEN]>,
        outcome: &BodyOutcome,
    ) -> Result<Self, Error> {
        let protocol = ProtocolData {
            fees_burned: outcome.fees_burned,
            missed_proposer: None,
        };
        Self::from_parts(
            BlockHeader {
                protocol_version: HEADER_PROFILE,
                chain_id: CHAIN_ID,
                slot: view.slot(),
                block_kind: BlockKind::Validator,
                parent_hash: view.parent().hash,
                proposer_id: proposer_id(selection.producer()),
                ticket_id: selection.ticket_id(),
                transaction_root: ordered_transaction_root(&outcome.transaction_ids)
                    .ok_or_else(overflow)?,
                state_root: [0; 32],
                receipts_root: *EMPTY_RECEIPTS_ROOT,
                gas_used: outcome.gas_used,
                protocol_data_root: protocol.root(),
            },
            selection.producer().into(),
            protocol,
            transactions,
        )
    }
    /// Exact profile3 header/count statement; signing inspection is not signing protection.
    pub fn claim(&self) -> &HeaderClaim {
        &self.claim
    }
    /// Immutable header-derived H, excluding the producer signature.
    pub fn hash(&self) -> Hash {
        self.claim.hash()
    }
    /// Exact ordered signed native entries.
    pub fn transactions(&self) -> &[[u8; SIGNED_LEN]] {
        &self.transactions
    }
    /// Exact encoding1 native fee data; never an aggregate issuance/slash field.
    pub fn protocol_data(&self) -> &ProtocolData {
        &self.protocol
    }
    /// New wire4: u8 wire, H32, header229, BE32/text, BE32/pd10, BE64 count, BE32/tx199.
    pub fn wire_bytes(&self) -> Vec<u8> {
        let mut out = vec![INNER_WIRE];
        out.extend_from_slice(&self.hash());
        out.extend_from_slice(&self.claim.header().canonical_bytes());
        out.extend_from_slice(&(self.claim.producer().len() as u32).to_be_bytes());
        out.extend_from_slice(self.claim.producer().as_bytes());
        out.extend_from_slice(&10u32.to_be_bytes());
        out.extend_from_slice(&self.protocol.canonical_bytes());
        out.extend_from_slice(&(self.transactions.len() as u64).to_be_bytes());
        for tx in &self.transactions {
            out.extend_from_slice(&(SIGNED_LEN as u32).to_be_bytes());
            out.extend_from_slice(tx);
        }
        out
    }
    /// Strict bounded new-profile decoding; old frames, noncanonical claims and tails fail.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BLOCK_BYTES {
            return Err(Error::Codec("block size"));
        }
        let mut d = Decoder { bytes, at: 0 };
        if d.field::<1>()? != [INNER_WIRE] {
            return Err(Error::Codec("inner wire"));
        }
        let claimed: Hash = d.field()?;
        let header =
            BlockHeader::from_canonical_bytes(d.take(229)?).ok_or(Error::Codec("header"))?;
        if d.u32()? != 7 {
            return Err(Error::Codec("closed producer length"));
        }
        let producer = std::str::from_utf8(d.take(7)?)
            .map_err(|_| Error::Codec("producer ASCII"))?
            .into();
        if d.u32()? != 10 {
            return Err(Error::Codec("protocol length"));
        }
        let protocol =
            ProtocolData::from_canonical_bytes(d.take(10)?).ok_or(Error::Codec("protocol"))?;
        let count = d.u64()?;
        if count > MAX_ENTRIES || bytes.len().saturating_sub(d.at) != count as usize * 203 {
            return Err(Error::Codec("exact body size"));
        }
        let mut transactions = Vec::with_capacity(count as usize);
        for _ in 0..count {
            if d.u32()? != SIGNED_LEN as u32 {
                return Err(Error::Codec("entry length"));
            }
            transactions.push(d.field()?);
        }
        let block = Self::from_parts(header, producer, protocol, transactions)?;
        if block.hash() != claimed {
            return Err(Error::Codec("claimed H"));
        }
        Ok(block)
    }
    pub(super) fn match_outcome(&self, outcome: &BodyOutcome) -> Result<(), Error> {
        let ids: Vec<_> = self
            .transactions
            .iter()
            .map(|b| hash_with_domain(ID_DOMAIN, b))
            .collect();
        if ids != outcome.transaction_ids
            || outcome.gas_used != self.claim.header().gas_used
            || outcome.fees_burned != self.protocol.fees_burned
        {
            return Err(Error::Codec("native outcome"));
        }
        Ok(())
    }
}

/// Syntax/content-checked exact outer4 object, still without producer attribution or admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    block: Block,
    network: Hash,
    signature: [u8; 65],
}
impl Envelope {
    /// Assemble offline externally signed evidence; this does not sign or grant canonical authority.
    pub fn from_parts(block: Block, network: Hash, signature: [u8; 65]) -> Self {
        Self {
            block,
            network,
            signature,
        }
    }
    /// Exact bounded outer4/auth1/rules2/network/BE32-inner-length/inner/S65 decoder.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(Error::Codec("envelope size"));
        }
        let mut d = Decoder { bytes, at: 0 };
        if d.field::<1>()? != [OUTER_WIRE]
            || d.field::<1>()? != [AUTH_ENCODING]
            || d.u32()? != AUTH_RULES
        {
            return Err(Error::Codec("outer/auth profile"));
        }
        let network = d.field()?;
        let len = d.u32()? as usize;
        if !(295..=MAX_BLOCK_BYTES).contains(&len) || len.checked_add(107) != Some(bytes.len()) {
            return Err(Error::Codec("exact envelope length"));
        }
        let block = Block::from_wire_bytes(d.take(len)?)?;
        Ok(Self {
            block,
            network,
            signature: d.field()?,
        })
    }
    /// Deterministically reconstruct the original bytes, including original S.
    pub fn wire_bytes(&self) -> Vec<u8> {
        let inner = self.block.wire_bytes();
        let mut out = vec![OUTER_WIRE, AUTH_ENCODING];
        out.extend_from_slice(&AUTH_RULES.to_be_bytes());
        out.extend_from_slice(&self.network);
        out.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        out.extend_from_slice(&inner);
        out.extend_from_slice(&self.signature);
        out
    }
    /// Exact signature-bearing identity under the existing envelope-ID domain and new exact frame.
    pub fn id(&self) -> Hash {
        hash_with_domain(
            crate::block_authentication::ENVELOPE_ID_DOMAIN,
            &self.wire_bytes(),
        )
    }
    /// Immutable unsigned content.
    pub fn block(&self) -> &Block {
        &self.block
    }
    /// Received network claim, compared with independent genesis during authentication.
    pub fn network_id(&self) -> Hash {
        self.network
    }
    /// Original received compact evidence; never silently normalized.
    pub fn signature_bytes(&self) -> &[u8; 65] {
        &self.signature
    }
    /// One full-key producer authentication. A valid non-selected producer still gets attribution.
    pub fn authenticate(self, genesis: &Genesis) -> Result<AuthenticatedEnvelope, Error> {
        #[cfg(test)]
        phase_evidence::authentication();
        let header = self
            .block
            .claim
            .authenticate(genesis, self.network, &self.signature)?;
        Ok(AuthenticatedEnvelope {
            envelope: self,
            header,
        })
    }
}
/// Private proof of producer attribution only; no public conversion into an owner preparation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedEnvelope {
    envelope: Envelope,
    header: AuthenticatedHeader,
}
impl AuthenticatedEnvelope {
    /// Original exact envelope, not a commit receipt.
    pub fn envelope(&self) -> &Envelope {
        &self.envelope
    }
    /// Full-key proof under profile3/auth2.
    pub fn header(&self) -> &AuthenticatedHeader {
        &self.header
    }
}

pub(super) fn native_context(g: &Genesis) -> AuthenticationContext {
    AuthenticationContext::new(CHAIN_ID, g.network_id(), 1).expect("validated C1/native profile")
}
pub(super) fn native_state(s: &ClosedState) -> TransferState {
    TransferState::new(
        s.input()
            .accounts
            .iter()
            .map(|a| {
                (
                    a.address,
                    TransferAccount {
                        balance_quarks: a.balance,
                        nonce: a.nonce,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>(),
        s.input().gas_used,
        s.input().fees_burned,
    )
}
// P2.1 supports supplied lifecycle views for pure comparisons; the authoritative C1 engine only
// reaches the approved closed active state. Do not turn unsupported economics into no-op execution.
pub(super) fn supported(s: &ClosedState) -> Result<(), Error> {
    if s.input().validators.iter().any(|v| {
        v.status != ValidatorStatus::Active
            || v.misses != 0
            || v.offenses != 0
            || v.cooldown_until.is_some()
    }) || s.input().tickets.iter().any(|t| {
        t.status != TicketStatus::Active || t.retire_start.is_some() || t.retire_effective.is_some()
    }) {
        return Err(invalid("unsupported C1 pre-state transition"));
    }
    Ok(())
}
pub(super) fn stage_native(
    view: &SlotStartView,
    body: &[Vec<u8>],
) -> Result<(TransferState, crate::native_transfer::AppliedBody), Error> {
    supported(view.state())?;
    if body.len() > MAX_ENTRIES as usize {
        return Err(Error::Codec("body bound"));
    }
    let (_, candidate, record) = stage_body(
        &native_state(view.state()),
        &native_context(view.genesis()),
        view.slot(),
        body,
    )
    .map_err(Error::Body)?
    .into_parts();
    Ok((candidate, record))
}
// The only economic application consumes an already-staged native candidate. Its cumulative totals
// already include fees/gas; copying them (not adding the body outcome) prevents double charging.
pub(super) fn compound(
    view: &SlotStartView,
    block: &Block,
    native: TransferState,
    outcome: &BodyOutcome,
) -> Result<ClosedState, Error> {
    supported(view.state())?;
    let selection = view.select()?;
    if block.claim.header().slot != view.slot()
        || block.claim.header().parent_hash != view.parent().hash
    {
        return Err(super::Error::Context("compound parent/slot").into());
    }
    if block.claim.producer() != selection.producer()
        || block.claim.header().ticket_id != selection.ticket_id()
    {
        return Err(super::Error::NotSelected.into());
    }
    block.match_outcome(outcome)?;
    let mut data = view.state().input().clone();
    data.position = Position {
        slot: view.slot(),
        hash: block.hash(),
    };
    data.accounts = native
        .accounts()
        .iter()
        .map(|(address, a)| Account {
            address: *address,
            balance: a.balance_quarks,
            nonce: a.nonce,
        })
        .collect();
    data.gas_used = native.gas_used_total();
    data.fees_burned = native.fees_burned_total();
    let reward = view.genesis().year_zero().reward;
    let v = data
        .validators
        .iter_mut()
        .find(|v| v.id == selection.producer())
        .ok_or_else(|| invalid("selected registry"))?;
    v.vault = v.vault.checked_add(reward).ok_or_else(overflow)?;
    v.locked = v.locked.checked_add(reward).ok_or_else(overflow)?;
    v.produced = v.produced.checked_add(1).ok_or_else(overflow)?;
    data.base_issuance = data
        .base_issuance
        .checked_add(reward)
        .ok_or_else(overflow)?;
    data.credits.push(RewardCredit {
        slot: view.slot(),
        validator: v.id.clone(),
        amount: reward,
    });
    // Revalidate supply, all retained credits/participation, collateral and complete metadata before
    // any SQL work. Locked liability is a subset of the vault, never a second supply credit.
    Ok(ClosedState::from_trusted_snapshot(view.genesis(), data)?)
}

#[cfg(test)]
pub(super) mod phase_evidence {
    use std::cell::Cell;
    thread_local! { static AUTH: Cell<usize> = const { Cell::new(0) }; }
    pub fn reset() {
        AUTH.set(0);
    }
    pub fn count() -> usize {
        AUTH.get()
    }
    pub fn authentication() {
        AUTH.set(AUTH.get() + 1);
    }
}
