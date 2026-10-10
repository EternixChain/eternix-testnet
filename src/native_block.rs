//! Experimental wire-2/header-profile-2 blocks for the isolated offline harness only.
//! Numbers here are not production assignments. Structural validity is not producer authorization.

use crate::block_commitment::{
    BLOCK_HEADER_LEN, BlockHeader, BlockKind, EMPTY_RECEIPTS_ROOT, PLACEHOLDER_STATE_ROOT,
    ProtocolData, hash_with_domain, ordered_transaction_root, proposer_id,
};
use crate::native_transaction::{AuthenticationContext, Hash, ID_DOMAIN, SIGNED_LEN};
use crate::native_transfer::BodyOutcome;
use std::fmt;

/// Experimental offline envelope value, independent of native transaction encoding and schema.
pub const EXPERIMENTAL_WIRE_VERSION: u8 = 2;
/// Experimental offline header discriminator, not an activated production protocol revision.
pub const EXPERIMENTAL_HEADER_PROFILE: u32 = 2;
/// Approved bounded native profile count.
pub const MAX_TRANSACTIONS: usize = 3000;
/// Approved actual-gas cap; signed gas limits are not summed.
pub const MAX_GAS: u64 = 16_000_000;
/// Raw UTF-8 proposer byte bound, without normalization.
pub const MAX_PROPOSER_BYTES: usize = 256;
/// Exact maximum envelope: fixed fields 288 + proposer + 203 bytes per signed entry.
pub const MAX_WIRE_BYTES: usize = 288 + MAX_PROPOSER_BYTES + (4 + SIGNED_LEN) * MAX_TRANSACTIONS;

/// Deterministic envelope/preflight/post-staging failures, never an authentication proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockError {
    /// Syntax/limit failure, optionally at the first failing zero-based body position.
    Frame {
        reason: &'static str,
        position: Option<usize>,
    },
    /// Header discriminator differs from the experimental profile.
    Profile,
    /// Header chain differs from trusted context.
    Chain,
    /// Only validator-kind blocks are supported in this experiment.
    Kind,
    /// Proposer text/commitment is invalid.
    Proposer,
    /// Ticket must be nonzero structurally, without claiming eligibility.
    Ticket,
    /// State root must retain its reserved zero value.
    StateRoot,
    /// Receipt root must retain the historical empty-list commitment.
    ReceiptRoot,
    /// Claimed actual gas exceeds the approved cap.
    GasCap,
    /// Only encoding-1 burns with no missed-proposer field is allowed.
    ProtocolData,
    /// Claimed identity disagrees with the exact header hash.
    ClaimedHash,
    /// Exact protocol data differs from its header commitment.
    ProtocolRoot,
    /// Exact count/order/signed bytes differ from the header root.
    TransactionRoot,
    /// Sealed application bytes/IDs unexpectedly differ from the received body.
    StagedIdentity,
    /// Actual staged gas differs from the header's claim.
    ActualGas,
    /// Actual staged burn differs from exact protocol data.
    ActualBurn,
}
impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "experimental native block: {self:?}")
    }
}
impl std::error::Error for BlockError {}
fn frame(reason: &'static str, position: Option<usize>) -> BlockError {
    BlockError::Frame { reason, position }
}

/// Owned exact block constituents. Decoding/construction does not authenticate any transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeBlock {
    header: BlockHeader,
    claimed_hash: Hash,
    proposer: String,
    protocol_data: ProtocolData,
    transactions: Vec<[u8; SIGNED_LEN]>,
}
impl NativeBlock {
    /// Bounded syntax construction for inspection/fixtures; preflight and stateful staging follow.
    pub fn from_parts(
        header: BlockHeader,
        proposer: String,
        protocol_data: ProtocolData,
        transactions: Vec<[u8; SIGNED_LEN]>,
    ) -> Result<Self, BlockError> {
        if proposer.len() > MAX_PROPOSER_BYTES {
            return Err(frame("proposer length", None));
        }
        if protocol_data.missed_proposer.is_some() {
            return Err(frame("protocol data length", None));
        }
        if transactions.len() > MAX_TRANSACTIONS {
            return Err(frame("transaction count", None));
        }
        Ok(Self {
            claimed_hash: header.hash(),
            header,
            proposer,
            protocol_data,
            transactions,
        })
    }
    /// Builds a producer header from a successful shared body outcome, not a second execution.
    pub(crate) fn build(
        context: &AuthenticationContext,
        slot: u64,
        parent: Hash,
        proposer: String,
        ticket: u64,
        transactions: Vec<[u8; SIGNED_LEN]>,
        outcome: &BodyOutcome,
    ) -> Result<Self, BlockError> {
        let protocol_data = ProtocolData {
            fees_burned: outcome.fees_burned,
            missed_proposer: None,
        };
        let header = BlockHeader {
            protocol_version: EXPERIMENTAL_HEADER_PROFILE,
            chain_id: context.chain_id(),
            slot,
            block_kind: BlockKind::Validator,
            parent_hash: parent,
            proposer_id: proposer_id(&proposer),
            ticket_id: ticket,
            transaction_root: ordered_transaction_root(&outcome.transaction_ids)
                .ok_or(frame("count width", None))?,
            state_root: PLACEHOLDER_STATE_ROOT,
            receipts_root: *EMPTY_RECEIPTS_ROOT,
            gas_used: outcome.gas_used,
            protocol_data_root: protocol_data.root(),
        };
        let block = Self::from_parts(header, proposer, protocol_data, transactions)?;
        block.preflight(context)?;
        Ok(block)
    }
    /// Explicit synthetic empty checkpoint constructor; it supplies no post-anchor account authority.
    pub fn empty_fixture_anchor(
        context: &AuthenticationContext,
        slot: u64,
        parent: Hash,
        proposer: String,
        ticket: u64,
    ) -> Result<Self, BlockError> {
        Self::build(
            context,
            slot,
            parent,
            proposer,
            ticket,
            Vec::new(),
            &BodyOutcome::default(),
        )
    }
    /// Read-only mandatory header; no mutation after sealing.
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }
    /// Read-only exact proposer spelling.
    pub fn proposer(&self) -> &str {
        &self.proposer
    }
    /// Read-only exact protocol data.
    pub fn protocol_data(&self) -> &ProtocolData {
        &self.protocol_data
    }
    /// Exact signed objects in original body order, still not an authentication proof.
    pub fn transactions(&self) -> &[[u8; SIGNED_LEN]] {
        &self.transactions
    }
    /// Content-derived identity, independent of storage revision or acknowledgement.
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }
    /// Deterministically reconstructs the envelope, without silently altering claimed identities.
    pub fn wire_bytes(&self) -> Vec<u8> {
        let mut bytes =
            Vec::with_capacity(288 + self.proposer.len() + 203 * self.transactions.len());
        bytes.push(EXPERIMENTAL_WIRE_VERSION);
        bytes.extend_from_slice(&self.claimed_hash);
        bytes.extend_from_slice(&self.header.canonical_bytes());
        bytes.extend_from_slice(&(self.proposer.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.proposer.as_bytes());
        let pd = self.protocol_data.canonical_bytes();
        bytes.extend_from_slice(&(pd.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&pd);
        bytes.extend_from_slice(&(self.transactions.len() as u64).to_be_bytes());
        for tx in &self.transactions {
            bytes.extend_from_slice(&(SIGNED_LEN as u32).to_be_bytes());
            bytes.extend_from_slice(tx);
        }
        bytes
    }
    /// Phase 2 only: bounded exact envelope decoding in wire order; native entries stay opaque.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, BlockError> {
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(frame("envelope size", None));
        }
        let mut d = Decoder { bytes, offset: 0 };
        if d.field::<1>(None)?[0] != EXPERIMENTAL_WIRE_VERSION {
            return Err(frame("wire version", None));
        }
        let claimed_hash = d.field(None)?;
        let header = BlockHeader::from_canonical_bytes(d.take(BLOCK_HEADER_LEN, None)?)
            .ok_or(frame("header", None))?;
        let len = usize::try_from(u32::from_be_bytes(d.field(None)?))
            .map_err(|_| frame("proposer width", None))?;
        if len > MAX_PROPOSER_BYTES {
            return Err(frame("proposer length", None));
        }
        let proposer = std::str::from_utf8(d.take(len, None)?)
            .map_err(|_| frame("proposer UTF-8", None))?
            .to_owned();
        if u32::from_be_bytes(d.field(None)?) != 10 {
            return Err(frame("protocol data length", None));
        }
        let protocol_data = ProtocolData::from_canonical_bytes(d.take(10, None)?)
            .ok_or(frame("protocol data", None))?;
        let count = usize::try_from(u64::from_be_bytes(d.field(None)?))
            .map_err(|_| frame("count width", None))?;
        if count > MAX_TRANSACTIONS {
            return Err(frame("transaction count", None));
        }
        let body_size = count
            .checked_mul(4 + SIGNED_LEN)
            .ok_or(frame("body size overflow", None))?;
        // Bound the declared allocation to actual remaining bytes before constructing its Vec.
        if body_size > bytes.len().saturating_sub(d.offset) {
            return Err(frame(
                "truncated body",
                Some(bytes.len().saturating_sub(d.offset) / (4 + SIGNED_LEN)),
            ));
        }
        let mut transactions = Vec::with_capacity(count);
        for i in 0..count {
            if u32::from_be_bytes(d.field(Some(i))?) != SIGNED_LEN as u32 {
                return Err(frame("signed length", Some(i)));
            }
            transactions.push(d.field(Some(i))?);
        }
        if d.offset != bytes.len() {
            return Err(frame("trailing bytes", None));
        }
        Ok(Self {
            header,
            claimed_hash,
            proposer,
            protocol_data,
            transactions,
        })
    }
    /// Phase 3 in its approved predicate order. Raw-ID hashing is not signature authentication.
    pub fn preflight(&self, context: &AuthenticationContext) -> Result<Vec<Hash>, BlockError> {
        let h = &self.header;
        if h.protocol_version != EXPERIMENTAL_HEADER_PROFILE {
            return Err(BlockError::Profile);
        }
        if h.chain_id != context.chain_id() {
            return Err(BlockError::Chain);
        }
        if h.block_kind != BlockKind::Validator {
            return Err(BlockError::Kind);
        }
        if self.proposer.is_empty()
            || self.proposer == "protocol"
            || h.proposer_id == [0; 32]
            || h.proposer_id != proposer_id(&self.proposer)
        {
            return Err(BlockError::Proposer);
        }
        if h.ticket_id == 0 {
            return Err(BlockError::Ticket);
        }
        if h.state_root != PLACEHOLDER_STATE_ROOT {
            return Err(BlockError::StateRoot);
        }
        if h.receipts_root != *EMPTY_RECEIPTS_ROOT {
            return Err(BlockError::ReceiptRoot);
        }
        if h.gas_used > MAX_GAS {
            return Err(BlockError::GasCap);
        }
        if self.protocol_data.missed_proposer.is_some() {
            return Err(BlockError::ProtocolData);
        }
        if self.claimed_hash != self.hash() {
            return Err(BlockError::ClaimedHash);
        }
        if h.protocol_data_root != self.protocol_data.root() {
            return Err(BlockError::ProtocolRoot);
        }
        let ids: Vec<_> = self
            .transactions
            .iter()
            .map(|b| hash_with_domain(ID_DOMAIN, b))
            .collect();
        if Some(h.transaction_root) != ordered_transaction_root(&ids) {
            return Err(BlockError::TransactionRoot);
        }
        Ok(ids)
    }
    /// Phase 7 identity/gas/burn consistency, without authenticating or executing again.
    pub(crate) fn match_outcome(
        &self,
        bytes: &[[u8; SIGNED_LEN]],
        ids: &[Hash],
        outcome: &BodyOutcome,
    ) -> Result<(), BlockError> {
        if bytes != self.transactions || ids != outcome.transaction_ids {
            return Err(BlockError::StagedIdentity);
        }
        if self.header.gas_used != outcome.gas_used {
            return Err(BlockError::ActualGas);
        }
        if self.protocol_data.fees_burned != outcome.fees_burned {
            return Err(BlockError::ActualBurn);
        }
        Ok(())
    }
}
struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Decoder<'a> {
    fn take(&mut self, len: usize, position: Option<usize>) -> Result<&'a [u8], BlockError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(frame("offset overflow", position))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(frame("truncation", position))?;
        self.offset = end;
        Ok(bytes)
    }
    fn field<const N: usize>(&mut self, position: Option<usize>) -> Result<[u8; N], BlockError> {
        self.take(N, position)?
            .try_into()
            .map_err(|_| frame("fixed width", position))
    }
}
