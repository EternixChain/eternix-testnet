//! Shared pure block commitments, mechanically extracted from the V1 binary codec.
//!
//! Layout/hash versions are not activation policy. The 229-byte layout, domains, kind tags and
//! reserved roots are unchanged; callers must select and validate their own explicit block profile.

use crate::native_transaction::Hash;
use sha3::{Digest, Keccak256};
use std::sync::LazyLock;

/// Fixed V1-layout header width; no serialization defaults or optional roots.
pub const BLOCK_HEADER_LEN: usize = 229;
/// Historical header-hash domain, with no trailing terminator.
pub const BLOCK_HEADER_DOMAIN: &[u8] = b"ETERNIX_BLOCK_HEADER_V1";
/// Ordered-ID commitment domain; transaction families choose their own IDs first.
pub const TX_LIST_DOMAIN: &[u8] = b"ETERNIX_TX_LIST_V1";
/// Historical protocol-data domain.
pub const PROTOCOL_DATA_DOMAIN: &[u8] = b"ETERNIX_PROTOCOL_DATA_V1";
/// Historical empty-receipt-list domain.
pub const RECEIPT_LIST_DOMAIN: &[u8] = b"ETERNIX_RECEIPT_LIST_V1";
/// Exact UTF-8 proposer identity commitment domain.
pub const PROPOSER_ID_DOMAIN: &[u8] = b"ETERNIX_PROPOSER_ID_V1";
/// Reserved state root, not an implemented state commitment.
pub const PLACEHOLDER_STATE_ROOT: Hash = [0; 32];
/// Count-zero ordered transaction commitment.
pub static EMPTY_TX_ROOT: LazyLock<Hash> = LazyLock::new(|| {
    let mut bytes = Vec::from(TX_LIST_DOMAIN);
    bytes.extend_from_slice(&0u64.to_be_bytes());
    keccak256(&bytes)
});
/// Count-zero receipt commitment, distinct from the zero state root.
pub static EMPTY_RECEIPTS_ROOT: LazyLock<Hash> = LazyLock::new(|| {
    let mut bytes = Vec::from(RECEIPT_LIST_DOMAIN);
    bytes.extend_from_slice(&0u64.to_be_bytes());
    keccak256(&bytes)
});
/// Encoding-1 empty protocol-data commitment.
pub static EMPTY_PROTOCOL_DATA_ROOT: LazyLock<Hash> = LazyLock::new(|| {
    hash_with_domain(
        PROTOCOL_DATA_DOMAIN,
        &ProtocolData::empty().canonical_bytes(),
    )
});

/// Keccak-256 (not standardized SHA3-256), returning raw bytes.
pub fn keccak256(bytes: &[u8]) -> Hash {
    Keccak256::digest(bytes).into()
}
/// Hashes exact domain || canonical bytes; no lengths or terminators are inserted.
pub fn hash_with_domain(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut h = Keccak256::new();
    h.update(domain);
    h.update(bytes);
    h.finalize().into()
}
/// Hashes count and exact ID order without changing any transaction-family ID rule.
pub fn ordered_transaction_root(ids: &[Hash]) -> Option<Hash> {
    let count = u64::try_from(ids.len()).ok()?;
    let mut h = Keccak256::new();
    h.update(TX_LIST_DOMAIN);
    h.update(count.to_be_bytes());
    for id in ids {
        h.update(id);
    }
    Some(h.finalize().into())
}
/// Preserves the V1 BE64-length-prefixed, non-normalized UTF-8 proposer commitment.
pub fn proposer_id(id: &str) -> Hash {
    let mut bytes = Vec::with_capacity(8 + id.len());
    bytes.extend_from_slice(
        &u64::try_from(id.len())
            .expect("validator IDs fit u64")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(id.as_bytes());
    hash_with_domain(PROPOSER_ID_DOMAIN, &bytes)
}

/// Historical kind tags. Recognition does not authorize protocol-block execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockKind {
    /// Validator-produced metadata.
    Validator,
    /// Historical missed-leader metadata.
    ProtocolMiss,
    /// Historical collision metadata.
    ProtocolCollision,
    /// Historical zero-eligibility metadata.
    ProtocolNoTickets,
}
impl BlockKind {
    /// Fixed tags independent of Rust declaration order.
    pub const fn consensus_code(self) -> u8 {
        match self {
            Self::Validator => 0,
            Self::ProtocolMiss => 1,
            Self::ProtocolNoTickets => 2,
            Self::ProtocolCollision => 3,
        }
    }
    /// Rejects unknown tags rather than treating them as validator blocks.
    pub const fn from_consensus_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Validator),
            1 => Some(Self::ProtocolMiss),
            2 => Some(Self::ProtocolNoTickets),
            3 => Some(Self::ProtocolCollision),
            _ => None,
        }
    }
}

/// Mandatory fixed-layout header, shared by historical V1 and explicitly selected offline profiles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockHeader {
    /// Caller-selected block profile; the codec does not activate it.
    pub protocol_version: u32,
    /// Explicit chain ID.
    pub chain_id: u64,
    /// Inclusion slot, not a local storage revision.
    pub slot: u64,
    /// Exact historical kind tag.
    pub block_kind: BlockKind,
    /// Computed predecessor hash.
    pub parent_hash: Hash,
    /// Fixed proposer commitment.
    pub proposer_id: Hash,
    /// Unsigned ticket identity; eligibility is outside this codec.
    pub ticket_id: u64,
    /// Count-and-order commitment to transaction IDs.
    pub transaction_root: Hash,
    /// Mandatory reserved root for the currently supported profiles.
    pub state_root: Hash,
    /// Mandatory reserved receipt root.
    pub receipts_root: Hash,
    /// Actual execution gas, interpreted by the selected profile.
    pub gas_used: u64,
    /// Exact protocol-data commitment.
    pub protocol_data_root: Hash,
}
impl BlockHeader {
    /// Unchanged V1 field order and big-endian widths, exactly 229 bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BLOCK_HEADER_LEN);
        out.extend_from_slice(&self.protocol_version.to_be_bytes());
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.extend_from_slice(&self.slot.to_be_bytes());
        out.push(self.block_kind.consensus_code());
        out.extend_from_slice(&self.parent_hash);
        out.extend_from_slice(&self.proposer_id);
        out.extend_from_slice(&self.ticket_id.to_be_bytes());
        out.extend_from_slice(&self.transaction_root);
        out.extend_from_slice(&self.state_root);
        out.extend_from_slice(&self.receipts_root);
        out.extend_from_slice(&self.gas_used.to_be_bytes());
        out.extend_from_slice(&self.protocol_data_root);
        debug_assert_eq!(out.len(), BLOCK_HEADER_LEN);
        out
    }
    /// Exact layout decoding only; no native transaction or producer authentication.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != BLOCK_HEADER_LEN {
            return None;
        }
        let mut d = Decoder::new(bytes);
        let h = Self {
            protocol_version: d.u32()?,
            chain_id: d.u64()?,
            slot: d.u64()?,
            block_kind: BlockKind::from_consensus_code(d.u8()?)?,
            parent_hash: d.field()?,
            proposer_id: d.field()?,
            ticket_id: d.u64()?,
            transaction_root: d.field()?,
            state_root: d.field()?,
            receipts_root: d.field()?,
            gas_used: d.u64()?,
            protocol_data_root: d.field()?,
        };
        d.finished().then_some(h)
    }
    /// Exact historical domain || header hash, excluding transport and local storage metadata.
    pub fn hash(&self) -> Hash {
        hash_with_domain(BLOCK_HEADER_DOMAIN, &self.canonical_bytes())
    }
}

/// Encoding-1 protocol data, retained for historical compatibility without implementing economics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolData {
    /// Historical optional missed proposer, encoded explicitly rather than omitted by defaults.
    pub missed_proposer: Option<String>,
    /// Per-block burns in the established unsigned width.
    pub fees_burned: u64,
}
impl ProtocolData {
    /// Canonical empty protocol data.
    pub fn empty() -> Self {
        Self {
            missed_proposer: None,
            fees_burned: 0,
        }
    }
    /// Exact encoding 1, BE64 burns, presence flag and optional BE32-prefixed UTF-8.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = vec![1];
        out.extend_from_slice(&self.fees_burned.to_be_bytes());
        match &self.missed_proposer {
            Some(p) => {
                out.push(1);
                out.extend_from_slice(
                    &u32::try_from(p.len())
                        .expect("validator IDs fit u32")
                        .to_be_bytes(),
                );
                out.extend_from_slice(p.as_bytes());
            }
            None => out.push(0),
        }
        out
    }
    /// Preserves historical optional-field decoding; callers enforce their block profile separately.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Option<Self> {
        let mut d = Decoder::new(bytes);
        if d.u8()? != 1 {
            return None;
        }
        let fees_burned = d.u64()?;
        let missed_proposer = match d.u8()? {
            0 => None,
            1 => {
                let len = usize::try_from(d.u32()?).ok()?;
                Some(String::from_utf8(d.take(len)?.to_vec()).ok()?)
            }
            _ => return None,
        };
        d.finished().then_some(Self {
            missed_proposer,
            fees_burned,
        })
    }
    /// Historical protocol-data root, including the same empty commitment.
    pub fn root(&self) -> Hash {
        hash_with_domain(PROTOCOL_DATA_DOMAIN, &self.canonical_bytes())
    }
}

// Explicit bounds and byte order are shared only for these pure codecs, not node state decoding.
struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(len)?;
        let bytes = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(bytes)
    }
    fn field<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.field::<1>()?[0])
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.field()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.field()?))
    }
    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
