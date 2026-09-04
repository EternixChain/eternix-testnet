use std::collections::HashMap;
use std::sync::LazyLock;

use serde_json::{Value, json};
use sha3::{Digest, Keccak256};

use crate::models::{Block, BlockHeader, BlockKind, Hash, ProtocolData, Tx, TxKind};

pub const PROTOCOL_VERSION: u32 = 1;
pub const CHAIN_ID: u64 = 1162;
pub const ZERO_HASH: Hash = [0; 32];
pub const ZERO_PROPOSER_ID: Hash = [0; 32];
pub const ZERO_TICKET_ID: u64 = 0;
pub const PLACEHOLDER_STATE_ROOT: Hash = [0; 32];
pub const MAX_BLOCK_TRANSACTIONS: usize = 3000;
pub const MAX_BLOCK_GAS: u64 = 16_000_000;

pub const BLOCK_HEADER_DOMAIN: &[u8] = b"ETERNIX_BLOCK_HEADER_V1";
pub const TX_DOMAIN: &[u8] = b"ETERNIX_TX_V1";
pub const TX_LIST_DOMAIN: &[u8] = b"ETERNIX_TX_LIST_V1";
pub const PROTOCOL_DATA_DOMAIN: &[u8] = b"ETERNIX_PROTOCOL_DATA_V1";
pub const RECEIPT_LIST_DOMAIN: &[u8] = b"ETERNIX_RECEIPT_LIST_V1";
pub const PROPOSER_ID_DOMAIN: &[u8] = b"ETERNIX_PROPOSER_ID_V1";
pub const GENESIS_DOMAIN: &[u8] = b"ETERNIX_GENESIS_V1";
pub const LEGACY_TICKET_ID_DOMAIN: &[u8] = b"ETERNIX_LEGACY_TICKET_ID_V1";
pub const EPOCH_SEED_DOMAIN: &[u8] = b"ETERNIX_EPOCH_SEED_V1";

const TX_ENCODING_VERSION: u8 = 1;
const PROTOCOL_DATA_ENCODING_VERSION: u8 = 1;
const BLOCK_WIRE_VERSION: u8 = 1;
const BLOCK_HEADER_LEN: usize = 229;

pub static EMPTY_TX_ROOT: LazyLock<Hash> = LazyLock::new(|| {
    let mut preimage = Vec::from(TX_LIST_DOMAIN);
    preimage.extend_from_slice(&0_u64.to_be_bytes());
    keccak256(&preimage)
});

pub static EMPTY_RECEIPTS_ROOT: LazyLock<Hash> = LazyLock::new(|| {
    let mut preimage = Vec::from(RECEIPT_LIST_DOMAIN);
    preimage.extend_from_slice(&0_u64.to_be_bytes());
    keccak256(&preimage)
});

pub static EMPTY_PROTOCOL_DATA_ROOT: LazyLock<Hash> = LazyLock::new(|| {
    let empty = ProtocolData::empty();
    hash_with_domain(PROTOCOL_DATA_DOMAIN, &empty.canonical_bytes())
});

pub static GENESIS_HASH: LazyLock<Hash> = LazyLock::new(|| {
    let mut preimage = Vec::from(GENESIS_DOMAIN);
    preimage.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    preimage.extend_from_slice(&CHAIN_ID.to_be_bytes());
    keccak256(&preimage)
});

pub fn keccak256(bytes: &[u8]) -> Hash {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

pub fn hash_with_domain(domain: &[u8], canonical_bytes: &[u8]) -> Hash {
    let mut hasher = Keccak256::new();
    hasher.update(domain);
    hasher.update(canonical_bytes);
    hasher.finalize().into()
}

pub fn format_hash(hash: &Hash) -> String {
    format!("0x{}", hex::encode(hash))
}

pub fn parse_hash(value: &str) -> Option<Hash> {
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    hex::decode(value).ok()?.try_into().ok()
}

pub fn short_hash(hash: &Hash) -> String {
    let encoded = hex::encode(hash);
    format!("0x{}...{}", &encoded[..8], &encoded[60..])
}

pub fn proposer_id(validator_id: &str) -> Hash {
    let bytes = validator_id.as_bytes();
    let mut canonical = Vec::with_capacity(8 + bytes.len());
    canonical.extend_from_slice(
        &u64::try_from(bytes.len())
            .expect("validator IDs fit the canonical u64 length")
            .to_be_bytes(),
    );
    canonical.extend_from_slice(bytes);
    hash_with_domain(PROPOSER_ID_DOMAIN, &canonical)
}

impl BlockKind {
    pub const fn consensus_code(self) -> u8 {
        match self {
            Self::Validator => 0,
            Self::ProtocolMiss => 1,
            Self::ProtocolNoTickets => 2,
            Self::ProtocolCollision => 3,
        }
    }

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

impl TxKind {
    pub const fn consensus_code(self) -> u8 {
        match self {
            Self::Transfer => 0x00,
            Self::Contract => 0x01,
            Self::System => 0x02,
            Self::Pbm => 0x03,
            Self::RegisterValidator => 0x10,
            Self::BuyTicket => 0x11,
            Self::WalletToVault => 0x12,
            Self::VaultToWallet => 0x13,
            Self::BurnTicket => 0x14,
        }
    }

    pub const fn from_consensus_code(code: u8) -> Option<Self> {
        match code {
            0x00 => Some(Self::Transfer),
            0x01 => Some(Self::Contract),
            0x02 => Some(Self::System),
            0x03 => Some(Self::Pbm),
            0x10 => Some(Self::RegisterValidator),
            0x11 => Some(Self::BuyTicket),
            0x12 => Some(Self::WalletToVault),
            0x13 => Some(Self::VaultToWallet),
            0x14 => Some(Self::BurnTicket),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::Contract => "contract",
            Self::System => "system",
            Self::Pbm => "pbm_tx",
            Self::RegisterValidator => "registerValidator",
            Self::BuyTicket => "buyTicket",
            Self::WalletToVault => "walletToVault",
            Self::VaultToWallet => "vaultToWallet",
            Self::BurnTicket => "burnTicket",
        }
    }
}

impl Tx {
    // V1 order: version, kind, chain_id, from, nonce, to, token_id, value, gas,
    // fee_quarks, max_fee_per_gas, valid_after_slot, fee_token_id, data, signature.
    // Integers are big-endian and every variable byte field has a u32 big-endian length.
    pub fn canonical_bytes(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        out.push(TX_ENCODING_VERSION);
        out.push(self.kind.consensus_code());
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        append_bytes(&mut out, self.from.as_bytes())?;
        out.extend_from_slice(&self.nonce.to_be_bytes());
        append_bytes(&mut out, self.to.as_bytes())?;
        out.extend_from_slice(&self.token_id.to_be_bytes());
        out.extend_from_slice(&self.value.to_be_bytes());
        out.extend_from_slice(&self.gas.to_be_bytes());
        out.extend_from_slice(&self.fee_quarks.to_be_bytes());
        out.extend_from_slice(&self.max_fee_per_gas.to_be_bytes());
        out.extend_from_slice(&self.valid_after_slot.to_be_bytes());
        out.extend_from_slice(&self.fee_token_id.to_be_bytes());

        if self.kind == TxKind::RegisterValidator {
            let (validator_pubkey, reward_address) = registration_fields(&self.data)?;
            out.push(1);
            append_bytes(&mut out, validator_pubkey.as_bytes())?;
            append_bytes(&mut out, reward_address.as_bytes())?;
        } else {
            out.push(0);
            append_bytes(&mut out, self.data.as_bytes())?;
        }

        let signature = decode_hex_bytes(&self.signature_hex)?;
        append_bytes(&mut out, &signature)?;
        Some(out)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        if decoder.u8()? != TX_ENCODING_VERSION {
            return None;
        }
        let kind = TxKind::from_consensus_code(decoder.u8()?)?;
        let chain_id = decoder.u64()?;
        let from = decoder.string()?;
        let nonce = decoder.u64()?;
        let to = decoder.string()?;
        let token_id = decoder.u64()?;
        let value = decoder.u128()?;
        let gas = decoder.u64()?;
        let fee_quarks = decoder.u64()?;
        let max_fee_per_gas = decoder.u64()?;
        let valid_after_slot = decoder.u64()?;
        let fee_token_id = decoder.u64()?;
        let data_encoding = decoder.u8()?;
        let data = match (kind, data_encoding) {
            (TxKind::RegisterValidator, 1) => {
                let validator_pubkey = decoder.string()?;
                let reward_address = decoder.string()?;
                json!({
                    "validator_pubkey": validator_pubkey,
                    "reward_address": reward_address,
                })
                .to_string()
            }
            (TxKind::RegisterValidator, _) => return None,
            (_, 0) => decoder.string()?,
            _ => return None,
        };
        let signature = decoder.bytes()?;
        if !decoder.finished() {
            return None;
        }
        let signature_hex = if signature.is_empty() {
            String::new()
        } else {
            format!("0x{}", hex::encode(signature))
        };
        Some(Self {
            chain_id,
            from,
            nonce,
            to,
            token_id,
            value,
            gas,
            fee_quarks,
            max_fee_per_gas,
            kind,
            valid_after_slot,
            fee_token_id,
            data,
            signature_hex,
        })
    }

    // This is the full transaction ID and includes the currently available signature bytes.
    // The existing signing preimage remains separate and is not a transaction ID.
    pub fn hash(&self) -> Option<Hash> {
        Some(hash_with_domain(TX_DOMAIN, &self.canonical_bytes()?))
    }
}

pub fn transaction_root(transactions: &[Tx]) -> Option<Hash> {
    if transactions.is_empty() {
        return Some(*EMPTY_TX_ROOT);
    }
    let mut preimage = Vec::with_capacity(TX_LIST_DOMAIN.len() + 8 + transactions.len() * 32);
    preimage.extend_from_slice(TX_LIST_DOMAIN);
    preimage.extend_from_slice(&u64::try_from(transactions.len()).ok()?.to_be_bytes());
    for transaction in transactions {
        preimage.extend_from_slice(&transaction.hash()?);
    }
    Some(keccak256(&preimage))
}

impl ProtocolData {
    pub fn empty() -> Self {
        Self {
            missed_proposer: None,
            fees_burned: 0,
        }
    }

    // V1 commits fee burns plus the missed validator ID when a miss block applies one.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(PROTOCOL_DATA_ENCODING_VERSION);
        out.extend_from_slice(&self.fees_burned.to_be_bytes());
        match &self.missed_proposer {
            Some(proposer) => {
                out.push(1);
                append_bytes(&mut out, proposer.as_bytes())
                    .expect("validator IDs fit the canonical u32 length");
            }
            None => out.push(0),
        }
        out
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        if decoder.u8()? != PROTOCOL_DATA_ENCODING_VERSION {
            return None;
        }
        let fees_burned = decoder.u64()?;
        let missed_proposer = match decoder.u8()? {
            0 => None,
            1 => Some(decoder.string()?),
            _ => return None,
        };
        if !decoder.finished() {
            return None;
        }
        Some(Self {
            missed_proposer,
            fees_burned,
        })
    }

    pub fn root(&self) -> Hash {
        if self == &Self::empty() {
            return *EMPTY_PROTOCOL_DATA_ROOT;
        }
        hash_with_domain(PROTOCOL_DATA_DOMAIN, &self.canonical_bytes())
    }
}

impl BlockHeader {
    // Consensus V1 field order is fixed exactly as written here. All integers are big-endian.
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

    pub fn from_canonical_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != BLOCK_HEADER_LEN {
            return None;
        }
        let mut decoder = Decoder::new(bytes);
        let header = Self {
            protocol_version: decoder.u32()?,
            chain_id: decoder.u64()?,
            slot: decoder.u64()?,
            block_kind: BlockKind::from_consensus_code(decoder.u8()?)?,
            parent_hash: decoder.hash()?,
            proposer_id: decoder.hash()?,
            ticket_id: decoder.u64()?,
            transaction_root: decoder.hash()?,
            state_root: decoder.hash()?,
            receipts_root: decoder.hash()?,
            gas_used: decoder.u64()?,
            protocol_data_root: decoder.hash()?,
        };
        decoder.finished().then_some(header)
    }

    pub fn hash(&self) -> Hash {
        hash_with_domain(BLOCK_HEADER_DOMAIN, &self.canonical_bytes())
    }
}

impl Block {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        slot: u64,
        block_kind: BlockKind,
        parent_hash: Hash,
        proposer: Option<String>,
        ticket_id: u64,
        transactions: Vec<Tx>,
        gas_used: u64,
        protocol_data: ProtocolData,
    ) -> Option<Self> {
        let proposer_id = proposer
            .as_deref()
            .map(proposer_id)
            .unwrap_or(ZERO_PROPOSER_ID);
        let header = BlockHeader {
            protocol_version: PROTOCOL_VERSION,
            chain_id: CHAIN_ID,
            slot,
            block_kind,
            parent_hash,
            proposer_id,
            ticket_id,
            transaction_root: transaction_root(&transactions)?,
            // A real deterministic state commitment requires a protocol-versioned consensus change.
            state_root: PLACEHOLDER_STATE_ROOT,
            receipts_root: *EMPTY_RECEIPTS_ROOT,
            gas_used,
            protocol_data_root: protocol_data.root(),
        };
        let block = Self {
            header,
            proposer,
            transactions,
            protocol_data,
        };
        block.validate_commitments().then_some(block)
    }

    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    pub fn slot(&self) -> u64 {
        self.header.slot
    }

    pub fn kind(&self) -> BlockKind {
        self.header.block_kind
    }

    pub fn gas_used(&self) -> u64 {
        self.header.gas_used
    }

    pub fn tx_count(&self) -> u32 {
        u32::try_from(self.transactions.len()).unwrap_or(u32::MAX)
    }

    pub fn fees_burned(&self) -> u64 {
        self.protocol_data.fees_burned
    }

    pub fn leader(&self) -> &str {
        self.proposer
            .as_deref()
            .or(self.protocol_data.missed_proposer.as_deref())
            .unwrap_or("protocol")
    }

    pub fn transaction_hashes(&self) -> Option<Vec<Hash>> {
        self.transactions.iter().map(Tx::hash).collect()
    }

    pub fn validate_parent(&self, expected_parent: Hash) -> bool {
        self.header.parent_hash == expected_parent
    }

    pub fn validate_commitments(&self) -> bool {
        let Some(expected_transaction_root) = transaction_root(&self.transactions) else {
            return false;
        };
        if self.header.protocol_version != PROTOCOL_VERSION
            || self.header.chain_id != CHAIN_ID
            || self.header.state_root != PLACEHOLDER_STATE_ROOT
            || self.header.receipts_root != *EMPTY_RECEIPTS_ROOT
            || self.header.transaction_root != expected_transaction_root
            || self.header.protocol_data_root != self.protocol_data.root()
        {
            return false;
        }

        let Some(gas_used) = self
            .transactions
            .iter()
            .try_fold(0_u64, |total, tx| total.checked_add(tx.gas))
        else {
            return false;
        };
        let Some(fees_burned) = self
            .transactions
            .iter()
            .try_fold(0_u64, |total, tx| total.checked_add(tx.fee_quarks))
        else {
            return false;
        };
        if gas_used != self.header.gas_used || fees_burned != self.protocol_data.fees_burned {
            return false;
        }
        if self.transactions.len() > MAX_BLOCK_TRANSACTIONS || gas_used > MAX_BLOCK_GAS {
            return false;
        }
        if self
            .transactions
            .iter()
            .any(|tx| tx.chain_id != CHAIN_ID || tx.valid_after_slot > self.header.slot)
        {
            return false;
        }

        match self.header.block_kind {
            BlockKind::Validator => {
                let Some(proposer) = self.proposer.as_deref() else {
                    return false;
                };
                self.header.proposer_id == proposer_id(proposer)
                    && self.header.proposer_id != ZERO_PROPOSER_ID
                    && self.header.ticket_id != ZERO_TICKET_ID
                    && self.protocol_data.missed_proposer.is_none()
            }
            BlockKind::ProtocolMiss => {
                self.proposer.is_none()
                    && self.header.proposer_id == ZERO_PROPOSER_ID
                    && self.header.ticket_id == ZERO_TICKET_ID
                    && self
                        .protocol_data
                        .missed_proposer
                        .as_deref()
                        .is_some_and(|id| !id.is_empty() && id != "protocol")
                    && self.transactions.is_empty()
            }
            BlockKind::ProtocolNoTickets => {
                self.proposer.is_none()
                    && self.header.proposer_id == ZERO_PROPOSER_ID
                    && self.header.ticket_id == ZERO_TICKET_ID
                    && self.protocol_data.missed_proposer.is_none()
                    && self.transactions.len() <= 1
            }
            BlockKind::ProtocolCollision => {
                self.proposer.is_none()
                    && self.header.proposer_id == ZERO_PROPOSER_ID
                    && self.header.ticket_id == ZERO_TICKET_ID
                    && self.protocol_data.missed_proposer.is_none()
                    && self.transactions.is_empty()
            }
        }
    }

    // This framing is only the current UDP transport. The consensus identity remains header.hash().
    pub fn wire_bytes(&self) -> Option<Vec<u8>> {
        if !self.validate_commitments() {
            return None;
        }
        let mut out = Vec::new();
        out.push(BLOCK_WIRE_VERSION);
        out.extend_from_slice(&self.hash());
        out.extend_from_slice(&self.header.canonical_bytes());
        append_bytes(
            &mut out,
            self.proposer.as_deref().unwrap_or_default().as_bytes(),
        )?;
        let protocol_data = self.protocol_data.canonical_bytes();
        append_bytes(&mut out, &protocol_data)?;
        out.extend_from_slice(&u64::try_from(self.transactions.len()).ok()?.to_be_bytes());
        for transaction in &self.transactions {
            let transaction = transaction.canonical_bytes()?;
            append_bytes(&mut out, &transaction)?;
        }
        Some(out)
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        if decoder.u8()? != BLOCK_WIRE_VERSION {
            return None;
        }
        let claimed_hash = decoder.hash()?;
        let header = BlockHeader::from_canonical_bytes(decoder.take(BLOCK_HEADER_LEN)?)?;
        let proposer = match decoder.string()? {
            value if value.is_empty() => None,
            value => Some(value),
        };
        let protocol_data = ProtocolData::from_canonical_bytes(decoder.bytes()?)?;
        let transaction_count = usize::try_from(decoder.u64()?).ok()?;
        if transaction_count > MAX_BLOCK_TRANSACTIONS {
            return None;
        }
        let mut transactions = Vec::with_capacity(transaction_count);
        for _ in 0..transaction_count {
            transactions.push(Tx::from_canonical_bytes(decoder.bytes()?)?);
        }
        if !decoder.finished() {
            return None;
        }
        let block = Self {
            header,
            proposer,
            transactions,
            protocol_data,
        };
        (block.hash() == claimed_hash && block.validate_commitments()).then_some(block)
    }
}

pub fn historical_block_hash(blocks: &HashMap<u64, Block>, slot: u64) -> Option<Hash> {
    if slot < crate::leader_selection::BLOCK_HASH_LOOKBACK_SLOTS {
        return Some(*GENESIS_HASH);
    }
    blocks
        .get(&crate::leader_selection::historical_block_slot(slot))
        .map(Block::hash)
}

fn registration_fields(data: &str) -> Option<(String, String)> {
    let value: Value = serde_json::from_str(data).ok()?;
    Some((
        value.get("validator_pubkey")?.as_str()?.to_string(),
        value.get("reward_address")?.as_str()?.to_string(),
    ))
}

fn decode_hex_bytes(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() {
        return Some(Vec::new());
    }
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    hex::decode(value).ok()
}

fn append_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
    let len = u32::try_from(bytes.len()).ok()?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Some(())
}

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
        let value = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(value)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(*self.take(1)?.first()?)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }

    fn u128(&mut self) -> Option<u128> {
        Some(u128::from_be_bytes(self.take(16)?.try_into().ok()?))
    }

    fn hash(&mut self) -> Option<Hash> {
        self.take(32)?.try_into().ok()
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let len = usize::try_from(self.u32()?).ok()?;
        self.take(len)
    }

    fn string(&mut self) -> Option<String> {
        String::from_utf8(self.bytes()?.to_vec()).ok()
    }

    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> BlockHeader {
        BlockHeader {
            protocol_version: PROTOCOL_VERSION,
            chain_id: CHAIN_ID,
            slot: 42,
            block_kind: BlockKind::Validator,
            parent_hash: [0x11; 32],
            proposer_id: [0x22; 32],
            ticket_id: 7,
            transaction_root: [0x33; 32],
            state_root: PLACEHOLDER_STATE_ROOT,
            receipts_root: [0x44; 32],
            gas_used: 21_000,
            protocol_data_root: [0x55; 32],
        }
    }

    fn sample_tx(nonce: u64) -> Tx {
        Tx {
            chain_id: CHAIN_ID,
            from: "0x1111111111111111111111111111111111111111".to_string(),
            nonce,
            to: "0x2222222222222222222222222222222222222222".to_string(),
            token_id: 3,
            value: 999,
            gas: 21_000,
            fee_quarks: 42_000,
            max_fee_per_gas: 2,
            kind: TxKind::Transfer,
            valid_after_slot: 0,
            fee_token_id: 0,
            data: "0x0102".to_string(),
            signature_hex: "0xaabb".to_string(),
        }
    }

    fn validator_block(parent_hash: Hash, slot: u64) -> Block {
        Block::new(
            slot,
            BlockKind::Validator,
            parent_hash,
            Some("val-0001".to_string()),
            7,
            Vec::new(),
            0,
            ProtocolData::empty(),
        )
        .unwrap()
    }

    fn protocol_block(parent_hash: Hash, slot: u64) -> Block {
        Block::new(
            slot,
            BlockKind::ProtocolNoTickets,
            parent_hash,
            None,
            ZERO_TICKET_ID,
            Vec::new(),
            0,
            ProtocolData::empty(),
        )
        .unwrap()
    }

    #[test]
    fn same_header_has_same_canonical_bytes_and_hash() {
        let first = sample_header();
        let second = first.clone();
        assert_eq!(first.canonical_bytes(), second.canonical_bytes());
        assert_eq!(first.hash(), second.hash());
    }

    #[test]
    fn canonical_header_round_trip_preserves_hash() {
        let header = sample_header();
        let canonical = header.canonical_bytes();
        let decoded = BlockHeader::from_canonical_bytes(&canonical).unwrap();
        assert_eq!(decoded.canonical_bytes(), canonical);
        assert_eq!(decoded.hash(), header.hash());
    }

    #[test]
    fn every_header_field_changes_the_hash() {
        let base = sample_header();
        let base_hash = base.hash();

        let mut changed = base.clone();
        changed.protocol_version += 1;
        assert_ne!(changed.hash(), base_hash);
        let mut changed = base.clone();
        changed.chain_id += 1;
        assert_ne!(changed.hash(), base_hash);
        let mut changed = base.clone();
        changed.slot += 1;
        assert_ne!(changed.hash(), base_hash);
        let mut changed = base.clone();
        changed.block_kind = BlockKind::ProtocolMiss;
        assert_ne!(changed.hash(), base_hash);
        let mut changed = base.clone();
        changed.parent_hash[0] ^= 1;
        assert_ne!(changed.hash(), base_hash);
        let mut changed = base.clone();
        changed.proposer_id[0] ^= 1;
        assert_ne!(changed.hash(), base_hash);
        let mut changed = base.clone();
        changed.ticket_id += 1;
        assert_ne!(changed.hash(), base_hash);
        let mut changed = base.clone();
        changed.transaction_root[0] ^= 1;
        assert_ne!(changed.hash(), base_hash);
        let mut changed = base.clone();
        changed.state_root[0] ^= 1;
        assert_ne!(changed.hash(), base_hash);
        let mut changed = base.clone();
        changed.receipts_root[0] ^= 1;
        assert_ne!(changed.hash(), base_hash);
        let mut changed = base.clone();
        changed.gas_used += 1;
        assert_ne!(changed.hash(), base_hash);
        let mut changed = base;
        changed.protocol_data_root[0] ^= 1;
        assert_ne!(changed.hash(), base_hash);
    }

    #[test]
    fn transaction_content_and_order_change_commitments() {
        let first = sample_tx(1);
        let mut changed = first.clone();
        changed.value += 1;
        assert_ne!(first.hash(), changed.hash());
        assert_ne!(
            transaction_root(std::slice::from_ref(&first)),
            transaction_root(std::slice::from_ref(&changed))
        );

        let second = sample_tx(2);
        assert_ne!(
            transaction_root(std::slice::from_ref(&first)),
            transaction_root(&[first.clone(), second.clone()])
        );
        assert_ne!(
            transaction_root(&[first.clone(), second.clone()]),
            transaction_root(&[second, first])
        );
    }

    #[test]
    fn canonical_transaction_round_trip_preserves_id() {
        let transaction = sample_tx(4);
        let bytes = transaction.canonical_bytes().unwrap();
        let decoded = Tx::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, transaction);
        assert_eq!(decoded.hash(), transaction.hash());
    }

    #[test]
    fn registration_json_format_does_not_change_transaction_id() {
        let mut first = sample_tx(5);
        first.kind = TxKind::RegisterValidator;
        first.data = r#"{"validator_pubkey":"0x0102","reward_address":"0x0304"}"#.to_string();
        let mut second = first.clone();
        second.data = r#"{ "reward_address": "0x0304", "validator_pubkey": "0x0102" }"#.to_string();
        assert_eq!(first.canonical_bytes(), second.canonical_bytes());
        assert_eq!(first.hash(), second.hash());
    }

    #[test]
    fn malformed_signature_has_no_transaction_id() {
        let mut transaction = sample_tx(6);
        transaction.signature_hex = "not-hex".to_string();
        assert!(transaction.canonical_bytes().is_none());
        assert!(transaction.hash().is_none());
    }

    #[test]
    fn block_rejects_foreign_chain_or_immature_transactions() {
        let mut foreign = sample_tx(7);
        foreign.chain_id = CHAIN_ID + 1;
        assert!(
            Block::new(
                10,
                BlockKind::Validator,
                [1; 32],
                Some("val-0001".to_string()),
                7,
                vec![foreign],
                21_000,
                ProtocolData {
                    missed_proposer: None,
                    fees_burned: 42_000,
                },
            )
            .is_none()
        );

        let mut immature = sample_tx(8);
        immature.valid_after_slot = 11;
        assert!(
            Block::new(
                10,
                BlockKind::Validator,
                [1; 32],
                Some("val-0001".to_string()),
                7,
                vec![immature],
                21_000,
                ProtocolData {
                    missed_proposer: None,
                    fees_burned: 42_000,
                },
            )
            .is_none()
        );
    }

    #[test]
    fn protocol_data_root_commits_to_all_current_fields() {
        let empty = ProtocolData::empty();
        let with_fees = ProtocolData {
            missed_proposer: None,
            fees_burned: 1,
        };
        let with_miss = ProtocolData {
            missed_proposer: Some("val-0001".to_string()),
            fees_burned: 0,
        };
        assert_eq!(empty.root(), *EMPTY_PROTOCOL_DATA_ROOT);
        assert_ne!(empty.root(), with_fees.root());
        assert_ne!(empty.root(), with_miss.root());
        assert_ne!(with_fees.root(), with_miss.root());
    }

    #[test]
    fn empty_transaction_root_uses_the_canonical_list_algorithm() {
        let mut preimage = Vec::from(TX_LIST_DOMAIN);
        preimage.extend_from_slice(&0_u64.to_be_bytes());
        assert_eq!(transaction_root(&[]), Some(*EMPTY_TX_ROOT));
        assert_eq!(*EMPTY_TX_ROOT, keccak256(&preimage));
        assert_eq!(transaction_root(&[]), transaction_root(&[]));
    }

    #[test]
    fn current_state_root_is_exactly_zero() {
        let block = validator_block(ZERO_HASH, 0);
        assert_eq!(PLACEHOLDER_STATE_ROOT, [0_u8; 32]);
        assert_eq!(block.header.state_root, [0_u8; 32]);
        assert_eq!(block.header.parent_hash, ZERO_HASH);
        assert_ne!(*EMPTY_RECEIPTS_ROOT, PLACEHOLDER_STATE_ROOT);
    }

    #[test]
    fn validator_and_protocol_kinds_have_distinct_hashes() {
        let validator = validator_block(ZERO_HASH, 0);
        let protocol = protocol_block(ZERO_HASH, 0);
        assert_ne!(validator.hash(), protocol.hash());
    }

    #[test]
    fn protocol_block_construction_is_deterministic() {
        let first = protocol_block([9; 32], 91);
        let second = protocol_block([9; 32], 91);
        assert_eq!(first, second);
        assert_eq!(first.hash(), second.hash());
        assert_eq!(first.header.transaction_root, *EMPTY_TX_ROOT);
        assert_eq!(first.header.protocol_data_root, *EMPTY_PROTOCOL_DATA_ROOT);
    }

    #[test]
    fn parent_linkage_uses_the_computed_parent_hash() {
        let parent = protocol_block(ZERO_HASH, 0);
        let child = validator_block(parent.hash(), 1);
        assert!(child.validate_parent(parent.hash()));
        assert!(!child.validate_parent([0xff; 32]));
        assert_eq!(child.header.parent_hash, parent.hash());
    }

    #[test]
    fn lookback_uses_canonical_block_hash_and_genesis_fallback() {
        let ancestor = protocol_block([0xaa; 32], 32);
        let mut blocks = HashMap::new();
        blocks.insert(32, ancestor.clone());

        assert_eq!(historical_block_hash(&blocks, 31), Some(*GENESIS_HASH));
        assert_eq!(historical_block_hash(&blocks, 64), Some(ancestor.hash()));
        assert_ne!(ancestor.hash(), *GENESIS_HASH);
    }

    #[test]
    fn genesis_lookback_hash_is_frozen() {
        assert_eq!(
            format_hash(&GENESIS_HASH),
            "0x8c075fc48e4644553a028fa2040f5c5313d8eaaad779f3ffde384c6697512d24"
        );
    }

    #[test]
    fn integers_are_serialized_big_endian() {
        let header = sample_header();
        let bytes = header.canonical_bytes();
        assert_eq!(&bytes[0..4], &1_u32.to_be_bytes());
        assert_eq!(&bytes[4..12], &CHAIN_ID.to_be_bytes());
        assert_eq!(&bytes[12..20], &42_u64.to_be_bytes());
        assert_eq!(&bytes[85..93], &7_u64.to_be_bytes());
        assert_eq!(&bytes[189..197], &21_000_u64.to_be_bytes());
    }

    #[test]
    fn invalid_block_kind_encoding_is_rejected() {
        let mut bytes = sample_header().canonical_bytes();
        bytes[20] = 0xff;
        assert!(BlockHeader::from_canonical_bytes(&bytes).is_none());
    }

    #[test]
    fn protocol_blocks_reject_nonzero_proposer_or_ticket() {
        let block = protocol_block(ZERO_HASH, 0);
        let mut bad_proposer = block.clone();
        bad_proposer.header.proposer_id = [1; 32];
        assert!(!bad_proposer.validate_commitments());

        let mut bad_ticket = block;
        bad_ticket.header.ticket_id = 1;
        assert!(!bad_ticket.validate_commitments());
    }

    #[test]
    fn block_wire_round_trip_recomputes_claimed_hash() {
        let block = validator_block([3; 32], 8);
        let mut bytes = block.wire_bytes().unwrap();
        assert_eq!(Block::from_wire_bytes(&bytes), Some(block));
        bytes[1] ^= 1;
        assert!(Block::from_wire_bytes(&bytes).is_none());
    }

    #[test]
    fn validator_header_consensus_vector() {
        // version=1, chain=1162, slot=42, kind=0, parent=11*32, proposer=22*32,
        // ticket=7, tx_root=33*32, state_root=00*32, receipts=44*32,
        // gas=21000, protocol_data_root=55*32.
        let header = sample_header();
        let expected_bytes = concat!(
            "00000001",
            "000000000000048a",
            "000000000000002a",
            "00",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222222222222222222222222222",
            "0000000000000007",
            "3333333333333333333333333333333333333333333333333333333333333333",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "4444444444444444444444444444444444444444444444444444444444444444",
            "0000000000005208",
            "5555555555555555555555555555555555555555555555555555555555555555"
        );
        assert_eq!(hex::encode(header.canonical_bytes()), expected_bytes);
        assert_eq!(
            format_hash(&header.hash()),
            "0x496169a3e244e4429f3c254494f9d0bd34cb571d2b02bfed970d9d7172b69ede"
        );
    }

    #[test]
    fn protocol_header_consensus_vector() {
        // version=1, chain=1162, slot=43, kind=1, parent=aa*32, zero proposer/ticket,
        // canonical empty tx/state/receipt values, gas=0, and missed proposer val-0001.
        let block = Block::new(
            43,
            BlockKind::ProtocolMiss,
            [0xaa; 32],
            None,
            ZERO_TICKET_ID,
            Vec::new(),
            0,
            ProtocolData {
                missed_proposer: Some("val-0001".to_string()),
                fees_burned: 0,
            },
        )
        .unwrap();
        assert_eq!(
            hex::encode(block.header.canonical_bytes()),
            concat!(
                "00000001000000000000048a000000000000002b01",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000",
                "184b8280ae263c33e0f0c662a002c933ccc51e032b947f9e9280a75c21a13a21",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "a9aba5369d9222f6156f71278ba3c938810cc6702efc58814f9facfa3057d94b",
                "0000000000000000",
                "5d003cf5a6fb3abf8de94d2b58aa4f54a01123bb7cd46709125aa7444ccffe54"
            )
        );
        assert_eq!(
            format_hash(&block.hash()),
            "0xe7df1a033be02ecce137169ecb204e9ffc8614b3ca228806d5dd2d38369e11b8"
        );
    }
}
