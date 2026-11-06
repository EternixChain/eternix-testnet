//! Exact closed C1 initialization. The independent full descriptor, not an anchor header, binds N.
use super::*;
use crate::block_authentication::ProducerBinding;
use crate::block_commitment::{
    BlockHeader, BlockKind, EMPTY_RECEIPTS_ROOT, EMPTY_TX_ROOT, ProtocolData, keccak256,
    proposer_id,
};
use std::sync::Arc;

/// Literal descriptor (including its final zero), not a production genesis/signing standard.
pub const GENESIS_DESCRIPTOR: &[u8] = b"ETERNIX_POASH_C1_GENESIS\0";
/// Initial C1 state codec is bounded independently of existing profiles and SQL schemas.
pub const MAX_GENESIS_BYTES: usize = 16 * 1024;

/// Explicit independent public association, logically separate from owner/reward accounts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatorConfig {
    /// Exact C1 identity; no trimming, case folding or discovery.
    pub id: String,
    /// Full canonical SEC1 point, not a recovered arbitrary address.
    pub public_key: [u8; 33],
    /// Native spending authority for future supported operations, not producer authority.
    pub owner: Address,
    /// Public metadata; C1 rewards go into the vault, not directly to this account.
    pub reward: Address,
    /// Explicit supplied synthetic collateral; validated against the approved fixture.
    pub initial_vault: u128,
}

/// Complete caller-supplied initialization input. Only run/reset label is variable in this closed
/// fixture; literal public points/allocations are the approved test inputs, not deployment defaults.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenesisInput {
    /// Fresh explicit ASCII label; changing it changes the canonical-genesis network identity.
    pub run_id: String,
    /// Explicit Alice/Bob/Carol rows; input order does not choose the byte order.
    pub accounts: Vec<Account>,
    /// Explicit two-validator registry, independent of all candidate headers.
    pub validators: Vec<ValidatorConfig>,
    /// Explicit initial active tickets1/255 and their exact owners/home buckets.
    pub tickets: Vec<Ticket>,
}

/// Retained initial annual record. C1 application uses this fixed amount; no year-boundary engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct YearZero {
    /// Independently approved post-initialization supply, not current snapshot supply.
    pub supply: u128,
    /// Exact first-year rate numerator.
    pub numerator: u128,
    /// Exact first-year rate denominator, not a rounded parts-per-billion value.
    pub denominator: u128,
    /// Whole-quark amount retained for year-index0.
    pub reward: u128,
    /// Audit remainder, neither minted nor carried.
    pub remainder: u128,
}
impl YearZero {
    pub(super) fn approved() -> Self {
        // Only genesis initialization is in scope; no general annual update/calculation engine.
        let total = INITIAL_SUPPLY * 3;
        let divisor = 50 * YEAR_SLOTS as u128;
        Self {
            supply: INITIAL_SUPPLY,
            numerator: 3,
            denominator: 50,
            reward: total / divisor,
            remainder: total % divisor,
        }
    }
    pub(super) fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&0u64.to_be_bytes()); // year index and boundary slot
        out.extend_from_slice(&0u64.to_be_bytes());
        out.extend_from_slice(&1u64.to_be_bytes());
        for n in [
            self.supply,
            self.numerator,
            self.denominator,
            self.reward,
            self.remainder,
            50 * YEAR_SLOTS as u128,
        ] {
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Policy {
    pub run_id: String,
    pub network: Hash,
    pub anchor: BlockHeader,
    pub configs: Vec<ValidatorConfig>,
    pub tickets: Vec<Ticket>,
    pub seeds: Vec<Address>,
}

/// Immutable validated synthetic genesis; N is Keccak of canonical bytes, excluding local schema,
/// secret material, peer endpoints, timers and its own computed N/G declarations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Genesis {
    pub(super) policy: Arc<Policy>,
    initial: ClosedState,
    bytes: Vec<u8>,
}
impl Genesis {
    /// Validate every approved public field, canonicalize ordered maps, and derive N once.
    pub fn new(mut input: GenesisInput) -> Result<Self, Error> {
        if input.run_id.is_empty()
            || input.run_id.len() > 64
            || !input
                .run_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Error::Profile("run label"));
        }
        if input.accounts.len() != 3 || input.validators.len() != 2 || input.tickets.len() != 2 {
            return Err(Error::Profile("closed genesis counts"));
        }
        input.accounts.sort_by_key(|a| a.address);
        input.validators.sort_by(|a, b| a.id.cmp(&b.id));
        input.tickets.sort_by_key(|t| t.id);
        let a = address("7e5f4552091a69125d5dfcb7b8c2659029395bdf");
        let b = address("6813eb9362372eef6200f3b1dbc3f819671cba69");
        let c = address("1eff47bc3a10a45d4b230b5d10e37751fe6aa718");
        let mut expected = vec![
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
                address: c,
                balance: 0,
                nonce: 0,
            },
        ];
        expected.sort_by_key(|a| a.address);
        if input.accounts != expected {
            return Err(Error::Profile("closed initial account seeds"));
        }
        for (i, (id, key, owner)) in [
            (
                "trial-A",
                "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                a,
            ),
            (
                "trial-B",
                "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
                b,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let v = &input.validators[i];
            ProducerBinding::new(&v.id, &v.public_key)
                .map_err(|_| Error::Profile("producer binding"))?;
            if v.id != id
                || hex::encode(v.public_key) != key
                || v.owner != owner
                || v.reward != owner
                || v.initial_vault != INITIAL_VAULT
            {
                return Err(Error::Profile("closed producer/collateral association"));
            }
        }
        for (t, (id, owner)) in input.tickets.iter().zip([(1, "trial-A"), (255, "trial-B")]) {
            if t.id != id
                || t.owner != owner
                || t.bucket != 3
                || t.status != TicketStatus::Active
                || t.retire_start.is_some()
                || t.retire_effective.is_some()
            {
                return Err(Error::Profile("closed initial ticket"));
            }
        }
        let anchor = anchor();
        let data = SnapshotInput {
            position: Position {
                slot: 0,
                hash: anchor.hash(),
            },
            accounts: input.accounts,
            validators: input
                .validators
                .iter()
                .map(|v| Validator {
                    id: v.id.clone(),
                    status: ValidatorStatus::Active,
                    vault: v.initial_vault,
                    locked: 0,
                    misses: 0,
                    offenses: 0,
                    produced: 0,
                    cooldown_until: None,
                })
                .collect(),
            tickets: input.tickets.clone(),
            credits: Vec::new(),
            gas_used: 0,
            fees_burned: 0,
            base_issuance: 0,
        };
        let mut bytes = Vec::from(GENESIS_DESCRIPTOR);
        bytes.extend_from_slice(&1u32.to_be_bytes());
        text(&mut bytes, &input.run_id);
        bytes.extend_from_slice(&parameters());
        bytes.extend_from_slice(&anchor.canonical_bytes());
        bytes.extend_from_slice(&2u16.to_be_bytes());
        for v in &input.validators {
            text(&mut bytes, &v.id);
            bytes.extend_from_slice(&v.public_key);
            bytes.extend_from_slice(&v.owner);
            bytes.extend_from_slice(&v.reward);
            bytes.extend_from_slice(&v.initial_vault.to_be_bytes());
        }
        // This initial payload has no N field, so N does not enter its own preimage. Snapshot IDs
        // below separately include the resulting N and are NOT the reserved header state root.
        let payload = state::encode(&data);
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&payload);
        if bytes.len() > MAX_GENESIS_BYTES {
            return Err(Error::Encoding("genesis bound"));
        }
        let seeds = data.accounts.iter().map(|a| a.address).collect();
        let policy = Arc::new(Policy {
            run_id: input.run_id,
            network: keccak256(&bytes),
            anchor,
            configs: input.validators,
            tickets: input.tickets,
            seeds,
        });
        let initial = ClosedState::checked(policy.clone(), data)?;
        Ok(Self {
            policy,
            initial,
            bytes,
        })
    }
    /// Strict exact decoding of this new descriptor only. Noncanonical order/trailing bytes fail;
    /// decoding cannot silently normalize bytes into a different network identity.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_GENESIS_BYTES {
            return Err(Error::Encoding("genesis bound"));
        }
        let mut d = Decoder { bytes, at: 0 };
        if d.take(GENESIS_DESCRIPTOR.len())? != GENESIS_DESCRIPTOR || d.u32()? != 1 {
            return Err(Error::Encoding("genesis descriptor/version"));
        }
        let run_id = d.text(64)?;
        let params = parameters();
        if d.take(params.len())? != params {
            return Err(Error::Profile("C1 parameters"));
        }
        if d.take(229)? != anchor().canonical_bytes() {
            return Err(Error::Profile("trusted anchor"));
        }
        if d.u16()? != 2 {
            return Err(Error::Profile("closed registry count"));
        }
        let mut validators = Vec::with_capacity(2);
        for _ in 0..2 {
            validators.push(ValidatorConfig {
                id: d.text(7)?,
                public_key: d.field()?,
                owner: d.field()?,
                reward: d.field()?,
                initial_vault: d.u128()?,
            });
        }
        let n = d.u32()? as usize;
        if n > MAX_GENESIS_BYTES {
            return Err(Error::Encoding("initial payload bound"));
        }
        let payload = d.take(n)?;
        // Initial rows/credits/counters have one approved shape. Decode only variable public account
        // and ticket fields; reconstructing the entire approved payload catches every fixed byte.
        let mut s = Decoder {
            bytes: payload,
            at: 0,
        };
        if s.u32()? != 1 {
            return Err(Error::Encoding("state encoding"));
        }
        s.take(40)?;
        if s.u32()? != 3 {
            return Err(Error::Profile("initial account count"));
        }
        let mut accounts = Vec::with_capacity(3);
        for _ in 0..3 {
            accounts.push(Account {
                address: s.field()?,
                balance: s.u128()?,
                nonce: s.u64()?,
            });
        }
        // Tickets are fixed by the independently reviewed closed profile, not learned from bytes
        // later skipped here. Exact final equality rejects alterations to ALL remaining fields.
        let tickets = vec![Ticket::active(1, "trial-A"), Ticket::active(255, "trial-B")];
        let g = Self::new(GenesisInput {
            run_id,
            accounts,
            validators,
            tickets,
        })?;
        if d.at != bytes.len() || g.bytes != bytes {
            return Err(Error::Encoding("noncanonical/trailing genesis"));
        }
        Ok(g)
    }
    /// Exact complete canonical descriptor, without normalization at the hash boundary.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Full-genesis startup G=N; not the anchor header hash.
    pub fn network_id(&self) -> Hash {
        self.policy.network
    }
    /// Explicit public reset label, not an incoming handshake identity.
    pub fn run_id(&self) -> &str {
        &self.policy.run_id
    }
    /// Separately typed/checked unsigned anchor; never a produced or rewarded record.
    pub fn anchor(&self) -> &BlockHeader {
        &self.policy.anchor
    }
    /// Approved immutable initial state, not a mutable account owner.
    pub fn initial_state(&self) -> &ClosedState {
        &self.initial
    }
    /// Independent static full-key registry; no candidate can install a new binding.
    pub fn validators(&self) -> &[ValidatorConfig] {
        &self.policy.configs
    }
    /// Only the retained year-index0 record is in this pure initialization boundary.
    pub fn year_zero(&self) -> YearZero {
        YearZero::approved()
    }
}

fn address(s: &str) -> Address {
    hex::decode(s)
        .expect("literal public address")
        .try_into()
        .expect("literal address width")
}
fn anchor() -> BlockHeader {
    BlockHeader {
        protocol_version: HEADER_PROFILE,
        chain_id: CHAIN_ID,
        slot: 0,
        block_kind: BlockKind::Validator,
        parent_hash: [0; 32],
        proposer_id: proposer_id("c1-anchor"),
        ticket_id: 1,
        transaction_root: *EMPTY_TX_ROOT,
        state_root: [0; 32],
        receipts_root: *EMPTY_RECEIPTS_ROOT,
        gas_used: 0,
        protocol_data_root: ProtocolData::empty().root(),
    }
}

// Widths/order are explicitly frozen and reproduced independently. No schema number, network
// self-field, deferred k/slashing/retirement policy or operating-system clock is included.
pub(super) fn parameters() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&CHAIN_ID.to_be_bytes());
    p.push(2);
    p.extend_from_slice(&1u32.to_be_bytes());
    p.extend_from_slice(&POASH_RULES.to_be_bytes());
    p.extend_from_slice(&HEADER_PROFILE.to_be_bytes());
    p.extend_from_slice(&[INNER_WIRE, OUTER_WIRE, AUTH_ENCODING]);
    p.extend_from_slice(&AUTH_RULES.to_be_bytes());
    for n in [3000u32, 2000, 2100] {
        p.extend_from_slice(&n.to_be_bytes());
    }
    for n in [
        1200u64,
        24,
        LOOKBACK,
        20,
        20,
        REWARD_HOLD_EPOCHS,
        YEAR_SLOTS,
    ] {
        p.extend_from_slice(&n.to_be_bytes());
    }
    for n in [TICKET_COST, 5, 2, 3, 50, 9, 10, 1, 200] {
        p.extend_from_slice(&n.to_be_bytes());
    }
    p.extend_from_slice(&MAX_SLOTS.to_be_bytes());
    p.extend_from_slice(&MAX_ENTRIES.to_be_bytes());
    p.extend_from_slice(&3000u32.to_be_bytes());
    p.extend_from_slice(&16_000_000u64.to_be_bytes());
    p.push(1); // supported operation mask: primitive ETX transfer only; NOT a PBM/default kind
    p
}
