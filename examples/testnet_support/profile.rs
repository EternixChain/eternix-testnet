//! Strict public fixture inputs. This test-only genesis encoding is not a consensus format change.
use eternix_testnet::authenticated_fixture::{AuthenticatedFixtureManifest, Snapshot};
use eternix_testnet::block_authentication::{BlockAuthenticationContext, ProducerBinding};
use eternix_testnet::canonical_fixture::{FixtureAdmissionGrant, FixtureManifest, Tip};
use eternix_testnet::native_block::NativeBlock;
use eternix_testnet::native_transaction::{
    AuthenticationContext, Hash, network_id_from_genesis_bytes,
};
use eternix_testnet::native_transfer::{TransferAccount, TransferState};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Per-run experiment bounds, independent of the library's unchanged 3,000-entry block limit.
pub const MAX_BLOCKS: usize = 200;
pub const MAX_TRANSACTIONS: usize = 16;
pub const MAX_PROFILE_BYTES: usize = 16 * 1024;
pub const MAX_APPROVAL_BYTES: usize = 512 * 1024;
/// P's one-byte ID yields exactly this maximum existing signed-envelope size at N=16.
pub const MAX_PACKET_BYTES: usize = 288 + 1 + 203 * MAX_TRANSACTIONS + 107;
/// Literal descriptor, including its final zero, followed by the explicit encoding below.
pub const GENESIS_DESCRIPTOR: &[u8] = b"ETERNIX_FIXTURE_GENESIS_S1\0";

/// Human-readable public profile. All fields are mandatory; unknown/duplicate fields fail decoding.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileDocument {
    pub format: String,
    pub run_id: String,
    pub chain_id: u64,
    pub native_encoding: u8,
    pub native_rules: u32,
    pub inner_wire: u8,
    pub header_profile: u32,
    pub outer_wire: u8,
    pub auth_encoding: u8,
    pub auth_rules: u32,
    pub storage_schema: u32,
    pub network_id: String,
    pub anchor_wire: String,
    pub provenance: String,
    pub accounts: [Seed; 3],
    pub seed_gas: u64,
    pub seed_burn: String,
    pub producer_id: String,
    pub producer_key: String,
    pub max_blocks: u64,
    pub max_transactions: u32,
}

/// Ordered Alice/Bob/Carol public seeds; balances are canonical decimal strings, never floats.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Seed {
    pub role: String,
    pub address: String,
    pub balance_quarks: String,
    pub nonce: u64,
}

/// Parsed immutable independent authority. Only the archive owns mutable canonical state.
pub struct Profile {
    pub manifest: AuthenticatedFixtureManifest,
    pub network: Hash,
    pub genesis: Vec<u8>,
    pub run_id: String,
}

/// Read only a regular, bounded file, including one overflow-detection byte; no unbounded read_to_end.
pub fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    if !path.metadata().map_err(|_| "input file missing")?.is_file() {
        return Err("input must be a regular file".into());
    }
    let file = File::open(path).map_err(|_| "cannot open input file")?;
    if !file
        .metadata()
        .map_err(|_| "cannot inspect input file")?
        .is_file()
    {
        return Err("input must be a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read input file")?;
    if bytes.len() > maximum {
        return Err("input file exceeds byte limit".into());
    }
    Ok(bytes)
}

/// Require exact lowercase hex with no prefix/whitespace; validate length before allocating.
pub fn fixed_hex<const N: usize>(text: &str) -> Result<[u8; N], String> {
    let bytes = bounded_hex(text, N)?;
    bytes.try_into().map_err(|_| "wrong fixed hex width".into())
}

/// Bounded opaque packet bytes; decoding is not an authentication proof or approval.
pub fn bounded_hex(text: &str, maximum: usize) -> Result<Vec<u8>, String> {
    if text.len() > maximum * 2
        || !text.len().is_multiple_of(2)
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid bounded lowercase hex".into());
    }
    hex::decode(text).map_err(|_| "invalid hex".into())
}

fn text(bytes: &mut Vec<u8>, value: &str) {
    // Every caller validates <=96 bytes; test-genesis strings have an explicit BE16 byte length.
    bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

impl Profile {
    /// Load the operator's independent public profile; it is never supplied through Apply.
    pub fn load(path: &Path) -> Result<Self, String> {
        Self::from_bytes(&read_bounded(path, MAX_PROFILE_BYTES)?)
    }

    /// Validate D2 and freeze the complete deterministic genesis before constructing caller policy.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err("profile byte limit".into());
        }
        let d: ProfileDocument =
            serde_json::from_slice(bytes).map_err(|_| "invalid strict profile JSON")?;
        if d.format != "eternix-fixture-profile-v1"
            || d.run_id.is_empty()
            || d.run_id.len() > 64
            || !d
                .run_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || d.chain_id != 1162
            || (
                d.native_encoding,
                d.native_rules,
                d.inner_wire,
                d.header_profile,
                d.outer_wire,
                d.auth_encoding,
                d.auth_rules,
                d.storage_schema,
            ) != (2, 1, 2, 2, 3, 1, 1, 3)
            || d.provenance != format!("controller-fixture-S1:{}", d.run_id)
            || d.seed_gas != 0
            || d.seed_burn != "0"
            || d.producer_id != "P"
            || d.max_blocks != MAX_BLOCKS as u64
            || d.max_transactions != MAX_TRANSACTIONS as u32
        {
            return Err("unsupported S1 profile parameters".into());
        }
        let anchor_wire = bounded_hex(&d.anchor_wire, 512)?;
        let anchor =
            NativeBlock::from_wire_bytes(&anchor_wire).map_err(|_| "invalid anchor encoding")?;
        let key = fixed_hex::<33>(&d.producer_key)?;
        let binding =
            ProducerBinding::new(&d.producer_id, &key).map_err(|_| "invalid producer binding")?;
        let mut genesis = Vec::from(GENESIS_DESCRIPTOR);
        genesis.extend_from_slice(&1u32.to_be_bytes());
        text(&mut genesis, &d.run_id);
        genesis.extend_from_slice(&d.chain_id.to_be_bytes());
        genesis.push(d.native_encoding);
        genesis.extend_from_slice(&d.native_rules.to_be_bytes());
        genesis.push(d.inner_wire);
        genesis.extend_from_slice(&d.header_profile.to_be_bytes());
        genesis.extend_from_slice(&[d.outer_wire, d.auth_encoding]);
        genesis.extend_from_slice(&d.auth_rules.to_be_bytes());
        genesis.extend_from_slice(&d.storage_schema.to_be_bytes());
        genesis.extend_from_slice(&(anchor_wire.len() as u32).to_be_bytes());
        genesis.extend_from_slice(&anchor_wire);
        text(&mut genesis, &d.provenance);
        genesis.extend_from_slice(&3u16.to_be_bytes());
        let mut seeds = BTreeMap::new();
        for (i, (seed, role)) in d.accounts.iter().zip(["alice", "bob", "carol"]).enumerate() {
            let balance = if i == 0 { 1_000_000_000u128 } else { 0 };
            if seed.role != role || seed.balance_quarks != balance.to_string() || seed.nonce != 0 {
                return Err("wrong ordered D2 seed".into());
            }
            let address = fixed_hex::<20>(&seed.address)?;
            if seeds
                .insert(
                    address,
                    TransferAccount {
                        balance_quarks: balance,
                        nonce: 0,
                    },
                )
                .is_some()
            {
                return Err("duplicate seed address".into());
            }
            genesis.push(i as u8);
            genesis.extend_from_slice(&address);
            genesis.extend_from_slice(&balance.to_be_bytes());
            genesis.extend_from_slice(&seed.nonce.to_be_bytes());
        }
        genesis.extend_from_slice(&d.seed_gas.to_be_bytes());
        genesis.extend_from_slice(&0u128.to_be_bytes());
        genesis.extend_from_slice(&1u16.to_be_bytes());
        text(&mut genesis, &d.producer_id);
        genesis.extend_from_slice(&key);
        genesis.extend_from_slice(&d.max_blocks.to_be_bytes());
        genesis.extend_from_slice(&d.max_transactions.to_be_bytes());
        // Neither this computed network ID nor a self-hash enters its own preimage.
        let network = network_id_from_genesis_bytes(&genesis);
        if fixed_hex::<32>(&d.network_id)? != network {
            return Err("test-genesis network mismatch".into());
        }
        let context = AuthenticationContext::new(d.chain_id, network, d.native_rules)
            .map_err(|_| "invalid native context")?;
        let expected =
            NativeBlock::empty_fixture_anchor(&context, 0, [0; 32], "fixture-anchor".into(), 1)
                .map_err(|_| "invalid anchor recipe")?;
        if anchor != expected || anchor.wire_bytes() != anchor_wire {
            return Err("wrong literal D2 anchor".into());
        }
        let fixture = FixtureManifest::new(
            context,
            anchor,
            TransferState::new(seeds, 0, 0),
            d.provenance,
        )
        .map_err(|_| "invalid fixture manifest")?;
        let auth = BlockAuthenticationContext::new(context, d.header_profile, d.auth_rules)
            .map_err(|_| "invalid authentication context")?;
        let manifest = AuthenticatedFixtureManifest::new(fixture, auth, vec![binding])
            .map_err(|_| "invalid producer policy")?;
        Ok(Self {
            manifest,
            network,
            genesis,
            run_id: d.run_id,
        })
    }

    /// Revision zero is the explicit unsigned anchor, never an authenticated appended record.
    pub fn anchor_tip(&self) -> Tip {
        Tip {
            hash: self.manifest.fixture().anchor().hash(),
            slot: 0,
            revision: 0,
        }
    }
}

/// Independent operator-selected base and exact content/evidence identity, not packet authority.
#[derive(Clone, Copy)]
pub struct Selection {
    pub base: Tip,
    pub tip: Tip,
    pub envelope_id: Hash,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalDocument {
    format: String,
    network_id: String,
    anchor_hash: String,
    producer_id: String,
    ticket_id: u64,
    steps: Vec<StepDocument>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StepDocument {
    base: TipDocument,
    slot: u64,
    block_hash: String,
    envelope_id: String,
}

/// Exact unsigned Tip representation at the local JSON boundary.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TipDocument {
    hash: String,
    slot: u64,
    revision: u64,
}

/// Immutable finite selected sequence supplied independently through a startup file, never Apply.
pub struct Approvals(pub Vec<Selection>);
impl Approvals {
    /// Bind every selected request to independent context/anchor/base before receiving any envelope.
    pub fn load(path: &Path, p: &Profile) -> Result<Self, String> {
        let d: ApprovalDocument = serde_json::from_slice(&read_bounded(path, MAX_APPROVAL_BYTES)?)
            .map_err(|_| "invalid strict approvals JSON")?;
        if d.format != "eternix-fixture-approvals-v1"
            || fixed_hex::<32>(&d.network_id)? != p.network
            || fixed_hex::<32>(&d.anchor_hash)? != p.anchor_tip().hash
            || d.producer_id != "P"
            || d.ticket_id != 1
            || d.steps.len() > MAX_BLOCKS
        {
            return Err("wrong approval policy".into());
        }
        let mut previous = p.anchor_tip();
        let mut hashes = BTreeSet::from([previous.hash]);
        let mut ids = BTreeSet::new();
        let mut selections = Vec::with_capacity(d.steps.len());
        // Previous starts at slot/revision zero and only advances through <=200 contiguous steps.
        // These increments are therefore bounded independently of the untrusted candidate fields.
        for step in d.steps {
            let base = Tip {
                hash: fixed_hex(&step.base.hash)?,
                slot: step.base.slot,
                revision: step.base.revision,
            };
            let hash = fixed_hex::<32>(&step.block_hash)?;
            let id = fixed_hex::<32>(&step.envelope_id)?;
            if base != previous
                || step.slot != previous.slot + 1
                || !hashes.insert(hash)
                || !ids.insert(id)
            {
                return Err("noncontiguous or repeated selected identity".into());
            }
            let tip = Tip {
                hash,
                slot: step.slot,
                revision: previous.revision + 1,
            };
            selections.push(Selection {
                base,
                tip,
                envelope_id: id,
            });
            previous = tip;
        }
        Ok(Self(selections))
    }

    /// Fresh attribution is insufficient: compare every retained positive revision to caller pins.
    pub fn check_prefix(&self, snapshot: &Snapshot) -> Result<(), String> {
        if snapshot.records.len() > self.0.len() + 1 {
            return Err("archive exceeds selected prefix".into());
        }
        for (record, selected) in snapshot.records.iter().skip(1).zip(&self.0) {
            let proof = record.producer_proof().ok_or("missing append evidence")?;
            if record.tip() != selected.tip
                || proof.envelope_id() != selected.envelope_id
                || record.block().proposer() != "P"
                || record.block().header().ticket_id != 1
                || record.block().transactions().len() > MAX_TRANSACTIONS
            {
                return Err("archive differs from independently selected prefix".into());
            }
        }
        Ok(())
    }
}
impl Selection {
    /// Only independent selection fields become a grant; no envelope-derived base/H is substituted.
    pub fn grant(&self, profile: &Profile) -> FixtureAdmissionGrant {
        FixtureAdmissionGrant::explicit_offline(
            profile.manifest.fixture().context(),
            profile.anchor_tip().hash,
            self.base,
            self.tip.hash,
            self.tip.slot,
        )
    }
}
