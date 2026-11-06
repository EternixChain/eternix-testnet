//! Immutable typed C1 snapshots. Checks are input invariants, not an economic transition engine.
use super::*;
use crate::block_commitment::hash_with_domain;
use genesis::Policy;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Exact historical position supplied independently of the candidate; no local SQL revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Position {
    /// Canonical inclusion slot, anchor zero.
    pub slot: u64,
    /// Computed header H, not E-ID or an advertised height.
    pub hash: Hash,
}
/// Native account row only; no wallet, pending nonce or fee override.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Account {
    /// Raw address key.
    pub address: Address,
    /// ETX quarks.
    pub balance: u128,
    /// Canonical native nonce.
    pub nonce: u64,
}
/// Canonical lifecycle categories; no prototype flag/bucket contradictions are normalized away.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ValidatorStatus {
    /// Eligible only with sufficient backing and active tickets.
    Active = 0,
    /// Ineligible independently of current key attribution.
    PausedLowVault = 1,
    /// Ineligible while the supplied punishment state persists.
    Cooldown = 2,
    /// Ineligible closed identity; no activation transition is implemented here.
    Inactive = 3,
    /// Ineligible; all owned tickets must be DEAD.
    Jailed = 4,
}
/// Runtime fields for an independently fixed genesis identity/key association.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Validator {
    /// Exact independent ID.
    pub id: String,
    /// Authoritative supplied lifecycle status, not inferred from a signature.
    pub status: ValidatorStatus,
    /// Total slashable vault, including locked rewards.
    pub vault: u128,
    /// Locked subset, reconciled to supplied credits.
    pub locked: u128,
    /// Recorded counter; no decay/penalty is applied by validation.
    pub misses: u32,
    /// Recorded counter; no slash is applied here.
    pub offenses: u32,
    /// Accepted validator participation within this first sub-epoch.
    pub produced: u64,
    /// Supplied metadata only, never advanced using wall time.
    pub cooldown_until: Option<u64>,
}
/// Ticket lifecycle and physical bucket must agree with the owner status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TicketStatus {
    /// Selectable only for an ACTIVE owner.
    Active = 0,
    /// Temporarily ineligible, bucket1.
    Muted = 1,
    /// Permanently ineligible, bucket0.
    Dead = 2,
    /// Exiting/ineligible, bucket1; no retirement operation is implemented.
    Retiring = 3,
}
/// Globally unique ticket and exact ownership; C1's public state retains its two closed identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ticket {
    /// Nonzero global ID.
    pub id: u64,
    /// Exact validator registry ID.
    pub owner: String,
    /// Physical category/active bucket.
    pub bucket: u8,
    /// Lifecycle, independent of container order.
    pub status: TicketStatus,
    /// Supplied exit metadata, not an implicit start rule.
    pub retire_start: Option<u64>,
    /// Supplied exit metadata; no e+2 rule is invented.
    pub retire_effective: Option<u64>,
}
impl Ticket {
    /// Construct explicit active input, still unvalidated until the closed snapshot constructor.
    pub fn active(id: u64, owner: &str) -> Self {
        Self {
            id,
            owner: owner.into(),
            bucket: home_bucket(id),
            status: TicketStatus::Active,
            retire_start: None,
            retire_effective: None,
        }
    }
}
/// One retained earning event; C1 records its hold without executing deferred maturity/unlocks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RewardCredit {
    /// Earning slot identifies one event, not a delivery receipt.
    pub slot: u64,
    /// Exact validator receiving the vault liability.
    pub validator: String,
    /// Whole quarks; reconciles to the locked vault subset.
    pub amount: u128,
}
/// Explicit complete input for the supported C1 snapshot projection. Other burn/issuance kinds and
/// epoch/year transitions cannot be represented as executable defaults in this restricted type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotInput {
    /// Position after the complete parent transition.
    pub position: Position,
    /// Full native account projection, not a pending balance mirror.
    pub accounts: Vec<Account>,
    /// Runtime closed registry rows, keys remain in independent genesis.
    pub validators: Vec<Validator>,
    /// Closed ticket identities/lifecycle rows.
    pub tickets: Vec<Ticket>,
    /// Unreleased credits, all still held during slots0..200.
    pub credits: Vec<RewardCredit>,
    /// Cumulative actual native gas.
    pub gas_used: u64,
    /// Cumulative native ETX fees, not ticket/slash burns.
    pub fees_burned: u128,
    /// Supplied cumulative base issuance, validated against participation/record.
    pub base_issuance: u128,
}

/// Immutable checked snapshot and exact local comparison identity. Its ID is NOT an implemented
/// header state-root/checkpoint proof; historical execution provenance remains caller authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosedState {
    pub(super) policy: Arc<Policy>,
    pub(super) data: SnapshotInput,
    bytes: Vec<u8>,
    id: Hash,
}
impl ClosedState {
    /// Validate an independently supplied post-parent snapshot; never call with peer-provided
    /// eligibility claims. Structural/accounting checks do not establish reachability by execution.
    pub fn from_trusted_snapshot(genesis: &Genesis, input: SnapshotInput) -> Result<Self, Error> {
        Self::checked(genesis.policy.clone(), input)
    }
    pub(super) fn checked(policy: Arc<Policy>, mut data: SnapshotInput) -> Result<Self, Error> {
        if data.position.slot > MAX_SLOTS
            || data.accounts.len() > MAX_ACCOUNTS
            || data.accounts.len() < 3
            || data.validators.len() != 2
            || data.tickets.len() != 2
            || data.credits.len() > MAX_SLOTS as usize
        {
            return Err(Error::State("C1 snapshot bounds"));
        }
        data.accounts.sort_by_key(|a| a.address);
        data.validators.sort_by(|a, b| a.id.cmp(&b.id));
        data.tickets.sort_by_key(|t| t.id);
        data.credits.sort_by_key(|c| c.slot);
        if data
            .accounts
            .windows(2)
            .any(|p| p[0].address == p[1].address)
        {
            return Err(Error::Duplicate("account"));
        }
        validate_eligibility(&data.validators, &data.tickets)?;
        for (v, c) in data.validators.iter().zip(&policy.configs) {
            if v.id != c.id {
                return Err(Error::State("closed validator identity"));
            }
        }
        for (t, initial) in data.tickets.iter().zip(&policy.tickets) {
            if t.id != initial.id || t.owner != initial.owner {
                return Err(Error::State("closed ticket identity/ownership"));
            }
        }
        if data.gas_used > MAX_SLOTS * MAX_ENTRIES * 1000
            || !data.gas_used.is_multiple_of(1000)
            || data.fees_burned != data.gas_used as u128 * 10
        {
            return Err(Error::State("native cumulative gas/fees"));
        }
        let mut supply = 0u128;
        let mut nonce_sum = 0u64;
        for a in &data.accounts {
            supply = supply.checked_add(a.balance).ok_or(Error::Overflow)?;
            nonce_sum = nonce_sum.checked_add(a.nonce).ok_or(Error::Overflow)?;
        }
        if nonce_sum != data.gas_used / 1000 {
            return Err(Error::State("canonical nonce/gas total"));
        }
        let record = YearZero::approved();
        let mut produced = 0u64;
        for v in &data.validators {
            produced = produced.checked_add(v.produced).ok_or(Error::Overflow)?;
            supply = supply.checked_add(v.vault).ok_or(Error::Overflow)?;
        }
        if produced != data.position.slot || data.base_issuance != record.reward * produced as u128
        {
            return Err(Error::State("participation/base record"));
        }
        let expected = INITIAL_SUPPLY
            .checked_add(data.base_issuance)
            .and_then(|s| s.checked_sub(data.fees_burned))
            .ok_or(Error::Overflow)?;
        if supply != expected {
            return Err(Error::State("ETX supply conservation"));
        }
        let mut sums = BTreeMap::<&str, (u64, u128)>::new();
        let mut prior = 0;
        for c in &data.credits {
            if c.slot == 0
                || c.slot > data.position.slot
                || c.slot == prior
                || c.amount != record.reward
            {
                return Err(Error::State("earning credit slot/amount"));
            }
            prior = c.slot;
            if !policy.configs.iter().any(|v| v.id == c.validator) {
                return Err(Error::State("credit identity"));
            }
            let e = sums.entry(&c.validator).or_default();
            e.0 += 1;
            e.1 = e.1.checked_add(c.amount).ok_or(Error::Overflow)?;
        }
        if data.credits.len() as u64 != produced {
            return Err(Error::State("missing earning event"));
        }
        for v in &data.validators {
            let (n, total) = sums.get(v.id.as_str()).copied().unwrap_or_default();
            if n != v.produced || total != v.locked {
                return Err(Error::State("locked credit reconciliation"));
            }
            // C1 has no deposits, withdrawals, slashes or unlocks: retained credits are the only
            // permitted vault delta. This is a snapshot invariant, not application of a reward.
            if v.vault != INITIAL_VAULT.checked_add(total).ok_or(Error::Overflow)? {
                return Err(Error::State("C1 vault/retained credits"));
            }
        }
        // Original seeds remain represented even when zero. Reads must never manufacture accounts.
        for seed in &policy.seeds {
            if !data.accounts.iter().any(|a| a.address == *seed) {
                return Err(Error::State("initial account omitted"));
            }
        }
        let bytes = encode(&data);
        let mut pre = Vec::from(policy.network);
        pre.extend_from_slice(&bytes);
        let id = hash_with_domain(b"ETERNIX_POASH_C1_SNAPSHOT\0", &pre);
        Ok(Self {
            policy,
            data,
            bytes,
            id,
        })
    }
    /// Read-only complete supported snapshot; cloning this input cannot mutate the checked value.
    pub fn input(&self) -> &SnapshotInput {
        &self.data
    }
    /// Exact canonical comparison bytes; not a consensus wire block or SQL representation.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Network-scoped hash of the COMPLETE snapshot, including accounts and economic metadata.
    pub fn id(&self) -> Hash {
        self.id
    }
    /// Exact independently supplied post-parent position.
    pub fn position(&self) -> Position {
        self.data.position
    }
}

pub(super) fn home_bucket(id: u64) -> u8 {
    2 + (id % 254) as u8
}

// Shared checked selector input validation also supports test-only synthetic multi-bucket/count
// fixtures. The public ClosedState adds the strict two-ticket genesis-identity check above: these
// kernel fixtures do not implement or admit ticket creation into C1.
pub(super) fn validate_eligibility(
    validators: &[Validator],
    tickets: &[Ticket],
) -> Result<(), Error> {
    if validators.len() != 2 || tickets.len() > MAX_TICKETS {
        return Err(Error::State("eligibility bounds"));
    }
    let mut ids = BTreeSet::new();
    for v in validators {
        if !matches!(v.id.as_str(), "trial-A" | "trial-B") {
            return Err(Error::State("validator identity"));
        }
        if !ids.insert(v.id.as_str()) {
            return Err(Error::Duplicate("validator"));
        }
        if v.locked > v.vault {
            return Err(Error::State("locked exceeds vault"));
        }
        if (v.status == ValidatorStatus::Cooldown) != v.cooldown_until.is_some() {
            return Err(Error::State("cooldown metadata"));
        }
    }
    let mut tids = BTreeSet::new();
    for t in tickets {
        if t.id == 0 {
            return Err(Error::State("zero ticket"));
        }
        if !tids.insert(t.id) {
            return Err(Error::Duplicate("ticket"));
        }
        let v = validators
            .iter()
            .find(|v| v.id == t.owner)
            .ok_or(Error::State("ticket owner"))?;
        let bucket = match t.status {
            TicketStatus::Active => {
                if v.status != ValidatorStatus::Active {
                    return Err(Error::State("active ticket/inactive owner"));
                }
                home_bucket(t.id)
            }
            TicketStatus::Muted | TicketStatus::Retiring => 1,
            TicketStatus::Dead => 0,
        };
        if t.bucket != bucket
            || (v.status == ValidatorStatus::Jailed && t.status != TicketStatus::Dead)
        {
            return Err(Error::State("ticket category/bucket"));
        }
        match (t.retire_start, t.retire_effective) {
            (None, None) if t.status != TicketStatus::Retiring => {}
            (Some(a), Some(b)) if a < b && t.status != TicketStatus::Active => {}
            _ => return Err(Error::State("retirement metadata")),
        }
    }
    for v in validators
        .iter()
        .filter(|v| v.status == ValidatorStatus::Active)
    {
        if !tickets
            .iter()
            .any(|t| t.owner == v.id && t.status == TicketStatus::Active)
        {
            return Err(Error::State("ACTIVE validator without active ticket"));
        }
        let n = tickets
            .iter()
            .filter(|t| t.owner == v.id && t.status != TicketStatus::Dead)
            .count() as u128;
        let minimum = 5 * TICKET_COST + (TICKET_COST / 2) * n;
        if v.vault < minimum {
            return Err(Error::InsufficientCollateral(v.id.clone()));
        }
    }
    Ok(())
}

pub(super) fn encode(d: &SnapshotInput) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&d.position.slot.to_be_bytes());
    b.extend_from_slice(&d.position.hash);
    b.extend_from_slice(&(d.accounts.len() as u32).to_be_bytes());
    for a in &d.accounts {
        b.extend_from_slice(&a.address);
        b.extend_from_slice(&a.balance.to_be_bytes());
        b.extend_from_slice(&a.nonce.to_be_bytes());
    }
    b.extend_from_slice(&(d.validators.len() as u16).to_be_bytes());
    for v in &d.validators {
        text(&mut b, &v.id);
        b.push(v.status as u8);
        for n in [v.vault, v.locked] {
            b.extend_from_slice(&n.to_be_bytes());
        }
        b.extend_from_slice(&v.misses.to_be_bytes());
        b.extend_from_slice(&v.offenses.to_be_bytes());
        b.extend_from_slice(&v.produced.to_be_bytes());
        optional(&mut b, v.cooldown_until);
    }
    b.extend_from_slice(&(d.tickets.len() as u16).to_be_bytes());
    for t in &d.tickets {
        b.extend_from_slice(&t.id.to_be_bytes());
        text(&mut b, &t.owner);
        b.extend_from_slice(&[t.bucket, t.status as u8]);
        optional(&mut b, t.retire_start);
        optional(&mut b, t.retire_effective);
    }
    b.extend_from_slice(&(d.credits.len() as u16).to_be_bytes());
    for c in &d.credits {
        b.extend_from_slice(&c.slot.to_be_bytes());
        text(&mut b, &c.validator);
        b.extend_from_slice(&c.amount.to_be_bytes());
        b.extend_from_slice(&0u64.to_be_bytes());
        b.extend_from_slice(&REWARD_HOLD_EPOCHS.to_be_bytes());
    }
    b.extend_from_slice(&d.gas_used.to_be_bytes());
    for n in [d.fees_burned, 2 * TICKET_COST, d.base_issuance, 0, 0, 0, 0] {
        b.extend_from_slice(&n.to_be_bytes());
    }
    // C1 spans only year/epoch/sub-epoch0; no deferred boundary policy is smuggled in as executable.
    b.extend_from_slice(&[0; 24]);
    YearZero::approved().encode(&mut b);
    b
}
