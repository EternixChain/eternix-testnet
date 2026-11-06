//! Bounded C1 genesis, historical planning and separately owned offline application/storage.
//!
//! Historical state is independent caller authority, never learned from a candidate. Validation
//! here establishes canonical input/linkage/invariants, NOT execution provenance, finality or a
//! commit permission. Only `storage` derives canonical authority from its independently seeded,
//! audited prefix; no supplied snapshot/plan or fixture-grant conversion authorizes that owner.
mod admission;
pub mod application;
mod genesis;
mod history;
mod selection;
mod state;
pub mod storage;

pub use admission::{AdmissionPlan, AuthenticatedHeader, HeaderClaim};
pub use genesis::{
    GENESIS_DESCRIPTOR, Genesis, GenesisInput, MAX_GENESIS_BYTES, ValidatorConfig, YearZero,
};
pub use history::{HistoricalHeader, PrefixContext, SlotStartView};
pub use selection::Selection;
pub use state::{
    Account, ClosedState, Position, RewardCredit, SnapshotInput, Ticket, TicketStatus, Validator,
    ValidatorStatus,
};

use crate::native_transaction::{Address, Hash};
use std::fmt;

/// Separate experimental C1 interpretation; does not broaden fixture header profile 2.
pub const HEADER_PROFILE: u32 = 3;
/// C1 outer descriptor in the signed statement and explicit `application::Envelope` codec.
pub const OUTER_WIRE: u8 = 4;
/// C1 inner descriptor, independent of header/schema version numbers.
pub const INNER_WIRE: u8 = 4;
/// Existing compact signature encoding is retained under distinct authentication rules.
pub const AUTH_ENCODING: u8 = 1;
/// C1 signing-context/profile mapping, separate from offline authentication rules 1.
pub const AUTH_RULES: u32 = 2;
/// Approved C1 eligibility/initialization interpretation, not production activation.
pub const POASH_RULES: u32 = 1;
/// Test-only chain choice, not a finalized public genesis assignment.
pub const CHAIN_ID: u64 = 1162;
/// Finite experiment successors; no global PoAsh slot constant is changed.
pub const MAX_SLOTS: u64 = 200;
/// Finite per-body experiment budget; native library limits remain unchanged.
pub const MAX_ENTRIES: u64 = 16;
/// Explicit caller-input resource bound, not a dynamic ticket-creation rule.
pub const MAX_TICKETS: usize = 256;
/// Every possible new primitive recipient within the finite experiment, plus initial seeds.
pub const MAX_ACCOUNTS: usize = 3 + MAX_SLOTS as usize * MAX_ENTRIES as usize;
/// Confirmed random-ancestor distance; this does NOT delay the eligibility-state snapshot.
pub const LOOKBACK: u64 = 32;
/// Fixed even-quark C1 price; odd-price governance is outside this profile.
pub const TICKET_COST: u128 = 10_000_000_000_000;
/// Approved synthetic post-burn supply, not the master's public 100,000,000-ETX genesis.
pub const INITIAL_SUPPLY: u128 = 1_752_000_000_000_000;
/// Approved synthetic vault value for each of the two closed validators.
pub const INITIAL_VAULT: u128 = 60_000_000_000_000;
/// Fixed protocol-year length; only the initial retained record is represented in P2.1.
pub const YEAR_SLOTS: u64 = 10_512_000;
/// Four-epoch hold is recorded without implementing a release/maturity transition.
pub const REWARD_HOLD_EPOCHS: u64 = 4;

/// Distinguishable boundary failures; no failure is interpreted as zero eligibility or a miss.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Fixed codec/resource input limit or malformed representation.
    Encoding(&'static str),
    /// Input is outside the approved closed synthetic genesis or C1 profile.
    Profile(&'static str),
    /// Duplicate ordered-map identity; canonicalization never silently overwrites a row.
    Duplicate(&'static str),
    /// Snapshot invariant failure, without applying or repairing an economic transition.
    State(&'static str),
    /// An ACTIVE validator cannot be admitted with insufficient backing.
    InsufficientCollateral(String),
    /// Caller did not supply the required ancestor/link; no genesis/zero-hash fallback exists.
    MissingHistory(u64),
    /// Header, post-state position, parent or independent genesis association differs.
    Context(&'static str),
    /// No unimplemented profile/slot/outcome is assigned a default interpretation.
    ExperimentLimit,
    /// Genuine empty validated eligibility set; distinct from every invalid/missing input.
    NoEligibleTickets,
    /// Exact producer is not in the independent closed key registry.
    UnknownProducer,
    /// Existing canonical signature parsing/recovery failed.
    Signature(crate::native_transaction::Error),
    /// Signature verifies/recoveries to a key other than the independently bound producer.
    KeyMismatch,
    /// Correct attribution does not confer selected-producer/ticket permission.
    NotSelected,
    /// A privately built plan cannot be reused with another view or candidate proof.
    PlanMismatch,
    /// Checked counters, totals or selection retry index cannot be represented.
    Overflow,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pure C1 eligibility: {self:?}")
    }
}
impl std::error::Error for Error {}

fn text(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}
fn optional(out: &mut Vec<u8>, n: Option<u64>) {
    match n {
        None => out.push(0),
        Some(n) => {
            out.push(1);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

// A deliberately small decoder for the new public-genesis codec only. Bounds precede allocation;
// existing native/block/fixture decoders are neither reused with new meanings nor modified.
struct Decoder<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Decoder<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).ok_or(Error::Overflow)?;
        let b = self
            .bytes
            .get(self.at..end)
            .ok_or(Error::Encoding("truncation"))?;
        self.at = end;
        Ok(b)
    }
    fn field<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::Encoding("field"))
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.field()?))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.field()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.field()?))
    }
    fn u128(&mut self) -> Result<u128, Error> {
        Ok(u128::from_be_bytes(self.field()?))
    }
    fn text(&mut self, max: usize) -> Result<String, Error> {
        let n = self.u16()? as usize;
        if n > max {
            return Err(Error::Encoding("text bound"));
        }
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| Error::Encoding("text UTF-8"))
    }
}

#[cfg(test)]
mod tests;
