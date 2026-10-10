//! Anchored, append-only native block projection for explicit offline fixtures, schema 2.
//! This is not live consensus admission, producer authentication, migration, or a complete checkpoint.

use crate::block_commitment::{BlockHeader, ProtocolData, hash_with_domain};
use crate::durable_fixture::{self as disk, StorageSettings, StoreError, blob};
use crate::native_block::{BlockError, MAX_PROPOSER_BYTES, MAX_TRANSACTIONS, NativeBlock};
use crate::native_transaction::{Address, AuthenticationContext, Hash, ID_DOMAIN, SIGNED_LEN};
use crate::native_transfer::{BodyError, BodyOutcome, TransferState, stage_body};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

mod schema;
#[cfg(test)]
mod tests;
const SCHEMA_VERSION: u32 = 2;
#[cfg(test)]
type Hook = Box<dyn FnMut(&str) -> Result<(), Error>>;

/// Explicit connection-local resource policy for the schema-2 offline experiment only.
/// It changes neither durable metadata nor validation/synchronization/spill policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CachePolicy {
    /// Preserve the pinned SQLite existing default (~2 MiB, PRAGMA cache_size=-2000).
    #[default]
    ExistingDefault,
    /// Authorized opt-in 32 MiB trial; not a new default or a hard process-RSS limit.
    Trial32MiB,
}
impl CachePolicy {
    /// Expected negative KiB PRAGMA value, queried after every connection configuration.
    pub const fn pragma_value(self) -> i64 {
        match self {
            Self::ExistingDefault => -2000,
            Self::Trial32MiB => -32768,
        }
    }
}
fn configure_cache(connection: &Connection, policy: CachePolicy) -> Result<(), Error> {
    // Keep the common schema-1 durability helper untouched. No cache_spill assignment is issued:
    // SQLite may naturally report a different numeric spill threshold as cache_size changes.
    disk::configure(connection)?;
    let spill_before: i64 = connection
        .query_row("PRAGMA cache_spill", [], |r| r.get(0))
        .map_err(sql)?;
    if policy == CachePolicy::Trial32MiB {
        connection
            .execute_batch("PRAGMA cache_size=-32768")
            .map_err(sql)?;
    }
    let actual: i64 = connection
        .query_row("PRAGMA cache_size", [], |r| r.get(0))
        .map_err(sql)?;
    let spill_after: i64 = connection
        .query_row("PRAGMA cache_spill", [], |r| r.get(0))
        .map_err(sql)?;
    if actual != policy.pragma_value() || (spill_before > 0) != (spill_after > 0) {
        return Err(invalid(
            "explicit cache policy/spill configuration verification failed",
        ));
    }
    Ok(())
}

/// One stored identity: slot/hash are header-derived; revision is a separate local sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tip {
    /// Exact content-derived hash.
    pub hash: Hash,
    /// Exact inclusion slot.
    pub slot: u64,
    /// Local commit sequence; the explicit anchor is revision zero.
    pub revision: u64,
}
impl Tip {
    fn at(block: &NativeBlock, revision: u64) -> Self {
        Self {
            hash: block.hash(),
            slot: block.header().slot,
            revision,
        }
    }
}

/// Deterministic stage/storage rejection with structured native body cause and position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Ordinary filesystem/SQLite errors or explicit storage recovery requirement.
    Storage(StoreError),
    /// Syntax or block preflight/post-stage failure.
    Block(BlockError),
    /// Shared authenticate-all-then-execute failure, preserving the existing cause ordering.
    Body(BodyError),
    /// No reconciled publication or staging is available.
    Blocked,
    /// Owner/recovery generation, state, revision or tip changed.
    Stale,
    /// Previously stored exact block, a no-op reference rather than a new acknowledgement.
    AlreadyCommitted(Tip),
    /// Another identity already occupies this slot; replacement is unsupported.
    SlotConflict,
    /// The slot is not the checked canonical successor.
    Slot,
    /// The parent is not the exact canonical tip hash.
    Parent,
    /// The explicit offline fixture grant does not bind this dataset/base/block.
    Grant,
    /// Slot, revision or recovery counter cannot advance representably.
    Overflow,
    /// Defense-in-depth duplicate discovered after successful native staging.
    DuplicateTransaction(usize),
    /// Persistent logical corruption/incompatibility, never repaired with defaults.
    Invalid(String),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "offline canonical fixture: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<StoreError> for Error {
    fn from(e: StoreError) -> Self {
        Self::Storage(e)
    }
}
impl From<BlockError> for Error {
    fn from(e: BlockError) -> Self {
        Self::Block(e)
    }
}
fn sql(e: rusqlite::Error) -> Error {
    disk::invalid(e).into()
}
fn invalid(message: impl fmt::Display) -> Error {
    Error::Invalid(message.to_string())
}
fn recovery_error(e: impl fmt::Display) -> Error {
    Error::Storage(StoreError::RecoveryRequired(e.to_string()))
}

/// Trusted test-only post-anchor authority. Reopen compares these immutable seeds, not current state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureManifest {
    context: AuthenticationContext,
    anchor: NativeBlock,
    initial: TransferState,
    provenance: String,
}
impl FixtureManifest {
    /// Accepts a named synthetic empty anchor and explicit post-anchor native projection/baseline.
    /// This is caller authority, not proof from the reserved state root or imported prototype values.
    pub fn new(
        context: AuthenticationContext,
        anchor: NativeBlock,
        initial: TransferState,
        provenance: String,
    ) -> Result<Self, Error> {
        anchor.preflight(&context)?;
        if provenance.is_empty()
            || !anchor.transactions().is_empty()
            || anchor.header().gas_used != 0
            || anchor.protocol_data().fees_burned != 0
            || (anchor.header().slot == 0 && anchor.header().parent_hash != [0; 32])
        {
            return Err(invalid("invalid empty fixture anchor/provenance"));
        }
        Ok(Self {
            context,
            anchor,
            initial,
            provenance,
        })
    }
    /// Exact approved fixture anchor.
    pub fn anchor(&self) -> &NativeBlock {
        &self.anchor
    }
    /// Explicit native validation context, with no production defaults.
    pub fn context(&self) -> AuthenticationContext {
        self.context
    }
    /// Immutable trusted post-anchor snapshot, never reapplied onto materialized state.
    pub fn initial_state(&self) -> &TransferState {
        &self.initial
    }
    /// Dataset authority label, independently retained from current accounts.
    pub fn provenance(&self) -> &str {
        &self.provenance
    }
}

/// Explicit fixture admission grant. It is not a producer signature or consensus authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixtureAdmissionGrant {
    context: AuthenticationContext,
    anchor: Hash,
    base: Tip,
    hash: Hash,
    slot: u64,
}
impl FixtureAdmissionGrant {
    /// Trusted offline test code/manifest must explicitly supply every binding. Never derive a
    /// grant in the receiver from its received block, or use this API as a live authorizer.
    pub fn explicit_offline(
        context: AuthenticationContext,
        anchor: Hash,
        base: Tip,
        hash: Hash,
        slot: u64,
    ) -> Self {
        Self {
            context,
            anchor,
            base,
            hash,
            slot,
        }
    }
    fn matches(
        &self,
        context: AuthenticationContext,
        anchor: Hash,
        base: Tip,
        block: &NativeBlock,
    ) -> bool {
        self.context == context
            && self.anchor == anchor
            && self.base == base
            && self.hash == block.hash()
            && self.slot == block.header().slot
    }
}

/// Exact block/body journal row in memory. Signed bytes are owned once by the block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedBlock {
    /// Content/slot and local sequence membership.
    pub tip: Tip,
    /// Exact canonical constituents, not a V1 transaction wrapper.
    pub block: NativeBlock,
    /// Shared native execution results; anchor outcome is explicitly empty.
    pub outcome: BodyOutcome,
}
/// Native transaction membership, not an implemented receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Membership {
    /// Associated content-derived block identity/slot/local revision.
    pub tip: Tip,
    /// Zero-based original body position.
    pub position: u64,
}
/// Coherent Ready projection/cache. All fields replace together after durable COMMIT/recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Materialized native accounts/accounting, not the complete prototype economy.
    pub state: TransferState,
    /// Last block, always present (initially the trusted anchor).
    pub tip: Tip,
    /// Retained archive including the anchor at index/revision zero.
    pub blocks: Vec<CommittedBlock>,
    /// ID -> exact canonical block and position.
    pub transactions: BTreeMap<Hash, Membership>,
    /// Canonical native sender/nonce uniqueness cache.
    pub sender_nonces: BTreeMap<(Address, u64), Membership>,
    /// Slot -> content-derived identity.
    pub slots: BTreeMap<u64, Hash>,
    /// Hash -> canonical local revision/slot.
    pub hashes: BTreeMap<Hash, Tip>,
}
impl Snapshot {
    fn insert_record(&mut self, record: CommittedBlock) -> Result<(), Error> {
        for (position, (bytes, id)) in record
            .block
            .transactions()
            .iter()
            .zip(&record.outcome.transaction_ids)
            .enumerate()
        {
            let member = Membership {
                tip: record.tip,
                position: u64::try_from(position).map_err(|_| Error::Overflow)?,
            };
            if self.transactions.insert(*id, member).is_some()
                || self
                    .sender_nonces
                    .insert(sender_nonce(bytes), member)
                    .is_some()
            {
                return Err(Error::DuplicateTransaction(position));
            }
        }
        if self
            .slots
            .insert(record.tip.slot, record.tip.hash)
            .is_some()
            || self.hashes.insert(record.tip.hash, record.tip).is_some()
        {
            return Err(invalid("duplicate block index"));
        }
        self.tip = record.tip;
        self.blocks.push(record);
        Ok(())
    }
}

// Fixed offsets apply only to exact 199-byte objects; authentication remains exclusively stage_body.
fn sender_nonce(bytes: &[u8; SIGNED_LEN]) -> (Address, u64) {
    (
        bytes[46..66].try_into().expect("fixed address"),
        u64::from_be_bytes(bytes[66..74].try_into().expect("fixed nonce")),
    )
}
#[derive(Debug)]
struct Base {
    generation: u64,
    context: AuthenticationContext,
    anchor: Hash,
    tip: Tip,
    state: TransferState,
}
/// Producer-prepared native execution awaiting an explicit fixture grant, never commit-capable alone.
#[derive(Debug)]
pub struct PreparedNativeBlock {
    base: Base,
    candidate: TransferState,
    record: CommittedBlock,
    stage_time: Duration,
}
impl PreparedNativeBlock {
    /// Read-only completed producer bytes/identity used by trusted fixture grant construction.
    pub fn block(&self) -> &NativeBlock {
        &self.record.block
    }
    /// Captured parent/tip, not a reservation of a future canonical slot.
    pub fn base_tip(&self) -> Tip {
        self.base.tip
    }
    /// Seals this already-executed body with explicit offline authority, without authentication again.
    pub fn authorize(self, grant: FixtureAdmissionGrant) -> Result<StagedNativeBlock, Error> {
        if !grant.matches(
            self.base.context,
            self.base.anchor,
            self.base.tip,
            &self.record.block,
        ) {
            return Err(Error::Grant);
        }
        Ok(StagedNativeBlock {
            prepared: self,
            grant,
        })
    }
}
/// Private owned candidate, consumed once by commitment; callers cannot alter state/bytes/base/grant.
#[derive(Debug)]
pub struct StagedNativeBlock {
    prepared: PreparedNativeBlock,
    grant: FixtureAdmissionGrant,
}
impl StagedNativeBlock {
    /// Inspects the exact block to be committed, not an acknowledgement.
    pub fn block(&self) -> &NativeBlock {
        &self.prepared.record.block
    }
    /// Inspects independently owned effects, never publishing them as reconciled canonical state.
    pub fn candidate(&self) -> &TransferState {
        &self.prepared.candidate
    }
}

/// Successful append timings; copying and destruction stay in the caller's complete wall path.
#[derive(Clone, Copy, Debug, Default)]
pub struct AppendTimings {
    /// Complete producer/receiver staging elapsed before commitment, including preflight where used.
    pub staging: Duration,
    /// Full in-memory base equality at commit.
    pub memory_comparison: Duration,
    /// Full-history/body/index and candidate cloning before SQL, never subtracted from pipeline.
    pub cache_preparation: Duration,
    /// Materialized SQL base read/decode/compare, also included in durable_commit.
    pub stored_comparison: Duration,
    /// BEGIN IMMEDIATE acquisition through successful EXTRA COMMIT.
    pub durable_commit: Duration,
    /// Explicit destruction of previous complete cache after durable commitment.
    pub cache_destruction: Duration,
    /// Owned new-cache installation move.
    pub installation: Duration,
    /// Optional phase observations from commit_profiled; ordinary commitment takes no extra clocks.
    pub sql_profile: Option<SqlProfile>,
}

/// Opt-in elapsed SQL phase observations. They are diagnostics, never inputs to validation,
/// rollback classification, acknowledgement, or durability. No SQL operation/check is omitted.
#[derive(Clone, Copy, Debug, Default)]
pub struct SqlProfile {
    /// BEGIN IMMEDIATE including writer-lock acquisition.
    pub acquisition: Duration,
    /// Trusted metadata and exact persisted tip checks.
    pub metadata_base: Duration,
    /// Complete materialized account/accounting read/decode/equality, also in stored_comparison.
    pub account_comparison: Duration,
    /// All existing block and per-transaction ID/sender-nonce uniqueness probes before writes.
    pub uniqueness_probes: Duration,
    /// Candidate/base changed-account determination and exactly the existing account writes.
    pub changed_account_writes: Duration,
    /// Cumulative accounting update.
    pub accounting_write: Duration,
    /// Exact block/header insertion with its indexes/FKs.
    pub block_insertion: Duration,
    /// Exact body insertion with its indexes/FKs.
    pub body_insertion: Duration,
    /// Exact signed transaction and all primary/secondary index insertion.
    pub transaction_index_insertion: Duration,
    /// Conditional revision and tip updates, including their checks.
    pub revision_tip: Duration,
    /// COMMIT return including SQLite's required synchronization; sync may also occur on spills
    /// during earlier writes, so this is not assumed to be all transaction-wide synchronization.
    pub commit_return: Duration,
}
impl SqlProfile {
    /// Sum of disjoint observed phases; aggregate durable_commit additionally contains clock,
    /// bookkeeping and test-hook overhead. Medians of phases need not sum to median total.
    pub fn observed_total(&self) -> Duration {
        self.acquisition
            + self.metadata_base
            + self.account_comparison
            + self.uniqueness_probes
            + self.changed_account_writes
            + self.accounting_write
            + self.block_insertion
            + self.body_insertion
            + self.transaction_index_insertion
            + self.revision_tip
            + self.commit_return
    }
}
/// Only Committed permits a new acknowledgement/broadcast/local cleanup action.
#[derive(Debug)]
// Keep opt-in observations inline: no new heap allocation is introduced after durable COMMIT.
#[allow(clippy::large_enum_variant)]
pub enum AppendOutcome {
    /// Durable commitment and coherent memory installation completed.
    Committed {
        tip: Tip,
        outcome: BodyOutcome,
        timings: AppendTimings,
    },
    /// This request has no committed effects; stale SQL base can require explicit refresh.
    Aborted(Error),
    /// Owner is poisoned until explicit synchronized recovery; no success/publication/retry.
    RecoveryRequired(Error),
}
/// Whole reopen/audit/recovery timing attribution, including expensive retained-history work.
#[derive(Clone, Copy, Debug, Default)]
pub struct LoadTimings {
    /// Open/configuration; fresh-owner manifest cloning is attributed to installation.
    pub open_configuration: Duration,
    /// Schema/integrity/FK/state/archive/index read/decode/rebuild, excluding timed audit/equality.
    pub validation_materialization: Duration,
    /// One combined stage_body per retained appended body, including its repeated account clones.
    pub audit: Duration,
    /// Audit/materialized state and immutable seed authority equality checks.
    pub equality: Duration,
    /// Checked dirty-page barrier plus database/directory sync.
    pub barrier: Duration,
    /// Complete old-cache destruction/new-cache installation where applicable.
    pub installation: Duration,
    /// Whole open/recover through readiness, including interleaved overhead.
    pub total: Duration,
}
/// Exact reconciliation result, never retroactive acknowledgement of a failed append.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryReport {
    /// Validated final tip.
    pub tip: Tip,
    /// Exact attempted block/body membership, not inferred from revision >= attempted revision.
    pub attempted_present: Option<bool>,
}
#[derive(Clone)]
struct Attempt {
    base: Tip,
    record: CommittedBlock,
}

/// Single serialized offline owner of state, archive, indexes, tip and recovery availability.
pub struct CanonicalFixtureStore {
    path: PathBuf,
    manifest: FixtureManifest,
    connection: Option<Connection>,
    snapshot: Snapshot,
    generation: u64,
    poisoned: bool,
    attempted: Option<Attempt>,
    load_timings: LoadTimings,
    cache_policy: CachePolicy,
    #[cfg(test)]
    hook: Option<Hook>,
    #[cfg(test)]
    vfs: Option<String>,
}
impl CanonicalFixtureStore {
    /// Exclusive new-path initialization; anchor/seeds/state/body/indexes/tip/marker share one COMMIT.
    pub fn create_anchored_fixture(
        path: impl AsRef<Path>,
        manifest: &FixtureManifest,
    ) -> Result<Self, Error> {
        Self::create_inner(path.as_ref(), manifest, None, |_| Ok(()))
    }
    /// Exclusive creation with explicit offline connection memory budget; default API is unchanged.
    pub fn create_anchored_fixture_with_cache_policy(
        path: impl AsRef<Path>,
        manifest: &FixtureManifest,
        policy: CachePolicy,
    ) -> Result<Self, Error> {
        Self::create_inner_with_cache(path.as_ref(), manifest, policy, None, |_| Ok(()))
    }
    /// Strict no-create reopening, full retained-archive audit and synchronized barrier before Ready.
    pub fn reopen(path: impl AsRef<Path>, manifest: &FixtureManifest) -> Result<Self, Error> {
        Self::load(path.as_ref(), manifest, None)
    }
    /// Strict existing-file reopen/full audit/barrier with the caller's explicit cache policy.
    pub fn reopen_with_cache_policy(
        path: impl AsRef<Path>,
        manifest: &FixtureManifest,
        policy: CachePolicy,
    ) -> Result<Self, Error> {
        Self::load_with_cache(path.as_ref(), manifest, policy, None)
    }
    /// Explicit recovery of a prior process's uncertain initialization/append; never a creator.
    pub fn recover_existing(
        path: impl AsRef<Path>,
        manifest: &FixtureManifest,
    ) -> Result<Self, Error> {
        Self::load(path.as_ref(), manifest, None)
    }
    /// Prior-process recovery with explicit policy; never initializes or promotes another schema.
    pub fn recover_existing_with_cache_policy(
        path: impl AsRef<Path>,
        manifest: &FixtureManifest,
        policy: CachePolicy,
    ) -> Result<Self, Error> {
        Self::load_with_cache(path.as_ref(), manifest, policy, None)
    }
    /// Selected resource policy, diagnostic only and blocked while canonical state is unreconciled.
    pub fn cache_policy(&self) -> Result<CachePolicy, Error> {
        self.ready()?;
        Ok(self.cache_policy)
    }
    /// Ready publication only; poisoned memory cannot be represented as canonical results.
    pub fn snapshot(&self) -> Result<&Snapshot, Error> {
        self.ready()?;
        Ok(&self.snapshot)
    }
    /// Diagnostic availability, with no success acknowledgement implied.
    pub fn is_ready(&self) -> bool {
        !self.poisoned
    }
    /// Last successful full reopen/recovery attribution, blocked until reconciliation succeeds.
    pub fn load_timings(&self) -> Result<LoadTimings, Error> {
        self.ready()?;
        Ok(self.load_timings)
    }
    /// Actual connection settings for the workload, not a weaker diagnostic connection.
    pub fn settings(&self) -> Result<StorageSettings, Error> {
        self.ready()?;
        let integer = |p| {
            self.conn()
                .query_row(&format!("PRAGMA {p}"), [], |r| r.get::<_, i64>(0))
                .map_err(sql)
        };
        Ok(StorageSettings {
            journal_mode: self
                .conn()
                .query_row("PRAGMA journal_mode", [], |r| r.get(0))
                .map_err(sql)?,
            synchronous: integer("synchronous")?,
            foreign_keys: integer("foreign_keys")? == 1,
            page_size: integer("page_size")?,
            cache_size: integer("cache_size")?,
        })
    }
    /// Producer construction reuses the shared executor once; no caller-supplied root/gas/burn claim.
    pub fn prepare_next(
        &self,
        proposer: &str,
        ticket: u64,
        body: &[Vec<u8>],
    ) -> Result<PreparedNativeBlock, Error> {
        let start = Instant::now();
        self.ready()?;
        if proposer.len() > MAX_PROPOSER_BYTES || body.len() > MAX_TRANSACTIONS {
            return Err(invalid("producer resource bound"));
        }
        if let Some(i) = body.iter().position(|b| b.len() != SIGNED_LEN) {
            return Err(BlockError::Frame {
                reason: "signed length",
                position: Some(i),
            }
            .into());
        }
        if proposer.is_empty() || proposer == "protocol" {
            return Err(BlockError::Proposer.into());
        }
        if ticket == 0 {
            return Err(BlockError::Ticket.into());
        }
        let slot = self
            .snapshot
            .tip
            .slot
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let revision = self
            .snapshot
            .tip
            .revision
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let (base, candidate, applied) =
            stage_body(&self.snapshot.state, &self.manifest.context, slot, body)
                .map_err(Error::Body)?
                .into_parts();
        let block = NativeBlock::build(
            &self.manifest.context,
            slot,
            self.snapshot.tip.hash,
            proposer.to_owned(),
            ticket,
            applied.transactions.clone(),
            &applied.outcome,
        )?;
        let ids = block.preflight(&self.manifest.context)?;
        block.match_outcome(&applied.transactions, &ids, &applied.outcome)?;
        self.check_transactions(&block, &applied.outcome)?;
        Ok(PreparedNativeBlock {
            base: self.base(base),
            candidate,
            record: CommittedBlock {
                tip: Tip::at(&block, revision),
                block,
                outcome: applied.outcome,
            },
            stage_time: start.elapsed(),
        })
    }
    /// Receiver phases 1–7: block preflight/admission, one authenticate-all-then-execute stage,
    /// identity/gas/burn consistency and finally transaction uniqueness. Commit does not repeat it.
    pub fn stage_received(
        &self,
        bytes: &[u8],
        grant: FixtureAdmissionGrant,
    ) -> Result<StagedNativeBlock, Error> {
        let start = Instant::now();
        self.ready()?;
        let block = NativeBlock::from_wire_bytes(bytes)?;
        let ids = block.preflight(&self.manifest.context)?;
        self.check_append(&block, Some(grant))?;
        let (base, candidate, applied) = stage_body(
            &self.snapshot.state,
            &self.manifest.context,
            block.header().slot,
            &block
                .transactions()
                .iter()
                .map(|b| b.to_vec())
                .collect::<Vec<_>>(),
        )
        .map_err(Error::Body)?
        .into_parts();
        block.match_outcome(&applied.transactions, &ids, &applied.outcome)?;
        self.check_transactions(&block, &applied.outcome)?;
        let revision = self
            .snapshot
            .tip
            .revision
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        Ok(StagedNativeBlock {
            prepared: PreparedNativeBlock {
                base: self.base(base),
                candidate,
                record: CommittedBlock {
                    tip: Tip::at(&block, revision),
                    block,
                    outcome: applied.outcome,
                },
                stage_time: start.elapsed(),
            },
            grant,
        })
    }
    fn base(&self, state: TransferState) -> Base {
        Base {
            generation: self.generation,
            context: self.manifest.context,
            anchor: self.manifest.anchor.hash(),
            tip: self.snapshot.tip,
            state,
        }
    }
    fn check_append(
        &self,
        block: &NativeBlock,
        grant: Option<FixtureAdmissionGrant>,
    ) -> Result<(), Error> {
        if let Some(tip) = self.snapshot.hashes.get(&block.hash()) {
            let i = usize::try_from(tip.revision).map_err(|_| Error::Overflow)?;
            if self.snapshot.blocks.get(i).map(|r| &r.block) == Some(block) {
                return Err(Error::AlreadyCommitted(*tip));
            }
            return Err(invalid("stored hash differs in exact block constituents"));
        }
        if self.snapshot.slots.contains_key(&block.header().slot) {
            return Err(Error::SlotConflict);
        }
        let next = self
            .snapshot
            .tip
            .slot
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        if block.header().slot != next {
            return Err(Error::Slot);
        }
        if block.header().parent_hash != self.snapshot.tip.hash {
            return Err(Error::Parent);
        }
        self.snapshot
            .tip
            .revision
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        if grant.is_some_and(|g| {
            !g.matches(
                self.manifest.context,
                self.manifest.anchor.hash(),
                self.snapshot.tip,
                block,
            )
        }) {
            return Err(Error::Grant);
        }
        Ok(())
    }
    fn check_transactions(&self, block: &NativeBlock, outcome: &BodyOutcome) -> Result<(), Error> {
        let mut ids = BTreeSet::new();
        let mut pairs = BTreeSet::new();
        for (i, (bytes, id)) in block
            .transactions()
            .iter()
            .zip(&outcome.transaction_ids)
            .enumerate()
        {
            if self.snapshot.transactions.contains_key(id) || !ids.insert(*id) {
                return Err(Error::DuplicateTransaction(i));
            }
            let pair = sender_nonce(bytes);
            if self.snapshot.sender_nonces.contains_key(&pair) || !pairs.insert(pair) {
                return Err(Error::DuplicateTransaction(i));
            }
        }
        Ok(())
    }
    /// One SQL transaction for block/state/body/index/accounting/tip, then one coherent installation.
    pub fn commit(&mut self, staged: StagedNativeBlock) -> AppendOutcome {
        self.commit_inner(staged, false)
    }
    /// Observes SQL phase elapsed time while using the exact same commit/check/recovery path.
    /// Profiling adds fixed phase-boundary clocks only, not clocks or alternate SQL inside loops.
    pub fn commit_profiled(&mut self, staged: StagedNativeBlock) -> AppendOutcome {
        self.commit_inner(staged, true)
    }
    fn commit_inner(&mut self, staged: StagedNativeBlock, profiling: bool) -> AppendOutcome {
        if let Err(e) = self.ready() {
            return AppendOutcome::Aborted(e);
        }
        let p = staged.prepared;
        let now = Instant::now();
        if p.base.generation != self.generation
            || p.base.context != self.manifest.context
            || p.base.anchor != self.manifest.anchor.hash()
            || p.base.tip != self.snapshot.tip
            || p.base.state != self.snapshot.state
        {
            return AppendOutcome::Aborted(Error::Stale);
        }
        let mut times = AppendTimings {
            staging: p.stage_time,
            memory_comparison: now.elapsed(),
            ..Default::default()
        };
        if let Err(e) = self.check_append(&p.record.block, Some(staged.grant)) {
            return AppendOutcome::Aborted(e);
        }
        // Baseline deliberately clones full retained caches. Measure it, rather than optimizing
        // history ownership while establishing the new correctness boundary.
        let prepare = Instant::now();
        let mut prepared = Snapshot {
            state: p.candidate.clone(),
            tip: self.snapshot.tip,
            blocks: self.snapshot.blocks.clone(),
            transactions: self.snapshot.transactions.clone(),
            sender_nonces: self.snapshot.sender_nonces.clone(),
            slots: self.snapshot.slots.clone(),
            hashes: self.snapshot.hashes.clone(),
        };
        if let Err(e) = prepared.insert_record(p.record.clone()) {
            return AppendOutcome::Aborted(e);
        }
        let attempted = Attempt {
            base: p.base.tip,
            record: p.record.clone(),
        };
        times.cache_preparation = prepare.elapsed();
        if let Err(e) = self.point("before_begin") {
            return AppendOutcome::Aborted(e);
        }
        let durable = Instant::now();
        let mut profile = profiling.then(SqlProfile::default);
        let phase = profiling.then(Instant::now);
        if let Err(e) = self.conn().execute_batch("BEGIN IMMEDIATE") {
            return AppendOutcome::Aborted(sql(e));
        }
        if let Some(p) = &mut profile {
            p.acquisition = phase.expect("profiling clock").elapsed();
        }
        self.attempted = Some(attempted);
        let writes = (|| {
            let phase = profiling.then(Instant::now);
            verify_metadata(self.conn(), &self.manifest, Some(p.base.tip.revision))?;
            if read_tip(self.conn())? != p.base.tip {
                return Err(Error::Stale);
            }
            if let Some(p) = &mut profile {
                p.metadata_base = phase.expect("profiling clock").elapsed();
            }
            let compare = Instant::now();
            let state = disk::read_state(self.conn())?;
            let equal = state == p.base.state;
            times.stored_comparison = compare.elapsed();
            if let Some(p) = &mut profile {
                p.account_comparison = times.stored_comparison;
            }
            if !equal {
                return Err(Error::Stale);
            }
            // Uniqueness probes precede every write; constraints remain authoritative too.
            let phase = profiling.then(Instant::now);
            let present: bool = self
                .conn()
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM blocks WHERE hash=?1 OR slot=?2)",
                    params![
                        p.record.tip.hash.as_slice(),
                        p.record.tip.slot.to_be_bytes().as_slice()
                    ],
                    |r| r.get(0),
                )
                .map_err(sql)?;
            if present {
                return Err(Error::Stale);
            }
            for (bytes, id) in p
                .record
                .block
                .transactions()
                .iter()
                .zip(&p.record.outcome.transaction_ids)
            {
                let (sender, nonce) = sender_nonce(bytes);
                let exists: bool = self.conn().query_row("SELECT EXISTS(SELECT 1 FROM transactions WHERE id=?1 OR (sender=?2 AND nonce=?3))", params![id.as_slice(), sender.as_slice(), nonce.to_be_bytes().as_slice()], |r| r.get(0)).map_err(sql)?;
                if exists {
                    return Err(Error::Stale);
                }
            }
            if let Some(p) = &mut profile {
                p.uniqueness_probes = phase.expect("profiling clock").elapsed();
            }
            let phase = profiling.then(Instant::now);
            for (address, account) in p.candidate.accounts() {
                if p.base.state.accounts().get(address) != Some(account) {
                    self.conn().execute("INSERT INTO accounts VALUES(?1,?2,?3) ON CONFLICT(address) DO UPDATE SET balance=excluded.balance,nonce=excluded.nonce",
                        params![address.as_slice(), account.balance_quarks.to_be_bytes().as_slice(), account.nonce.to_be_bytes().as_slice()]).map_err(sql)?;
                }
            }
            if let Some(p) = &mut profile {
                p.changed_account_writes = phase.expect("profiling clock").elapsed();
            }
            self.point("accounts")?;
            let phase = profiling.then(Instant::now);
            disk::write_accounting(self.conn(), &p.candidate)?;
            if let Some(p) = &mut profile {
                p.accounting_write = phase.expect("profiling clock").elapsed();
            }
            self.point("accounting")?;
            let phase = profiling.then(Instant::now);
            insert_block(self.conn(), &p.record)?;
            if let Some(p) = &mut profile {
                p.block_insertion = phase.expect("profiling clock").elapsed();
            }
            self.point("block")?;
            let phase = profiling.then(Instant::now);
            insert_body(self.conn(), &p.record)?;
            if let Some(p) = &mut profile {
                p.body_insertion = phase.expect("profiling clock").elapsed();
            }
            self.point("body")?;
            let phase = profiling.then(Instant::now);
            insert_transactions(self.conn(), &p.record)?;
            if let Some(p) = &mut profile {
                p.transaction_index_insertion = phase.expect("profiling clock").elapsed();
            }
            self.point("indexes")?;
            let phase = profiling.then(Instant::now);
            if self
                .conn()
                .execute(
                    "UPDATE metadata SET revision=?1 WHERE id=1 AND revision=?2",
                    params![
                        p.record.tip.revision.to_be_bytes().as_slice(),
                        p.base.tip.revision.to_be_bytes().as_slice()
                    ],
                )
                .map_err(sql)?
                != 1
            {
                return Err(invalid("revision conditional update failed"));
            }
            self.point("revision")?;
            if self.conn().execute("UPDATE canonical_tip SET hash=?1,slot=?2,revision=?3 WHERE id=1 AND hash=?4 AND slot=?5 AND revision=?6",
                params![p.record.tip.hash.as_slice(), p.record.tip.slot.to_be_bytes().as_slice(), p.record.tip.revision.to_be_bytes().as_slice(), p.base.tip.hash.as_slice(), p.base.tip.slot.to_be_bytes().as_slice(), p.base.tip.revision.to_be_bytes().as_slice()]).map_err(sql)? != 1 { return Err(invalid("tip conditional update failed")); }
            self.point("tip")?;
            if let Some(p) = &mut profile {
                p.revision_tip = phase.expect("profiling clock").elapsed();
            }
            self.point("before_commit")?;
            Ok(())
        })();
        if let Err(e) = writes {
            if e == Error::Stale {
                // No writes preceded this observed external-base change. Explicit refresh is
                // needed before this owner's stale RAM can be served as reconciled state.
                match self.conn().execute_batch("ROLLBACK") {
                    Ok(()) if self.conn().is_autocommit() => {
                        self.attempted = None;
                        self.poisoned = true;
                        return AppendOutcome::Aborted(Error::Stale);
                    }
                    _ => return self.poison(e),
                }
            }
            return self.abort(e);
        }
        let phase = profiling.then(Instant::now);
        if let Err(e) = self.conn().execute_batch("COMMIT") {
            return self.poison(sql(e));
        }
        if let Some(p) = &mut profile {
            p.commit_return = phase.expect("profiling clock").elapsed();
        }
        times.durable_commit = durable.elapsed();
        times.sql_profile = profile;
        if let Err(e) = self.point("after_commit") {
            return self.poison(e);
        }
        let install = Instant::now();
        let old = std::mem::replace(&mut self.snapshot, prepared);
        times.installation = install.elapsed();
        let destroy = Instant::now();
        drop(old);
        times.cache_destruction = destroy.elapsed();
        if let Err(e) = self.point("after_install") {
            return self.poison(e);
        }
        self.attempted = None;
        AppendOutcome::Committed {
            tip: p.record.tip,
            outcome: p.record.outcome,
            timings: times,
        }
    }
    /// Explicit full reload/audit/exact-attempt reconciliation and dirty-page durability barrier.
    /// Any failure leaves the owner blocked and every pre-recovery overlay permanently stale.
    pub fn recover(&mut self) -> Result<RecoveryReport, Error> {
        let whole = Instant::now();
        self.poisoned = true;
        self.generation = disk::next_generation()?;
        self.connection.take();
        self.point("recovery_reopen")?;
        let now = Instant::now();
        let connection = disk::open(&self.path, self.vfs_name())?;
        configure_cache(&connection, self.cache_policy)?;
        let mut times = LoadTimings {
            open_configuration: now.elapsed(),
            ..Default::default()
        };
        self.connection = Some(connection);
        self.point("recovery_validate")?;
        let snapshot = load_snapshot(self.conn(), &self.manifest, &mut times)?;
        let attempted_present = reconcile(self.attempted.as_ref(), &snapshot)?;
        self.point("recovery_barrier")?;
        let now = Instant::now();
        barrier(self.conn(), &self.path, &self.manifest, snapshot.tip)?;
        times.barrier = now.elapsed();
        self.point("recovery_install")?;
        let now = Instant::now();
        self.snapshot = snapshot;
        times.installation = now.elapsed();
        self.attempted = None;
        self.poisoned = false;
        times.total = whole.elapsed();
        self.load_timings = times;
        Ok(RecoveryReport {
            tip: self.snapshot.tip,
            attempted_present,
        })
    }
    fn ready(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::Blocked)
        } else {
            Ok(())
        }
    }
    fn conn(&self) -> &Connection {
        self.connection.as_ref().expect("connected owner")
    }
    fn point(&mut self, _name: &str) -> Result<(), Error> {
        #[cfg(test)]
        if let Some(h) = &mut self.hook {
            return h(_name);
        }
        Ok(())
    }
    fn vfs_name(&self) -> Option<&str> {
        #[cfg(test)]
        {
            self.vfs.as_deref()
        }
        #[cfg(not(test))]
        {
            None
        }
    }
    fn poison(&mut self, e: Error) -> AppendOutcome {
        self.poisoned = true;
        AppendOutcome::RecoveryRequired(recovery_error(e))
    }
    fn abort(&mut self, e: Error) -> AppendOutcome {
        if !self.conn().is_autocommit()
            && let Err(r) = self
                .point("rollback")
                .and_then(|_| self.conn().execute_batch("ROLLBACK").map_err(sql))
        {
            return self.poison(invalid(format!("{e}; rollback: {r}")));
        }
        if !self.conn().is_autocommit() {
            return self.poison(e);
        }
        // SQL ROLLBACK can swallow pager failures. Validate the complete previous prefix before
        // claiming Aborted; sticky errors or mixed rows must poison, not continue from old RAM.
        let mut times = LoadTimings::default();
        match load_snapshot(self.conn(), &self.manifest, &mut times) {
            Ok(old) if old == self.snapshot => {
                self.attempted = None;
                AppendOutcome::Aborted(e)
            }
            other => self.poison(invalid(format!(
                "{e}; unconfirmed old prefix: {:?}",
                other.err()
            ))),
        }
    }
    fn create_inner(
        path: &Path,
        manifest: &FixtureManifest,
        vfs: Option<&str>,
        point: impl FnMut(&str) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        Self::create_inner_with_cache(path, manifest, CachePolicy::ExistingDefault, vfs, point)
    }
    fn create_inner_with_cache(
        path: &Path,
        manifest: &FixtureManifest,
        policy: CachePolicy,
        vfs: Option<&str>,
        mut point: impl FnMut(&str) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        let started = Instant::now();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Error::Storage(StoreError::AlreadyExists)
                } else {
                    disk::invalid(e).into()
                }
            })?;
        let conn = disk::open(path, vfs)?;
        configure_cache(&conn, policy)
            .map_err(|e| Error::Storage(StoreError::Aborted(e.to_string())))?;
        // Prepare every owned publication allocation and generation before initialization COMMIT.
        // A process can then die in the durable/install gap without a partially published owner.
        let anchor = CommittedBlock {
            tip: Tip::at(&manifest.anchor, 0),
            block: manifest.anchor.clone(),
            outcome: BodyOutcome::default(),
        };
        let mut snapshot = Snapshot {
            state: manifest.initial.clone(),
            tip: anchor.tip,
            blocks: Vec::new(),
            transactions: BTreeMap::new(),
            sender_nonces: BTreeMap::new(),
            slots: BTreeMap::new(),
            hashes: BTreeMap::new(),
        };
        snapshot.insert_record(anchor.clone())?;
        let mut owner = Self::owner(path, manifest, conn, snapshot, policy, vfs)?;
        let conn = owner.conn();
        conn.execute_batch("BEGIN IMMEDIATE").map_err(sql)?;
        let initialization: Result<(), Error> = (|| {
            for (_, ddl) in schema::TABLES {
                conn.execute_batch(ddl).map_err(sql)?;
            }
            point("schema")?;
            conn.execute("INSERT INTO metadata VALUES(1,?1,'offline-native-blocks',?2,?3,?4,?5,?6,?7,?8,?9,?9,?10,x'02',x'00000002',0)", params![SCHEMA_VERSION.to_be_bytes().as_slice(), manifest.context.chain_id().to_be_bytes().as_slice(), manifest.context.network_id().as_slice(), manifest.context.native_rules_version().to_be_bytes().as_slice(), manifest.provenance, manifest.initial.gas_used_total().to_be_bytes().as_slice(), manifest.initial.fees_burned_total().to_be_bytes().as_slice(), (manifest.initial.accounts().len() as u64).to_be_bytes().as_slice(), 0u64.to_be_bytes().as_slice(), anchor.tip.hash.as_slice()]).map_err(sql)?;
            point("context")?;
            let mut seed = conn
                .prepare("INSERT INTO seed_accounts VALUES(?1,?2,?3)")
                .map_err(sql)?;
            let mut state = conn
                .prepare("INSERT INTO accounts VALUES(?1,?2,?3)")
                .map_err(sql)?;
            for (address, account) in manifest.initial.accounts() {
                let balance = account.balance_quarks.to_be_bytes();
                let nonce = account.nonce.to_be_bytes();
                seed.execute(params![
                    address.as_slice(),
                    balance.as_slice(),
                    nonce.as_slice()
                ])
                .map_err(sql)?;
                state
                    .execute(params![
                        address.as_slice(),
                        balance.as_slice(),
                        nonce.as_slice()
                    ])
                    .map_err(sql)?;
                point("fixture_account")?;
            }
            drop(seed);
            drop(state);
            point("fixture_accounts")?;
            conn.execute(
                "INSERT INTO accounting VALUES(1,?1,?2)",
                params![
                    manifest.initial.gas_used_total().to_be_bytes().as_slice(),
                    manifest
                        .initial
                        .fees_burned_total()
                        .to_be_bytes()
                        .as_slice()
                ],
            )
            .map_err(sql)?;
            point("initial_accounting")?;
            insert_block(conn, &anchor)?;
            point("anchor")?;
            insert_body(conn, &anchor)?;
            point("anchor_body")?;
            conn.execute(
                "INSERT INTO canonical_tip VALUES(1,?1,?2,?3)",
                params![
                    anchor.tip.hash.as_slice(),
                    anchor.tip.slot.to_be_bytes().as_slice(),
                    0u64.to_be_bytes().as_slice()
                ],
            )
            .map_err(sql)?;
            point("initial_tip")?;
            point("provenance")?;
            conn.execute_batch("UPDATE metadata SET initialized=1 WHERE id=1")
                .map_err(sql)?;
            point("marker")?;
            point("init_before_commit")?;
            Ok(())
        })();
        if let Err(e) = initialization {
            let rolled = if conn.is_autocommit() {
                Ok(())
            } else {
                conn.execute_batch("ROLLBACK").map_err(sql)
            };
            if let Err(r) = rolled {
                return Err(recovery_error(format!("{e}; rollback failure: {r}")));
            }
            let mut t = LoadTimings::default();
            return match load_snapshot(conn, manifest, &mut t) {
                Err(Error::Storage(StoreError::Uninitialized)) => {
                    Err(Error::Storage(StoreError::Aborted(e.to_string())))
                }
                other => Err(recovery_error(format!(
                    "{e}; initialization rollback validation: {:?}",
                    other.err()
                ))),
            };
        }
        conn.execute_batch("COMMIT")
            .map_err(|e| recovery_error(sql(e)))?;
        point("init_after_commit").map_err(recovery_error)?;
        point("init_directory_sync")
            .and_then(|_| disk::sync_path(path).map_err(Error::from))
            .map_err(recovery_error)?;
        owner.load_timings.total = started.elapsed();
        Ok(owner)
    }
    fn load(path: &Path, manifest: &FixtureManifest, vfs: Option<&str>) -> Result<Self, Error> {
        Self::load_with_cache(path, manifest, CachePolicy::ExistingDefault, vfs)
    }
    fn load_with_cache(
        path: &Path,
        manifest: &FixtureManifest,
        policy: CachePolicy,
        vfs: Option<&str>,
    ) -> Result<Self, Error> {
        let whole = Instant::now();
        let now = Instant::now();
        let conn = disk::open(path, vfs)?;
        configure_cache(&conn, policy)?;
        let mut t = LoadTimings {
            open_configuration: now.elapsed(),
            ..Default::default()
        };
        let snapshot = load_snapshot(&conn, manifest, &mut t)?;
        let now = Instant::now();
        barrier(&conn, path, manifest, snapshot.tip)?;
        t.barrier = now.elapsed();
        let now = Instant::now();
        let mut owner = Self::owner(path, manifest, conn, snapshot, policy, vfs)?;
        t.installation = now.elapsed();
        t.total = whole.elapsed();
        owner.load_timings = t;
        Ok(owner)
    }
    fn owner(
        path: &Path,
        manifest: &FixtureManifest,
        connection: Connection,
        snapshot: Snapshot,
        cache_policy: CachePolicy,
        _vfs: Option<&str>,
    ) -> Result<Self, Error> {
        Ok(Self {
            path: path.to_owned(),
            manifest: manifest.clone(),
            connection: Some(connection),
            snapshot,
            generation: disk::next_generation()?,
            poisoned: false,
            attempted: None,
            load_timings: LoadTimings::default(),
            cache_policy,
            #[cfg(test)]
            hook: None,
            #[cfg(test)]
            vfs: _vfs.map(str::to_owned),
        })
    }
}

fn insert_block(c: &Connection, r: &CommittedBlock) -> Result<(), Error> {
    c.execute(
        "INSERT INTO blocks VALUES(?1,?2,?3,?4,?5,?6,?7,?3,?8)",
        params![
            r.tip.hash.as_slice(),
            r.tip.slot.to_be_bytes().as_slice(),
            r.tip.revision.to_be_bytes().as_slice(),
            r.block.header().canonical_bytes(),
            r.block.proposer().as_bytes(),
            r.block.protocol_data().canonical_bytes(),
            r.block.header().parent_hash.as_slice(),
            i64::from(r.tip.revision == 0)
        ],
    )
    .map_err(sql)?;
    Ok(())
}
fn insert_body(c: &Connection, r: &CommittedBlock) -> Result<(), Error> {
    c.execute(
        "INSERT INTO bodies VALUES(?1,?2,?3,x'02',x'00000001',?4,?5,?6)",
        params![
            r.tip.revision.to_be_bytes().as_slice(),
            r.tip.hash.as_slice(),
            r.tip.slot.to_be_bytes().as_slice(),
            (r.block.transactions().len() as u64)
                .to_be_bytes()
                .as_slice(),
            r.outcome.gas_used.to_be_bytes().as_slice(),
            r.outcome.fees_burned.to_be_bytes().as_slice()
        ],
    )
    .map_err(sql)?;
    Ok(())
}
fn insert_transactions(c: &Connection, r: &CommittedBlock) -> Result<(), Error> {
    let mut s = c
        .prepare("INSERT INTO transactions VALUES(?1,?2,?3,?4,?5,?6)")
        .map_err(sql)?;
    for (i, (b, id)) in r
        .block
        .transactions()
        .iter()
        .zip(&r.outcome.transaction_ids)
        .enumerate()
    {
        let (sender, nonce) = sender_nonce(b);
        s.execute(params![
            id.as_slice(),
            r.tip.revision.to_be_bytes().as_slice(),
            (i as u64).to_be_bytes().as_slice(),
            sender.as_slice(),
            nonce.to_be_bytes().as_slice(),
            b.as_slice()
        ])
        .map_err(sql)?;
    }
    Ok(())
}
fn read_tip(c: &Connection) -> Result<Tip, Error> {
    c.query_row(
        "SELECT hash,slot,revision FROM canonical_tip WHERE id=1",
        [],
        |r| {
            Ok(Tip {
                hash: blob(r, 0)?,
                slot: u64::from_be_bytes(blob(r, 1)?),
                revision: u64::from_be_bytes(blob(r, 2)?),
            })
        },
    )
    .map_err(sql)
}
fn verify_metadata(
    c: &Connection,
    m: &FixtureManifest,
    expected: Option<u64>,
) -> Result<u64, Error> {
    let row = c.query_row("SELECT schema_version,mode,chain,network,rules,provenance,seed_gas,seed_burn,seed_count,revision,anchor_hash,wire,profile,initialized FROM metadata WHERE id=1", [], |r| Ok((blob::<4>(r,0)?, r.get::<_,String>(1)?, blob::<8>(r,2)?, blob::<32>(r,3)?, blob::<4>(r,4)?, r.get::<_,String>(5)?, blob::<8>(r,6)?, blob::<16>(r,7)?, blob::<8>(r,8)?, blob::<8>(r,9)?, blob::<32>(r,10)?, blob::<1>(r,11)?, blob::<4>(r,12)?, r.get::<_,i64>(13)?))).optional().map_err(sql)?.ok_or(Error::Storage(StoreError::Uninitialized))?;
    if row.13 != 1 {
        return Err(StoreError::Uninitialized.into());
    }
    if u32::from_be_bytes(row.0) != SCHEMA_VERSION
        || row.1 != "offline-native-blocks"
        || u64::from_be_bytes(row.2) != m.context.chain_id()
        || row.3 != m.context.network_id()
        || u32::from_be_bytes(row.4) != m.context.native_rules_version()
        || row.5 != m.provenance
        || u64::from_be_bytes(row.6) != m.initial.gas_used_total()
        || u128::from_be_bytes(row.7) != m.initial.fees_burned_total()
        || u64::from_be_bytes(row.8) != m.initial.accounts().len() as u64
        || row.10 != m.anchor.hash()
        || row.11 != [2]
        || u32::from_be_bytes(row.12) != 2
    {
        return Err(invalid("schema/mode/profile/fixture authority mismatch"));
    }
    let revision = u64::from_be_bytes(row.9);
    if expected.is_some_and(|r| r != revision) {
        return Err(Error::Stale);
    }
    Ok(revision)
}
fn barrier(c: &Connection, path: &Path, m: &FixtureManifest, tip: Tip) -> Result<(), Error> {
    // Dirty a real metadata page under the owner/writer gate. Readability after failed sync does
    // not establish durability; EXTRA COMMIT and explicit file/directory sync are mandatory.
    c.execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| recovery_error(sql(e)))?;
    let result = (|| {
        verify_metadata(c, m, Some(tip.revision))?;
        if read_tip(c)? != tip {
            return Err(Error::Stale);
        }
        let old = c
            .query_row("SELECT barrier FROM metadata WHERE id=1", [], |r| {
                blob::<8>(r, 0)
            })
            .map_err(sql)?;
        let next = u64::from_be_bytes(old)
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        c.execute(
            "UPDATE metadata SET barrier=?1 WHERE id=1",
            params![next.to_be_bytes().as_slice()],
        )
        .map_err(sql)?;
        c.execute_batch("COMMIT").map_err(sql)?;
        disk::sync_path(path)?;
        Ok(())
    })();
    result.map_err(recovery_error)
}
fn reconcile(attempt: Option<&Attempt>, snapshot: &Snapshot) -> Result<Option<bool>, Error> {
    let Some(a) = attempt else {
        return Ok(None);
    };
    if let Some(r) = snapshot
        .blocks
        .get(usize::try_from(a.record.tip.revision).map_err(|_| Error::Overflow)?)
    {
        if r != &a.record
            || snapshot
                .blocks
                .get(usize::try_from(a.base.revision).map_err(|_| Error::Overflow)?)
                .map(|r| r.tip)
                != Some(a.base)
        {
            return Err(recovery_error(
                "different block/body occupies uncertain attempt",
            ));
        }
        return Ok(Some(true));
    }
    if snapshot.tip == a.base {
        Ok(Some(false))
    } else {
        Err(recovery_error(
            "uncertain attempt is neither exact old nor exact stored new prefix",
        ))
    }
}
fn load_snapshot(
    c: &Connection,
    m: &FixtureManifest,
    t: &mut LoadTimings,
) -> Result<Snapshot, Error> {
    let whole = Instant::now();
    c.execute_batch("BEGIN").map_err(sql)?;
    let result = load_transaction(c, m, t);
    let end = c.execute_batch("ROLLBACK").map_err(sql);
    t.validation_materialization = whole
        .elapsed()
        .saturating_sub(t.audit)
        .saturating_sub(t.equality);
    result.and_then(|s| end.map(|_| s))
}
fn load_transaction(
    c: &Connection,
    m: &FixtureManifest,
    t: &mut LoadTimings,
) -> Result<Snapshot, Error> {
    let present: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='metadata')",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if !present {
        return Err(StoreError::Uninitialized.into());
    }
    for (name, expected) in schema::TABLES {
        let ddl: String = c
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
                [name],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if ddl != *expected {
            return Err(invalid(format!("incompatible schema {name}")));
        }
    }
    let integrity: String = c
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .map_err(sql)?;
    if integrity != "ok" {
        return Err(invalid(integrity));
    }
    if c.prepare("PRAGMA foreign_key_check")
        .map_err(sql)?
        .query([])
        .map_err(sql)?
        .next()
        .map_err(sql)?
        .is_some()
    {
        return Err(invalid("foreign key inconsistency"));
    }
    let revision = verify_metadata(c, m, None)?;
    let tip = read_tip(c)?;
    let seeds = TransferState::new(
        disk::read_accounts(c, "seed_accounts")?,
        m.initial.gas_used_total(),
        m.initial.fees_burned_total(),
    );
    let eq = Instant::now();
    let same = seeds == m.initial;
    t.equality += eq.elapsed();
    if !same {
        return Err(invalid("immutable seed authority mismatch"));
    }
    let state = disk::read_state(c)?;
    let mut snapshot = Snapshot {
        state,
        tip,
        blocks: Vec::new(),
        transactions: BTreeMap::new(),
        sender_nonces: BTreeMap::new(),
        slots: BTreeMap::new(),
        hashes: BTreeMap::new(),
    };
    let mut audit = seeds;
    let mut query = c.prepare("SELECT b.hash,b.slot,b.revision,b.header,b.proposer,b.protocol_data,b.parent,b.body_revision,b.is_anchor,d.block_hash,d.slot,d.encoding,d.rules,d.count,d.gas,d.burn FROM blocks b JOIN bodies d ON d.revision=b.revision ORDER BY b.revision").map_err(sql)?;
    let mut rows = query.query([]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        let hash = blob::<32>(row, 0).map_err(sql)?;
        let slot = u64::from_be_bytes(blob(row, 1).map_err(sql)?);
        let rev = u64::from_be_bytes(blob(row, 2).map_err(sql)?);
        if rev != snapshot.blocks.len() as u64 {
            return Err(invalid("noncontiguous block revisions"));
        }
        let header_bytes = blob::<229>(row, 3).map_err(sql)?;
        let header = BlockHeader::from_canonical_bytes(&header_bytes)
            .ok_or_else(|| invalid("stored header codec"))?;
        let proposer: Vec<u8> = row.get(4).map_err(sql)?;
        let proposer = String::from_utf8(proposer).map_err(invalid)?;
        let pd = blob::<10>(row, 5).map_err(sql)?;
        let pd = ProtocolData::from_canonical_bytes(&pd)
            .ok_or_else(|| invalid("stored protocol codec"))?;
        if header.slot != slot
            || header.hash() != hash
            || header.parent_hash != blob::<32>(row, 6).map_err(sql)?
            || u64::from_be_bytes(blob(row, 7).map_err(sql)?) != rev
            || row.get::<_, i64>(8).map_err(sql)? != i64::from(rev == 0)
            || blob::<32>(row, 9).map_err(sql)? != hash
            || u64::from_be_bytes(blob(row, 10).map_err(sql)?) != slot
            || blob::<1>(row, 11).map_err(sql)? != [2]
            || u32::from_be_bytes(blob(row, 12).map_err(sql)?) != 1
        {
            return Err(invalid("block/body metadata mismatch"));
        }
        let count = u64::from_be_bytes(blob(row, 13).map_err(sql)?);
        if count > MAX_TRANSACTIONS as u64 {
            return Err(invalid("stored body count"));
        }
        let gas_used = u64::from_be_bytes(blob(row, 14).map_err(sql)?);
        let fees_burned = u64::from_be_bytes(blob(row, 15).map_err(sql)?);
        let mut txquery = c.prepare("SELECT id,position,sender,nonce,signed FROM transactions WHERE revision=?1 ORDER BY position").map_err(sql)?;
        let entries = txquery
            .query_map(params![rev.to_be_bytes().as_slice()], |r| {
                Ok((
                    blob::<32>(r, 0)?,
                    u64::from_be_bytes(blob(r, 1)?),
                    blob::<20>(r, 2)?,
                    u64::from_be_bytes(blob(r, 3)?),
                    blob::<SIGNED_LEN>(r, 4)?,
                ))
            })
            .map_err(sql)?;
        let mut bytes = Vec::new();
        let mut ids = Vec::new();
        for entry in entries {
            let (id, position, sender, nonce, signed) = entry.map_err(sql)?;
            if position != bytes.len() as u64
                || sender_nonce(&signed) != (sender, nonce)
                || hash_with_domain(ID_DOMAIN, &signed) != id
            {
                return Err(invalid("stored transaction/index identity"));
            }
            bytes.push(signed);
            ids.push(id);
        }
        if count != bytes.len() as u64 {
            return Err(invalid("missing stored entries"));
        }
        let block = NativeBlock::from_parts(header, proposer, pd, bytes)?;
        let raw_ids = block.preflight(&m.context)?;
        let outcome = BodyOutcome {
            transaction_ids: ids,
            gas_used,
            fees_burned,
        };
        if rev == 0 {
            if block != m.anchor || outcome != BodyOutcome::default() {
                return Err(invalid("anchor changed"));
            }
        } else {
            if snapshot.tip.slot.checked_add(1) != Some(slot)
                || snapshot.tip.hash != block.header().parent_hash
            {
                return Err(invalid("stored parent/slot prefix"));
            }
            let now = Instant::now();
            let staged = stage_body(
                &audit,
                &m.context,
                slot,
                &block
                    .transactions()
                    .iter()
                    .map(|b| b.to_vec())
                    .collect::<Vec<_>>(),
            )
            .map_err(Error::Body)?;
            t.audit += now.elapsed();
            block.match_outcome(
                &staged.record().transactions,
                &raw_ids,
                &staged.record().outcome,
            )?;
            if staged.record().outcome != outcome {
                return Err(invalid("stored body outcome"));
            }
            let (_, candidate, _) = staged.into_parts();
            audit = candidate;
        }
        snapshot.insert_record(CommittedBlock {
            tip: Tip {
                hash,
                slot,
                revision: rev,
            },
            block,
            outcome,
        })?;
    }
    if snapshot.blocks.is_empty() || snapshot.tip != tip || snapshot.tip.revision != revision {
        return Err(invalid("missing/final tip mismatch"));
    }
    // The cyclic FKs prevent missing pairs; counts also reject extra unattached body rows.
    for table in ["blocks", "bodies"] {
        let count: i64 = c
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .map_err(sql)?;
        if u64::try_from(count).ok() != Some(snapshot.blocks.len() as u64) {
            return Err(invalid("archive pair count"));
        }
    }
    let now = Instant::now();
    let equal = audit == snapshot.state;
    t.equality += now.elapsed();
    if !equal {
        return Err(invalid("materialized state differs from seed audit"));
    }
    Ok(snapshot)
}
