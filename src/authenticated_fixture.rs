//! Fresh schema-3 offline archive with compact durable producer evidence and native state.
//!
//! Caller policy is independent authority; the stored declaration is only checked data. The unsigned
//! anchor is trusted, appended envelopes are attributed/audited, and exact accepted evidence is
//! immutable through this API. This does not independently pin archive selection/freshness or which
//! legitimate alternate signature a database adversary retained. No live admission or migration.
use crate::block_authentication::{
    self as auth, AuthenticatedProducerBlock, BlockAuthenticationContext, ProducerBinding,
    SignedBlockEnvelope,
};
use crate::block_commitment::{BlockHeader, ProtocolData, hash_with_domain};
use crate::canonical_fixture::{
    self as canonical, FixtureAdmissionGrant, FixtureManifest, Membership, Tip,
};
use crate::durable_fixture::{self as disk, StorageSettings, StoreError};
use crate::native_block::{BlockError, MAX_PROPOSER_BYTES, MAX_TRANSACTIONS, NativeBlock};
use crate::native_transaction::{Address, Hash, ID_DOMAIN, SIGNED_LEN};
use crate::native_transfer::{BodyError, BodyOutcome, TransferState, stage_body};
use rusqlite::{Connection, OptionalExtension, Row, params, types::ValueRef};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
mod schema;
#[cfg(test)]
mod tests;
#[cfg(test)]
type Hook = Box<dyn FnMut(&str) -> Result<(), Error>>;

/// Deterministic public rejection/poison causes. A duplicate reference is never new commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Existing filesystem/SQLite outcome, including explicit inability to establish recovery.
    Storage(StoreError),
    /// Signed framing/context/canonicality/producer attribution failure.
    Authentication(auth::Error),
    /// Current native inner structural/outcome error.
    Block(BlockError),
    /// Shared ordered user authentication/execution failure and original body index.
    Body(BodyError),
    /// Caller auth/native contexts disagree or the static binding list is empty/ambiguous.
    Policy,
    /// Exact producer is absent from independently supplied policy.
    UnknownProducer,
    /// Owner is unavailable pending explicit reconciliation/barrier.
    Blocked,
    /// Generation/policy/base changed; no prepared effects can be installed.
    Stale,
    /// Existing block, exposing exact retained and submitted evidence IDs without replacement.
    AlreadyCommitted {
        tip: Tip,
        retained_envelope_id: Hash,
        submitted_envelope_id: Hash,
    },
    /// Stored unsigned checkpoint reference, never authenticated appended evidence.
    TrustedAnchorReference(Tip),
    /// Another content identity occupies this slot; no canonical replacement.
    SlotConflict,
    /// Not the checked successor of the current canonical tip.
    Slot,
    /// Parent differs from the current canonical tip hash.
    Parent,
    /// Independent fixture grant does not bind context/anchor/base/content/slot.
    Grant,
    /// Signature proof names different exact inner content than the producer preparation.
    PreparedIdentity,
    /// Unsigned arithmetic, revision, length or barrier cannot be represented.
    Overflow,
    /// ID/sender-nonce uniqueness failure following shared native staging.
    DuplicateTransaction(usize),
    /// Schema, policy, widths, archive associations or audit state are inconsistent; never repaired.
    Invalid(String),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "offline authenticated fixture: {self:?}")
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
impl From<auth::Error> for Error {
    fn from(e: auth::Error) -> Self {
        Self::Authentication(e)
    }
}
fn sql(e: rusqlite::Error) -> Error {
    Error::Storage(disk::invalid(e))
}
fn invalid(e: impl fmt::Display) -> Error {
    Error::Invalid(e.to_string())
}
fn uncertain(e: impl fmt::Display) -> Error {
    Error::Storage(StoreError::RecoveryRequired(e.to_string()))
}

/// Independently supplied complete fixture/producer policy, immutable for this archive operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedFixtureManifest {
    fixture: FixtureManifest,
    context: BlockAuthenticationContext,
    bindings: BTreeMap<String, ProducerBinding>,
}
impl AuthenticatedFixtureManifest {
    /// Validates exact static names/keys and matching contexts, not registration/eligibility authority.
    pub fn new(
        fixture: FixtureManifest,
        context: BlockAuthenticationContext,
        bindings: Vec<ProducerBinding>,
    ) -> Result<Self, Error> {
        if fixture.context() != context.native_context() || bindings.is_empty() {
            return Err(Error::Policy);
        }
        let mut map = BTreeMap::new();
        let mut keys = BTreeSet::new();
        for b in bindings {
            if !keys.insert(*b.public_key()) || map.insert(b.producer_id().to_owned(), b).is_some()
            {
                return Err(Error::Policy);
            }
        }
        Ok(Self {
            fixture,
            context,
            bindings: map,
        })
    }
    /// Original independently trusted checkpoint/seeds/native context, not stored self-authority.
    pub fn fixture(&self) -> &FixtureManifest {
        &self.fixture
    }
    /// Explicit frozen signed/native profile policy used to authenticate every append and history row.
    pub fn context(&self) -> BlockAuthenticationContext {
        self.context
    }
    /// Lookup in caller authority, never incoming/stored key discovery.
    pub fn binding(&self, id: &str) -> Result<&ProducerBinding, Error> {
        self.bindings.get(id).ok_or(Error::UnknownProducer)
    }
    /// Exact static declaration in deterministic raw-UTF-8 order; no rotations or aliases.
    pub fn bindings(&self) -> impl Iterator<Item = &ProducerBinding> {
        self.bindings.values()
    }
}

/// One canonical record: the initialization authority is not a signed appended block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArchiveRecord {
    /// Trusted exact unsigned empty checkpoint and explicitly empty outcome.
    TrustedAnchor(Box<canonical::CommittedBlock>),
    /// One producer proof owns the inner body; no second full envelope/body cache is added.
    AuthenticatedAppend {
        tip: Tip,
        proof: Box<AuthenticatedProducerBlock>,
        outcome: BodyOutcome,
    },
}
impl ArchiveRecord {
    /// Canonical local sequence and header-derived content identity.
    pub fn tip(&self) -> Tip {
        match self {
            Self::TrustedAnchor(r) => r.tip,
            Self::AuthenticatedAppend { tip, .. } => *tip,
        }
    }
    /// Exact inner content, independent of producer-signature variants.
    pub fn block(&self) -> &NativeBlock {
        match self {
            Self::TrustedAnchor(r) => &r.block,
            Self::AuthenticatedAppend { proof, .. } => proof.envelope().block(),
        }
    }
    /// Native execution result, not an implemented receipt/economic checkpoint.
    pub fn outcome(&self) -> &BodyOutcome {
        match self {
            Self::TrustedAnchor(r) => &r.outcome,
            Self::AuthenticatedAppend { outcome, .. } => outcome,
        }
    }
    /// None only for the trusted anchor; every appended record has complete canonical evidence.
    pub fn producer_proof(&self) -> Option<&AuthenticatedProducerBlock> {
        match self {
            Self::TrustedAnchor(_) => None,
            Self::AuthenticatedAppend { proof, .. } => Some(proof),
        }
    }
    fn identity(&self) -> Identity {
        Identity {
            tip: self.tip(),
            evidence: self
                .producer_proof()
                .map(|p| (*p.signature().as_bytes(), p.envelope_id())),
        }
    }
}
/// Coherent Ready projection, including exact retained evidence and all original native indexes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Native materialized state/accounting, not complete live node state.
    pub state: TransferState,
    /// Required current canonical tip, initially the trusted checkpoint.
    pub tip: Tip,
    /// Full history with unsigned anchor represented separately from attributed suffix.
    pub records: Vec<ArchiveRecord>,
    /// Exact native ID membership.
    pub transactions: BTreeMap<Hash, Membership>,
    /// Canonical native sender/nonce membership.
    pub sender_nonces: BTreeMap<(Address, u64), Membership>,
    /// Slot/content lookup.
    pub slots: BTreeMap<u64, Hash>,
    /// Content/local-sequence lookup.
    pub hashes: BTreeMap<Hash, Tip>,
}
impl Snapshot {
    fn insert(&mut self, r: ArchiveRecord) -> Result<(), Error> {
        let tip = r.tip();
        for (position, (bytes, id)) in r
            .block()
            .transactions()
            .iter()
            .zip(&r.outcome().transaction_ids)
            .enumerate()
        {
            let member = Membership {
                tip,
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
        if self.slots.insert(tip.slot, tip.hash).is_some()
            || self.hashes.insert(tip.hash, tip).is_some()
        {
            return Err(invalid("duplicate canonical block"));
        }
        self.tip = tip;
        self.records.push(r);
        Ok(())
    }
    fn identities(&self) -> Vec<Identity> {
        self.records.iter().map(ArchiveRecord::identity).collect()
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Identity {
    tip: Tip,
    evidence: Option<([u8; 65], Hash)>,
}
#[derive(Clone, Debug)]
struct Base {
    generation: u64,
    policy: Arc<AuthenticatedFixtureManifest>,
    tip: Tip,
    state: TransferState,
    prefix: Vec<Identity>,
}
/// Native producer effects awaiting an exact independently authenticated signed envelope.
#[derive(Debug)]
pub struct PreparedAuthenticatedBody {
    base: Base,
    candidate: TransferState,
    block: NativeBlock,
    outcome: BodyOutcome,
    staging: Duration,
}
impl PreparedAuthenticatedBody {
    /// Immutable finalized block that the controller signs with existing sign_block.
    pub fn block(&self) -> &NativeBlock {
        &self.block
    }
    /// Expected base for independent trusted fixture grant construction.
    pub fn base_tip(&self) -> Tip {
        self.base.tip
    }
}
/// Private once-consumed signed candidate, never constructible from an old unsigned stage.
#[derive(Debug)]
pub struct StagedAuthenticatedBlock {
    base: Base,
    candidate: TransferState,
    record: ArchiveRecord,
    grant: FixtureAdmissionGrant,
    staging: Duration,
    producer_authentication: Duration,
}
impl StagedAuthenticatedBlock {
    /// Exact accepted signed content/evidence, not commitment permission.
    pub fn producer_proof(&self) -> &AuthenticatedProducerBlock {
        self.record.producer_proof().expect("sealed append")
    }
    /// Owned candidate effects, never a published canonical snapshot.
    pub fn candidate(&self) -> &TransferState {
        &self.candidate
    }
}
/// Included coarse diagnostic spans. None is a consensus or durability input.
#[derive(Clone, Copy, Debug, Default)]
pub struct AppendTimings {
    /// Original ownership/native/SQL/cache/installation spans; SQL block insertion includes evidence.
    pub canonical: canonical::AppendTimings,
    /// Whole cold producer attribution call, already included in staging/pipeline.
    pub producer_authentication: Duration,
    /// Independent policy plus exact prior-evidence prefix reads, included in durable SQL.
    pub policy_and_prefix: Duration,
}
/// Only Committed permits a new success notification or publication/cleanup.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // all publication storage stays preallocated before COMMIT
pub enum AppendOutcome {
    /// Exact evidence/effects were durably committed and coherently installed.
    Committed {
        tip: Tip,
        outcome: BodyOutcome,
        envelope_id: Hash,
        timings: AppendTimings,
    },
    /// No new committed effects; stale SQL owner may remain unavailable until explicit refresh.
    Aborted(Error),
    /// Exact attempt or durability unresolved, owner poisoned until explicit complete recovery.
    RecoveryRequired(Error),
}
/// Full authenticated reload spans. Crypto/native audit costs are included, never bypassed.
#[derive(Clone, Copy, Debug, Default)]
pub struct LoadTimings {
    /// Original complete loader categories, with native audit in audit and producer checks below.
    pub canonical: canonical::LoadTimings,
    /// Historical exact-envelope reconstruction/attribution, included in total.
    pub producer_audit: Duration,
}
/// Exact receipt-like reconciliation diagnostic, not retroactive acknowledgement or retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryReport {
    /// Fully validated current tip.
    pub tip: Tip,
    /// Exact original evidence/effects membership, not revision or block hash alone.
    pub attempted_present: Option<bool>,
}
#[derive(Clone)]
struct Attempt {
    base: Base,
    record: ArchiveRecord,
    candidate: TransferState,
}
struct Loaded {
    snapshot: Snapshot,
    at_base: Option<TransferState>,
    at_attempt: Option<TransferState>,
}

/// Separate exclusive offline schema-3 owner; no migration, raw connection or unsigned admission API.
pub struct AuthenticatedFixtureStore {
    path: PathBuf,
    policy: Arc<AuthenticatedFixtureManifest>,
    connection: Option<Connection>,
    snapshot: Snapshot,
    generation: u64,
    poisoned: bool,
    attempt: Option<Attempt>,
    load_timings: LoadTimings,
    #[cfg(test)]
    hook: Option<Hook>,
    #[cfg(test)]
    vfs: Option<String>,
}
impl AuthenticatedFixtureStore {
    /// Reserve a fresh path and initialize policy/seeds/unsigned anchor/marker in one durable transaction.
    pub fn create_authenticated_fixture(
        path: impl AsRef<Path>,
        policy: &AuthenticatedFixtureManifest,
    ) -> Result<Self, Error> {
        Self::create_inner(path.as_ref(), policy, None, |_| Ok(()))
    }
    /// Strict no-create complete producer/native audit and synchronized barrier before Ready.
    pub fn reopen(
        path: impl AsRef<Path>,
        policy: &AuthenticatedFixtureManifest,
    ) -> Result<Self, Error> {
        Self::load(path.as_ref(), policy, None)
    }
    /// Prior-process archive reconciliation; no original in-memory request receipt is fabricated.
    pub fn recover_existing(
        path: impl AsRef<Path>,
        policy: &AuthenticatedFixtureManifest,
    ) -> Result<Self, Error> {
        Self::load(path.as_ref(), policy, None)
    }
    /// Coherent state/evidence publication only while ready.
    pub fn snapshot(&self) -> Result<&Snapshot, Error> {
        self.ready()?;
        Ok(&self.snapshot)
    }
    /// Diagnostic availability, never new commitment permission.
    pub fn is_ready(&self) -> bool {
        !self.poisoned
    }
    /// Full authenticated loader timings, hidden while unresolved.
    pub fn load_timings(&self) -> Result<LoadTimings, Error> {
        self.ready()?;
        Ok(self.load_timings)
    }
    /// Queried default cache and mandatory durability from the actual owner connection.
    pub fn settings(&self) -> Result<StorageSettings, Error> {
        self.ready()?;
        settings(self.conn())
    }
    /// Reconstruct exact accepted evidence; the trusted anchor has no signed-envelope export.
    pub fn export_signed_envelope(&self, revision: u64) -> Result<Vec<u8>, Error> {
        self.ready()?;
        let r = self
            .snapshot
            .records
            .get(usize::try_from(revision).map_err(|_| Error::Overflow)?)
            .ok_or_else(|| invalid("no record"))?;
        r.producer_proof()
            .map(|p| p.envelope().wire_bytes())
            .ok_or(Error::TrustedAnchorReference(r.tip()))
    }
    /// Stage producer native effects exactly once. This preparation alone cannot commit.
    pub fn prepare_next(
        &self,
        producer: &str,
        ticket: u64,
        body: &[Vec<u8>],
    ) -> Result<PreparedAuthenticatedBody, Error> {
        let now = Instant::now();
        self.ready()?;
        self.policy.binding(producer)?;
        if producer.len() > MAX_PROPOSER_BYTES || body.len() > MAX_TRANSACTIONS {
            return Err(invalid("producer resource bound"));
        }
        if let Some(i) = body.iter().position(|b| b.len() != SIGNED_LEN) {
            return Err(BlockError::Frame {
                reason: "signed length",
                position: Some(i),
            }
            .into());
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
        self.snapshot
            .tip
            .revision
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let (base, candidate, applied) = stage_body(
            &self.snapshot.state,
            &self.policy.fixture.context(),
            slot,
            body,
        )
        .map_err(Error::Body)?
        .into_parts();
        let block = NativeBlock::build(
            &self.policy.fixture.context(),
            slot,
            self.snapshot.tip.hash,
            producer.to_owned(),
            ticket,
            applied.transactions.clone(),
            &applied.outcome,
        )?;
        block.match_outcome(
            &applied.transactions,
            &block.preflight(&self.policy.fixture.context())?,
            &applied.outcome,
        )?;
        self.check_transactions(&block, &applied.outcome)?;
        Ok(PreparedAuthenticatedBody {
            base: self.base(base),
            candidate,
            block,
            outcome: applied.outcome,
            staging: now.elapsed(),
        })
    }
    /// Check base before packet processing; authenticate exactly once and move prepared effects.
    pub fn seal_prepared(
        &self,
        prepared: PreparedAuthenticatedBody,
        bytes: &[u8],
        grant: FixtureAdmissionGrant,
    ) -> Result<StagedAuthenticatedBlock, Error> {
        let now = Instant::now();
        self.check_base(&prepared.base)?;
        let begin = Instant::now();
        let proof = self.authenticate(bytes, None)?;
        let auth_time = begin.elapsed();
        if proof.envelope().block() != &prepared.block {
            return Err(Error::PreparedIdentity);
        }
        self.check_append(&proof, grant)?;
        let revision = self
            .snapshot
            .tip
            .revision
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let tip = Tip {
            hash: proof.block_hash(),
            slot: proof.envelope().block().header().slot,
            revision,
        };
        Ok(StagedAuthenticatedBlock {
            base: prepared.base,
            candidate: prepared.candidate,
            record: ArchiveRecord::AuthenticatedAppend {
                tip,
                proof: Box::new(proof),
                outcome: prepared.outcome,
            },
            grant,
            staging: prepared.staging + now.elapsed(),
            producer_authentication: auth_time,
        })
    }
    /// Mandatory signed receiver route: one producer attribution and one combined native body stage.
    pub fn stage_received(
        &self,
        bytes: &[u8],
        grant: FixtureAdmissionGrant,
    ) -> Result<StagedAuthenticatedBlock, Error> {
        let start = Instant::now();
        self.ready()?;
        let now = Instant::now();
        let proof = self.authenticate(bytes, None)?;
        let auth_time = now.elapsed();
        self.check_append(&proof, grant)?;
        let b = proof.envelope().block();
        let input: Vec<_> = b.transactions().iter().map(|b| b.to_vec()).collect();
        let (base, candidate, applied) = stage_body(
            &self.snapshot.state,
            &self.policy.fixture.context(),
            b.header().slot,
            &input,
        )
        .map_err(Error::Body)?
        .into_parts();
        b.match_outcome(
            &applied.transactions,
            &b.preflight(&self.policy.fixture.context())?,
            &applied.outcome,
        )?;
        self.check_transactions(b, &applied.outcome)?;
        let tip = Tip {
            hash: proof.block_hash(),
            slot: b.header().slot,
            revision: self
                .snapshot
                .tip
                .revision
                .checked_add(1)
                .ok_or(Error::Overflow)?,
        };
        Ok(StagedAuthenticatedBlock {
            base: self.base(base),
            candidate,
            record: ArchiveRecord::AuthenticatedAppend {
                tip,
                proof: Box::new(proof),
                outcome: applied.outcome,
            },
            grant,
            staging: start.elapsed(),
            producer_authentication: auth_time,
        })
    }
    fn authenticate(
        &self,
        bytes: &[u8],
        id: Option<&Hash>,
    ) -> Result<AuthenticatedProducerBlock, Error> {
        authenticate(bytes, &self.policy, id)
    }
    fn base(&self, state: TransferState) -> Base {
        Base {
            generation: self.generation,
            policy: self.policy.clone(),
            tip: self.snapshot.tip,
            state,
            prefix: self.snapshot.identities(),
        }
    }
    fn check_base(&self, b: &Base) -> Result<(), Error> {
        self.ready()?;
        if b.generation != self.generation
            || b.policy != self.policy
            || b.tip != self.snapshot.tip
            || b.state != self.snapshot.state
            || b.prefix != self.snapshot.identities()
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    fn check_append(
        &self,
        p: &AuthenticatedProducerBlock,
        g: FixtureAdmissionGrant,
    ) -> Result<(), Error> {
        let b = p.envelope().block();
        if let Some(tip) = self.snapshot.hashes.get(&b.hash()) {
            let r = self
                .snapshot
                .records
                .get(usize::try_from(tip.revision).map_err(|_| Error::Overflow)?)
                .ok_or_else(|| invalid("hash index"))?;
            if r.block() != b {
                return Err(invalid("stored hash exact content mismatch"));
            }
            return Err(match r.producer_proof() {
                None => Error::TrustedAnchorReference(*tip),
                Some(old) => Error::AlreadyCommitted {
                    tip: *tip,
                    retained_envelope_id: old.envelope_id(),
                    submitted_envelope_id: p.envelope_id(),
                },
            });
        }
        if self.snapshot.slots.contains_key(&b.header().slot) {
            return Err(Error::SlotConflict);
        }
        if self.snapshot.tip.slot.checked_add(1) != Some(b.header().slot) {
            return Err(Error::Slot);
        }
        if b.header().parent_hash != self.snapshot.tip.hash {
            return Err(Error::Parent);
        }
        self.snapshot
            .tip
            .revision
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        if !g.matches(
            self.policy.fixture.context(),
            self.policy.fixture.anchor().hash(),
            self.snapshot.tip,
            b,
        ) {
            return Err(Error::Grant);
        }
        Ok(())
    }
    fn check_transactions(&self, b: &NativeBlock, o: &BodyOutcome) -> Result<(), Error> {
        let mut ids = BTreeSet::new();
        let mut nonces = BTreeSet::new();
        for (i, (bytes, id)) in b.transactions().iter().zip(&o.transaction_ids).enumerate() {
            let nonce = sender_nonce(bytes);
            if self.snapshot.transactions.contains_key(id)
                || !ids.insert(*id)
                || self.snapshot.sender_nonces.contains_key(&nonce)
                || !nonces.insert(nonce)
            {
                return Err(Error::DuplicateTransaction(i));
            }
        }
        Ok(())
    }
    /// One SQL transaction for exact evidence and every canonical effect, then coherent installation.
    pub fn commit(&mut self, stage: StagedAuthenticatedBlock) -> AppendOutcome {
        self.commit_inner(stage, false)
    }
    /// Same checks/writes exposing the coarse SQL breakdown, never another crypto/application path.
    /// The ordinary writer retains fixed boundary clocks too, but does not return this breakdown.
    pub fn commit_profiled(&mut self, stage: StagedAuthenticatedBlock) -> AppendOutcome {
        self.commit_inner(stage, true)
    }
    fn commit_inner(&mut self, s: StagedAuthenticatedBlock, profiled: bool) -> AppendOutcome {
        let begin = Instant::now();
        if let Err(e) = self.check_base(&s.base) {
            return AppendOutcome::Aborted(e);
        }
        if let Err(e) = self.check_append(s.record.producer_proof().expect("sealed"), s.grant) {
            return AppendOutcome::Aborted(e);
        }
        let mut times = AppendTimings {
            producer_authentication: s.producer_authentication,
            ..Default::default()
        };
        times.canonical.staging = s.staging;
        times.canonical.memory_comparison = begin.elapsed();
        let prep = Instant::now();
        let mut next = self.snapshot.clone();
        next.state = s.candidate.clone();
        if let Err(e) = next.insert(s.record.clone()) {
            return AppendOutcome::Aborted(e);
        }
        let attempt = Attempt {
            base: s.base.clone(),
            record: s.record.clone(),
            candidate: s.candidate.clone(),
        };
        times.canonical.cache_preparation = prep.elapsed();
        if let Err(e) = self.point("before_begin") {
            return AppendOutcome::Aborted(e);
        }
        let durable = Instant::now();
        let mut p = canonical::SqlProfile::default();
        let now = Instant::now();
        if let Err(e) = self.conn().execute_batch("BEGIN IMMEDIATE") {
            return AppendOutcome::Aborted(sql(e));
        }
        p.acquisition = now.elapsed();
        self.attempt = Some(attempt);
        let writes = (|| -> Result<(), Error> {
            let now = Instant::now();
            // The metadata sequence is part of the base, independently of the matching tip row.
            // Reject changes before any candidate write rather than discovering them at the later CAS.
            let revision = verify_policy(self.conn(), &self.policy)?;
            if revision != s.base.tip.revision
                || read_tip(self.conn())? != s.base.tip
                || read_prefix(self.conn(), s.base.prefix.len())? != s.base.prefix
            {
                return Err(Error::Stale);
            }
            times.policy_and_prefix = now.elapsed();
            p.metadata_base = times.policy_and_prefix;
            let now = Instant::now();
            validate_state_widths(self.conn())?;
            if disk::read_state(self.conn())? != s.base.state {
                return Err(Error::Stale);
            }
            p.account_comparison = now.elapsed();
            times.canonical.stored_comparison = p.account_comparison;
            let now = Instant::now();
            let tip = s.record.tip();
            let present: bool = self
                .conn()
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM blocks WHERE hash=?1 OR slot=?2)",
                    params![tip.hash.as_slice(), tip.slot.to_be_bytes().as_slice()],
                    |r| r.get(0),
                )
                .map_err(sql)?;
            if present {
                return Err(Error::Stale);
            }
            for (bytes, id) in s
                .record
                .block()
                .transactions()
                .iter()
                .zip(&s.record.outcome().transaction_ids)
            {
                let (sender, nonce) = sender_nonce(bytes);
                let exists:bool=self.conn().query_row("SELECT EXISTS(SELECT 1 FROM transactions WHERE id=?1 OR (sender=?2 AND nonce=?3))",params![id.as_slice(),sender.as_slice(),nonce.to_be_bytes().as_slice()],|r|r.get(0)).map_err(sql)?;
                if exists {
                    return Err(Error::Stale);
                }
            }
            p.uniqueness_probes = now.elapsed();
            let now = Instant::now();
            for (address, account) in s.candidate.accounts() {
                if s.base.state.accounts().get(address) != Some(account) {
                    self.conn().execute("INSERT INTO accounts VALUES(?1,?2,?3) ON CONFLICT(address) DO UPDATE SET balance=excluded.balance,nonce=excluded.nonce",params![address.as_slice(),account.balance_quarks.to_be_bytes().as_slice(),account.nonce.to_be_bytes().as_slice()]).map_err(sql)?;
                }
            }
            p.changed_account_writes = now.elapsed();
            self.point("accounts")?;
            let now = Instant::now();
            disk::write_accounting(self.conn(), &s.candidate)?;
            p.accounting_write = now.elapsed();
            self.point("accounting")?;
            let now = Instant::now();
            insert_block(self.conn(), &s.record)?;
            p.block_insertion = now.elapsed();
            self.point("block_evidence")?;
            let now = Instant::now();
            insert_body(self.conn(), &s.record)?;
            p.body_insertion = now.elapsed();
            self.point("body")?;
            let now = Instant::now();
            insert_transactions(self.conn(), &s.record)?;
            p.transaction_index_insertion = now.elapsed();
            self.point("indexes")?;
            let now = Instant::now();
            if self
                .conn()
                .execute(
                    "UPDATE metadata SET revision=?1 WHERE id=1 AND revision=?2",
                    params![
                        tip.revision.to_be_bytes().as_slice(),
                        s.base.tip.revision.to_be_bytes().as_slice()
                    ],
                )
                .map_err(sql)?
                != 1
            {
                return Err(invalid("revision CAS"));
            }
            self.point("revision")?;
            if self.conn().execute("UPDATE canonical_tip SET hash=?1,slot=?2,revision=?3 WHERE id=1 AND hash=?4 AND slot=?5 AND revision=?6",params![tip.hash.as_slice(),tip.slot.to_be_bytes().as_slice(),tip.revision.to_be_bytes().as_slice(),s.base.tip.hash.as_slice(),s.base.tip.slot.to_be_bytes().as_slice(),s.base.tip.revision.to_be_bytes().as_slice()]).map_err(sql)?!=1{return Err(invalid("tip CAS"));}
            self.point("tip")?;
            p.revision_tip = now.elapsed();
            self.point("before_commit")?;
            Ok(())
        })();
        if let Err(e) = writes {
            if e == Error::Stale {
                match self.conn().execute_batch("ROLLBACK") {
                    Ok(()) if self.conn().is_autocommit() => {
                        self.attempt = None;
                        self.poisoned = true;
                        return AppendOutcome::Aborted(e);
                    }
                    _ => return self.poison(e),
                }
            }
            return self.abort(e);
        }
        let now = Instant::now();
        if let Err(e) = self.conn().execute_batch("COMMIT") {
            return self.poison(sql(e));
        }
        p.commit_return = now.elapsed();
        times.canonical.durable_commit = durable.elapsed();
        if profiled {
            times.canonical.sql_profile = Some(p);
        }
        if let Err(e) = self.point("after_commit") {
            return self.poison(e);
        }
        let now = Instant::now();
        let old = std::mem::replace(&mut self.snapshot, next);
        times.canonical.installation = now.elapsed();
        let now = Instant::now();
        drop(old);
        times.canonical.cache_destruction = now.elapsed();
        if let Err(e) = self.point("after_install") {
            return self.poison(e);
        }
        self.attempt = None;
        let envelope_id = s.record.producer_proof().expect("sealed").envelope_id();
        let tip = s.record.tip();
        let outcome = match s.record {
            ArchiveRecord::AuthenticatedAppend { outcome, .. } => outcome,
            _ => unreachable!(),
        };
        AppendOutcome::Committed {
            tip,
            outcome,
            envelope_id,
            timings: times,
        }
    }
    fn abort(&mut self, e: Error) -> AppendOutcome {
        if !self.conn().is_autocommit()
            && let Err(r) = self
                .point("rollback")
                .and_then(|_| self.conn().execute_batch("ROLLBACK").map_err(sql))
        {
            return self.poison(invalid(format!("{e}; rollback {r}")));
        }
        if !self.conn().is_autocommit() {
            return self.poison(e);
        }
        match load_snapshot(self.conn(), &self.policy, None, &mut LoadTimings::default()) {
            Ok(old) if old.snapshot == self.snapshot => {
                self.attempt = None;
                AppendOutcome::Aborted(e)
            }
            other => self.poison(invalid(format!(
                "{e}; unconfirmed previous evidence/effects: {:?}",
                other.err()
            ))),
        }
    }
    fn poison(&mut self, e: Error) -> AppendOutcome {
        self.poisoned = true;
        AppendOutcome::RecoveryRequired(uncertain(e))
    }
    /// Invalidate overlays, fully attribute/audit/reconcile exact attempt, synchronize, then publish.
    pub fn recover(&mut self) -> Result<RecoveryReport, Error> {
        let whole = Instant::now();
        self.poisoned = true;
        self.generation = disk::next_generation()?;
        self.connection.take();
        self.point("recovery_reopen")?;
        let now = Instant::now();
        let conn = disk::open(&self.path, self.vfs_name())?;
        configure(&conn)?;
        let mut t = LoadTimings::default();
        t.canonical.open_configuration = now.elapsed();
        self.connection = Some(conn);
        self.point("recovery_validate")?;
        let loaded = load_snapshot(self.conn(), &self.policy, self.attempt.as_ref(), &mut t)?;
        if self.attempt.is_none() {
            // A refresh may discover valid descendants, but this owner already knows its accepted
            // prefix. Fresh-process attribution cannot substitute for that exact-evidence pin.
            let known = self.snapshot.identities();
            let recovered = loaded.snapshot.identities();
            if !recovered.starts_with(&known) {
                return Err(uncertain("known accepted evidence prefix differs"));
            }
        }
        let present = reconcile(self.attempt.as_ref(), &loaded)?;
        self.point("recovery_barrier")?;
        let now = Instant::now();
        barrier(self.conn(), &self.path, &self.policy, &loaded.snapshot)?;
        t.canonical.barrier = now.elapsed();
        self.point("recovery_install")?;
        let now = Instant::now();
        self.snapshot = loaded.snapshot;
        t.canonical.installation = now.elapsed();
        self.attempt = None;
        self.poisoned = false;
        t.canonical.total = whole.elapsed();
        self.load_timings = t;
        Ok(RecoveryReport {
            tip: self.snapshot.tip,
            attempted_present: present,
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
    fn point(&mut self, _p: &str) -> Result<(), Error> {
        #[cfg(test)]
        if let Some(h) = &mut self.hook {
            return h(_p);
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
    fn owner(
        path: &Path,
        policy: &AuthenticatedFixtureManifest,
        conn: Connection,
        snapshot: Snapshot,
        _vfs: Option<&str>,
    ) -> Result<Self, Error> {
        Ok(Self {
            path: path.to_owned(),
            policy: Arc::new(policy.clone()),
            connection: Some(conn),
            snapshot,
            generation: disk::next_generation()?,
            poisoned: false,
            attempt: None,
            load_timings: LoadTimings::default(),
            #[cfg(test)]
            hook: None,
            #[cfg(test)]
            vfs: _vfs.map(str::to_owned),
        })
    }
    fn create_inner(
        path: &Path,
        m: &AuthenticatedFixtureManifest,
        vfs: Option<&str>,
        mut point: impl FnMut(&str) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        let start = Instant::now();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Error::Storage(StoreError::AlreadyExists)
                } else {
                    Error::Storage(disk::invalid(e))
                }
            })?;
        let c = disk::open(path, vfs)?;
        configure(&c)?;
        let anchor = ArchiveRecord::TrustedAnchor(Box::new(canonical::CommittedBlock {
            tip: Tip {
                hash: m.fixture.anchor().hash(),
                slot: m.fixture.anchor().header().slot,
                revision: 0,
            },
            block: m.fixture.anchor().clone(),
            outcome: BodyOutcome::default(),
        }));
        let mut snapshot = empty_snapshot(m.fixture.initial_state().clone(), anchor.tip());
        snapshot.insert(anchor.clone())?;
        let mut owner = Self::owner(path, m, c, snapshot, vfs)?;
        let c = owner.conn();
        c.execute_batch("BEGIN IMMEDIATE").map_err(sql)?;
        let init = (|| -> Result<(), Error> {
            for (_, ddl) in schema::TABLES {
                c.execute_batch(ddl).map_err(sql)?;
            }
            for (_, ddl) in schema::triggers() {
                c.execute_batch(&ddl).map_err(sql)?;
            }
            point("schema")?;
            c.execute("INSERT INTO metadata VALUES(1,x'00000003','offline-authenticated-native-blocks',?1,?2,x'00000001',?3,?4,?5,?6,?7,?7,?8,x'02',x'00000002',0,x'03',x'01',x'00000001',?9)",params![m.fixture.context().chain_id().to_be_bytes().as_slice(),m.fixture.context().network_id().as_slice(),m.fixture.provenance(),m.fixture.initial_state().gas_used_total().to_be_bytes().as_slice(),m.fixture.initial_state().fees_burned_total().to_be_bytes().as_slice(),(m.fixture.initial_state().accounts().len()as u64).to_be_bytes().as_slice(),0u64.to_be_bytes().as_slice(),m.fixture.anchor().hash().as_slice(),(m.bindings.len()as u64).to_be_bytes().as_slice()]).map_err(sql)?;
            point("context")?;
            for b in m.bindings.values() {
                c.execute(
                    "INSERT INTO producer_bindings VALUES(?1,?2)",
                    params![b.producer_id().as_bytes(), b.public_key().as_slice()],
                )
                .map_err(sql)?;
                point("producer_binding")?;
            }
            point("bindings")?;
            {
                let mut seed = c
                    .prepare("INSERT INTO seed_accounts VALUES(?1,?2,?3)")
                    .map_err(sql)?;
                let mut state = c
                    .prepare("INSERT INTO accounts VALUES(?1,?2,?3)")
                    .map_err(sql)?;
                for (a, account) in m.fixture.initial_state().accounts() {
                    let balance = account.balance_quarks.to_be_bytes();
                    let nonce = account.nonce.to_be_bytes();
                    seed.execute(params![a.as_slice(), balance.as_slice(), nonce.as_slice()])
                        .map_err(sql)?;
                    state
                        .execute(params![a.as_slice(), balance.as_slice(), nonce.as_slice()])
                        .map_err(sql)?;
                    point("fixture_account")?;
                }
            }
            point("fixture_accounts")?;
            c.execute(
                "INSERT INTO accounting VALUES(1,?1,?2)",
                params![
                    m.fixture
                        .initial_state()
                        .gas_used_total()
                        .to_be_bytes()
                        .as_slice(),
                    m.fixture
                        .initial_state()
                        .fees_burned_total()
                        .to_be_bytes()
                        .as_slice()
                ],
            )
            .map_err(sql)?;
            point("initial_accounting")?;
            insert_block(c, &anchor)?;
            point("anchor")?;
            insert_body(c, &anchor)?;
            point("anchor_body")?;
            let tip = anchor.tip();
            c.execute(
                "INSERT INTO canonical_tip VALUES(1,?1,?2,?3)",
                params![
                    tip.hash.as_slice(),
                    tip.slot.to_be_bytes().as_slice(),
                    0u64.to_be_bytes().as_slice()
                ],
            )
            .map_err(sql)?;
            point("initial_tip")?;
            c.execute_batch("UPDATE metadata SET initialized=1 WHERE id=1")
                .map_err(sql)?;
            point("marker")?;
            point("init_before_commit")?;
            Ok(())
        })();
        if let Err(e) = init {
            if !c.is_autocommit() {
                c.execute_batch("ROLLBACK")
                    .map_err(|r| uncertain(format!("{e}; rollback {r}")))?;
            }
            return match load_snapshot(c, m, None, &mut LoadTimings::default()) {
                Err(Error::Storage(StoreError::Uninitialized)) => {
                    Err(Error::Storage(StoreError::Aborted(e.to_string())))
                }
                _ => Err(uncertain(e)),
            };
        }
        c.execute_batch("COMMIT").map_err(|e| uncertain(sql(e)))?;
        point("init_after_commit").map_err(uncertain)?;
        point("init_directory_sync")
            .and_then(|_| disk::sync_path(path).map_err(Error::from))
            .map_err(uncertain)?;
        owner.load_timings.canonical.total = start.elapsed();
        Ok(owner)
    }
    fn load(
        path: &Path,
        m: &AuthenticatedFixtureManifest,
        vfs: Option<&str>,
    ) -> Result<Self, Error> {
        let whole = Instant::now();
        let now = Instant::now();
        let c = disk::open(path, vfs)?;
        configure(&c)?;
        let mut t = LoadTimings::default();
        t.canonical.open_configuration = now.elapsed();
        let loaded = load_snapshot(&c, m, None, &mut t)?;
        let now = Instant::now();
        barrier(&c, path, m, &loaded.snapshot)?;
        t.canonical.barrier = now.elapsed();
        let now = Instant::now();
        let mut owner = Self::owner(path, m, c, loaded.snapshot, vfs)?;
        t.canonical.installation = now.elapsed();
        t.canonical.total = whole.elapsed();
        owner.load_timings = t;
        Ok(owner)
    }
}

fn configure(c: &Connection) -> Result<(), Error> {
    disk::configure(c)?;
    let size: i64 = c
        .query_row("PRAGMA cache_size", [], |r| r.get(0))
        .map_err(sql)?;
    let spill: i64 = c
        .query_row("PRAGMA cache_spill", [], |r| r.get(0))
        .map_err(sql)?;
    if size != -2000 || spill <= 0 {
        return Err(invalid("required existing default cache/spill policy"));
    }
    Ok(())
}
fn settings(c: &Connection) -> Result<StorageSettings, Error> {
    let q = |s: &str| c.query_row(s, [], |r| r.get::<_, i64>(0)).map_err(sql);
    Ok(StorageSettings {
        journal_mode: c
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .map_err(sql)?,
        synchronous: q("PRAGMA synchronous")?,
        foreign_keys: q("PRAGMA foreign_keys")? == 1,
        page_size: q("PRAGMA page_size")?,
        cache_size: q("PRAGMA cache_size")?,
    })
}
fn empty_snapshot(state: TransferState, tip: Tip) -> Snapshot {
    Snapshot {
        state,
        tip,
        records: vec![],
        transactions: BTreeMap::new(),
        sender_nonces: BTreeMap::new(),
        slots: BTreeMap::new(),
        hashes: BTreeMap::new(),
    }
}
fn sender_nonce(b: &[u8; SIGNED_LEN]) -> (Address, u64) {
    (
        b[46..66].try_into().expect("fixed authenticated address"),
        u64::from_be_bytes(b[66..74].try_into().expect("fixed authenticated nonce")),
    )
}
// Bounded borrowed SQL values avoid allocating based on corrupt untrusted stored lengths.
fn bytes<'a>(r: &'a Row<'_>, col: usize, min: usize, max: usize) -> rusqlite::Result<&'a [u8]> {
    match r.get_ref(col)? {
        ValueRef::Blob(b) if (min..=max).contains(&b.len()) => Ok(b),
        _ => Err(rusqlite::Error::InvalidColumnType(
            col,
            "bounded BLOB".into(),
            r.get_ref(col)?.data_type(),
        )),
    }
}
fn fixed<const N: usize>(r: &Row<'_>, col: usize) -> rusqlite::Result<[u8; N]> {
    Ok(bytes(r, col, N, N)?.try_into().expect("checked fixed BLOB"))
}
fn authenticate(
    wire: &[u8],
    m: &AuthenticatedFixtureManifest,
    id: Option<&Hash>,
) -> Result<AuthenticatedProducerBlock, Error> {
    // Structural dispatch never supplies key authority or performs producer/native authentication.
    let e = SignedBlockEnvelope::from_wire_bytes(wire)?;
    if e.network_id() != m.fixture.context().network_id() {
        return Err(auth::Error::NetworkMismatch.into());
    }
    e.block().preflight(&m.fixture.context())?;
    let binding = m.binding(e.block().proposer())?;
    Ok(auth::authenticate_block(wire, &m.context, binding, id)?)
}
fn insert_block(c: &Connection, r: &ArchiveRecord) -> Result<(), Error> {
    let tip = r.tip();
    let b = r.block();
    let s = r
        .producer_proof()
        .map(|p| p.signature().as_bytes().as_slice());
    let id = r
        .producer_proof()
        .map(AuthenticatedProducerBlock::envelope_id);
    c.execute(
        "INSERT INTO blocks VALUES(?1,?2,?3,?4,?5,?6,?7,?3,?8,?9,?10)",
        params![
            tip.hash.as_slice(),
            tip.slot.to_be_bytes().as_slice(),
            tip.revision.to_be_bytes().as_slice(),
            b.header().canonical_bytes(),
            b.proposer().as_bytes(),
            b.protocol_data().canonical_bytes(),
            b.header().parent_hash.as_slice(),
            i64::from(tip.revision == 0),
            s,
            id.as_ref().map(|b| b.as_slice())
        ],
    )
    .map_err(sql)?;
    Ok(())
}
fn insert_body(c: &Connection, r: &ArchiveRecord) -> Result<(), Error> {
    let t = r.tip();
    c.execute(
        "INSERT INTO bodies VALUES(?1,?2,?3,x'02',x'00000001',?4,?5,?6)",
        params![
            t.revision.to_be_bytes().as_slice(),
            t.hash.as_slice(),
            t.slot.to_be_bytes().as_slice(),
            (r.block().transactions().len() as u64)
                .to_be_bytes()
                .as_slice(),
            r.outcome().gas_used.to_be_bytes().as_slice(),
            r.outcome().fees_burned.to_be_bytes().as_slice()
        ],
    )
    .map_err(sql)?;
    Ok(())
}
fn insert_transactions(c: &Connection, r: &ArchiveRecord) -> Result<(), Error> {
    let mut q = c
        .prepare("INSERT INTO transactions VALUES(?1,?2,?3,?4,?5,?6)")
        .map_err(sql)?;
    for (i, (b, id)) in r
        .block()
        .transactions()
        .iter()
        .zip(&r.outcome().transaction_ids)
        .enumerate()
    {
        let (a, n) = sender_nonce(b);
        q.execute(params![
            id.as_slice(),
            r.tip().revision.to_be_bytes().as_slice(),
            (i as u64).to_be_bytes().as_slice(),
            a.as_slice(),
            n.to_be_bytes().as_slice(),
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
                hash: fixed(r, 0)?,
                slot: u64::from_be_bytes(fixed(r, 1)?),
                revision: u64::from_be_bytes(fixed(r, 2)?),
            })
        },
    )
    .map_err(sql)
}
fn count(c: &Connection, table: &str) -> Result<u64, Error> {
    let n: i64 = c
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .map_err(sql)?;
    u64::try_from(n).map_err(|_| invalid("negative count"))
}
fn verify_policy(c: &Connection, m: &AuthenticatedFixtureManifest) -> Result<u64, Error> {
    let rev=c.query_row("SELECT schema_version,mode,chain,network,rules,provenance,seed_gas,seed_burn,seed_count,revision,anchor_hash,wire,profile,initialized,outer_wire,auth_encoding,auth_rules,producer_count FROM metadata WHERE id=1",[],|r|{
  let marker:i64=r.get(13)?;if marker!=1{return Ok(None);}
  let provenance=r.get_ref(5)?;let mode=r.get_ref(1)?;
  let valid=fixed::<4>(r,0)?==3u32.to_be_bytes()&&mode==ValueRef::Text(b"offline-authenticated-native-blocks")&&u64::from_be_bytes(fixed(r,2)?)==m.fixture.context().chain_id()&&fixed::<32>(r,3)?==m.fixture.context().network_id()&&fixed::<4>(r,4)?==1u32.to_be_bytes()&&provenance==ValueRef::Text(m.fixture.provenance().as_bytes())&&u64::from_be_bytes(fixed(r,6)?)==m.fixture.initial_state().gas_used_total()&&u128::from_be_bytes(fixed(r,7)?)==m.fixture.initial_state().fees_burned_total()&&u64::from_be_bytes(fixed(r,8)?)==m.fixture.initial_state().accounts().len()as u64&&fixed::<32>(r,10)?==m.fixture.anchor().hash()&&fixed::<1>(r,11)?==[2]&&fixed::<4>(r,12)?==2u32.to_be_bytes()&&fixed::<1>(r,14)?==[3]&&fixed::<1>(r,15)?==[1]&&fixed::<4>(r,16)?==1u32.to_be_bytes()&&u64::from_be_bytes(fixed(r,17)?)==m.bindings.len()as u64;
  Ok(Some((valid,u64::from_be_bytes(fixed(r,9)?))))
 }).optional().map_err(sql)?.flatten().ok_or(Error::Storage(StoreError::Uninitialized))?;
    if !rev.0 || count(c, "metadata")? != 1 {
        return Err(invalid("independent fixture policy mismatch"));
    }
    if count(c, "producer_bindings")? != m.bindings.len() as u64 {
        return Err(invalid("independent binding count"));
    }
    let mut q = c
        .prepare("SELECT producer,public_key FROM producer_bindings ORDER BY producer")
        .map_err(sql)?;
    let mut rows = q.query([]).map_err(sql)?;
    for expected in m.bindings.values() {
        let r = rows
            .next()
            .map_err(sql)?
            .ok_or_else(|| invalid("missing binding"))?;
        if bytes(r, 0, 1, 256).map_err(sql)? != expected.producer_id().as_bytes()
            || fixed::<33>(r, 1).map_err(sql)? != *expected.public_key()
        {
            return Err(invalid("independent producer declaration mismatch"));
        }
    }
    if rows.next().map_err(sql)?.is_some() {
        return Err(invalid("extra binding"));
    }
    Ok(rev.1)
}
fn read_prefix(c: &Connection, expected: usize) -> Result<Vec<Identity>, Error> {
    if count(c, "blocks")? != expected as u64 {
        return Err(Error::Stale);
    }
    let mut q=c.prepare("SELECT hash,slot,revision,producer_signature,signed_envelope_id FROM blocks ORDER BY revision").map_err(sql)?;
    let mut rows = q.query([]).map_err(sql)?;
    let mut out = Vec::with_capacity(expected);
    while let Some(r) = rows.next().map_err(sql)? {
        let tip = Tip {
            hash: fixed(r, 0).map_err(sql)?,
            slot: u64::from_be_bytes(fixed(r, 1).map_err(sql)?),
            revision: u64::from_be_bytes(fixed(r, 2).map_err(sql)?),
        };
        if tip.revision != out.len() as u64 {
            return Err(invalid("prefix revision"));
        }
        let evidence = if tip.revision == 0 {
            if r.get_ref(3).map_err(sql)? != ValueRef::Null
                || r.get_ref(4).map_err(sql)? != ValueRef::Null
            {
                return Err(invalid("anchor evidence"));
            }
            None
        } else {
            Some((fixed(r, 3).map_err(sql)?, fixed(r, 4).map_err(sql)?))
        };
        out.push(Identity { tip, evidence });
    }
    Ok(out)
}
fn validate_accounts(c: &Connection, table: &str) -> Result<(), Error> {
    let bad:bool=c.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE typeof(address)<>'blob' OR length(address)<>20 OR typeof(balance)<>'blob' OR length(balance)<>16 OR typeof(nonce)<>'blob' OR length(nonce)<>8)"),[],|r|r.get(0)).map_err(sql)?;
    if bad {
        return Err(invalid("account widths"));
    }
    Ok(())
}
fn validate_state_widths(c: &Connection) -> Result<(), Error> {
    validate_accounts(c, "accounts")?;
    if count(c, "accounting")? != 1 {
        return Err(invalid("accounting singleton"));
    }
    c.query_row("SELECT gas,burn FROM accounting WHERE id=1", [], |r| {
        fixed::<8>(r, 0)?;
        fixed::<16>(r, 1)?;
        Ok(())
    })
    .map_err(sql)
}
fn check_schema(c: &Connection) -> Result<(), Error> {
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
    let mut expected: BTreeMap<(String, String), String> = schema::TABLES
        .iter()
        .map(|(n, d)| (("table".into(), (*n).into()), (*d).into()))
        .collect();
    for (n, d) in schema::triggers() {
        expected.insert(("trigger".into(), n), d);
    }
    // Literal prefix comparison: LIKE's '_' is a wildcard and would hide attacker-named objects.
    let mut q=c.prepare("SELECT type,name,sql FROM sqlite_schema WHERE substr(name,1,7)<>'sqlite_' ORDER BY type,name").map_err(sql)?;
    let actual = q
        .query_map([], |r| {
            Ok((
                (r.get::<_, String>(0)?, r.get::<_, String>(1)?),
                r.get::<_, String>(2)?,
            ))
        })
        .map_err(sql)?
        .collect::<rusqlite::Result<BTreeMap<_, _>>>()
        .map_err(sql)?;
    if actual != expected {
        return Err(invalid("exact schema/index/trigger contract"));
    }
    if c.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
        .map_err(sql)?
        != "ok"
    {
        return Err(invalid("integrity"));
    }
    if c.prepare("PRAGMA foreign_key_check")
        .map_err(sql)?
        .query([])
        .map_err(sql)?
        .next()
        .map_err(sql)?
        .is_some()
    {
        return Err(invalid("foreign keys"));
    }
    Ok(())
}
fn barrier(
    c: &Connection,
    path: &Path,
    m: &AuthenticatedFixtureManifest,
    s: &Snapshot,
) -> Result<(), Error> {
    c.execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| uncertain(sql(e)))?;
    let work = (|| -> Result<(), Error> {
        let rev = verify_policy(c, m)?;
        if rev != s.tip.revision
            || read_tip(c)? != s.tip
            || read_prefix(c, s.records.len())? != s.identities()
        {
            return Err(Error::Stale);
        }
        let old = c
            .query_row("SELECT barrier FROM metadata WHERE id=1", [], |r| {
                fixed::<8>(r, 0)
            })
            .map_err(sql)?;
        let next = u64::from_be_bytes(old)
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        if c.execute(
            "UPDATE metadata SET barrier=?1 WHERE id=1 AND barrier=?2",
            params![next.to_be_bytes().as_slice(), old.as_slice()],
        )
        .map_err(sql)?
            != 1
        {
            return Err(invalid("barrier CAS"));
        }
        c.execute_batch("COMMIT").map_err(sql)?;
        disk::sync_path(path)?;
        Ok(())
    })();
    work.map_err(uncertain)
}
fn reconcile(a: Option<&Attempt>, loaded: &Loaded) -> Result<Option<bool>, Error> {
    let Some(a) = a else {
        return Ok(None);
    };
    let snap = &loaded.snapshot;
    let base_len = usize::try_from(a.base.tip.revision)
        .map_err(|_| Error::Overflow)?
        .checked_add(1)
        .ok_or(Error::Overflow)?;
    if snap.records.len() < base_len
        || snap.identities()[..base_len] != a.base.prefix
        || loaded.at_base.as_ref() != Some(&a.base.state)
    {
        return Err(uncertain("exact accepted base differs"));
    }
    if let Some(record) = snap
        .records
        .get(usize::try_from(a.record.tip().revision).map_err(|_| Error::Overflow)?)
    {
        if record != &a.record || loaded.at_attempt.as_ref() != Some(&a.candidate) {
            return Err(uncertain("different exact attempted evidence/effects"));
        }
        return Ok(Some(true));
    }
    if snap.tip == a.base.tip && snap.state == a.base.state && snap.identities() == a.base.prefix {
        return Ok(Some(false));
    }
    Err(uncertain("not exact old or exact accepted attempt"))
}
fn load_snapshot(
    c: &Connection,
    m: &AuthenticatedFixtureManifest,
    a: Option<&Attempt>,
    t: &mut LoadTimings,
) -> Result<Loaded, Error> {
    let now = Instant::now();
    c.execute_batch("BEGIN").map_err(sql)?;
    let result = load_transaction(c, m, a, t);
    let end = c.execute_batch("ROLLBACK").map_err(sql);
    t.canonical.validation_materialization = now
        .elapsed()
        .saturating_sub(t.canonical.audit)
        .saturating_sub(t.producer_audit)
        .saturating_sub(t.canonical.equality);
    result.and_then(|s| end.map(|_| s))
}
fn load_transaction(
    c: &Connection,
    m: &AuthenticatedFixtureManifest,
    attempt: Option<&Attempt>,
    t: &mut LoadTimings,
) -> Result<Loaded, Error> {
    check_schema(c)?;
    let revision = verify_policy(c, m)?;
    let final_tip = read_tip(c)?;
    validate_accounts(c, "seed_accounts")?;
    validate_state_widths(c)?;
    let seeds = TransferState::new(
        disk::read_accounts(c, "seed_accounts")?,
        m.fixture.initial_state().gas_used_total(),
        m.fixture.initial_state().fees_burned_total(),
    );
    if &seeds != m.fixture.initial_state() {
        return Err(invalid("independent seed authority"));
    }
    let mut audit = seeds;
    let mut snap = empty_snapshot(disk::read_state(c)?, final_tip);
    let mut at_base = None;
    let mut at_attempt = None;
    let mut query=c.prepare("SELECT b.hash,b.slot,b.revision,b.header,b.proposer,b.protocol_data,b.parent,b.body_revision,b.is_anchor,b.producer_signature,b.signed_envelope_id,d.block_hash,d.slot,d.encoding,d.rules,d.count,d.gas,d.burn FROM blocks b LEFT JOIN bodies d ON d.revision=b.revision ORDER BY b.revision").map_err(sql)?;
    let mut rows = query.query([]).map_err(sql)?;
    while let Some(r) = rows.next().map_err(sql)? {
        let tip = Tip {
            hash: fixed(r, 0).map_err(sql)?,
            slot: u64::from_be_bytes(fixed(r, 1).map_err(sql)?),
            revision: u64::from_be_bytes(fixed(r, 2).map_err(sql)?),
        };
        let rev = tip.revision;
        if rev != snap.records.len() as u64 {
            return Err(invalid("contiguous revisions"));
        }
        let header = BlockHeader::from_canonical_bytes(&fixed::<229>(r, 3).map_err(sql)?)
            .ok_or_else(|| invalid("header codec"))?;
        let proposer = std::str::from_utf8(bytes(r, 4, 1, 256).map_err(sql)?)
            .map_err(invalid)?
            .to_owned();
        let pd = ProtocolData::from_canonical_bytes(&fixed::<10>(r, 5).map_err(sql)?)
            .ok_or_else(|| invalid("protocol codec"))?;
        if header.hash() != tip.hash
            || header.slot != tip.slot
            || header.parent_hash != fixed::<32>(r, 6).map_err(sql)?
            || u64::from_be_bytes(fixed(r, 7).map_err(sql)?) != rev
            || r.get::<_, i64>(8).map_err(sql)? != i64::from(rev == 0)
            || fixed::<32>(r, 11).map_err(sql)? != tip.hash
            || u64::from_be_bytes(fixed(r, 12).map_err(sql)?) != tip.slot
            || fixed::<1>(r, 13).map_err(sql)? != [2]
            || fixed::<4>(r, 14).map_err(sql)? != 1u32.to_be_bytes()
        {
            return Err(invalid("block/body metadata"));
        }
        let n = u64::from_be_bytes(fixed(r, 15).map_err(sql)?);
        if n > MAX_TRANSACTIONS as u64 {
            return Err(invalid("body count bound"));
        }
        let mut txs = Vec::with_capacity(n as usize);
        let mut ids = Vec::with_capacity(n as usize);
        let mut q=c.prepare("SELECT id,position,sender,nonce,signed FROM transactions WHERE revision=?1 ORDER BY position").map_err(sql)?;
        let mut entries = q.query([rev.to_be_bytes().as_slice()]).map_err(sql)?;
        while let Some(row) = entries.next().map_err(sql)? {
            if txs.len() >= n as usize {
                return Err(invalid("extra body entries"));
            }
            let b = fixed::<SIGNED_LEN>(row, 4).map_err(sql)?;
            let id = fixed::<32>(row, 0).map_err(sql)?;
            if u64::from_be_bytes(fixed(row, 1).map_err(sql)?) != txs.len() as u64
                || sender_nonce(&b)
                    != (
                        fixed(row, 2).map_err(sql)?,
                        u64::from_be_bytes(fixed(row, 3).map_err(sql)?),
                    )
                || hash_with_domain(ID_DOMAIN, &b) != id
            {
                return Err(invalid("body positions/indexes/bytes"));
            }
            txs.push(b);
            ids.push(id);
        }
        if txs.len() != n as usize {
            return Err(invalid("missing body entries"));
        }
        let block = NativeBlock::from_parts(header, proposer, pd, txs)?;
        let outcome = BodyOutcome {
            transaction_ids: ids,
            gas_used: u64::from_be_bytes(fixed(r, 16).map_err(sql)?),
            fees_burned: u64::from_be_bytes(fixed(r, 17).map_err(sql)?),
        };
        let record = if rev == 0 {
            block.preflight(&m.fixture.context())?;
            if &block != m.fixture.anchor()
                || outcome != BodyOutcome::default()
                || r.get_ref(9).map_err(sql)? != ValueRef::Null
                || r.get_ref(10).map_err(sql)? != ValueRef::Null
            {
                return Err(invalid("trusted unsigned anchor"));
            }
            ArchiveRecord::TrustedAnchor(Box::new(canonical::CommittedBlock {
                tip,
                block,
                outcome,
            }))
        } else {
            if snap.tip.slot.checked_add(1) != Some(tip.slot)
                || block.header().parent_hash != snap.tip.hash
            {
                return Err(invalid("successor/parent prefix"));
            }
            let s = fixed::<65>(r, 9).map_err(sql)?;
            let id = fixed::<32>(r, 10).map_err(sql)?;
            let now = Instant::now();
            let envelope =
                SignedBlockEnvelope::from_parts(block, m.fixture.context().network_id(), s)?;
            let proof = authenticate(&envelope.wire_bytes(), m, Some(&id))?;
            t.producer_audit += now.elapsed();
            let b = proof.envelope().block();
            let raw_ids = b.preflight(&m.fixture.context())?;
            let now = Instant::now();
            let input: Vec<_> = b.transactions().iter().map(|b| b.to_vec()).collect();
            let staged =
                stage_body(&audit, &m.fixture.context(), tip.slot, &input).map_err(Error::Body)?;
            t.canonical.audit += now.elapsed();
            b.match_outcome(
                &staged.record().transactions,
                &raw_ids,
                &staged.record().outcome,
            )?;
            if staged.record().outcome != outcome {
                return Err(invalid("native stored outcome"));
            }
            let (_, candidate, _) = staged.into_parts();
            audit = candidate;
            ArchiveRecord::AuthenticatedAppend {
                tip,
                proof: Box::new(proof),
                outcome,
            }
        };
        if let Some(a) = attempt {
            if rev == a.base.tip.revision {
                at_base = Some(audit.clone());
            }
            if rev == a.record.tip().revision {
                at_attempt = Some(audit.clone());
            }
        }
        snap.insert(record)?;
    }
    if snap.records.is_empty() || snap.tip != final_tip || snap.tip.revision != revision {
        return Err(invalid("final tip/marker archive"));
    }
    for table in ["blocks", "bodies"] {
        if count(c, table)? != snap.records.len() as u64 {
            return Err(invalid("archive pair count"));
        }
    }
    if count(c, "transactions")? != snap.transactions.len() as u64 {
        return Err(invalid("transaction count"));
    }
    let now = Instant::now();
    let equal = audit == snap.state;
    t.canonical.equality += now.elapsed();
    if !equal {
        return Err(invalid(
            "materialized state differs from independent seed audit",
        ));
    }
    Ok(Loaded {
        snapshot: snap,
        at_base,
        at_attempt,
    })
}
