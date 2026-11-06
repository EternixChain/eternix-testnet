//! Fresh schema4 authoritative C1 owner. No migration, raw writer or caller-snapshot admission.
//!
//! Readiness means an independently seeded full historical audit plus a dirty-page synchronization
//! barrier. Preparations bind a unique owner generation and the complete state/original-evidence
//! prefix. Only a confirmed atomic commit followed by installation returns new success.
use super::application::{
    self as app, AuthenticatedEnvelope, Block, Envelope, Error, invalid, overflow,
};
use super::*;
use crate::durable_fixture::{self as disk, StorageSettings, StoreError};
use crate::native_transaction::{Address, Hash, SIGNED_LEN};
use crate::native_transfer::BodyOutcome;
use rusqlite::{Connection, params};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
mod sql;
#[cfg(test)]
mod tests;
#[cfg(test)]
type Hook = Box<dyn FnMut(&str) -> Result<(), Error>>;

/// Exact canonical native membership; signatures do not affect the parent H.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Membership {
    /// Complete owning block position.
    pub position: Position,
    /// Zero-based native body index.
    pub index: u64,
}
/// One completely audited append, preserving original producer evidence and full supported post-state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    proof: AuthenticatedEnvelope,
    outcome: BodyOutcome,
    state: ClosedState,
}
impl Record {
    /// Original authenticated envelope, not a newly generated signature.
    pub fn proof(&self) -> &AuthenticatedEnvelope {
        &self.proof
    }
    /// Shared native result, without a second fee charge.
    pub fn outcome(&self) -> &BodyOutcome {
        &self.outcome
    }
    /// Complete supported state after native execution and reward accrual.
    pub fn state(&self) -> &ClosedState {
        &self.state
    }
}
/// Coherent Ready projection. Clones are diagnostic values and cannot authorize owner writes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Exact complete current supported state, including earning/locked/retained-year metadata.
    pub state: ClosedState,
    /// Appended slots1..tip; the independently trusted anchor is not produced or rewarded.
    pub records: Vec<Record>,
    /// Native signed-ID membership.
    pub transactions: BTreeMap<Hash, Membership>,
    /// Canonical native sender/nonce membership.
    pub sender_nonces: BTreeMap<(Address, u64), Membership>,
}
impl Snapshot {
    /// Current canonical position, initially independent unsigned slot0.
    pub fn tip(&self) -> Position {
        self.state.position()
    }
    fn initial(g: &Genesis) -> Self {
        Self {
            state: g.initial_state().clone(),
            records: vec![],
            transactions: BTreeMap::new(),
            sender_nonces: BTreeMap::new(),
        }
    }
    // This constructor is private: every appended record has been authenticated/selected/executed
    // against this owner's or the replay engine's own audited prefix, never peer-supplied snapshots.
    fn prefix(&self, g: &Genesis) -> Result<PrefixContext, Error> {
        let mut headers = vec![HistoricalHeader::new(
            g.anchor().clone(),
            g.anchor().hash(),
        )?];
        for r in &self.records {
            let b = r.proof.envelope().block();
            headers.push(HistoricalHeader::new(b.claim().header().clone(), b.hash())?);
        }
        Ok(PrefixContext::from_trusted_history(
            g,
            headers,
            self.state.clone(),
        )?)
    }
    fn insert(&mut self, r: Record) -> Result<(), Error> {
        let b = r.proof.envelope().block();
        let position = r.state.position();
        if position.slot != self.tip().slot.checked_add(1).ok_or_else(overflow)?
            || b.claim().header().parent_hash != self.tip().hash
            || position.hash != b.hash()
        {
            return Err(invalid("record successor"));
        }
        for (index, (bytes, id)) in b
            .transactions()
            .iter()
            .zip(&r.outcome.transaction_ids)
            .enumerate()
        {
            let membership = Membership {
                position,
                index: index as u64,
            };
            if self.transactions.insert(*id, membership).is_some()
                || self
                    .sender_nonces
                    .insert(sender_nonce(bytes), membership)
                    .is_some()
            {
                return Err(Error::DuplicateTransaction(index));
            }
        }
        self.state = r.state.clone();
        self.records.push(r);
        Ok(())
    }
}
#[derive(Clone, Debug)]
struct Base {
    generation: u64,
    genesis: Genesis,
    snapshot: Snapshot,
}
/// Non-cloneable selected producer preparation; contains one native stage and compound candidate.
#[derive(Debug)]
pub struct PreparedBlock {
    base: Base,
    block: Block,
    candidate: ClosedState,
    outcome: BodyOutcome,
}
impl PreparedBlock {
    /// Finalized unsigned C1 block for an external/test signer; no signature is made here.
    pub fn block(&self) -> &Block {
        &self.block
    }
    /// Complete once-computed candidate, not canonical publication.
    pub fn candidate(&self) -> &ClosedState {
        &self.candidate
    }
}
/// Privately sealed one-use candidate, bound to the owner's exact audited prefix and generation.
#[derive(Debug)]
pub struct StagedBlock {
    base: Base,
    record: Record,
}
impl StagedBlock {
    /// Original checked producer evidence.
    pub fn proof(&self) -> &AuthenticatedEnvelope {
        &self.record.proof
    }
    /// Complete compound candidate; inspecting it grants no commit permission elsewhere.
    pub fn candidate(&self) -> &ClosedState {
        &self.record.state
    }
}
/// Only Committed permits a new acknowledgement/publication. Recovery is never an implicit retry.
#[derive(Debug)]
pub enum AppendOutcome {
    /// Exact state, indexes and original evidence are durable and coherently installed.
    Committed {
        /// Canonical content position.
        position: Position,
        /// Original signature-bearing ID.
        envelope_id: Hash,
        /// Native once-applied outcome.
        outcome: BodyOutcome,
    },
    /// No candidate effects committed; a stale external base can still require explicit refresh.
    Aborted(Error),
    /// Exact attempt or durability unresolved; all canonical queries/work are blocked.
    RecoveryRequired(Error),
}
/// Exact-attempt reconciliation diagnostic, not retroactive delivery of a success receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryReport {
    /// Audited synchronized current position.
    pub position: Position,
    /// Exact candidate and original evidence found, exactly absent, or no local uncertain attempt.
    pub attempted_present: Option<bool>,
}
#[derive(Clone)]
struct Attempt {
    base: Base,
    record: Record,
}

/// Separate schema4 owner; no public connection, snapshot importer, plan/grant writer or live hook.
pub struct PoashTrialStore {
    path: PathBuf,
    genesis: Genesis,
    connection: Option<Connection>,
    snapshot: Snapshot,
    generation: u64,
    poisoned: bool,
    halted: bool,
    attempt: Option<Attempt>,
    #[cfg(test)]
    hook: Option<Hook>,
    #[cfg(test)]
    vfs: Option<String>,
}
impl PoashTrialStore {
    /// Exclusively reserve a fresh file and atomically initialize independent genesis and all state.
    pub fn create(path: impl AsRef<Path>, genesis: &Genesis) -> Result<Self, Error> {
        Self::create_inner(path.as_ref(), genesis, None, |_| Ok(()))
    }
    /// No-create independent genesis/schema/full historical audit, then dirty-page durable barrier.
    pub fn reopen(path: impl AsRef<Path>, genesis: &Genesis) -> Result<Self, Error> {
        Self::load(path.as_ref(), genesis, None)
    }
    /// Prior-process recovery is the same full audited/synchronized load, never reseeding or repair.
    pub fn recover_existing(path: impl AsRef<Path>, genesis: &Genesis) -> Result<Self, Error> {
        Self::load(path.as_ref(), genesis, None)
    }
    /// Coherent authoritative state/evidence, hidden during uncertainty. Diagnostic conflict halts
    /// preserve readable existing history, but cannot admit more blocks on this owner instance.
    pub fn snapshot(&self) -> Result<&Snapshot, Error> {
        self.ready()?;
        Ok(&self.snapshot)
    }
    /// Diagnostic durability availability, not progress or finality permission.
    pub fn is_ready(&self) -> bool {
        !self.poisoned
    }
    /// Selected-key conflict prevents affected progress, without manufacturing a protocol result.
    pub fn is_halted(&self) -> bool {
        self.halted
    }
    /// Reconstruct next-slot view exclusively from this owner's complete audited prefix.
    pub fn slot_start(&self) -> Result<SlotStartView, Error> {
        self.work_ready()?;
        Ok(self.snapshot.prefix(&self.genesis)?.slot_start()?)
    }
    /// Queried required SQLite policy on the actual Ready connection.
    pub fn settings(&self) -> Result<StorageSettings, Error> {
        self.ready()?;
        sql::settings(self.conn())
    }
    /// Exact original appended envelope. Anchor0 has no fabricated producer signature.
    pub fn export_envelope(&self, slot: u64) -> Result<Vec<u8>, Error> {
        self.ready()?;
        self.snapshot
            .records
            .get(
                slot.checked_sub(1)
                    .ok_or_else(|| invalid("unsigned anchor"))? as usize,
            )
            .filter(|r| r.state.position().slot == slot)
            .map(|r| r.proof.envelope().wire_bytes())
            .ok_or_else(|| invalid("missing canonical record"))
    }
    /// Require this owner's selected identity before native preparation, then stage/apply once.
    /// This offline helper does not sign, reserve a signing intent or protect an external signer.
    pub fn prepare_next(
        &self,
        producer: &str,
        ticket: u64,
        body: &[Vec<u8>],
    ) -> Result<PreparedBlock, Error> {
        let view = self.slot_start()?;
        let selection = view.select()?;
        if producer != selection.producer() || ticket != selection.ticket_id() {
            return Err(super::Error::NotSelected.into());
        }
        let (native, applied) = app::stage_native(&view, body)?;
        let block = Block::build(&view, &selection, applied.transactions, &applied.outcome)?;
        self.check_transactions(&block, &applied.outcome)?;
        let candidate = app::compound(&view, &block, native, &applied.outcome)?;
        Ok(PreparedBlock {
            base: self.base(),
            block,
            candidate,
            outcome: applied.outcome,
        })
    }
    /// Check generation/exact base before packet work; authenticate once, compare exact finalized
    /// block, and move owned native/economic effects without staging or charging them again.
    pub fn seal_prepared(
        &mut self,
        prepared: PreparedBlock,
        bytes: &[u8],
    ) -> Result<StagedBlock, Error> {
        self.check_base(&prepared.base)?;
        let proof = Envelope::from_wire_bytes(bytes)?.authenticate(&self.genesis)?;
        if proof.envelope().block() != &prepared.block {
            return Err(Error::PreparedIdentity);
        }
        self.admit(&proof)?;
        Ok(StagedBlock {
            base: prepared.base,
            record: Record {
                proof,
                outcome: prepared.outcome,
                state: prepared.candidate,
            },
        })
    }
    /// Receiver admission derives historical authority locally, authenticates once, then stages the
    /// shared native body once and compounds the retained reward. No snapshot/plan argument exists.
    pub fn stage_received(&mut self, bytes: &[u8]) -> Result<StagedBlock, Error> {
        self.work_ready()?;
        let proof = Envelope::from_wire_bytes(bytes)?.authenticate(&self.genesis)?;
        self.admit(&proof)?;
        let view = self.slot_start()?;
        let block = proof.envelope().block();
        let body: Vec<_> = block.transactions().iter().map(|b| b.to_vec()).collect();
        let (native, applied) = app::stage_native(&view, &body)?;
        self.check_transactions(block, &applied.outcome)?;
        let state = app::compound(&view, block, native, &applied.outcome)?;
        Ok(StagedBlock {
            base: self.base(),
            record: Record {
                proof,
                outcome: applied.outcome,
                state,
            },
        })
    }
    fn base(&self) -> Base {
        Base {
            generation: self.generation,
            genesis: self.genesis.clone(),
            snapshot: self.snapshot.clone(),
        }
    }
    fn check_base(&self, b: &Base) -> Result<(), Error> {
        self.work_ready()?;
        if b.generation != self.generation
            || b.genesis != self.genesis
            || b.snapshot != self.snapshot
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    fn admit(&mut self, proof: &AuthenticatedEnvelope) -> Result<(), Error> {
        self.work_ready()?;
        let block = proof.envelope().block();
        let h = block.claim().header();
        if let Some(old) = self
            .snapshot
            .records
            .iter()
            .find(|r| r.state.position().hash == block.hash())
        {
            if old.proof.envelope().block() != block {
                return Err(invalid("known H exact content"));
            }
            return Err(Error::AlreadyCommitted {
                position: old.state.position(),
                retained_envelope_id: old.proof.envelope().id(),
                submitted_envelope_id: proof.envelope().id(),
            });
        }
        // Only a historically selected key, correct historical ticket and exact historical parent
        // qualify for a diagnostic conflict halt. Unrelated known-key traffic cannot freeze progress.
        if h.slot <= self.snapshot.tip().slot {
            let mut prior = Snapshot::initial(&self.genesis);
            for r in self
                .snapshot
                .records
                .iter()
                .take(h.slot.saturating_sub(1) as usize)
            {
                prior.insert(r.clone())?;
            }
            let view = prior.prefix(&self.genesis)?.slot_start()?;
            view.plan(proof.header())?;
            self.halted = true;
            return Err(Error::ConflictHalt);
        }
        self.slot_start()?.plan(proof.header())?;
        Ok(())
    }
    fn check_transactions(&self, block: &Block, outcome: &BodyOutcome) -> Result<(), Error> {
        let mut ids = std::collections::BTreeSet::new();
        let mut nonces = std::collections::BTreeSet::new();
        for (i, (bytes, id)) in block
            .transactions()
            .iter()
            .zip(&outcome.transaction_ids)
            .enumerate()
        {
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
    /// Atomically persist all supported state/effects and original evidence, then install once.
    /// Successful commit performs neither producer authentication nor native staging/application.
    pub fn commit(&mut self, stage: StagedBlock) -> AppendOutcome {
        if let Err(e) = self.check_base(&stage.base) {
            return AppendOutcome::Aborted(e);
        }
        let mut next = self.snapshot.clone();
        if let Err(e) = next.insert(stage.record.clone()) {
            return AppendOutcome::Aborted(e);
        }
        let attempt = Attempt {
            base: stage.base.clone(),
            record: stage.record.clone(),
        };
        // Reconstruct/hash publication evidence before COMMIT; installation/return only move owned
        // values, with no packet allocation or producer authentication after durable success.
        let envelope_id = stage.record.proof.envelope().id();
        if let Err(e) = self.point("before_begin") {
            return AppendOutcome::Aborted(e);
        }
        if let Err(e) = self.conn().execute_batch("BEGIN IMMEDIATE") {
            return AppendOutcome::Aborted(sql::error(e));
        }
        self.attempt = Some(attempt);
        let writes = (|| -> Result<(), Error> {
            // Exact SQL policy, every state field, complete body/index and original-evidence prefix
            // are checked under the write lock BEFORE the first candidate write, without replay.
            if sql::verify(self.conn(), &self.genesis, &stage.base.snapshot).is_err() {
                return Err(Error::Stale);
            }
            self.point("base_checked")?;
            sql::write_accounts(self.conn(), &next.state)?;
            self.point("accounts")?;
            sql::write_accounting(self.conn(), &next.state)?;
            self.point("accounting")?;
            sql::insert_block(self.conn(), &stage.record)?;
            self.point("block_evidence")?;
            sql::insert_body(self.conn(), &stage.record)?;
            self.point("body")?;
            sql::insert_transactions(self.conn(), &stage.record)?;
            self.point("indexes")?;
            sql::insert_reward(self.conn(), &stage.record)?;
            self.point("reward")?;
            sql::insert_state(self.conn(), &next.state)?;
            self.point("state")?;
            let old = stage.base.snapshot.tip();
            let tip = next.tip();
            if self
                .conn()
                .execute(
                    "UPDATE metadata SET revision=?1 WHERE id=1 AND revision=?2",
                    params![
                        tip.slot.to_be_bytes().as_slice(),
                        old.slot.to_be_bytes().as_slice()
                    ],
                )
                .map_err(sql::error)?
                != 1
            {
                return Err(invalid("revision CAS"));
            }
            self.point("revision")?;
            if self
                .conn()
                .execute(
                    "UPDATE canonical_tip SET slot=?1,hash=?2 WHERE id=1 AND slot=?3 AND hash=?4",
                    params![
                        tip.slot.to_be_bytes().as_slice(),
                        tip.hash.as_slice(),
                        old.slot.to_be_bytes().as_slice(),
                        old.hash.as_slice()
                    ],
                )
                .map_err(sql::error)?
                != 1
            {
                return Err(invalid("tip CAS"));
            }
            self.point("tip")?;
            self.point("before_commit")?;
            Ok(())
        })();
        if let Err(e) = writes {
            if e == Error::Stale {
                if self.conn().execute_batch("ROLLBACK").is_ok() && self.conn().is_autocommit() {
                    self.attempt = None;
                    self.poisoned = true;
                    return AppendOutcome::Aborted(e);
                }
                return self.poison(e);
            }
            return self.abort(e);
        }
        if let Err(e) = self.conn().execute_batch("COMMIT") {
            return self.poison(sql::error(e));
        }
        if let Err(e) = self.point("after_commit") {
            return self.poison(e);
        }
        self.snapshot = next;
        if let Err(e) = self.point("after_install") {
            return self.poison(e);
        }
        self.attempt = None;
        AppendOutcome::Committed {
            position: self.snapshot.tip(),
            envelope_id,
            outcome: stage.record.outcome,
        }
    }
    fn abort(&mut self, e: Error) -> AppendOutcome {
        if !self.conn().is_autocommit()
            && let Err(rollback) = self
                .point("rollback")
                .and_then(|_| self.conn().execute_batch("ROLLBACK").map_err(sql::error))
        {
            return self.poison(invalid(format!("{e}; rollback failed: {rollback}")));
        }
        // A confirmed abort must establish exact old state/evidence, not merely a readable old tip.
        if !self.conn().is_autocommit()
            || sql::verify(self.conn(), &self.genesis, &self.snapshot).is_err()
        {
            return self.poison(e);
        }
        self.attempt = None;
        AppendOutcome::Aborted(e)
    }
    fn poison(&mut self, e: Error) -> AppendOutcome {
        self.poisoned = true;
        AppendOutcome::RecoveryRequired(uncertain(e))
    }
    /// Invalidate every preparation first, reopen without CREATE, replay all history, reconcile the
    /// exact attempted state/original evidence and synchronize dirty pages before publishing RAM.
    pub fn recover(&mut self) -> Result<RecoveryReport, Error> {
        self.poisoned = true;
        self.generation = disk::next_generation()?;
        self.connection.take();
        self.point("recovery_reopen")?;
        let conn = disk::open(&self.path, self.vfs_name())?;
        sql::configure(&conn)?;
        self.connection = Some(conn);
        self.point("recovery_validate")?;
        let loaded = sql::audit(self.conn(), &self.genesis)?;
        let present = reconcile(self.attempt.as_ref(), &self.snapshot, &loaded)?;
        self.point("recovery_barrier")?;
        // The real barrier executes through the same VFS; readable replay is not sync durability.
        sql::barrier(self.conn(), &self.path, &self.genesis, &loaded)?;
        self.point("recovery_install")?;
        self.snapshot = loaded;
        self.attempt = None;
        self.poisoned = false;
        Ok(RecoveryReport {
            position: self.snapshot.tip(),
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
    fn work_ready(&self) -> Result<(), Error> {
        self.ready()?;
        if self.halted {
            Err(Error::ConflictHalt)
        } else {
            Ok(())
        }
    }
    fn conn(&self) -> &Connection {
        self.connection
            .as_ref()
            .expect("Ready/transaction owner connected")
    }
    fn point(&mut self, _point: &str) -> Result<(), Error> {
        #[cfg(test)]
        if let Some(h) = &mut self.hook {
            return h(_point);
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
        g: &Genesis,
        c: Connection,
        snapshot: Snapshot,
        _vfs: Option<&str>,
    ) -> Result<Self, Error> {
        Ok(Self {
            path: path.into(),
            genesis: g.clone(),
            connection: Some(c),
            snapshot,
            generation: disk::next_generation()?,
            poisoned: false,
            halted: false,
            attempt: None,
            #[cfg(test)]
            hook: None,
            #[cfg(test)]
            vfs: _vfs.map(str::to_owned),
        })
    }
    fn create_inner(
        path: &Path,
        g: &Genesis,
        vfs: Option<&str>,
        mut point: impl FnMut(&str) -> Result<(), Error>,
    ) -> Result<Self, Error> {
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
        sql::configure(&c)?;
        c.execute_batch("BEGIN IMMEDIATE").map_err(sql::error)?;
        let result = sql::initialize(&c, g, &mut point);
        if let Err(e) = result {
            if !c.is_autocommit() {
                c.execute_batch("ROLLBACK")
                    .map_err(|r| uncertain(format!("{e}; {r}")))?;
            }
            return Err(Error::Storage(StoreError::Aborted(e.to_string())));
        }
        c.execute_batch("COMMIT")
            .map_err(|e| uncertain(sql::error(e)))?;
        point("init_after_commit").map_err(uncertain)?;
        point("init_directory_sync")
            .and_then(|_| disk::sync_path(path).map_err(Error::from))
            .map_err(uncertain)?;
        Self::owner(path, g, c, Snapshot::initial(g), vfs)
    }
    fn load(path: &Path, g: &Genesis, vfs: Option<&str>) -> Result<Self, Error> {
        let c = disk::open(path, vfs)?;
        sql::configure(&c)?;
        let s = sql::audit(&c, g)?;
        sql::barrier(&c, path, g, &s)?;
        Self::owner(path, g, c, s, vfs)
    }
}
fn uncertain(e: impl std::fmt::Display) -> Error {
    Error::Storage(StoreError::RecoveryRequired(e.to_string()))
}
fn sender_nonce(b: &[u8; SIGNED_LEN]) -> (Address, u64) {
    (
        b[46..66].try_into().expect("fixed native address"),
        u64::from_be_bytes(b[66..74].try_into().expect("fixed nonce")),
    )
}
fn reconcile(
    a: Option<&Attempt>,
    known: &Snapshot,
    loaded: &Snapshot,
) -> Result<Option<bool>, Error> {
    let Some(a) = a else {
        if !loaded.records.starts_with(&known.records)
            || (loaded.records.len() == known.records.len() && loaded != known)
        {
            return Err(uncertain(
                "known complete state/original-evidence prefix differs",
            ));
        }
        return Ok(None);
    };
    let n = a.base.snapshot.records.len();
    if loaded.records.len() < n
        || loaded.records[..n] != a.base.snapshot.records
        || (n > 0 && loaded.records[n - 1].state != a.base.snapshot.state)
    {
        return Err(uncertain("exact attempted base differs"));
    }
    if let Some(r) = loaded.records.get(n) {
        if r != &a.record {
            return Err(uncertain("different exact attempted state/evidence"));
        }
        return Ok(Some(true));
    }
    if loaded == &a.base.snapshot {
        return Ok(Some(false));
    }
    Err(uncertain("neither exact present nor exact absent attempt"))
}
