//! File-backed SQLite ledger for explicit offline fixtures only.
//!
//! This owns publication through persist/install and deliberately does not implement AtomicBodyStore:
//! an uncertain I/O outcome poisons this owner until explicit recovery. There is no block adapter,
//! canonical tip, prototype importer, RPC/P2P admission, or live activation in this module.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use crate::native_transaction::{AuthenticationContext, Hash, SIGNED_LEN, SignedTransaction};
use crate::native_transfer::{
    AppliedBody, BodyOutcome, TransferAccount, TransferState, stage_body,
};

mod schema;
#[cfg(test)]
pub(crate) mod tests;

const SCHEMA_VERSION: u32 = 1;
static GENERATION: AtomicU64 = AtomicU64::new(1);
#[cfg(test)]
type TestHook = Box<dyn FnMut(&str) -> Result<(), StoreError>>;

/// Explicit storage failure, including SQLite extended error codes in the diagnostic string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreError {
    /// Existing paths are never overwritten, including empty or abandoned creations.
    AlreadyExists,
    /// No-create reopen failed; it never seeds a missing path.
    Missing,
    /// A failed creation artifact has no complete initialized application dataset.
    Uninitialized,
    /// Local schema, context, exact widths, audit, or integrity checks failed.
    Invalid(String),
    /// The candidate's owner generation, revision, or full state no longer matches.
    Stale,
    /// No reconciled state, new staging, commit, or success publication is available.
    Blocked,
    /// Authentication/execution failed before any SQL transaction.
    Body(String),
    /// A confirmed rollback left committed storage unchanged.
    Aborted(String),
    /// Storage or memory publication requires an explicit successful recovery barrier.
    RecoveryRequired(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fixture storage: {self:?}")
    }
}
impl std::error::Error for StoreError {}

pub(crate) fn invalid(error: impl fmt::Display + fmt::Debug) -> StoreError {
    // SQLite Debug retains its extended operation code (Display often just says "disk I/O error").
    StoreError::Invalid(format!("{error} ({error:?})"))
}

/// One coherent cache loaded from materialized storage, with an explicitly absent fixture tip.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Committed accounts and cumulative accounting, never reseeded on reopen.
    pub state: TransferState,
    /// Local storage sequence; an empty body increments this too.
    pub revision: u64,
    /// Exact ordered body journal; these are not canonical blocks.
    pub bodies: Vec<AppliedBody>,
    /// Native ID to (local revision, body position), reconstructed and verified on load.
    pub transaction_index: BTreeMap<Hash, (u64, u64)>,
    /// Fixture mode never invents canonical identity from a slot or revision.
    pub canonical_tip: Option<(u64, Hash)>,
    /// Caller-supplied snapshot provenance, retained independently of current balances.
    pub provenance: String,
}

/// Non-cloneable prepared body carrying both a full base and an owner/recovery generation.
pub struct Overlay {
    generation: u64,
    revision: u64,
    base: TransferState,
    candidate: TransferState,
    record: AppliedBody,
}

/// Timing boundaries for a successful commit; comparison remains included in durable_commit.
#[derive(Clone, Copy, Debug, Default)]
pub struct CommitTimings {
    /// In-memory full-base equality, before beginning the SQL transaction.
    pub memory_comparison: Duration,
    /// Change/publication cache preparation and allocations, outside the durable boundary.
    pub publication_preparation: Duration,
    /// Persisted accounts/accounting decode and full-base comparison inside BEGIN IMMEDIATE.
    pub stored_comparison: Duration,
    /// BEGIN IMMEDIATE through confirmed EXTRA COMMIT return, including all comparison and writes.
    pub durable_commit: Duration,
    /// Owned state/cache installation, after durable commitment.
    pub installation: Duration,
}

/// Only Committed authorizes the caller to acknowledge success or clean up its local pool.
#[derive(Debug)]
pub enum CommitOutcome {
    /// Durable commit and exactly-once memory installation both completed.
    Committed {
        outcome: BodyOutcome,
        timings: CommitTimings,
    },
    /// Confirmed unchanged storage (or rejection before writes), never a success acknowledgement.
    Aborted(StoreError),
    /// Owner is blocked; even readable candidate rows do not clear this outcome.
    RecoveryRequired(StoreError),
}

/// Explicit recovery reports stored revision, never retroactively acknowledges a failed call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryReport {
    /// Revision reconciled from storage after SQLite recovery and the durability barrier.
    pub revision: u64,
    /// Whether the last uncertain attempted revision is present in the verified journal.
    pub attempted_revision_present: Option<bool>,
}

/// Queried connection settings for reproducible fixture benchmarks and diagnostics.
#[derive(Debug)]
pub struct StorageSettings {
    /// Must be `delete` on the workload connection.
    pub journal_mode: String,
    /// Must be 3 (EXTRA), not the default of a separate diagnostic connection.
    pub synchronous: i64,
    /// Must be enabled on the workload connection.
    pub foreign_keys: bool,
    /// Actual database page width.
    pub page_size: i64,
    /// SQLite cache limit (negative values are KiB).
    pub cache_size: i64,
}

/// Serialized fixture owner. Rust's exclusive borrow gates commit, recovery, and publication.
pub struct FixtureStore {
    path: PathBuf,
    context: AuthenticationContext,
    connection: Option<Connection>,
    snapshot: Snapshot,
    generation: u64,
    poisoned: bool,
    attempted_revision: Option<u64>,
    // Test hooks are compiled out of the backend; storage faults use the real SQLite VFS separately.
    #[cfg(test)]
    hook: Option<TestHook>,
    #[cfg(test)]
    vfs: Option<String>,
}

impl FixtureStore {
    /// Exclusively reserves a new path, then atomically initializes all fixture data and provenance.
    /// A RecoveryRequired error leaves an artifact for explicit recover_existing, never auto-retry.
    pub fn create_fixture(
        path: impl AsRef<Path>,
        context: AuthenticationContext,
        initial: TransferState,
        provenance: &str,
    ) -> Result<Self, StoreError> {
        Self::create_inner(
            path.as_ref(),
            context,
            initial,
            provenance,
            None,
            |_| Ok(()),
        )
    }

    /// Reopens without CREATE; verifies settings, schema, indexes, and an audit from immutable seed.
    /// Normal reopen does not clear an existing owner's poison; that owner must call recover.
    pub fn reopen(
        path: impl AsRef<Path>,
        context: AuthenticationContext,
    ) -> Result<Self, StoreError> {
        // A fresh process cannot know whether the last caller saw a failed sync. Establish the
        // same durable barrier on every public reopen rather than treating readable rows as durable.
        Self::load(path.as_ref(), context, None, true)
    }

    /// Explicitly reconciles an abandoned/uncertain creation or a prior process's uncertain commit.
    /// This never initializes, repairs missing rows, deletes journals, or resubmits a body.
    pub fn recover_existing(
        path: impl AsRef<Path>,
        context: AuthenticationContext,
    ) -> Result<Self, StoreError> {
        Self::load(path.as_ref(), context, None, true)
    }

    /// Only a Ready owner exposes a reconciled snapshot; old RAM is hidden while poisoned.
    pub fn snapshot(&self) -> Result<&Snapshot, StoreError> {
        self.ready()?;
        Ok(&self.snapshot)
    }

    /// Diagnostic availability flag; not a canonical success or state acknowledgement.
    pub fn is_ready(&self) -> bool {
        !self.poisoned
    }

    /// Queries actual Ready owner settings; no weaker alternate benchmark connection is used.
    pub fn settings(&self) -> Result<StorageSettings, StoreError> {
        self.ready()?;
        let integer = |name| {
            self.conn()
                .query_row(&format!("PRAGMA {name}"), [], |r| r.get::<_, i64>(0))
                .map_err(invalid)
        };
        Ok(StorageSettings {
            journal_mode: self
                .conn()
                .query_row("PRAGMA journal_mode", [], |r| r.get(0))
                .map_err(invalid)?,
            synchronous: integer("synchronous")?,
            foreign_keys: integer("foreign_keys")? == 1,
            page_size: integer("page_size")?,
            cache_size: integer("cache_size")?,
        })
    }

    /// Authenticates/executes against Ready memory, capturing revision and recovery generation.
    pub fn stage(&self, slot: u64, body: &[Vec<u8>]) -> Result<Overlay, StoreError> {
        self.ready()?;
        let staged = stage_body(&self.snapshot.state, &self.context, slot, body)
            .map_err(|e| StoreError::Body(e.to_string()))?;
        let (base, candidate, record) = staged.into_parts();
        Ok(Overlay {
            generation: self.generation,
            revision: self.snapshot.revision,
            base,
            candidate,
            record,
        })
    }

    /// Persists an already-executed overlay before installing it, with no second execution/fee burn.
    pub fn commit(&mut self, overlay: Overlay) -> CommitOutcome {
        if let Err(e) = self.ready() {
            return CommitOutcome::Aborted(e);
        }
        let compare = Instant::now();
        if overlay.generation != self.generation
            || overlay.revision != self.snapshot.revision
            || overlay.base != self.snapshot.state
        {
            return CommitOutcome::Aborted(StoreError::Stale);
        }
        let mut timings = CommitTimings {
            memory_comparison: compare.elapsed(),
            ..Default::default()
        };
        let Some(revision) = overlay.revision.checked_add(1) else {
            return CommitOutcome::Aborted(invalid("revision exhausted"));
        };
        let preparing = Instant::now();
        // Allocate publication caches before COMMIT. Installation below only moves owned values.
        let mut bodies = self.snapshot.bodies.clone();
        bodies.push(overlay.record.clone());
        let mut index = self.snapshot.transaction_index.clone();
        for (position, id) in overlay.record.outcome.transaction_ids.iter().enumerate() {
            if index.insert(*id, (revision, position as u64)).is_some() {
                return CommitOutcome::Aborted(invalid("native ID already committed"));
            }
        }
        let prepared = Snapshot {
            state: overlay.candidate.clone(),
            revision,
            bodies,
            transaction_index: index,
            canonical_tip: None,
            provenance: self.snapshot.provenance.clone(),
        };
        timings.publication_preparation = preparing.elapsed();
        let started = Instant::now();
        if let Err(e) = self.point("before_begin") {
            return CommitOutcome::Aborted(e);
        }
        if let Err(e) = self.conn().execute_batch("BEGIN IMMEDIATE") {
            return self.abort(format!("{e:?}"));
        }
        self.attempted_revision = Some(revision);
        let writes = (|| {
            verify_metadata(self.conn(), &self.context, Some(overlay.revision))?;
            let now = Instant::now();
            let persisted = read_state(self.conn())?;
            let same = persisted == overlay.base;
            timings.stored_comparison = now.elapsed();
            if !same {
                return Err(StoreError::Stale);
            }
            for (address, account) in overlay.candidate.accounts() {
                if overlay.base.accounts().get(address) != Some(account) {
                    self.conn().execute("INSERT INTO accounts VALUES(?1,?2,?3) ON CONFLICT(address) DO UPDATE SET balance=excluded.balance,nonce=excluded.nonce",
                        params![address.as_slice(), account.balance_quarks.to_be_bytes().as_slice(), account.nonce.to_be_bytes().as_slice()]).map_err(invalid)?;
                }
            }
            self.point("accounts")?;
            write_accounting(self.conn(), &overlay.candidate)?;
            self.point("accounting")?;
            let body = &overlay.record;
            self.conn()
                .execute(
                    "INSERT INTO bodies VALUES(?1,?2,2,?3,?4,?5,?6)",
                    params![
                        revision.to_be_bytes().as_slice(),
                        body.slot.to_be_bytes().as_slice(),
                        self.context.native_rules_version().to_be_bytes().as_slice(),
                        (body.transactions.len() as u64).to_be_bytes().as_slice(),
                        body.outcome.gas_used.to_be_bytes().as_slice(),
                        body.outcome.fees_burned.to_be_bytes().as_slice()
                    ],
                )
                .map_err(invalid)?;
            self.point("body")?;
            for (position, (bytes, id)) in body
                .transactions
                .iter()
                .zip(&body.outcome.transaction_ids)
                .enumerate()
            {
                let tx = SignedTransaction::from_canonical_bytes(bytes).map_err(invalid)?;
                let unsigned = tx.unsigned();
                self.conn()
                    .execute(
                        "INSERT INTO transactions VALUES(?1,?2,?3,?4,?5,?6)",
                        params![
                            id.as_slice(),
                            revision.to_be_bytes().as_slice(),
                            (position as u64).to_be_bytes().as_slice(),
                            unsigned.sender.as_slice(),
                            unsigned.nonce.to_be_bytes().as_slice(),
                            bytes.as_slice()
                        ],
                    )
                    .map_err(invalid)?;
            }
            self.point("indexes")?;
            self.conn()
                .execute(
                    "UPDATE metadata SET revision=?1 WHERE id=1",
                    params![revision.to_be_bytes().as_slice()],
                )
                .map_err(invalid)?;
            self.point("revision")?;
            self.point("before_commit")?;
            Ok::<_, StoreError>(())
        })();
        if let Err(e) = writes {
            if e == StoreError::Stale {
                // Stale checks precede every write. An intervening owner's valid revision is not
                // our old memory snapshot, but this rejected request has no effects to restore.
                return match self.conn().execute_batch("ROLLBACK") {
                    Ok(()) if self.conn().is_autocommit() => {
                        self.attempted_revision = None;
                        CommitOutcome::Aborted(StoreError::Stale)
                    }
                    result => {
                        self.poison(format!("stale rejection rollback unresolved: {result:?}"))
                    }
                };
            }
            return self.abort(e.to_string());
        }
        // Any COMMIT error is conservative RecoveryRequired, even if SQLite auto-rolled back.
        // A later readable snapshot is not evidence that a failed sync reached stable storage.
        if let Err(e) = self.conn().execute_batch("COMMIT") {
            return self.poison(format!("{e:?}"));
        }
        timings.durable_commit = started.elapsed();
        if let Err(e) = self.point("after_commit") {
            return self.poison(e.to_string());
        }
        let install = Instant::now();
        self.snapshot = prepared;
        timings.installation = install.elapsed();
        if let Err(e) = self.point("after_install") {
            return self.poison(e.to_string());
        }
        self.attempted_revision = None;
        CommitOutcome::Committed {
            outcome: overlay.record.outcome,
            timings,
        }
    }

    /// Invalidates every old overlay, runs SQLite recovery and a real synchronization barrier,
    /// then refreshes memory atomically. Failure leaves the owner blocked, including failed reopen.
    pub fn recover(&mut self) -> Result<RecoveryReport, StoreError> {
        self.poisoned = true;
        self.generation = next_generation()?;
        self.connection.take();
        self.point("recovery_reopen")?;
        let connection = open(&self.path, self.vfs_name())?;
        configure(&connection)?;
        self.connection = Some(connection);
        self.point("recovery_validate")?;
        let snapshot = load_snapshot(self.conn(), &self.context)?;
        self.point("recovery_barrier")?;
        barrier(self.conn(), &self.path, &self.context, snapshot.revision)?;
        self.point("recovery_install")?;
        let report = RecoveryReport {
            revision: snapshot.revision,
            attempted_revision_present: self.attempted_revision.map(|r| snapshot.revision >= r),
        };
        self.snapshot = snapshot;
        self.attempted_revision = None;
        self.poisoned = false;
        Ok(report)
    }

    fn ready(&self) -> Result<(), StoreError> {
        if self.poisoned {
            Err(StoreError::Blocked)
        } else {
            Ok(())
        }
    }
    fn conn(&self) -> &Connection {
        self.connection.as_ref().expect("ready/connected owner")
    }
    fn point(&mut self, _name: &str) -> Result<(), StoreError> {
        #[cfg(test)]
        if let Some(hook) = &mut self.hook {
            return hook(_name);
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
    fn poison(&mut self, message: String) -> CommitOutcome {
        self.poisoned = true;
        CommitOutcome::RecoveryRequired(StoreError::RecoveryRequired(message))
    }
    fn abort(&mut self, message: String) -> CommitOutcome {
        // Require an explicit successful rollback, or autocommit after SQLite's automatic rollback.
        if !self.conn().is_autocommit()
            && let Err(e) = self
                .point("rollback")
                .and_then(|_| self.conn().execute_batch("ROLLBACK").map_err(invalid))
        {
            return self.poison(format!("{message}; rollback unconfirmed: {e}"));
        }
        if !self.conn().is_autocommit() {
            return self.poison(message);
        }
        // SQLite may return OK from SQL ROLLBACK despite a pager restoration error. Re-read and
        // validate every old row/index before claiming Aborted; a sticky pager error or mismatch
        // is unresolved recovery, never permission to continue with the old memory cache.
        match load_snapshot(self.conn(), &self.context) {
            Ok(snapshot) if snapshot == self.snapshot => (),
            Ok(_) => return self.poison(format!("{message}; rollback state mismatch")),
            Err(e) => return self.poison(format!("{message}; rollback validation failed: {e}")),
        }
        self.attempted_revision = None;
        CommitOutcome::Aborted(StoreError::Aborted(message))
    }
    fn create_inner(
        path: &Path,
        context: AuthenticationContext,
        initial: TransferState,
        provenance: &str,
        vfs: Option<&str>,
        mut point: impl FnMut(&str) -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        if provenance.is_empty() {
            return Err(invalid("empty fixture provenance"));
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    StoreError::AlreadyExists
                } else {
                    invalid(e)
                }
            })?;
        drop(file);
        let connection = open(path, vfs)?;
        configure(&connection).map_err(|e| StoreError::Aborted(e.to_string()))?;
        connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| StoreError::Aborted(format!("{e:?}")))?;
        let initialize = (|| {
            for (_, sql) in schema::TABLES {
                connection.execute_batch(sql).map_err(invalid)?;
            }
            point("schema")?;
            connection.execute("INSERT INTO metadata VALUES(1,?1,'fixture-only',?2,?3,?4,'initializing',?5,?6,?7,?8,?8,NULL,0)", params![SCHEMA_VERSION.to_be_bytes().as_slice(), context.chain_id().to_be_bytes().as_slice(), context.network_id().as_slice(), context.native_rules_version().to_be_bytes().as_slice(), initial.gas_used_total().to_be_bytes().as_slice(), initial.fees_burned_total().to_be_bytes().as_slice(), (initial.accounts().len() as u64).to_be_bytes().as_slice(), 0u64.to_be_bytes().as_slice()]).map_err(invalid)?;
            point("context")?;
            for (address, account) in initial.accounts() {
                for table in ["seed_accounts", "accounts"] {
                    connection
                        .execute(
                            &format!("INSERT INTO {table} VALUES(?1,?2,?3)"),
                            params![
                                address.as_slice(),
                                account.balance_quarks.to_be_bytes().as_slice(),
                                account.nonce.to_be_bytes().as_slice()
                            ],
                        )
                        .map_err(invalid)?;
                }
                point("fixture_account")?;
            }
            point("fixture_accounts")?;
            connection
                .execute(
                    "INSERT INTO accounting VALUES(1,?1,?2)",
                    params![
                        initial.gas_used_total().to_be_bytes().as_slice(),
                        initial.fees_burned_total().to_be_bytes().as_slice()
                    ],
                )
                .map_err(invalid)?;
            point("initial_accounting")?;
            connection
                .execute(
                    "UPDATE metadata SET provenance=?1 WHERE id=1",
                    params![provenance],
                )
                .map_err(invalid)?;
            point("provenance")?;
            connection
                .execute_batch("UPDATE metadata SET initialized=1 WHERE id=1")
                .map_err(invalid)?;
            point("marker")?;
            point("init_before_commit")?;
            Ok::<_, StoreError>(())
        })();
        if let Err(e) = initialize {
            // Automatic rollback needs the same validation as explicit rollback; autocommit
            // alone cannot establish that a pager error left no initialized application rows.
            let rollback = if connection.is_autocommit() {
                Ok(())
            } else {
                connection.execute_batch("ROLLBACK")
            };
            return match rollback {
                Ok(()) => match load_snapshot(&connection, &context) {
                    Err(StoreError::Uninitialized) => Err(StoreError::Aborted(e.to_string())),
                    recovered => Err(StoreError::RecoveryRequired(format!(
                        "{e}; initialization rollback validation: {:?}",
                        recovered.err()
                    ))),
                },
                Err(rollback) => Err(StoreError::RecoveryRequired(format!("{e}; {rollback}"))),
            };
        }
        connection
            .execute_batch("COMMIT")
            .map_err(|e| StoreError::RecoveryRequired(format!("{e:?}")))?;
        point("init_after_commit").map_err(|e| StoreError::RecoveryRequired(e.to_string()))?;
        point("init_directory_sync")
            .and_then(|_| sync_path(path))
            .map_err(|e| StoreError::RecoveryRequired(e.to_string()))?;
        // No post-COMMIT audit/allocations are needed to publish the initial snapshot.
        Self::owner(
            path,
            context,
            connection,
            Snapshot {
                state: initial,
                revision: 0,
                bodies: Vec::new(),
                transaction_index: BTreeMap::new(),
                canonical_tip: None,
                provenance: provenance.to_owned(),
            },
            vfs,
        )
    }
    fn load(
        path: &Path,
        context: AuthenticationContext,
        vfs: Option<&str>,
        recover: bool,
    ) -> Result<Self, StoreError> {
        let connection = open(path, vfs)?;
        configure(&connection)?;
        let snapshot = load_snapshot(&connection, &context)?;
        if recover {
            barrier(&connection, path, &context, snapshot.revision)?;
        }
        Self::owner(path, context, connection, snapshot, vfs)
    }
    fn owner(
        path: &Path,
        context: AuthenticationContext,
        connection: Connection,
        snapshot: Snapshot,
        _vfs: Option<&str>,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            path: path.to_owned(),
            context,
            connection: Some(connection),
            snapshot,
            generation: next_generation()?,
            poisoned: false,
            attempted_revision: None,
            #[cfg(test)]
            hook: None,
            #[cfg(test)]
            vfs: _vfs.map(str::to_owned),
        })
    }
}

pub(crate) fn next_generation() -> Result<u64, StoreError> {
    GENERATION
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |g| g.checked_add(1))
        .map_err(|_| invalid("owner generation exhausted"))
}

pub(crate) fn open(path: &Path, vfs: Option<&str>) -> Result<Connection, StoreError> {
    if !path.try_exists().map_err(invalid)? {
        return Err(StoreError::Missing);
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    match vfs {
        Some(name) => Connection::open_with_flags_and_vfs(path, flags, name),
        None => Connection::open_with_flags(path, flags),
    }
    .map_err(invalid)
}

pub(crate) fn configure(connection: &Connection) -> Result<(), StoreError> {
    connection.busy_timeout(Duration::ZERO).map_err(invalid)?;
    connection
        .execute_batch(
            "PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; PRAGMA foreign_keys=ON",
        )
        .map_err(invalid)?;
    let mode: String = connection
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .map_err(invalid)?;
    let sync: i64 = connection
        .query_row("PRAGMA synchronous", [], |r| r.get(0))
        .map_err(invalid)?;
    let keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .map_err(invalid)?;
    if mode != "delete" || sync != 3 || keys != 1 {
        return Err(invalid(
            "required DELETE/EXTRA/foreign_keys settings unavailable",
        ));
    }
    Ok(())
}

pub(crate) fn sync_path(path: &Path) -> Result<(), StoreError> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(invalid)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(invalid)
}

fn barrier(
    connection: &Connection,
    path: &Path,
    context: &AuthenticationContext,
    revision: u64,
) -> Result<(), StoreError> {
    // A real dirty metadata page forces journal/data synchronization; a no-op read is insufficient.
    // Neither this field nor the extra filesystem sync advances the body revision or replays a body.
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| StoreError::RecoveryRequired(e.to_string()))?;
    let result = (|| {
        // Do not install a load that another writer changed between the read and this barrier.
        verify_metadata(connection, context, Some(revision))?;
        let value = connection
            .query_row("SELECT barrier FROM metadata WHERE id=1", [], |r| {
                blob::<8>(r, 0)
            })
            .map_err(invalid)?;
        let next = u64::from_be_bytes(value)
            .checked_add(1)
            .ok_or_else(|| invalid("recovery barrier exhausted"))?;
        connection
            .execute(
                "UPDATE metadata SET barrier=?1 WHERE id=1",
                params![next.to_be_bytes().as_slice()],
            )
            .map_err(invalid)?;
        connection.execute_batch("COMMIT").map_err(invalid)?;
        sync_path(path)
    })();
    result.map_err(|e| StoreError::RecoveryRequired(e.to_string()))
}

pub(crate) fn blob<const N: usize>(
    row: &rusqlite::Row<'_>,
    column: usize,
) -> rusqlite::Result<[u8; N]> {
    let value: Vec<u8> = row.get(column)?;
    value.try_into().map_err(|v: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Blob,
            format!("expected {N} bytes, got {}", v.len()).into(),
        )
    })
}

fn verify_metadata(
    connection: &Connection,
    context: &AuthenticationContext,
    revision: Option<u64>,
) -> Result<u64, StoreError> {
    let row = connection.query_row("SELECT schema_version,chain,network,rules,revision,canonical_tip,initialized,mode,provenance FROM metadata WHERE id=1", [], |r| {
        Ok((u32::from_be_bytes(blob(r, 0)?), u64::from_be_bytes(blob(r, 1)?), blob::<32>(r, 2)?, u32::from_be_bytes(blob(r, 3)?), u64::from_be_bytes(blob(r, 4)?), r.get::<_, Option<Vec<u8>>>(5)?, r.get::<_, i64>(6)?, r.get::<_, String>(7)?, r.get::<_, String>(8)?))
    }).optional().map_err(invalid)?.ok_or(StoreError::Uninitialized)?;
    if row.6 != 1 {
        return Err(StoreError::Uninitialized);
    }
    if row.0 != SCHEMA_VERSION
        || row.1 != context.chain_id()
        || row.2 != context.network_id()
        || row.3 != context.native_rules_version()
        || row.5.is_some()
        || row.7 != "fixture-only"
        || row.8.is_empty()
    {
        return Err(invalid("schema/context/fixture initialization mismatch"));
    }
    if revision.is_some_and(|r| r != row.4) {
        return Err(StoreError::Stale);
    }
    Ok(row.4)
}

pub(crate) fn read_accounts(
    connection: &Connection,
    table: &str,
) -> Result<BTreeMap<[u8; 20], TransferAccount>, StoreError> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT address,balance,nonce FROM {table} ORDER BY address"
        ))
        .map_err(invalid)?;
    let entries = statement
        .query_map([], |r| {
            Ok((
                blob::<20>(r, 0)?,
                TransferAccount {
                    balance_quarks: u128::from_be_bytes(blob(r, 1)?),
                    nonce: u64::from_be_bytes(blob(r, 2)?),
                },
            ))
        })
        .map_err(invalid)?;
    entries.collect::<rusqlite::Result<_>>().map_err(invalid)
}

pub(crate) fn read_state(connection: &Connection) -> Result<TransferState, StoreError> {
    let (gas, burn) = connection
        .query_row("SELECT gas,burn FROM accounting WHERE id=1", [], |r| {
            Ok((
                u64::from_be_bytes(blob(r, 0)?),
                u128::from_be_bytes(blob(r, 1)?),
            ))
        })
        .map_err(invalid)?;
    Ok(TransferState::new(
        read_accounts(connection, "accounts")?,
        gas,
        burn,
    ))
}

pub(crate) fn write_accounting(
    connection: &Connection,
    state: &TransferState,
) -> Result<(), StoreError> {
    if connection
        .execute(
            "UPDATE accounting SET gas=?1,burn=?2 WHERE id=1",
            params![
                state.gas_used_total().to_be_bytes().as_slice(),
                state.fees_burned_total().to_be_bytes().as_slice()
            ],
        )
        .map_err(invalid)?
        != 1
    {
        return Err(invalid("missing accounting row"));
    }
    Ok(())
}

fn load_snapshot(
    connection: &Connection,
    context: &AuthenticationContext,
) -> Result<Snapshot, StoreError> {
    connection.execute_batch("BEGIN").map_err(invalid)?;
    let result = load_snapshot_transaction(connection, context);
    let end = connection.execute_batch("ROLLBACK").map_err(invalid);
    result.and_then(|snapshot| end.map(|_| snapshot))
}

fn load_snapshot_transaction(
    connection: &Connection,
    context: &AuthenticationContext,
) -> Result<Snapshot, StoreError> {
    // Reading sqlite_schema first invokes SQLite hot-journal recovery; never unlink journals ourselves.
    let count: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='metadata'",
            [],
            |r| r.get(0),
        )
        .map_err(invalid)?;
    if count == 0 {
        return Err(StoreError::Uninitialized);
    }
    for (name, expected) in schema::TABLES {
        let sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
                [name],
                |r| r.get(0),
            )
            .map_err(invalid)?;
        if sql != *expected {
            return Err(invalid(format!("incompatible schema for {name}")));
        }
    }
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .map_err(invalid)?;
    if integrity != "ok" {
        return Err(invalid(integrity));
    }
    if connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(invalid)?
        .query([])
        .map_err(invalid)?
        .next()
        .map_err(invalid)?
        .is_some()
    {
        return Err(invalid("foreign key inconsistency"));
    }
    let revision = verify_metadata(connection, context, None)?;
    let (seed_gas, seed_burn, provenance, seed_count) = connection
        .query_row(
            "SELECT seed_gas,seed_burn,provenance,seed_count FROM metadata WHERE id=1",
            [],
            |r| {
                Ok((
                    u64::from_be_bytes(blob(r, 0)?),
                    u128::from_be_bytes(blob(r, 1)?),
                    r.get::<_, String>(2)?,
                    u64::from_be_bytes(blob(r, 3)?),
                ))
            },
        )
        .map_err(invalid)?;
    let seeds = read_accounts(connection, "seed_accounts")?;
    if seeds.len() as u64 != seed_count {
        return Err(invalid("incomplete fixture seed"));
    }
    let mut audit = TransferState::new(seeds, seed_gas, seed_burn);
    let state = read_state(connection)?;
    let mut bodies = Vec::new();
    let mut transaction_index = BTreeMap::new();
    let mut statement = connection
        .prepare("SELECT revision,slot,encoding,rules,count,gas,burn FROM bodies ORDER BY revision")
        .map_err(invalid)?;
    let rows = statement
        .query_map([], |r| {
            Ok((
                u64::from_be_bytes(blob(r, 0)?),
                u64::from_be_bytes(blob(r, 1)?),
                r.get::<_, u8>(2)?,
                u32::from_be_bytes(blob(r, 3)?),
                u64::from_be_bytes(blob(r, 4)?),
                u64::from_be_bytes(blob(r, 5)?),
                u64::from_be_bytes(blob(r, 6)?),
            ))
        })
        .map_err(invalid)?;
    for row in rows {
        let (rev, slot, encoding, rules, count, gas, burn) = row.map_err(invalid)?;
        if rev
            != (bodies.len() as u64)
                .checked_add(1)
                .ok_or_else(|| invalid("body sequence exhausted"))?
            || encoding != 2
            || rules != context.native_rules_version()
        {
            return Err(invalid("body sequence/descriptor mismatch"));
        }
        let mut txs = connection.prepare("SELECT id,position,sender,nonce,signed FROM transactions WHERE revision=?1 ORDER BY position").map_err(invalid)?;
        let entries = txs
            .query_map(params![rev.to_be_bytes().as_slice()], |r| {
                Ok((
                    blob::<32>(r, 0)?,
                    u64::from_be_bytes(blob(r, 1)?),
                    blob::<20>(r, 2)?,
                    u64::from_be_bytes(blob(r, 3)?),
                    blob::<SIGNED_LEN>(r, 4)?,
                ))
            })
            .map_err(invalid)?;
        let mut bytes = Vec::new();
        let mut ids = Vec::new();
        for entry in entries {
            let (id, position, sender, nonce, signed) = entry.map_err(invalid)?;
            let tx = SignedTransaction::from_canonical_bytes(&signed).map_err(invalid)?;
            if position != bytes.len() as u64
                || sender != tx.unsigned().sender
                || nonce != tx.unsigned().nonce
                || tx.transaction_id().map_err(invalid)? != id
                || transaction_index.insert(id, (rev, position)).is_some()
            {
                return Err(invalid("native index/bytes mismatch"));
            }
            bytes.push(signed.to_vec());
            ids.push(id);
        }
        if count != bytes.len() as u64 {
            return Err(invalid("missing body entries"));
        }
        // This audit executes only into a separate verification snapshot, never on materialized state.
        let staged = stage_body(&audit, context, slot, &bytes).map_err(invalid)?;
        if staged.record().outcome
            != (BodyOutcome {
                transaction_ids: ids,
                gas_used: gas,
                fees_burned: burn,
            })
        {
            return Err(invalid("body outcome mismatch"));
        }
        let (_, candidate, record) = staged.into_parts();
        audit = candidate;
        bodies.push(record);
    }
    if revision != bodies.len() as u64 || audit != state {
        return Err(invalid("materialized state/fixture audit mismatch"));
    }
    Ok(Snapshot {
        state,
        revision,
        bodies,
        transaction_index,
        canonical_tip: None,
        provenance,
    })
}
