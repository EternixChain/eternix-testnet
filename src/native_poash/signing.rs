//! Durable single-authority C1 signing protection, separate from canonical account storage.
//!
//! Every participating archive for a network/key MUST use the same explicitly configured protection
//! root. A derived per-network/full-key OS lock is held for this object's lifetime, never unlinked.
//! Operator-created key/store clones, alternate roots and signing-store rollback are outside D4's
//! honest single-authority threat model. Neither the lock nor SQLite claims rollback resistance.
use super::{application as app, storage::*, *};
use crate::durable_fixture as disk;
use crate::native_transaction::Hash;
use k256::ecdsa::SigningKey;
use rusqlite::{Connection, params};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
mod journal;
#[cfg(test)]
mod tests;

/// Exact local reservation codec identifier; never part of canonical genesis or account state.
pub const RESERVATION_DOMAIN: &[u8] = b"ETERNIX_C1_SIGN_RESERVATION\0";
/// Maximum checked reservation, including the entire finalized inner4 block.
pub const MAX_RESERVATION_BYTES: usize = app::MAX_BLOCK_BYTES + 512;
/// Distinguishable fencing, local-storage and owner-reconciliation failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Another participating authority owns the network/key fence, regardless of archive path.
    Owned,
    /// Explicit no-create protection store is absent.
    Missing,
    /// Exclusive creation never resets an existing protection file.
    Exists,
    /// Synchronization/attempt/owner generation unresolved; explicit recovery is required.
    Blocked,
    /// Slot was durably reserved without a complete original. It is NEVER signed again/released.
    Incomplete(u64),
    /// Exact slot candidate/base differs from its retained reservation.
    Conflict(u64),
    /// Canonical owner, preparation, attribution or profile failure.
    Application(app::Error),
    /// Vetted prehash signing failure, not permission to release a reservation.
    Signing(crate::block_authentication::Error),
    /// Filesystem/SQLite error or exact-format/reconciliation failure.
    Invalid(String),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "C1 signer: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<app::Error> for Error {
    fn from(e: app::Error) -> Self {
        Self::Application(e)
    }
}
fn invalid(e: impl fmt::Display) -> Error {
    Error::Invalid(e.to_string())
}

/// Included coarse monotonic spans, diagnostics only; never consensus timing/acceptance inputs.
#[derive(Clone, Copy, Debug, Default)]
pub struct SigningTimings {
    /// Owner/preparation/prefix/selection checks before durable reservation.
    pub validation: Duration,
    /// Reservation BEGIN through confirmed EXTRA COMMIT and explicit path/directory sync.
    pub reservation_sync: Duration,
    /// Vetted signing call only, no storage or publication.
    pub signature: Duration,
    /// Original-envelope transaction and explicit path/directory synchronization.
    pub original_sync: Duration,
    /// Whole protected request, including exact repeated-original lookup.
    pub total: Duration,
}
/// Original durable evidence. Returning this private-proposal value does NOT permit publication:
/// canonical commitment is a separate later operation, with no cross-file atomicity claim.
pub struct Original {
    bytes: Vec<u8>,
    id: Hash,
    timings: SigningTimings,
}
impl Original {
    /// Exact retained original E, never a fresh deterministic re-signing.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Original signature-bearing identity.
    pub fn envelope_id(&self) -> Hash {
        self.id
    }
    /// Diagnostic boundaries for this request; repeats have zero new signing/storage spans.
    pub fn timings(&self) -> SigningTimings {
        self.timings
    }
}
/// Explicit reconciliation result; no signing, application, publication or reservation release occurs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReport {
    /// Durable completed originals whose exact canonical records exist.
    pub committed: Vec<u64>,
    /// Complete original at its exact still-absent successor; explicit apply-original may follow.
    pub pending: Vec<u64>,
    /// Permanently fenced incomplete reservations. Their presence blocks further signing.
    pub incomplete: Vec<u64>,
    /// Exact last local journal attempt reconciled present/absent; not a prior receipt delivery.
    pub attempted_present: Option<bool>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Intent {
    reservation: Vec<u8>,
    original: Option<Vec<u8>>,
}
type Intents = BTreeMap<u64, Intent>;
#[derive(Clone)]
struct Attempt {
    before: Intents,
    after: Intents,
}
#[cfg(test)]
type Hook = Box<dyn FnMut(&str) -> Result<(), Error>>;

/// One non-cloneable secret-holding authority. No Debug/Serialize/raw-signing API or secret storage.
pub struct SigningAuthority {
    path: PathBuf,
    _fence: File,
    genesis: Genesis,
    producer: String,
    public_key: [u8; 33],
    key: SigningKey,
    connection: Option<Connection>,
    intents: Intents,
    poisoned: bool,
    generation: u64,
    signing_calls: u64,
    attempt: Option<Attempt>,
    #[cfg(test)]
    hook: Option<Hook>,
    #[cfg(test)]
    vfs: Option<String>,
}
impl SigningAuthority {
    /// Create fresh protection ONLY against independently initialized slot0. Replacing/backfilling
    /// protection after previously signed canonical history would silently defeat the signing fence.
    pub fn create(
        root: impl AsRef<Path>,
        genesis: &Genesis,
        producer: &str,
        key: SigningKey,
        owner: &PoashTrialStore,
    ) -> Result<Self, Error> {
        Self::open_inner(root.as_ref(), genesis, producer, key, owner, true, None)
    }
    /// Acquire the SAME network/key fence, no-create audit protection, reconcile both stores and
    /// establish a dirty-page synchronization barrier. Incomplete reservations stay fenced.
    pub fn reopen(
        root: impl AsRef<Path>,
        genesis: &Genesis,
        producer: &str,
        key: SigningKey,
        owner: &PoashTrialStore,
    ) -> Result<Self, Error> {
        Self::open_inner(root.as_ref(), genesis, producer, key, owner, false, None)
    }
    /// Diagnostic synchronization availability; incomplete reservations separately block signing.
    pub fn is_ready(&self) -> bool {
        !self.poisoned
    }
    /// Fixed checked configured identity, never a packet-selected producer.
    pub fn producer(&self) -> &str {
        &self.producer
    }
    /// Process-local protected prehash signing calls, including attempts whose replies were withheld.
    /// A vetted helper's rare x-overflow nonce retry remains internal to that one call.
    /// Reopen starts at zero; this diagnostic is neither a durable fence nor consensus state.
    pub fn signing_calls(&self) -> u64 {
        self.signing_calls
    }
    /// Check exact owned preparation, durably reserve before signing, durably retain original
    /// before returning ANY signature. An existing incomplete slot is never retried, even with same H.
    pub fn sign_prepared(
        &mut self,
        owner: &PoashTrialStore,
        prepared: &PreparedBlock,
    ) -> Result<Original, Error> {
        let start = Instant::now();
        self.ready(owner)?;
        let begin = Instant::now();
        let view = owner.signing_view(prepared)?;
        self.reconcile(owner)?;
        if prepared.block().claim().producer() != self.producer {
            return Err(invalid("not configured selected producer"));
        }
        let (_, evidence) = owner.signing_history(view.slot())?;
        let reservation = reservation(
            &view,
            evidence,
            self.public_key,
            prepared.block(),
            prepared.candidate().id(),
        );
        let slot = view.slot();
        if let Some(old) = self.intents.get(&slot) {
            if old.reservation != reservation {
                return Err(Error::Conflict(slot));
            }
            let bytes = old.original.clone().ok_or(Error::Incomplete(slot))?;
            return original(
                bytes,
                SigningTimings {
                    validation: begin.elapsed(),
                    total: start.elapsed(),
                    ..Default::default()
                },
            );
        }
        if let Some((slot, _)) = self.intents.iter().find(|(_, i)| i.original.is_none()) {
            return Err(Error::Incomplete(*slot));
        }
        let mut timings = SigningTimings {
            validation: begin.elapsed(),
            ..Default::default()
        };
        // From this point every error poisons the signing authority. Recovery never re-signs an
        // incomplete row; absent canonical SQL says nothing about whether a signature was created.
        let result = (|| -> Result<Original, Error> {
            self.point("before_reservation")?;
            let now = Instant::now();
            let mut next = self.intents.clone();
            next.insert(
                slot,
                Intent {
                    reservation,
                    original: None,
                },
            );
            self.persist(next, slot, false)?;
            timings.reservation_sync = now.elapsed();
            self.point("after_reservation_sync")?;
            self.point("before_signature")?;
            let now = Instant::now();
            #[cfg(test)]
            phase_evidence::signing();
            self.signing_calls = self
                .signing_calls
                .checked_add(1)
                .ok_or_else(|| invalid("signing diagnostic counter exhausted"))?;
            let signature = crate::block_authentication::sign_digest(
                &self.key,
                &prepared
                    .block()
                    .claim()
                    .signing_digest(self.genesis.network_id()),
            )
            .map_err(Error::Signing)?;
            timings.signature = now.elapsed();
            self.point("after_signature")?;
            let envelope = app::Envelope::from_parts(
                prepared.block().clone(),
                self.genesis.network_id(),
                signature,
            );
            let bytes = envelope.wire_bytes();
            let now = Instant::now();
            let mut next = self.intents.clone();
            next.get_mut(&slot).expect("durable reservation").original = Some(bytes.clone());
            self.persist(next, slot, true)?;
            timings.original_sync = now.elapsed();
            self.point("after_original_sync")?;
            timings.total = start.elapsed();
            // Preallocate all response data before exposing it. No public signer/proposal response
            // contains S unless the COMPLETE original is durably synchronized above.
            let value = original(bytes, timings)?;
            self.point("before_response")?;
            Ok(value)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    /// Return retained original after exact owner/journal reconciliation. Repeated/lost-reply
    /// requests use this route after canonical advancement, with no native stage or signing call.
    pub fn original(&mut self, owner: &PoashTrialStore, slot: u64) -> Result<Original, Error> {
        let start = Instant::now();
        self.ready(owner)?;
        self.reconcile(owner)?;
        let i = self
            .intents
            .get(&slot)
            .ok_or_else(|| invalid("no retained slot"))?;
        original(
            i.original.clone().ok_or(Error::Incomplete(slot))?,
            SigningTimings {
                total: start.elapsed(),
                ..Default::default()
            },
        )
    }
    /// Bind a separately staged explicit original application to the retained complete candidate.
    /// This compares owned values only; it neither authenticates/stages again nor commits anything.
    pub fn check_application(
        &self,
        owner: &PoashTrialStore,
        slot: u64,
        stage: &StagedBlock,
    ) -> Result<(), Error> {
        self.ready(owner)?;
        self.reconcile(owner)?;
        let i = self
            .intents
            .get(&slot)
            .ok_or_else(|| invalid("unreserved application"))?;
        let (_, candidate) = journal::decode_reservation(
            &i.reservation,
            &self.genesis,
            &self.producer,
            self.public_key,
        )?;
        if i.original.as_deref() != Some(stage.proof().envelope().wire_bytes().as_slice())
            || stage.candidate().id() != candidate
        {
            return Err(Error::Conflict(slot));
        }
        Ok(())
    }
    /// Explicit synchronized reconciliation only. Canonical recovery must be performed separately;
    /// this method does not apply absent originals, publish, sign, or release incomplete slots.
    pub fn recover(&mut self, owner: &PoashTrialStore) -> Result<RecoveryReport, Error> {
        self.poisoned = true;
        self.connection.take();
        self.point("recovery_reopen")?;
        let c = disk::open(&self.path, self.vfs_name()).map_err(invalid)?;
        journal::configure(&c)?;
        self.connection = Some(c);
        self.point("recovery_audit")?;
        let loaded = journal::load(self.conn(), &self.genesis, &self.producer, self.public_key)?;
        let present = if let Some(a) = &self.attempt {
            if loaded == a.after {
                Some(true)
            } else if loaded == a.before {
                Some(false)
            } else {
                return Err(invalid("different exact signing attempt"));
            }
        } else {
            if loaded != self.intents {
                return Err(invalid("known signing originals/reservations changed"));
            }
            None
        };
        let mut report = reconcile(
            &loaded,
            &self.genesis,
            &self.producer,
            self.public_key,
            owner,
        )?;
        self.point("recovery_barrier")?;
        journal::barrier(
            self.conn(),
            &self.path,
            &self.genesis,
            &self.producer,
            self.public_key,
            &loaded,
        )?;
        self.point("recovery_install")?;
        self.intents = loaded;
        self.attempt = None;
        self.generation = owner.signing_generation();
        self.poisoned = false;
        report.attempted_present = present;
        Ok(report)
    }
    /// Diagnostic reconciliation validates complete bases/originals, not just matching H/revision.
    pub fn status(&self, owner: &PoashTrialStore) -> Result<RecoveryReport, Error> {
        self.ready(owner)?;
        self.reconcile(owner)
    }
    fn ready(&self, owner: &PoashTrialStore) -> Result<(), Error> {
        if self.poisoned
            || !owner.is_ready()
            || owner.is_halted()
            || self.generation != owner.signing_generation()
        {
            return Err(Error::Blocked);
        }
        Ok(())
    }
    fn reconcile(&self, owner: &PoashTrialStore) -> Result<RecoveryReport, Error> {
        reconcile(
            &self.intents,
            &self.genesis,
            &self.producer,
            self.public_key,
            owner,
        )
    }
    fn persist(&mut self, next: Intents, slot: u64, completed: bool) -> Result<(), Error> {
        self.attempt = Some(Attempt {
            before: self.intents.clone(),
            after: next.clone(),
        });
        self.conn()
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(invalid)?;
        journal::verify(
            self.conn(),
            &self.genesis,
            &self.producer,
            self.public_key,
            &self.intents,
        )?;
        if completed {
            let bytes = next[&slot].original.as_ref().expect("complete original");
            let envelope = app::Envelope::from_wire_bytes(bytes)?;
            self.conn()
                .execute(
                    "INSERT INTO originals VALUES(?1,?2,?3,?4)",
                    params![
                        slot.to_be_bytes().as_slice(),
                        bytes,
                        envelope.signature_bytes().as_slice(),
                        envelope.id().as_slice()
                    ],
                )
                .map_err(invalid)?;
            self.point("original_written")?;
        } else {
            self.conn()
                .execute(
                    "INSERT INTO reservations VALUES(?1,?2)",
                    params![slot.to_be_bytes().as_slice(), next[&slot].reservation],
                )
                .map_err(invalid)?;
            self.point("reservation_written")?;
        }
        self.point(if completed {
            "before_original_commit"
        } else {
            "before_reservation_commit"
        })?;
        self.conn().execute_batch("COMMIT").map_err(invalid)?;
        self.point(if completed {
            "after_original_commit"
        } else {
            "after_reservation_commit"
        })?;
        disk::sync_path(&self.path).map_err(invalid)?;
        self.intents = next;
        self.attempt = None;
        Ok(())
    }
    fn conn(&self) -> &Connection {
        self.connection
            .as_ref()
            .expect("connected signing operation")
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
    fn open_inner(
        root: &Path,
        g: &Genesis,
        producer: &str,
        key: SigningKey,
        owner: &PoashTrialStore,
        create: bool,
        vfs: Option<&str>,
    ) -> Result<Self, Error> {
        let configured = g
            .validators()
            .iter()
            .find(|v| v.id == producer)
            .ok_or_else(|| invalid("unknown signer"))?;
        if key.verifying_key().to_encoded_point(true).as_bytes() != configured.public_key {
            return Err(invalid("configured signer key mismatch"));
        }
        let root = root.canonicalize().map_err(invalid)?;
        let name = format!(
            "{}-{}",
            hex::encode(g.network_id()),
            hex::encode(configured.public_key)
        );
        let lock = root.join(format!("{name}.lock"));
        let path = root.join(format!("{name}.sqlite"));
        let fence = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock)
            .map_err(invalid)?;
        fence.try_lock().map_err(|_| Error::Owned)?;
        if create {
            if owner.snapshot()?.tip().slot != 0 {
                return Err(invalid(
                    "fresh signing protection requires independent slot0",
                ));
            }
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                        Error::Exists
                    } else {
                        invalid(e)
                    }
                })?;
        } else if !path.try_exists().map_err(invalid)? {
            return Err(Error::Missing);
        }
        let c = disk::open(&path, vfs).map_err(invalid)?;
        journal::configure(&c)?;
        if create {
            journal::initialize(&c, g, producer, configured.public_key)?;
            disk::sync_path(&path).map_err(invalid)?;
        }
        let intents = journal::load(&c, g, producer, configured.public_key)?;
        reconcile(&intents, g, producer, configured.public_key, owner)?;
        journal::barrier(&c, &path, g, producer, configured.public_key, &intents)?;
        Ok(Self {
            path,
            _fence: fence,
            genesis: g.clone(),
            producer: producer.into(),
            public_key: configured.public_key,
            key,
            connection: Some(c),
            intents,
            poisoned: false,
            generation: owner.signing_generation(),
            signing_calls: 0,
            attempt: None,
            #[cfg(test)]
            hook: None,
            #[cfg(test)]
            vfs: vfs.map(str::to_owned),
        })
    }
}
fn original(bytes: Vec<u8>, timings: SigningTimings) -> Result<Original, Error> {
    let id = app::Envelope::from_wire_bytes(&bytes)?.id();
    Ok(Original { bytes, id, timings })
}

// Canonical comparison codec for signing safety, NOT a second execution/account ledger. Complete
// base state and original-evidence prefix are bound by collision-resistant IDs; full finalized inner
// content and expected compound candidate ID are retained to pin any later explicit application.
fn reservation(
    view: &SlotStartView,
    evidence: Hash,
    key: [u8; 33],
    block: &app::Block,
    candidate: Hash,
) -> Vec<u8> {
    let inner = block.wire_bytes();
    let mut out = Vec::from(RESERVATION_DOMAIN);
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&view.genesis().network_id());
    out.extend_from_slice(&POASH_RULES.to_be_bytes());
    out.extend_from_slice(&HEADER_PROFILE.to_be_bytes());
    out.extend_from_slice(&[INNER_WIRE, OUTER_WIRE, AUTH_ENCODING]);
    out.extend_from_slice(&AUTH_RULES.to_be_bytes());
    out.extend_from_slice(&key);
    super::text(&mut out, block.claim().producer());
    out.extend_from_slice(&view.slot().to_be_bytes());
    out.extend_from_slice(&block.hash());
    out.extend_from_slice(&view.parent().hash);
    out.extend_from_slice(&view.state().id());
    out.extend_from_slice(&view.prefix.id());
    out.extend_from_slice(&view.id());
    out.extend_from_slice(&evidence);
    out.extend_from_slice(&candidate);
    out.extend_from_slice(&(inner.len() as u32).to_be_bytes());
    out.extend_from_slice(&inner);
    out
}
fn reconcile(
    intents: &Intents,
    g: &Genesis,
    producer: &str,
    key: [u8; 33],
    owner: &PoashTrialStore,
) -> Result<RecoveryReport, Error> {
    let snapshot = owner.snapshot()?;
    if owner.signing_history(1)?.0.genesis() != g {
        return Err(invalid("independent signer/owner genesis differs"));
    }
    let mut report = RecoveryReport {
        committed: vec![],
        pending: vec![],
        incomplete: vec![],
        attempted_present: None,
    };
    for (slot, intent) in intents {
        let (view, evidence) = owner.signing_history(*slot)?;
        if view.genesis() != g {
            return Err(invalid("independent signer/owner genesis differs"));
        }
        let decoded = journal::decode_reservation(&intent.reservation, g, producer, key)?;
        let expected = reservation(&view, evidence, key, &decoded.0, decoded.1);
        let selection = view.select().map_err(|e| Error::Application(e.into()))?;
        if expected != intent.reservation
            || selection.producer() != producer
            || selection.ticket_id() != decoded.0.claim().header().ticket_id
        {
            return Err(Error::Conflict(*slot));
        }
        match (&intent.original, snapshot.records.get((*slot - 1) as usize)) {
            (None, None) => report.incomplete.push(*slot),
            (Some(bytes), Some(record)) => {
                if bytes != &record.proof().envelope().wire_bytes()
                    || decoded.1 != record.state().id()
                {
                    return Err(Error::Conflict(*slot));
                }
                report.committed.push(*slot);
            }
            (Some(_), None) => report.pending.push(*slot),
            (None, Some(_)) => return Err(invalid("canonical signature absent from protection")),
        }
    }
    // A canonical owner cannot bootstrap/backfill protection by claiming some already-signed
    // own-key blocks came from elsewhere. The one authority must retain every such original.
    for record in &snapshot.records {
        if record.proof().envelope().block().claim().producer() == producer
            && !intents.contains_key(&record.state().position().slot)
        {
            return Err(invalid(
                "own-key canonical history lacks original signing protection",
            ));
        }
    }
    Ok(report)
}
#[cfg(test)]
pub(super) mod phase_evidence {
    use std::cell::Cell;
    thread_local! {static SIGNINGS:Cell<usize>=const{Cell::new(0)};}
    pub fn signing() {
        SIGNINGS.set(SIGNINGS.get() + 1);
    }
    pub fn count() -> usize {
        SIGNINGS.get()
    }
    pub fn reset() {
        SIGNINGS.set(0);
    }
}
