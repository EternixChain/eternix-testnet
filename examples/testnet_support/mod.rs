//! S1/S2 example-only process boundary. The archive remains the sole mutable canonical owner.
mod framing;
pub mod producer;
pub mod profile;
#[cfg(test)]
mod tests;
#[allow(dead_code)] // Only the explicit S3 executable enables socket/operator multiplexing.
pub mod transport;

use eternix_testnet::authenticated_fixture::{
    AppendOutcome, AuthenticatedFixtureStore, Error, Snapshot,
};
use eternix_testnet::block_authentication::SignedBlockEnvelope;
use eternix_testnet::canonical_fixture::Tip;
use profile::{
    Approvals, MAX_BLOCKS, MAX_PACKET_BYTES, MAX_TRANSACTIONS, Profile, bounded_hex, fixed_hex,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    // Empty structs are intentional: Serde unit variants silently ignore surplus fields.
    Status {},
    Account {
        address: String,
    },
    Inspect {
        section: Section,
        offset: u32,
        limit: u16,
    },
    Export {
        revision: u64,
    },
    Apply {
        selection: u16,
        envelope: String,
    },
    ExtendApprovals {
        path: String,
    },
    SubmitNative {
        transaction: String,
    },
    Pool {
        offset: u16,
        limit: u16,
    },
    Prepare {},
    Propose {},
    CommitPrepared {
        selection: u16,
    },
    Recover {},
    Stop {},
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Section {
    Accounts,
    Records,
    Transactions,
    SenderNonces,
    Slots,
    Hashes,
}

fn tip(t: Tip) -> Value {
    json!({"hash":hex::encode(t.hash),"slot":t.slot,"revision":t.revision})
}
fn success(value: Value) -> Value {
    json!({"ok":true,"result":value})
}
fn failure(kind: &str, detail: impl AsRef<str>) -> Value {
    // Error payloads are diagnostics, not an unbounded echo of malformed JSON/SQL data.
    let text = detail.as_ref();
    let mut end = text.len().min(1024);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    json!({"ok":false,"error":{"kind":kind,"detail":&text[..end]}})
}

pub(crate) struct Worker {
    store: AuthenticatedFixtureStore,
    profile: Profile,
    approvals: Approvals,
    // A successful SQL recovery is still unavailable here until the independent selection pins match.
    pins_valid: bool,
    producer: Option<producer::Producer>,
}
impl Worker {
    /// The same constructor is used by the executable and actual-call counter tests inside the
    /// library test build; no caller can install arbitrary state/effects through this example.
    pub(crate) fn new(
        store: AuthenticatedFixtureStore,
        profile: Profile,
        approvals: Approvals,
        producer: Option<producer::Producer>,
    ) -> Result<Self, String> {
        approvals.check_prefix(store.snapshot().map_err(|e| e.to_string())?)?;
        Ok(Self {
            store,
            profile,
            approvals,
            pins_valid: true,
            producer,
        })
    }

    #[cfg(test)]
    #[allow(dead_code)] // Used by the library's same-source orchestration counter tests.
    pub(crate) fn test_command(&mut self, value: Value) -> Value {
        self.handle(serde_json::from_value(value).expect("test command schema"))
    }
    fn available(&self) -> bool {
        self.pins_valid && self.store.is_ready()
    }
    fn snapshot(&self) -> Result<&Snapshot, String> {
        if !self.available() {
            return Err("owner unavailable; explicit recovery required".into());
        }
        self.store.snapshot().map_err(|e| e.to_string())
    }
    fn status(&self) -> Result<Value, String> {
        let s = self.snapshot()?;
        Ok(
            json!({"state":"ready","run_id":self.profile.run_id,"network_id":hex::encode(self.profile.network),
            "anchor":tip(self.profile.anchor_tip()),"tip":tip(s.tip),"selected_steps":self.approvals.0.len(),
            "catching_up":s.tip.revision < self.approvals.0.len() as u64,
            "accounts":s.state.accounts().len(),"records":s.records.len(),"transactions":s.transactions.len(),
            "sender_nonces":s.sender_nonces.len(),"slots":s.slots.len(),"hashes":s.hashes.len(),
            "gas_used_total":s.state.gas_used_total(),"fees_burned_total":s.state.fees_burned_total().to_string(),
            "genesis_bytes":self.profile.genesis.len(),"max_blocks":MAX_BLOCKS,"max_transactions":MAX_TRANSACTIONS}),
        )
    }
    fn inspect(&self, section: Section, offset: u32, limit: u16) -> Result<Value, String> {
        let s = self.snapshot()?;
        if limit == 0 || limit > 16 || (matches!(section, Section::Records) && limit != 1) {
            return Err("page limit must be 1..16; records require 1".into());
        }
        let start = offset as usize;
        let n = limit as usize;
        // Each response materializes only one bounded page, not a second canonical snapshot.
        let (total,rows): (usize,Vec<Value>) = match section {
            Section::Accounts => (s.state.accounts().len(),s.state.accounts().iter().skip(start).take(n)
                .map(|(a,v)|json!({"address":hex::encode(a),"balance_quarks":v.balance_quarks.to_string(),"nonce":v.nonce})).collect()),
            Section::Records => (s.records.len(),s.records.iter().skip(start).take(n).map(|r| {
                let p = r.producer_proof();
                json!({"tip":tip(r.tip()),"kind":if p.is_some(){"authenticated_append"}else{"trusted_anchor"},
                    "inner":hex::encode(r.block().wire_bytes()),"signature":p.map(|p|hex::encode(p.signature().as_bytes())),
                    "envelope_id":p.map(|p|hex::encode(p.envelope_id())),
                    "outcome":{"transaction_ids":r.outcome().transaction_ids.iter().map(hex::encode).collect::<Vec<_>>(),
                        "gas_used":r.outcome().gas_used,"fees_burned":r.outcome().fees_burned}})
            }).collect()),
            Section::Transactions => (s.transactions.len(),s.transactions.iter().skip(start).take(n)
                .map(|(id,m)|json!({"id":hex::encode(id),"tip":tip(m.tip),"position":m.position})).collect()),
            Section::SenderNonces => (s.sender_nonces.len(),s.sender_nonces.iter().skip(start).take(n)
                .map(|((sender,nonce),m)|json!({"sender":hex::encode(sender),"nonce":nonce,"tip":tip(m.tip),"position":m.position})).collect()),
            Section::Slots => (s.slots.len(),s.slots.iter().skip(start).take(n)
                .map(|(slot,hash)|json!({"slot":slot,"hash":hex::encode(hash)})).collect()),
            Section::Hashes => (s.hashes.len(),s.hashes.iter().skip(start).take(n)
                .map(|(hash,t)|json!({"hash":hex::encode(hash),"tip":tip(*t)})).collect()),
        };
        Ok(json!({"total":total,"offset":offset,"rows":rows}))
    }
    fn apply(&mut self, selection: u16, encoded: &str) -> Value {
        if !self.available() {
            return failure("unavailable", "explicit recovery required");
        }
        if self.producer.as_ref().is_some_and(|p| p.pending.is_some()) {
            return failure(
                "producer",
                "owned preparation exists; seal it or explicitly recover before replay",
            );
        }
        let Some(selected) = selection
            .checked_sub(1)
            .and_then(|i| self.approvals.0.get(i as usize))
            .copied()
        else {
            return failure(
                "selection",
                "no independently approved request at this index",
            );
        };
        let result = (|| -> Result<_, String> {
            let bytes = bounded_hex(encoded, MAX_PACKET_BYTES)?;
            let envelope =
                SignedBlockEnvelope::from_wire_bytes(&bytes).map_err(|e| e.to_string())?;
            let block = envelope.block();
            if block.hash() != selected.tip.hash
                || block.header().slot != selected.tip.slot
                || block.header().parent_hash != selected.base.hash
                || block.proposer() != "P"
                || block.header().ticket_id != 1
                || block.transactions().len() > MAX_TRANSACTIONS
            {
                return Err("packet differs from independent selected content".into());
            }
            let s = self.snapshot()?;
            let known = s.hashes.contains_key(&selected.tip.hash);
            // Known-H alternatives may only reach the archive's authenticated no-op reference route.
            // They never acquire permission to replace the first retained exact envelope.
            if !known && (s.tip != selected.base || envelope.envelope_id() != selected.envelope_id)
            {
                return Err("independent selected base/envelope ID mismatch".into());
            }
            Ok((bytes, selected.grant(&self.profile)))
        })();
        let (bytes, grant) = match result {
            Ok(v) => v,
            Err(e) => return failure("selection", e),
        };
        let stage = match self.store.stage_received(&bytes, grant) {
            Ok(stage) => stage,
            Err(Error::AlreadyCommitted {
                tip: t,
                retained_envelope_id,
                submitted_envelope_id,
            }) => {
                if retained_envelope_id != selected.envelope_id {
                    self.pins_valid = false;
                    return failure(
                        "unavailable",
                        "retained evidence differs from selected request",
                    );
                }
                return success(
                    json!({"outcome":"already_committed","new_commit":false,"tip":tip(t),
                    "retained_envelope_id":hex::encode(retained_envelope_id),
                    "submitted_envelope_id":hex::encode(submitted_envelope_id)}),
                );
            }
            Err(e) => return failure("rejected", e.to_string()),
        };
        if stage.producer_proof().envelope_id() != selected.envelope_id {
            return failure("selection", "sealed evidence differs from selected request");
        }
        match self.store.commit(stage) {
            AppendOutcome::Committed {
                tip: t,
                envelope_id,
                ..
            } => {
                self.reconcile_pool();
                success(json!({"outcome":"committed","new_commit":true,
                    "tip":tip(t),"envelope_id":hex::encode(envelope_id)}))
            }
            AppendOutcome::Aborted(e) => failure("aborted", e.to_string()),
            AppendOutcome::RecoveryRequired(e) => failure("recovery_required", e.to_string()),
        }
    }
    fn reconcile_pool(&mut self) -> usize {
        if let Some(p) = &mut self.producer {
            // Committed/successful recovery guarantees a coherent Ready snapshot. No new crypto,
            // native application or persisted write is introduced by local pool reconciliation.
            p.reconcile(self.store.snapshot().expect("confirmed coherent owner"))
        } else {
            0
        }
    }
    fn commit_prepared(&mut self, selection: u16) -> Value {
        if !self.available() {
            return failure("unavailable", "explicit recovery required");
        }
        let Some(selected) = selection
            .checked_sub(1)
            .and_then(|i| self.approvals.0.get(i as usize))
            .copied()
        else {
            return failure("selection", "independent selection is not loaded");
        };
        let Some(p) = self.producer.as_mut() else {
            return failure("producer", "producer role required");
        };
        let Some(pending) = p.pending.as_ref() else {
            return failure(
                "producer",
                "no live owned preparation; replay original selected E explicitly",
            );
        };
        let Some(bytes) = pending.envelope.as_ref() else {
            return failure("producer", "propose explicitly before commitment");
        };
        let envelope =
            SignedBlockEnvelope::from_wire_bytes(bytes).expect("locally signed bounded envelope");
        // Reject wrong authority BEFORE consuming the non-cloneable native preparation. A corrected
        // operator request can still seal that exact preparation without restaging or re-signing.
        if selected.base != pending.base
            || self.store.snapshot().expect("ready").tip != pending.base
            || selected.tip.hash != envelope.block().hash()
            || selected.envelope_id != envelope.envelope_id()
        {
            return failure(
                "selection",
                "approval does not bind the original preparation/proposal",
            );
        }
        let pending = p.pending.take().expect("checked preparation");
        let bytes = pending.envelope.expect("checked original proposal");
        let stage =
            match self
                .store
                .seal_prepared(pending.prepared, &bytes, selected.grant(&self.profile))
            {
                Ok(s) => s,
                Err(e) => return failure("rejected", e.to_string()),
            };
        match self.store.commit(stage) {
            AppendOutcome::Committed {
                tip: t,
                envelope_id,
                ..
            } => {
                let removed = self.reconcile_pool();
                success(json!({"outcome":"committed","new_commit":true,"tip":tip(t),
                    "envelope_id":hex::encode(envelope_id),"envelope":hex::encode(bytes),"pool_removed":removed}))
            }
            AppendOutcome::Aborted(e) => failure("aborted", e.to_string()),
            AppendOutcome::RecoveryRequired(e) => failure("recovery_required", e.to_string()),
        }
    }
    fn handle(&mut self, command: Command) -> Value {
        // Only recovery/stop can proceed without coherent state. No read falls back to stale RAM.
        match command {
            Command::Apply {
                selection,
                envelope,
            } => self.apply(selection, &envelope),
            Command::CommitPrepared { selection } => self.commit_prepared(selection),
            Command::Recover {} => {
                self.pins_valid = false;
                // Every refresh invalidates generation, even an unsuccessful one. Never preserve
                // an old prepared body or automatically sign another request after recovery.
                if let Some(p) = &mut self.producer {
                    p.pending = None;
                }
                let result = self
                    .store
                    .recover()
                    .map_err(|e| e.to_string())
                    .and_then(|r| {
                        self.approvals
                            .check_prefix(self.store.snapshot().map_err(|e| e.to_string())?)?;
                        Ok(r)
                    });
                match result {
                    Ok(r) => {
                        self.pins_valid = true;
                        self.reconcile_pool();
                        success(json!({"outcome":"recovered","tip":tip(r.tip),
                        "attempted_present":r.attempted_present,"new_commit":false}))
                    }
                    Err(e) => failure("unavailable", e),
                }
            }
            Command::Stop {} => success(json!({"outcome":"stopped"})),
            other => {
                if !self.available() {
                    return failure("unavailable", "explicit recovery required");
                }
                let result = match other {
                    Command::Status {} => self.status(),
                    Command::Account { address } => (|| {
                        let a = fixed_hex::<20>(&address)?;
                        let s = self.snapshot()?;
                        let v = s.state.account(&a);
                        Ok(
                            json!({"address":hex::encode(a),"exists":s.state.accounts().contains_key(&a),
                            "balance_quarks":v.balance_quarks.to_string(),"nonce":v.nonce}),
                        )
                    })(),
                    Command::Inspect {
                        section,
                        offset,
                        limit,
                    } => self.inspect(section, offset, limit),
                    Command::Export { revision } => self
                        .store
                        .export_signed_envelope(revision)
                        .map(|bytes| json!({"revision":revision,"envelope":hex::encode(bytes)}))
                        .map_err(|e| e.to_string()),
                    Command::ExtendApprovals { path } => (|| {
                        if path.len() > 4096 {
                            return Err("approval path length bound".into());
                        }
                        let next = self.approvals.extension(
                            Path::new(&path),
                            &self.profile,
                            self.snapshot()?,
                        )?;
                        self.approvals = next;
                        Ok(
                            json!({"outcome":"approvals_extended","selected_steps":self.approvals.0.len(),"new_commit":false}),
                        )
                    })(),
                    Command::SubmitNative { transaction } => match &mut self.producer {
                        Some(p) => p.submit(
                            &transaction,
                            &self.profile,
                            self.store.snapshot().expect("ready"),
                        ),
                        None => Err("producer role required".into()),
                    },
                    Command::Pool { offset, limit } => match &self.producer {
                        Some(p) => p.view(offset, limit),
                        None => Err("producer role required".into()),
                    },
                    Command::Prepare {} => match &mut self.producer {
                        Some(p) => p.prepare(&self.store, self.approvals.head(&self.profile)),
                        None => Err("producer role required".into()),
                    },
                    Command::Propose {} => match &mut self.producer {
                        Some(p) => {
                            // A loaded selection may be ahead even while an older preparation is
                            // still alive. Only an ALREADY cached original proposal may be inspected;
                            // never newly sign after authority has selected an unresolved request.
                            if self.approvals.head(&self.profile)
                                != self.store.snapshot().expect("ready").tip
                                && p.pending
                                    .as_ref()
                                    .is_some_and(|pending| pending.envelope.is_none())
                            {
                                Err("selected request unresolved; do not sign another proposal"
                                    .into())
                            } else {
                                p.propose(&self.store, &self.profile)
                            }
                        }
                        None => Err("producer role required".into()),
                    },
                    _ => unreachable!(),
                };
                match result {
                    Ok(v) => success(v),
                    Err(e) => failure("rejected", e),
                }
            }
        }
    }
}

fn lock_directory(path: &Path, initialize: bool) -> Result<(File, std::path::PathBuf), String> {
    let directory = path
        .canonicalize()
        .map_err(|_| "data directory must already exist")?;
    if !directory.is_dir() {
        return Err("data path is not a directory".into());
    }
    let archive = directory.join("archive.sqlite");
    if !initialize && !archive.is_file() {
        return Err("archive missing; open never creates".into());
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(initialize)
        .truncate(false)
        .open(directory.join("worker.lock"))
        .map_err(|_| "cannot open lifetime lock; open never creates")?;
    if !lock
        .metadata()
        .map_err(|_| "cannot inspect lifetime lock")?
        .is_file()
    {
        return Err("invalid lock file".into());
    }
    lock.try_lock()
        .map_err(|_| "another worker owns this data directory")?;
    Ok((lock, archive))
}

fn serve(
    args: Vec<OsString>,
    input: &mut impl Read,
    output: &mut impl Write,
    producer_role: bool,
) -> Result<(), String> {
    if args.len() != if producer_role { 5 } else { 4 }
        || !matches!(args[0].to_str(), Some("init" | "open"))
    {
        return Err(if producer_role {
            "usage: testnet_fixture_producer init|open PROFILE_JSON APPROVALS_JSON EXISTING_DATA_DIR PRIVATE_KEY_FILE"
        } else {
            "usage: testnet_fixture_node init|open PROFILE_JSON APPROVALS_JSON EXISTING_DATA_DIR"
        }.into());
    }
    let initialize = args[0] == "init";
    let profile = Profile::load(Path::new(&args[1]))?;
    let approvals = Approvals::load(Path::new(&args[2]), &profile)?;
    let producer = if producer_role {
        Some(producer::load_signer(
            Path::new(&args[4]),
            Path::new(&args[3]),
            &profile,
        )?)
    } else {
        None
    };
    // Declared before Worker so its guard drops AFTER the store/SQLite connection on every exit.
    // Never unlink/replace this persistent lock inode; OS exit/SIGKILL releases its advisory lock.
    let (_guard, path) = lock_directory(Path::new(&args[3]), initialize)?;
    let store = if initialize {
        AuthenticatedFixtureStore::create_authenticated_fixture(&path, &profile.manifest)
    } else {
        AuthenticatedFixtureStore::reopen(&path, &profile.manifest)
    }
    .map_err(|e| e.to_string())?;
    let mut worker = Worker::new(store, profile, approvals, producer)?;
    framing::write_frame(output, &success(worker.status()?))?;
    while let Some(bytes) = framing::read_frame(input)? {
        let command: Command = match serde_json::from_slice(&bytes) {
            Ok(c) => c,
            Err(_) => {
                framing::write_frame(output, &failure("command", "invalid strict command JSON"))?;
                continue;
            }
        };
        let stop = matches!(command, Command::Stop {});
        let response = worker.handle(command);
        framing::write_frame(output, &response)?;
        if stop {
            break;
        }
    }
    Ok(())
}

/// Run exactly one serialized owner over trusted local stdin/stdout. No background queues or sockets.
#[allow(dead_code)] // Entry point of the S1 executable; both examples share this runtime module.
pub fn run(args: Vec<OsString>) -> Result<(), String> {
    run_role(args, false)
}

/// Separate S2 executable opt-in; the S1 entrypoint never loads signing material or enables a pool.
#[allow(dead_code)] // Entry point of the S2 executable; unused in the S1 executable by construction.
pub fn run_producer(args: Vec<OsString>) -> Result<(), String> {
    run_role(args, true)
}

fn run_role(args: Vec<OsString>, producer_role: bool) -> Result<(), String> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let result = serve(args, &mut input, &mut output, producer_role);
    if let Err(error) = &result {
        // One bounded terminal diagnostic; a broken/blocked consumer cannot trigger recursive output.
        let _ = framing::write_frame(&mut output, &failure("terminal", error));
    }
    result
}
