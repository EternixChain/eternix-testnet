//! Isolated finite C1 process owner, protected signer and peer3 exchange. No prototype/M1 runtime
//! import, wall-clock slot outcome, per-block approval or peer-provided snapshot authority exists.
use super::{
    application as app,
    peer::{self, Kind, Message},
    signing::{SigningAuthority, SigningTimings},
    storage::*,
    *,
};
use crate::block_commitment::hash_with_domain;
use k256::{ecdsa::SigningKey, elliptic_curve::zeroize::Zeroizing};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

const MAX_JSON: usize = 65536;
const MAX_TIMINGS: usize = 1024;
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Create,
    Reopen,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerConfig {
    id: String,
    key_file: PathBuf,
    authority_root: PathBuf,
    mode: Mode,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerConfig {
    id: String,
    address: SocketAddr,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    id: String,
    archive: PathBuf,
    genesis: PathBuf,
    mode: Mode,
    listen: SocketAddr,
    peers: Vec<PeerConfig>,
    producer: Option<ProducerConfig>,
    body_plan: Option<PathBuf>,
}
#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Status {},
    Advance {
        slot: u64,
    },
    ApplyOriginal {
        slot: u64,
    },
    Publish {
        slot: u64,
    },
    Catchup {
        source: String,
        target_slot: u64,
        target_hash: String,
    },
    Recover {},
    Export {
        slot: u64,
    },
    State {
        offset: u32,
        length: u16,
    },
    Inspect {
        section: Section,
        offset: u32,
        limit: u16,
    },
    Timings {
        offset: u16,
        limit: u16,
    },
    Stop {},
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Section {
    Records,
    Transactions,
    SenderNonces,
}
/// Per-operation complete included monotonic boundaries; zero means the phase was not called.
/// Sender publication includes receiver work/ack waits and overlaps receivers' own spans.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Timing {
    /// Actual processed slot or startup/recovery tip.
    pub slot: u64,
    /// Operation label; timing records never authorize protocol outcomes.
    pub action: &'static str,
    /// Local operation completed, not evidence of global delivery/finality.
    pub success: bool,
    /// Explicit initial owner-derived view/selection.
    pub selection_ns: u128,
    /// Native inclusion/compound preparation; includes its own required checks.
    pub preparation_ns: u128,
    /// Full signer base/journal/selection validation.
    pub signer_validation_ns: u128,
    /// Reservation transaction and synchronization.
    pub reservation_sync_ns: u128,
    /// Protected cryptographic signing call.
    pub signing_ns: u128,
    /// Original-envelope transaction and synchronization before private exposure.
    pub original_sync_ns: u128,
    /// One producer authentication and moving the prepared compound effects.
    pub seal_ns: u128,
    /// Receiver authentication/selection/one native stage/compound application.
    pub received_stage_ns: u128,
    /// Canonical exact-base comparison, SQL persistence, EXTRA commit and installation.
    pub commit_ns: u128,
    /// Post-commit complete network publication/acknowledgements, overlapping receiver work.
    pub publication_ns: u128,
    /// Live rows: accept-to-complete-frame I/O. Catch-up rows: complete outbound Get/E exchange.
    /// Neither is a consensus timestamp or part of the receiver's later stage/commit total.
    pub frame_receive_ns: u128,
    /// Independent canonical create/reopen/full replay/barrier/recovery.
    pub owner_recovery_ns: u128,
    /// Separate signing protection create/reopen/audit/reconcile/barrier/recovery.
    pub signer_recovery_ns: u128,
    /// Whole operation wall span, including fallible checks and response preparation.
    pub total_ns: u128,
}
impl Timing {
    fn signing(&mut self, t: SigningTimings) {
        self.signer_validation_ns = t.validation.as_nanos();
        self.reservation_sync_ns = t.reservation_sync.as_nanos();
        self.signing_ns = t.signature.as_nanos();
        self.original_sync_ns = t.original_sync.as_nanos();
    }
}
struct Node {
    id: String,
    g: Genesis,
    store: PoashTrialStore,
    signer: Option<SigningAuthority>,
    plan: Vec<Vec<Vec<u8>>>,
    peers: Vec<PeerConfig>,
    request: u64,
    halted: bool,
    available: bool,
    timings: Vec<Timing>,
    _archive_fence: File,
}
fn bounded_file(path: &Path, max: usize) -> Result<Vec<u8>, String> {
    let mut f = File::open(path).map_err(|e| e.to_string())?;
    let n = f.metadata().map_err(|e| e.to_string())?.len();
    if n > max as u64 {
        return Err("bounded C1 input file".into());
    }
    let mut bytes = Vec::with_capacity(n as usize);
    Read::by_ref(&mut f)
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > max {
        return Err("growing C1 input file".into());
    }
    Ok(bytes)
}
fn key_file(path: &Path) -> Result<SigningKey, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !m.is_file() || m.permissions().mode() & 0o077 != 0 {
            return Err("C1 external key must be a private regular file".into());
        }
    }
    let bytes = Zeroizing::new(bounded_file(path, 32)?);
    if bytes.len() != 32 {
        return Err("C1 external key width".into());
    }
    SigningKey::from_slice(&bytes).map_err(|_| "invalid external signing key".into())
}
fn encoded(s: &str, max: usize) -> Result<Vec<u8>, String> {
    if s.len() > max * 2 || !s.len().is_multiple_of(2) {
        return Err("bounded C1 hex".into());
    }
    hex::decode(s).map_err(|_| "C1 hex".into())
}
fn fail(detail: impl fmt::Display) -> Value {
    let text = detail.to_string();
    let mut n = text.len().min(256);
    while !text.is_char_boundary(n) {
        n -= 1;
    }
    json!({"ok":false,"error":&text[..n]})
}
fn ok(value: Value) -> Value {
    json!({"ok":true,"result":value})
}
use std::fmt;
impl Node {
    fn load(config: Config) -> Result<(Self, SocketAddr, TcpListener), String> {
        let start = Instant::now();
        if config.id.is_empty()
            || config.id.len() > 16
            || !config
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || !config.listen.ip().is_loopback()
            || config.peers.len() > 2
        {
            return Err("C1 process identity/loopback/peer bound".into());
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut addresses = std::collections::BTreeSet::new();
        for p in &config.peers {
            if p.id == config.id
                || !ids.insert(p.id.clone())
                || !addresses.insert(p.address)
                || !p.address.ip().is_loopback()
            {
                return Err("C1 fixed peer configuration".into());
            }
        }
        let g = Genesis::from_bytes(&bounded_file(&config.genesis, MAX_GENESIS_BYTES)?)
            .map_err(|e| e.to_string())?;
        let fence = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(config.archive.join("process.lock"))
            .map_err(|e| e.to_string())?;
        fence
            .try_lock()
            .map_err(|_| "C1 archive process already owned")?;
        let path = config.archive.join("canonical.sqlite");
        let now = Instant::now();
        let store = match config.mode {
            Mode::Create => PoashTrialStore::create(&path, &g),
            Mode::Reopen => PoashTrialStore::reopen(&path, &g),
        }
        .map_err(|e| e.to_string())?;
        let owner_ns = now.elapsed().as_nanos();
        let now = Instant::now();
        let signer = if let Some(p) = config.producer {
            let key = key_file(&p.key_file)?;
            Some(
                match p.mode {
                    Mode::Create => {
                        SigningAuthority::create(&p.authority_root, &g, &p.id, key, &store)
                    }
                    Mode::Reopen => {
                        SigningAuthority::reopen(&p.authority_root, &g, &p.id, key, &store)
                    }
                }
                .map_err(|e| e.to_string())?,
            )
        } else {
            None
        };
        let signer_ns = if signer.is_some() {
            now.elapsed().as_nanos()
        } else {
            0
        };
        let plan = if let Some(path) = config.body_plan {
            let raw: Vec<Vec<String>> = serde_json::from_slice(&bounded_file(&path, 2_000_000)?)
                .map_err(|_| "C1 body plan syntax")?;
            if raw.len() != MAX_SLOTS as usize || raw.iter().any(|b| b.len() > MAX_ENTRIES as usize)
            {
                return Err("C1 body plan requires explicit 200 bounded bodies".into());
            }
            raw.into_iter()
                .map(|b| {
                    b.into_iter()
                        .map(|s| {
                            let bytes = encoded(&s, 199)?;
                            if bytes.len() != 199 {
                                return Err("C1 opaque native entry width".into());
                            }
                            Ok(bytes)
                        })
                        .collect()
                })
                .collect::<Result<Vec<_>, String>>()?
        } else if signer.is_some() {
            return Err("producer requires explicit native body plan".into());
        } else {
            vec![]
        };
        if signer.is_some() && config.peers.is_empty() {
            return Err("producer requires explicit publication recipients".into());
        }
        let listener = TcpListener::bind(config.listen).map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let address = listener.local_addr().map_err(|e| e.to_string())?;
        let tip = store.snapshot().map_err(|e| e.to_string())?.tip();
        let timing = Timing {
            slot: tip.slot,
            action: if matches!(config.mode, Mode::Create) {
                "startup_create"
            } else {
                "startup_reopen"
            },
            success: true,
            owner_recovery_ns: owner_ns,
            signer_recovery_ns: signer_ns,
            total_ns: start.elapsed().as_nanos(),
            ..Default::default()
        };
        let halted = signer
            .as_ref()
            .is_some_and(|s| s.status(&store).map_or(true, |r| !r.incomplete.is_empty()));
        // Startup/reopen barriers are real recovery work too. Preserve these spans in the same
        // supervisor trace as live operations, including a subsequent lost-reply process kill.
        eprintln!(
            "C1_TIMING {}",
            serde_json::to_string(&timing).map_err(|e| e.to_string())?
        );
        Ok((
            Self {
                id: config.id,
                g,
                store,
                signer,
                plan,
                peers: config.peers,
                request: 0,
                halted,
                available: true,
                timings: vec![timing],
                _archive_fence: fence,
            },
            address,
            listener,
        ))
    }
    fn ready(&self) -> Result<&Snapshot, String> {
        if !self.available || self.signer.as_ref().is_some_and(|s| !s.is_ready()) {
            return Err("C1 process unavailable; explicit recover required".into());
        }
        self.store.snapshot().map_err(|e| e.to_string())
    }
    fn work(&self) -> Result<(), String> {
        self.ready()?;
        if self.halted || self.store.is_halted() {
            return Err("C1 progress halted; no fallback outcome".into());
        }
        Ok(())
    }
    fn log(&mut self, t: Timing) -> Result<(), String> {
        if self.timings.len() == MAX_TIMINGS {
            // Invalid/non-selected traffic must not exhaust a diagnostic vector and thereby
            // acquire conflict/progression authority. The supervisor keeps the complete stderr
            // trace; this bounded inspection window retains only the most recent observations.
            self.timings.remove(0);
        }
        // A public diagnostic copy survives a lost operator reply/process kill in the supervisor's
        // stderr capture. It contains durations/slot labels only, never keys or signing capability.
        eprintln!(
            "C1_TIMING {}",
            serde_json::to_string(&t).map_err(|e| e.to_string())?
        );
        self.timings.push(t);
        Ok(())
    }
    fn status(&self) -> Result<Value, String> {
        let s = self.ready()?;
        let selected = self
            .store
            .slot_start()
            .and_then(|v| v.select().map_err(Into::into))
            .ok();
        let protection = self
            .signer
            .as_ref()
            .map(|a| a.status(&self.store))
            .transpose()
            .map_err(|e| e.to_string())?;
        Ok(
            json!({"id":self.id,"network_id":hex::encode(self.g.network_id()),"slot":s.tip().slot,"hash":hex::encode(s.tip().hash),"state_id":hex::encode(s.state.id()),
            "halted":self.halted||self.store.is_halted(),"producer":self.signer.as_ref().map(|a|a.producer()),"selected":selected.as_ref().map(|s|s.producer()),"ticket":selected.as_ref().map(|s|s.ticket_id()),
            "gas":s.state.input().gas_used,"fees":s.state.input().fees_burned.to_string(),"issuance":s.state.input().base_issuance.to_string(),
            "records":s.records.len(),"transactions":s.transactions.len(),"sender_nonces":s.sender_nonces.len(),"snapshot_digest":hex::encode(snapshot_digest(&self.g,s)),
            "signing_pending":protection.as_ref().map(|r|&r.pending),"signing_incomplete":protection.as_ref().map(|r|&r.incomplete),
            "signing_calls":self.signer.as_ref().map(|s|s.signing_calls())}),
        )
    }
    fn request(&mut self, kind: Kind, body: Vec<u8>) -> Result<Message, String> {
        self.request = self
            .request
            .checked_add(1)
            .ok_or("C1 request counter exhausted")?;
        Message::new(kind, self.request, body)
    }
    fn publish(&mut self, slot: u64) -> Result<usize, String> {
        if !(1..=MAX_SLOTS).contains(&slot) {
            return Err("C1 publication slot bound".into());
        }
        let bytes = self
            .ready()?
            .records
            .get(slot.checked_sub(1).ok_or("unsigned anchor")? as usize)
            .ok_or("missing canonical original")?
            .proof()
            .envelope()
            .wire_bytes();
        let envelope = app::Envelope::from_wire_bytes(&bytes).map_err(|e| e.to_string())?;
        if self.peers.is_empty() {
            return Err("no configured publication recipients".into());
        }
        let peers: Vec<_> = self.peers.iter().map(|p| p.address).collect();
        let mut delivered = 0;
        let mut error = None;
        for address in peers {
            let request = self.request(Kind::Push, bytes.clone())?;
            match peer::exchange(address, &self.g, &request) {
                Ok(reply)
                    if reply.kind() == Kind::Ack
                        && reply.body()[..8] == slot.to_be_bytes()
                        && reply.body()[8..40] == envelope.block().hash()
                        && reply.body()[40..72] == envelope.id() =>
                {
                    delivered += 1;
                }
                other => {
                    error = Some(format!(
                        "C1 publication not confirmed: {}",
                        other
                            .err()
                            .unwrap_or_else(|| "peer rejected/different retained evidence".into())
                    ))
                }
            }
        }
        if let Some(e) = error {
            self.halted = true;
            Err(e)
        } else {
            Ok(delivered)
        }
    }
    fn advance(&mut self, slot: u64, explicit_original: bool) -> Result<Value, String> {
        let start = Instant::now();
        self.work()?;
        let tip = self.ready()?.tip();
        if slot <= tip.slot {
            let a = self.signer.as_mut().ok_or("observer cannot produce")?;
            let original = a.original(&self.store, slot).map_err(|e| e.to_string())?;
            return Ok(
                json!({"outcome":"retained_committed","new_commit":false,"envelope":hex::encode(original.bytes()),"envelope_id":hex::encode(original.envelope_id())}),
            );
        }
        if tip.slot.checked_add(1) != Some(slot) {
            return Err("C1 pacing slot is only an exact-successor guard".into());
        }
        let mut timing = Timing {
            slot,
            action: if explicit_original {
                "apply_original"
            } else {
                "advance"
            },
            ..Default::default()
        };
        let result = (|| -> Result<Value, String> {
            let now = Instant::now();
            let selected = self
                .store
                .slot_start()
                .map_err(|e| e.to_string())?
                .select()
                .map_err(|e| e.to_string())?;
            timing.selection_ns = now.elapsed().as_nanos();
            let a = self.signer.as_mut().ok_or("observer cannot produce")?;
            if a.producer() != selected.producer() {
                return Ok(
                    json!({"outcome":"not_selected","selected":selected.producer(),"new_commit":false}),
                );
            }
            let report = a.status(&self.store).map_err(|e| e.to_string())?;
            let now = Instant::now();
            let stage = if explicit_original {
                if !report.pending.contains(&slot) {
                    return Err("no exact pending original; never create/sign implicitly".into());
                }
                let original = a.original(&self.store, slot).map_err(|e| e.to_string())?;
                let stage = self
                    .store
                    .stage_received(original.bytes())
                    .map_err(|e| e.to_string())?;
                timing.received_stage_ns = now.elapsed().as_nanos();
                a.check_application(&self.store, slot, &stage)
                    .map_err(|e| e.to_string())?;
                stage
            } else {
                if !report.pending.is_empty() {
                    return Err("explicit apply_original required; recovery/advance does not retry application".into());
                }
                if !report.incomplete.is_empty() {
                    self.halted = true;
                    return Err("incomplete signing reservation remains fenced".into());
                }
                let body = self
                    .plan
                    .get((slot - 1) as usize)
                    .ok_or("missing explicit native body")?;
                let prepared = self
                    .store
                    .prepare_next(selected.producer(), selected.ticket_id(), body)
                    .map_err(|e| e.to_string())?;
                timing.preparation_ns = now.elapsed().as_nanos();
                let original = a
                    .sign_prepared(&self.store, &prepared)
                    .map_err(|e| e.to_string())?;
                timing.signing(original.timings());
                let now = Instant::now();
                let stage = self
                    .store
                    .seal_prepared(prepared, original.bytes())
                    .map_err(|e| e.to_string())?;
                a.check_application(&self.store, slot, &stage)
                    .map_err(|e| e.to_string())?;
                timing.seal_ns = now.elapsed().as_nanos();
                stage
            };
            let now = Instant::now();
            let outcome = self.store.commit(stage);
            timing.commit_ns = now.elapsed().as_nanos();
            match outcome {
                AppendOutcome::Committed {
                    position,
                    envelope_id,
                    ..
                } => {
                    let now = Instant::now();
                    let delivery = self.publish(position.slot);
                    timing.publication_ns = now.elapsed().as_nanos();
                    let delivered = delivery?;
                    Ok(
                        json!({"outcome":"committed","new_commit":true,"slot":position.slot,"hash":hex::encode(position.hash),"envelope_id":hex::encode(envelope_id),"producer":selected.producer(),"delivered":delivered}),
                    )
                }
                AppendOutcome::Aborted(e) => {
                    self.halted = true;
                    Err(format!("canonical abort; original remains fenced: {e}"))
                }
                AppendOutcome::RecoveryRequired(e) => {
                    self.available = false;
                    Err(format!(
                        "canonical uncertainty; explicit separate recovery required: {e}"
                    ))
                }
            }
        })();
        if self.signer.as_ref().is_some_and(|a| !a.is_ready()) {
            self.available = false;
        }
        timing.success = result.is_ok();
        timing.total_ns = start.elapsed().as_nanos();
        self.log(timing)?;
        result
    }
    fn receive(
        &mut self,
        bytes: &[u8],
        frame_ns: u128,
        action: &'static str,
    ) -> Result<Vec<u8>, String> {
        let start = Instant::now();
        self.work()?;
        let mut t = Timing {
            action,
            frame_receive_ns: frame_ns,
            ..Default::default()
        };
        let result = (|| -> Result<Vec<u8>, String> {
            let syntax = app::Envelope::from_wire_bytes(bytes).map_err(|e| e.to_string())?;
            t.slot = syntax.block().claim().header().slot;
            // A configured signer must not backfill its own protection from peer evidence. An
            // already-known H still reaches mandatory producer authentication/reference handling.
            if self
                .signer
                .as_ref()
                .is_some_and(|a| a.producer() == syntax.block().claim().producer())
                && !self
                    .ready()?
                    .records
                    .iter()
                    .any(|r| r.state().position().hash == syntax.block().hash())
            {
                let original = self
                    .signer
                    .as_mut()
                    .expect("configured")
                    .original(&self.store, t.slot)
                    .map_err(|e| e.to_string())?;
                if original.bytes() != bytes {
                    return Err("own-key incoming original differs from signing protection".into());
                }
            }
            let now = Instant::now();
            let staged = self.store.stage_received(bytes);
            t.received_stage_ns = now.elapsed().as_nanos();
            let stage = match staged {
                Ok(stage) => stage,
                Err(app::Error::AlreadyCommitted {
                    position,
                    retained_envelope_id,
                    ..
                }) => return Ok(ack(position, retained_envelope_id, false)),
                Err(e) => {
                    if self.store.is_halted() {
                        self.halted = true;
                    }
                    return Err(e.to_string());
                }
            };
            t.slot = stage.candidate().position().slot;
            if let Some(a) = &self.signer
                && a.producer() == stage.proof().envelope().block().claim().producer()
            {
                a.check_application(&self.store, t.slot, &stage)
                    .map_err(|e| e.to_string())?;
            }
            let now = Instant::now();
            let outcome = self.store.commit(stage);
            t.commit_ns = now.elapsed().as_nanos();
            match outcome {
                AppendOutcome::Committed {
                    position,
                    envelope_id,
                    ..
                } => Ok(ack(position, envelope_id, true)),
                AppendOutcome::Aborted(e) => Err(e.to_string()),
                AppendOutcome::RecoveryRequired(e) => {
                    self.available = false;
                    Err(e.to_string())
                }
            }
        })();
        t.success = result.is_ok();
        t.total_ns = start.elapsed().as_nanos();
        self.log(t)?;
        result
    }
    fn peer(&mut self, m: Message, frame_ns: u128) -> Result<Message, String> {
        let request = m.request();
        let result = match m.kind() {
            Kind::Status => self.ready().map(|s| {
                let mut b = s.tip().slot.to_be_bytes().to_vec();
                b.extend_from_slice(&s.tip().hash);
                b.extend_from_slice(&snapshot_digest(&self.g, s));
                (Kind::Tip, b)
            }),
            Kind::Get => self
                .ready()
                .and_then(|_| {
                    self.store
                        .export_envelope(u64::from_be_bytes(
                            m.body().try_into().expect("checked width"),
                        ))
                        .map_err(|e| e.to_string())
                })
                .map(|b| (Kind::Envelope, b)),
            Kind::Push => self
                .receive(m.body(), frame_ns, "peer_receive")
                .map(|b| (Kind::Ack, b)),
            _ => Err("unsolicited C1 reply kind".into()),
        };
        match result {
            Ok((kind, b)) => Message::new(kind, request, b),
            Err(_) => Message::new(
                Kind::Reject,
                request,
                vec![if !self.available {
                    1
                } else if self.halted || self.store.is_halted() {
                    2
                } else {
                    3
                }],
            ),
        }
    }
    fn catchup(
        &mut self,
        source: &str,
        target_slot: u64,
        target_hash: &str,
    ) -> Result<Value, String> {
        self.work()?;
        if target_slot > MAX_SLOTS {
            return Err("C1 catch-up domain".into());
        }
        let target: Hash = encoded(target_hash, 32)?
            .try_into()
            .map_err(|_| "target H width")?;
        let address = self
            .peers
            .iter()
            .find(|p| p.id == source)
            .ok_or("unconfigured retained source")?
            .address;
        let status = self.request(Kind::Status, vec![])?;
        let response = peer::exchange(address, &self.g, &status)?;
        if response.kind() != Kind::Tip
            || u64::from_be_bytes(response.body()[..8].try_into().expect("width")) < target_slot
        {
            return Err("source unavailable/short of explicitly pinned target".into());
        }
        while self.ready()?.tip().slot < target_slot {
            let slot = self.ready()?.tip().slot + 1;
            let start = Instant::now();
            let request = self.request(Kind::Get, slot.to_be_bytes().to_vec())?;
            let response = peer::exchange(address, &self.g, &request)?;
            if response.kind() != Kind::Envelope {
                return Err("source did not return an original envelope".into());
            }
            let envelope =
                app::Envelope::from_wire_bytes(response.body()).map_err(|e| e.to_string())?;
            if envelope.block().claim().header().slot != slot {
                return Err("retrieval returned another slot".into());
            }
            self.receive(
                response.body(),
                start.elapsed().as_nanos(),
                "catchup_receive",
            )?;
        }
        if self.ready()?.tip().slot != target_slot || self.ready()?.tip().hash != target {
            return Err(
                "exact catch-up target differs; no rollback or newest-peer inference".into(),
            );
        }
        Ok(json!({"outcome":"caught_up","slot":target_slot,"hash":hex::encode(target)}))
    }
    fn recover(&mut self) -> Result<Value, String> {
        let start = Instant::now();
        self.available = false;
        let mut t = Timing {
            action: "recovery",
            ..Default::default()
        };
        let now = Instant::now();
        self.store.recover().map_err(|e| e.to_string())?;
        t.owner_recovery_ns = now.elapsed().as_nanos();
        let now = Instant::now();
        let report = self
            .signer
            .as_mut()
            .map(|a| a.recover(&self.store))
            .transpose()
            .map_err(|e| e.to_string())?;
        t.signer_recovery_ns = if report.is_some() {
            now.elapsed().as_nanos()
        } else {
            0
        };
        self.available = true;
        self.halted =
            self.store.is_halted() || report.as_ref().is_some_and(|r| !r.incomplete.is_empty());
        t.slot = self.ready()?.tip().slot;
        t.success = true;
        t.total_ns = start.elapsed().as_nanos();
        self.log(t)?;
        Ok(
            json!({"outcome":"reconciled_no_automatic_application_or_publication","pending":report.as_ref().map(|r|&r.pending),"incomplete":report.as_ref().map(|r|&r.incomplete),"halted":self.halted}),
        )
    }
    fn handle(&mut self, c: Command) -> Value {
        let result = (|| -> Result<Value, String> {
            match c {
                Command::Status {} => self.status(),
                Command::Advance { slot } => self.advance(slot, false),
                Command::ApplyOriginal { slot } => self.advance(slot, true),
                Command::Publish { slot } => {
                    let start = Instant::now();
                    let result = self.publish(slot);
                    let t = Timing {
                        slot,
                        action: "explicit_publish",
                        success: result.is_ok(),
                        publication_ns: start.elapsed().as_nanos(),
                        total_ns: start.elapsed().as_nanos(),
                        ..Default::default()
                    };
                    self.log(t)?;
                    result.map(|n| json!({"delivered":n,"new_commit":false}))
                }
                Command::Catchup {
                    source,
                    target_slot,
                    target_hash,
                } => {
                    let result = self.catchup(&source, target_slot, &target_hash);
                    if result.is_err() {
                        self.halted = true;
                    }
                    result
                }
                Command::Recover {} => self.recover(),
                Command::Export { slot } => {
                    self.ready()?;
                    Ok(
                        json!({"envelope":hex::encode(self.store.export_envelope(slot).map_err(|e|e.to_string())?)}),
                    )
                }
                Command::State { offset, length } => {
                    if length == 0 || length > 1024 {
                        return Err("C1 state page bound".into());
                    }
                    let bytes = self.ready()?.state.canonical_bytes();
                    let start = (offset as usize).min(bytes.len());
                    let end = (start + length as usize).min(bytes.len());
                    Ok(
                        json!({"total":bytes.len(),"offset":offset,"hex":hex::encode(&bytes[start..end])}),
                    )
                }
                Command::Inspect {
                    section,
                    offset,
                    limit,
                } => self.inspect(section, offset, limit),
                Command::Timings { offset, limit } => {
                    if limit == 0 || limit > 16 {
                        return Err("C1 timing page bound".into());
                    }
                    Ok(
                        json!({"total":self.timings.len(),"rows":self.timings.iter().skip(offset as usize).take(limit as usize).collect::<Vec<_>>()}),
                    )
                }
                Command::Stop {} => Ok(json!({"outcome":"stopped"})),
            }
        })();
        match result {
            Ok(v) => ok(v),
            Err(e) => fail(e),
        }
    }
    fn inspect(&self, section: Section, offset: u32, limit: u16) -> Result<Value, String> {
        if limit == 0 || limit > 16 || matches!(section, Section::Records) && limit != 1 {
            return Err("C1 inspection page bound".into());
        }
        let s = self.ready()?;
        let start = offset as usize;
        let n = limit as usize;
        let(total,rows):(usize,Vec<Value>)=match section{
            Section::Records=>(s.records.len(),s.records.iter().skip(start).take(n).map(|r|json!({"slot":r.state().position().slot,"hash":hex::encode(r.state().position().hash),"state_id":hex::encode(r.state().id()),"envelope":hex::encode(r.proof().envelope().wire_bytes()),"envelope_id":hex::encode(r.proof().envelope().id()),"gas":r.outcome().gas_used,"fees":r.outcome().fees_burned,"transaction_ids":r.outcome().transaction_ids.iter().map(hex::encode).collect::<Vec<_>>()})).collect()),
            Section::Transactions=>(s.transactions.len(),s.transactions.iter().skip(start).take(n).map(|(id,m)|json!({"id":hex::encode(id),"slot":m.position.slot,"hash":hex::encode(m.position.hash),"index":m.index})).collect()),
            Section::SenderNonces=>(s.sender_nonces.len(),s.sender_nonces.iter().skip(start).take(n).map(|((a,nonce),m)|json!({"sender":hex::encode(a),"nonce":nonce,"slot":m.position.slot,"hash":hex::encode(m.position.hash),"index":m.index})).collect()),
        };
        Ok(json!({"total":total,"rows":rows}))
    }
}
fn ack(position: Position, id: Hash, new: bool) -> Vec<u8> {
    let mut b = position.slot.to_be_bytes().to_vec();
    b.extend_from_slice(&position.hash);
    b.extend_from_slice(&id);
    b.push(new as u8);
    b
}
// A diagnostic full-projection comparison, NOT a header state root, peer checkpoint or grant.
fn snapshot_digest(g: &Genesis, s: &Snapshot) -> Hash {
    let mut b = Vec::from(g.network_id());
    b.extend_from_slice(&(s.state.canonical_bytes().len() as u32).to_be_bytes());
    b.extend_from_slice(s.state.canonical_bytes());
    b.extend_from_slice(&(s.records.len() as u16).to_be_bytes());
    for r in &s.records {
        let e = r.proof().envelope().wire_bytes();
        b.extend_from_slice(&(e.len() as u32).to_be_bytes());
        b.extend_from_slice(&e);
        b.extend_from_slice(&r.state().id());
    }
    b.extend_from_slice(&(s.transactions.len() as u32).to_be_bytes());
    for (id, m) in &s.transactions {
        b.extend_from_slice(id);
        b.extend_from_slice(&m.position.slot.to_be_bytes());
        b.extend_from_slice(&m.position.hash);
        b.extend_from_slice(&m.index.to_be_bytes());
    }
    b.extend_from_slice(&(s.sender_nonces.len() as u32).to_be_bytes());
    for ((a, n), m) in &s.sender_nonces {
        b.extend_from_slice(a);
        b.extend_from_slice(&n.to_be_bytes());
        b.extend_from_slice(&m.position.slot.to_be_bytes());
        b.extend_from_slice(&m.position.hash);
        b.extend_from_slice(&m.index.to_be_bytes());
    }
    hash_with_domain(b"ETERNIX_C1_PROCESS_SNAPSHOT\0", &b)
}
fn read_local(input: &mut impl Read) -> Result<Option<Vec<u8>>, String> {
    let mut h = [0; 4];
    let n = input.read(&mut h[..1]).map_err(|e| e.to_string())?;
    if n == 0 {
        return Ok(None);
    }
    input.read_exact(&mut h[1..]).map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes(h) as usize;
    if len == 0 || len > MAX_JSON {
        return Err("C1 operator frame bound".into());
    }
    let mut bytes = vec![0; len];
    input.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    Ok(Some(bytes))
}
fn write_local(out: &mut impl Write, v: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec(v).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_JSON {
        return Err("C1 operator response bound".into());
    }
    out.write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| out.write_all(&bytes))
        .and_then(|_| out.flush())
        .map_err(|e| e.to_string())
}
struct Operator {
    input: Receiver<Result<Option<Vec<u8>>, String>>,
    output: SyncSender<Value>,
    ack: Receiver<Result<(), String>>,
    busy: bool,
}
impl Operator {
    fn start() -> Self {
        let (tx, input) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut stdin = std::io::stdin().lock();
            loop {
                let value = read_local(&mut stdin);
                let done = !matches!(value, Ok(Some(_)));
                if tx.send(value).is_err() || done {
                    break;
                }
            }
        });
        let (output, rx) = mpsc::sync_channel(1);
        let (ack_tx, ack) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut stdout = std::io::stdout().lock();
            for v in rx {
                let r = write_local(&mut stdout, &v);
                let done = r.is_err();
                if ack_tx.send(r).is_err() || done {
                    break;
                }
            }
        });
        Self {
            input,
            output,
            ack,
            busy: false,
        }
    }
    fn send(&mut self, v: Value) -> Result<(), String> {
        self.output
            .try_send(v)
            .map_err(|_| "C1 bounded operator writer")?;
        self.busy = true;
        Ok(())
    }
    fn poll(&mut self) -> Result<(), String> {
        if self.busy {
            match self.ack.try_recv() {
                Ok(r) => {
                    r?;
                    self.busy = false;
                }
                Err(TryRecvError::Empty) => {}
                Err(_) => return Err("C1 operator writer stopped".into()),
            }
        }
        Ok(())
    }
}
/// Run exactly one explicitly configured opt-in C1 process. Configuration, genesis and private-key
/// file paths are external input, never consensus fields or source defaults. No automatic retry.
pub fn run(args: Vec<OsString>) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: native_poash_node CONFIG.json".into());
    }
    let config: Config = serde_json::from_slice(&bounded_file(Path::new(&args[0]), 16384)?)
        .map_err(|_| "strict C1 configuration")?;
    let (mut node, address, listener) = Node::load(config)?;
    let mut operator = Operator::start();
    operator.send(ok(json!({"outcome":"ready","id":node.id,"address":address.to_string(),"network_id":hex::encode(node.g.network_id())})))?;
    loop {
        operator.poll()?;
        if !operator.busy {
            match operator.input.try_recv() {
                Ok(Ok(Some(bytes))) => {
                    let command = serde_json::from_slice::<Command>(&bytes);
                    let stop = matches!(command, Ok(Command::Stop {}));
                    let reply = match command {
                        Ok(c) => node.handle(c),
                        Err(_) => fail("strict C1 command schema"),
                    };
                    operator.send(reply)?;
                    if stop {
                        let end = Instant::now() + Duration::from_millis(250);
                        while operator.busy && Instant::now() < end {
                            operator.poll()?;
                            thread::sleep(Duration::from_millis(1));
                        }
                        return Ok(());
                    }
                }
                Ok(Ok(None)) | Err(TryRecvError::Disconnected) => return Ok(()),
                Ok(Err(e)) => return Err(e),
                Err(TryRecvError::Empty) => {}
            }
        }
        match listener.accept() {
            Ok((mut socket, address)) => {
                if address.ip().is_loopback() {
                    let now = Instant::now();
                    let end = now + peer::IO_TIMEOUT;
                    if let Ok(message) = peer::read(&mut socket, &node.g, end) {
                        let frame_ns = now.elapsed().as_nanos();
                        if let Ok(reply) = node.peer(message, frame_ns) {
                            let _ = peer::write(&mut socket, &node.g, &reply, end);
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.to_string()),
        }
        thread::sleep(Duration::from_millis(1));
    }
}
#[cfg(test)]
mod tests;
