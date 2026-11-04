//! S3 isolated fixture transport. One authoritative worker stays on this thread; two bounded
//! operator I/O threads own only bytes/JSON, never the archive. Peer sockets are nonblocking.
pub mod codec;
mod net;
use super::{
    Approvals, Command, Profile, Worker, failure, framing, lock_directory, producer, success,
};
use codec::{Delivery, Kind, Message, Reject};
use eternix_testnet::authenticated_fixture::AuthenticatedFixtureStore;
use eternix_testnet::block_authentication::ENVELOPE_ID_DOMAIN;
use eternix_testnet::block_commitment::hash_with_domain;
use net::{Config, Network};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::File;
use std::path::Path;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Local {
    PeerStatus {},
    PeerObservations { offset: u16, limit: u16 },
    PeerConnect { node_id: u16 },
    PeerDisconnect { node_id: u16 },
    Publish { revision: u64 },
    Retransmit { node_id: u16, revision: u64 },
}

type OperatorInput = Result<Option<(Vec<u8>, Instant)>, String>;
struct Operator {
    input: Receiver<OperatorInput>,
    output: SyncSender<Value>,
    ack: Receiver<Result<(), String>>,
    busy: bool,
}
impl Operator {
    fn start() -> Self {
        let (input_tx, input) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut stdin = std::io::stdin().lock();
            loop {
                let result = framing::read_frame(&mut stdin)
                    .map(|frame| frame.map(|bytes| (bytes, Instant::now())));
                let done = !matches!(result, Ok(Some(_)));
                if input_tx.send(result).is_err() || done {
                    break;
                }
            }
        });
        let (output, output_rx) = mpsc::sync_channel::<Value>(1);
        let (ack_tx, ack) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut stdout = std::io::stdout().lock();
            for value in output_rx {
                let result = framing::write_frame(&mut stdout, &value);
                let done = result.is_err();
                if ack_tx.send(result).is_err() || done {
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
    fn send(&mut self, value: Value) -> Result<(), String> {
        self.output
            .try_send(value)
            .map_err(|_| "bounded operator writer unavailable")?;
        self.busy = true;
        Ok(())
    }
    fn progress(&mut self) -> Result<(), String> {
        if self.busy {
            match self.ack.try_recv() {
                Ok(result) => {
                    self.busy = false;
                    result?;
                }
                Err(TryRecvError::Empty) => {}
                Err(_) => return Err("operator writer stopped".into()),
            }
        }
        Ok(())
    }
    fn finish(&mut self) {
        // Stop never joins a peer/stdio-blocked thread. Give a cooperative operator 250 ms to receive
        // the stop/terminal acknowledgement, then release the owner/lock and let process exit.
        let start = Instant::now();
        while self.busy && start.elapsed() < Duration::from_millis(250) {
            if self.progress().is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}

/// Result from the actual signed worker route; only `new_commit` can mint a relay opportunity.
pub(crate) struct Decision {
    pub reply: Vec<u8>,
    pub kind: Kind,
    pub new_commit: Option<u64>,
    pub duplicate: bool,
}
/// Header/context/routing has already been checked by the codec/network. Revision is only an index
/// into INDEPENDENT loaded operator approvals. No packet/handshake field creates a grant.
pub(crate) fn receive(worker: &mut Worker, revision: u64, envelope: &[u8]) -> Decision {
    let submitted = hash_with_domain(ENVELOPE_ID_DOMAIN, envelope);
    let error = |code| Decision {
        reply: codec::error(code, revision, submitted),
        kind: Kind::Error,
        new_commit: None,
        duplicate: false,
    };
    if !worker.available() {
        return error(Reject::Unavailable);
    }
    let Some(selected) = revision
        .checked_sub(1)
        .and_then(|i| worker.approvals.0.get(i as usize))
        .copied()
    else {
        return error(Reject::Unauthorized);
    };
    let response = worker.apply(revision as u16, &hex::encode(envelope));
    if response["ok"] != true {
        return error(if !worker.available() {
            Reject::Unavailable
        } else if response["error"]["kind"] == "selection" {
            Reject::Unauthorized
        } else {
            Reject::Invalid
        });
    }
    let result = &response["result"];
    if result["new_commit"] == true && result["outcome"] == "committed" {
        let d = Delivery {
            revision,
            hash: selected.tip.hash,
            submitted,
        };
        Decision {
            reply: codec::reference(true, d, selected.envelope_id),
            kind: Kind::Reference,
            new_commit: Some(revision),
            duplicate: false,
        }
    } else if result["outcome"] == "already_committed" {
        let d = Delivery {
            revision,
            hash: selected.tip.hash,
            submitted,
        };
        Decision {
            reply: codec::reference(false, d, selected.envelope_id),
            kind: Kind::Reference,
            new_commit: None,
            duplicate: true,
        }
    } else {
        error(Reject::Invalid)
    }
}

#[derive(Default)]
struct Counters {
    publications: u64,
    relays: u64,
    retransmissions: u64,
    not_queued: u64,
    new_peer_commits: u64,
    duplicates: u64,
    peer_commit_reports: u64,
    peer_references: u64,
    peer_errors: u64,
    statuses: u64,
    operator_dispatch_max_us: u128,
    recovery_dispatch_us: u128,
    recovery_action_us: u128,
    stop_dispatch_us: u128,
}
struct Observation {
    revision: u64,
    received_to_commit_us: u128,
    bytes: usize,
}
struct Runtime {
    worker: Worker,
    network: Network,
    fresh: BTreeSet<u64>,
    counters: Counters,
    observations: Vec<Observation>,
}
impl Runtime {
    fn suspend(&mut self) {
        self.fresh.clear();
        self.network.suspend();
    }
    fn packet(&self, revision: u64) -> Result<(Vec<u8>, Delivery), String> {
        let snapshot = self.worker.snapshot()?;
        let record = snapshot
            .records
            .get(usize::try_from(revision).map_err(|_| "revision width")?)
            .ok_or("no committed record")?;
        let proof = record
            .producer_proof()
            .ok_or("anchor has no signed export")?;
        let bytes = self
            .worker
            .store
            .export_signed_envelope(revision)
            .map_err(|e| e.to_string())?;
        Ok((
            bytes,
            Delivery {
                revision,
                hash: record.tip().hash,
                submitted: proof.envelope_id(),
            },
        ))
    }
    fn send_data(
        &mut self,
        revision: u64,
        except: Option<u16>,
        only: Option<u16>,
    ) -> Result<usize, String> {
        let (bytes, delivery) = self.packet(revision)?;
        let body = codec::committed(revision, &bytes);
        let targets = if let Some(n) = only {
            vec![(self.network.target(n)?, n)]
        } else {
            self.network.targets(except)
        };
        let mut queued = 0;
        if targets.is_empty() {
            self.counters.not_queued += 1;
        }
        for (id, _) in targets {
            if self
                .network
                .queue(id, Kind::Committed, &body, Some(delivery))
                .is_ok()
            {
                queued += 1;
            } else {
                self.counters.not_queued += 1;
            }
        }
        if queued == 0 {
            return Err(
                "publication not queued; committed E remains available for explicit retransmission"
                    .into(),
            );
        }
        Ok(queued)
    }
    fn local(&mut self, c: Local) -> Value {
        let result = (|| -> Result<Value, String> {
            match c {
                Local::PeerStatus {} => {
                    let mut v = self.network.status();
                    let n = &self.counters;
                    v["owner_available"] = json!(self.worker.available());
                    v["fresh_publications"] = json!(self.fresh.len());
                    v["publication_attempts"] = json!(n.publications);
                    v["relay_attempts"] = json!(n.relays);
                    v["retransmission_attempts"] = json!(n.retransmissions);
                    v["not_queued"] = json!(n.not_queued);
                    v["new_peer_commits"] = json!(n.new_peer_commits);
                    v["duplicate_deliveries"] = json!(n.duplicates);
                    v["peer_reported_commits"] = json!(n.peer_commit_reports);
                    v["peer_references"] = json!(n.peer_references);
                    v["peer_errors"] = json!(n.peer_errors);
                    v["statuses_received"] = json!(n.statuses);
                    v["operator_dispatch_max_us"] = json!(n.operator_dispatch_max_us);
                    v["recovery_dispatch_us"] = json!(n.recovery_dispatch_us);
                    v["recovery_action_us"] = json!(n.recovery_action_us);
                    v["stop_dispatch_us"] = json!(n.stop_dispatch_us);
                    Ok(v)
                }
                Local::PeerObservations { offset, limit } => {
                    if limit == 0 || limit > 16 {
                        return Err("observation page limit".into());
                    }
                    let rows:Vec<_>=self.observations.iter().skip(offset as usize).take(limit as usize).map(|o|
                        json!({"revision":o.revision,"received_to_commit_us":o.received_to_commit_us,"payload_bytes":o.bytes})).collect();
                    Ok(json!({"total":self.observations.len(),"rows":rows}))
                }
                Local::PeerDisconnect { node_id } => {
                    self.network.disconnect(node_id);
                    Ok(json!({"outcome":"disconnected","new_commit":false}))
                }
                other => {
                    if !self.worker.available() {
                        return Err("owner unavailable; explicit recovery required".into());
                    }
                    match other {
                        Local::PeerConnect { node_id } => {
                            let body = codec::status(self.worker.snapshot()?.tip);
                            self.network.connect(node_id, &body)?;
                            Ok(json!({"outcome":"connecting","new_commit":false}))
                        }
                        Local::Publish { revision } => {
                            if !self.fresh.remove(&revision) {
                                return Err("no first-publication permission; use explicit retransmit for retained history".into());
                            }
                            self.counters.publications += 1;
                            let count = self.send_data(revision, None, None)?;
                            Ok(
                                json!({"outcome":"publication_queued","queued_peers":count,"new_commit":false}),
                            )
                        }
                        Local::Retransmit { node_id, revision } => {
                            self.counters.retransmissions += 1;
                            let count = self.send_data(revision, None, Some(node_id))?;
                            Ok(
                                json!({"outcome":"retransmission_queued","queued_peers":count,"new_commit":false}),
                            )
                        }
                        _ => unreachable!(),
                    }
                }
            }
        })();
        match result {
            Ok(v) => success(v),
            Err(e) => failure("transport", e),
        }
    }
    fn operator(&mut self, bytes: &[u8], dispatch_us: u128) -> (Value, bool) {
        self.counters.operator_dispatch_max_us =
            self.counters.operator_dispatch_max_us.max(dispatch_us);
        if let Ok(local) = serde_json::from_slice::<Local>(bytes) {
            return (self.local(local), false);
        }
        let command: Command = match serde_json::from_slice(bytes) {
            Ok(c) => c,
            Err(_) => return (failure("command", "invalid strict operator JSON"), false),
        };
        let stop = matches!(command, Command::Stop {});
        let recovery = matches!(command, Command::Recover {});
        if recovery {
            self.counters.recovery_dispatch_us = dispatch_us;
        }
        if stop {
            self.counters.stop_dispatch_us = dispatch_us;
        }
        let action = Instant::now();
        if matches!(command, Command::Recover {}) || stop {
            self.suspend();
        }
        let response = self.worker.handle(command);
        if recovery {
            self.counters.recovery_action_us = action.elapsed().as_micros();
        }
        if !self.worker.available() {
            self.suspend();
        } else if response["ok"] == true
            && response["result"]["new_commit"] == true
            && response["result"]["outcome"] == "committed"
        {
            // Tokens exist only for new commits observed in this process. Readiness/recovery,
            // references, remote claims and cold history cannot mint another first publication.
            self.fresh.insert(
                response["result"]["tip"]["revision"]
                    .as_u64()
                    .expect("committed Tip"),
            );
        }
        (response, stop)
    }
    fn peer_tick(&mut self) {
        let available = self.worker.available();
        if !available {
            self.suspend();
        }
        let Some(event) = self.network.poll(available) else {
            return;
        };
        let result = codec::decode(event.header.kind, &event.body);
        match result {
            Err(_) => self.network.reject(event.connection),
            Ok(Message::Status(hint)) => {
                // Unauthenticated progress is only a hint. Never derive approval, eligibility,
                // catch-up requests, clock/slot changes or canonical state from it.
                let _ = hint;
                self.counters.statuses += 1;
                let status = codec::status(self.worker.snapshot().expect("available").tip);
                if self.network.establish(event.connection, &status).is_err() {
                    self.network.close(event.connection);
                }
            }
            Ok(Message::Committed { revision, envelope }) => {
                let decision = receive(&mut self.worker, revision, envelope);
                if !self.worker.available() {
                    self.suspend();
                } else {
                    if self
                        .network
                        .queue(event.connection, decision.kind, &decision.reply, None)
                        .is_err()
                    {
                        self.network.close(event.connection);
                    }
                    if let Some(revision) = decision.new_commit {
                        self.counters.new_peer_commits += 1;
                        self.observations.push(Observation {
                            revision,
                            received_to_commit_us: event.received.elapsed().as_micros(),
                            bytes: envelope.len(),
                        });
                        debug_assert!(self.observations.len() <= super::profile::MAX_BLOCKS);
                        // Only first local commitment permits relay. Duplicate/retransmitted input
                        // returns a reference below and can never restart a propagation loop.
                        if self
                            .network
                            .config
                            .peers
                            .iter()
                            .any(|p| p.node_id != event.sender)
                        {
                            self.counters.relays += 1;
                            let _ = self.send_data(revision, Some(event.sender), None);
                        }
                    }
                    if decision.duplicate {
                        self.counters.duplicates += 1;
                    }
                }
            }
            Ok(Message::Reference {
                new_commit,
                delivery,
                retained,
            }) => {
                if retained != delivery.submitted
                    || !self.network.acknowledge(event.connection, delivery)
                {
                    self.network.reject(event.connection);
                } else if new_commit {
                    self.counters.peer_commit_reports += 1;
                } else {
                    self.counters.peer_references += 1;
                }
            }
            Ok(Message::Error {
                code,
                revision,
                submitted,
            }) => {
                let _ = code;
                self.counters.peer_errors += 1;
                if !self
                    .network
                    .error_delivery(event.connection, revision, submitted)
                {
                    self.network.reject(event.connection);
                }
            }
        }
        // The dispatched body stayed charged to the transport budget through all owner work.
        drop(event);
        self.network.finish_event();
    }
}

fn setup(args: Vec<OsString>) -> Result<(File, Runtime), String> {
    let role = args.first().and_then(|s| s.to_str());
    let producer_role = role == Some("producer");
    if !matches!(role, Some("producer" | "follower"))
        || args.len() != if producer_role { 7 } else { 6 }
        || !matches!(args[1].to_str(), Some("init" | "open"))
    {
        return Err("usage: testnet_fixture_peer follower|producer init|open PROFILE APPROVALS DATA_DIR PEERS_JSON [PRIVATE_KEY_FILE]".into());
    }
    let profile = Profile::load(Path::new(&args[2]))?;
    let approvals = Approvals::load(Path::new(&args[3]), &profile)?;
    let config = Config::load(Path::new(&args[5]))?;
    let context = codec::Context::new(config.node_id, &profile);
    let producer = if producer_role {
        Some(producer::load_signer(
            Path::new(&args[6]),
            Path::new(&args[4]),
            &profile,
        )?)
    } else {
        None
    };
    let initialize = args[1] == "init";
    let (guard, path) = lock_directory(Path::new(&args[4]), initialize)?;
    let store = if initialize {
        AuthenticatedFixtureStore::create_authenticated_fixture(&path, &profile.manifest)
    } else {
        AuthenticatedFixtureStore::reopen(&path, &profile.manifest)
    }
    .map_err(|e| e.to_string())?;
    let worker = Worker::new(store, profile, approvals, producer)?;
    let network = Network::bind(config, context)?;
    Ok((
        guard,
        Runtime {
            worker,
            network,
            fresh: BTreeSet::new(),
            counters: Counters::default(),
            observations: Vec::with_capacity(super::profile::MAX_BLOCKS),
        },
    ))
}
/// Explicit S3 entrypoint only. S1/S2 keep their reviewed synchronous operator-only execution path.
pub fn run(args: Vec<OsString>) -> Result<(), String> {
    let (_guard, mut runtime) = match setup(args) {
        Ok(v) => v,
        Err(e) => {
            let _ = framing::write_frame(&mut std::io::stdout().lock(), &failure("terminal", &e));
            return Err(e);
        }
    };
    let mut operator = Operator::start();
    operator.send(success(runtime.worker.status()?))?;
    loop {
        operator.progress()?;
        // Operator control has priority over at most one bounded peer/SQL action per iteration.
        if !operator.busy {
            match operator.input.try_recv() {
                Ok(Ok(Some((bytes, arrived)))) => {
                    let (response, stop) = runtime.operator(&bytes, arrived.elapsed().as_micros());
                    operator.send(response)?;
                    if stop {
                        operator.finish();
                        break;
                    }
                }
                Ok(Ok(None)) | Err(TryRecvError::Disconnected) => {
                    runtime.suspend();
                    break;
                }
                Ok(Err(e)) => {
                    runtime.suspend();
                    operator.send(failure("terminal", &e))?;
                    operator.finish();
                    return Err(e);
                }
                Err(TryRecvError::Empty) => {}
            }
        }
        runtime.peer_tick();
        thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}
