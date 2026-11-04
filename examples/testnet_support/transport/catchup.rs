//! S4 explicit bounded retrieval. Independent operator pins select the target; peer heights/bytes
//! cannot expand authority, change that target or resume a halted/uncertain session.
use super::super::profile::{MAX_BLOCKS, fixed_hex, read_bounded};
use super::{Worker, codec, net::Network, receive};
use codec::{Kind, Reject, Request};
use eternix_testnet::block_authentication::SignedBlockEnvelope;
use eternix_testnet::canonical_fixture::Tip;
use eternix_testnet::native_transaction::Hash;
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::Path;
use std::time::{Duration, Instant};

/// Exact independently authorized terminal record, including the original signed-envelope identity.
#[derive(Clone, Copy)]
pub struct Target {
    pub tip: Tip,
    pub eid: Hash,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    format: String,
    run_id: String,
    network_id: String,
    anchor_hash: String,
    target: TargetTip,
    envelope_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetTip {
    hash: String,
    slot: u64,
    revision: u64,
}
impl Target {
    fn load(path: &Path, worker: &Worker) -> Result<Self, String> {
        let d: Document = serde_json::from_slice(&read_bounded(path, 4096)?)
            .map_err(|_| "strict catch-up target JSON")?;
        let p = &worker.profile;
        if d.format != "eternix-fixture-catchup-target-v1"
            || d.run_id != p.run_id
            || fixed_hex::<32>(&d.network_id)? != p.network
            || fixed_hex::<32>(&d.anchor_hash)? != p.anchor_tip().hash
        {
            return Err("independent catch-up target context mismatch".into());
        }
        let t = Self {
            tip: Tip {
                hash: fixed_hex(&d.target.hash)?,
                slot: d.target.slot,
                revision: d.target.revision,
            },
            eid: fixed_hex(&d.envelope_id)?,
        };
        if !(1..=MAX_BLOCKS as u64).contains(&t.tip.revision) {
            return Err("catch-up target outside experiment bounds".into());
        }
        let selected = t
            .tip
            .revision
            .checked_sub(1)
            .and_then(|i| worker.approvals.0.get(i as usize))
            .ok_or("target is not independently authorized")?;
        if selected.tip != t.tip || selected.envelope_id != t.eid {
            return Err("target differs from loaded immutable selection".into());
        }
        Ok(t)
    }
}

/// Read-only service of an ORIGINAL committed successor, never a sidecar, newly signed packet or
/// state snapshot. All request identities are comparisons to this owner's independently pinned cache.
pub(crate) fn serve(worker: &Worker, r: Request) -> Result<Vec<u8>, Reject> {
    // Keep the service safe for direct same-source tests as well as the checked wire dispatcher.
    if r.request_id == 0
        || r.base.slot != r.base.revision
        || r.target.slot != r.target.revision
        || r.base.revision >= r.target.revision
        || r.target.revision > MAX_BLOCKS as u64
        || (r.base.revision == 0 && r.base_eid != [0; 32])
    {
        return Err(Reject::Invalid);
    }
    let s = worker.snapshot().map_err(|_| Reject::Unavailable)?;
    let target = worker
        .approvals
        .0
        .get((r.target.revision - 1) as usize)
        .ok_or(Reject::Unauthorized)?;
    if target.tip != r.target || target.envelope_id != r.target_eid {
        return Err(Reject::Unauthorized);
    }
    let retained_target = s
        .records
        .get(r.target.revision as usize)
        .ok_or(Reject::Order)?;
    if retained_target.tip() != r.target
        || retained_target.producer_proof().map(|p| p.envelope_id()) != Some(r.target_eid)
    {
        return Err(Reject::Order);
    }
    let base = s
        .records
        .get(r.base.revision as usize)
        .ok_or(Reject::Order)?;
    let base_eid = base
        .producer_proof()
        .map(|p| p.envelope_id())
        .unwrap_or([0; 32]);
    if base.tip() != r.base || base_eid != r.base_eid {
        return Err(Reject::Order);
    }
    // Codec bounds establish base < target <=200; no input-derived search/allocation is used.
    let next = r.base.revision + 1;
    worker
        .store
        .export_signed_envelope(next)
        .map_err(|_| Reject::Order)
}

#[derive(Clone, Copy)]
struct Pending {
    connection: u64,
    request: Request,
    since: Instant,
}
struct Session {
    peer: u16,
    target: Target,
    phase: &'static str,
    reason: String,
    started: Instant,
    elapsed: Option<Duration>,
    pending: Option<Pending>,
    applied: u64,
    duplicates: u64,
    requests: u64,
}
/// Bounded state: one target, one request and one immediately completed response identity. No future
/// body buffer, automatic retry, signing, authority reload or canonical state mirror exists here.
#[derive(Default)]
pub struct Catchup {
    session: Option<Session>,
    last: Option<Pending>,
    sequence: u64,
}
impl Catchup {
    /// Only an explicit operator start can enter this phase.
    pub fn active(&self) -> bool {
        self.session.as_ref().is_some_and(|s| s.phase == "active")
    }
    /// Source selection is local operator policy; it is retained for explicit queue cancellation.
    pub fn source(&self) -> Option<u16> {
        self.session.as_ref().map(|s| s.peer)
    }
    /// Invalidate response correlation while retaining bounded diagnostic progress.
    pub fn halt(&mut self, reason: impl Into<String>) {
        if let Some(s) = &mut self.session
            && s.phase == "active"
        {
            s.phase = "halted";
            s.reason = reason.into();
            s.pending = None;
            s.elapsed = Some(s.started.elapsed());
        }
        self.last = None;
    }
    /// Pin a local-file target under existing approvals; no source claim is read for selection.
    pub fn start(
        &mut self,
        worker: &Worker,
        network: &Network,
        peer: u16,
        path: &Path,
    ) -> Result<Value, String> {
        if self.active() {
            return Err("cancel active catch-up before selecting another target".into());
        }
        if !worker.available() {
            return Err("owner unavailable; explicit recovery required".into());
        }
        if !network.config.peers.iter().any(|p| p.node_id == peer) {
            return Err("catch-up source is not an independently configured peer".into());
        }
        if worker
            .producer
            .as_ref()
            .is_some_and(|p| p.pending.is_some())
        {
            return Err("invalidate live producer preparation before catch-up".into());
        }
        let target = Target::load(path, worker)?;
        let snapshot = worker.snapshot()?;
        let complete = snapshot.tip.revision >= target.tip.revision;
        if complete {
            let r = &snapshot.records[target.tip.revision as usize];
            if r.tip() != target.tip
                || r.producer_proof().map(|p| p.envelope_id()) != Some(target.eid)
            {
                return Err("retained target evidence mismatch".into());
            }
        } else {
            network.target(peer)?;
        }
        self.last = None;
        self.session = Some(Session {
            peer,
            target,
            phase: if complete { "complete" } else { "active" },
            reason: String::new(),
            started: Instant::now(),
            elapsed: if complete { Some(Duration::ZERO) } else { None },
            pending: None,
            applied: 0,
            duplicates: 0,
            requests: 0,
        });
        Ok(
            json!({"outcome":if complete{"target_already_retained"}else{"catchup_started"},"new_commit":false,"target":super::super::tip(target.tip)}),
        )
    }
    /// The operator-started session may advance only after each confirmed exact successor. Timeouts,
    /// disconnects, busy queues and storage uncertainty HALT; none cause retry/application/re-signing.
    pub fn pump(&mut self, worker: &Worker, network: &mut Network) {
        if !self.active() {
            return;
        }
        if !worker.available() {
            self.halt("owner unavailable; explicitly recover then restart catch-up");
            return;
        }
        let s = self.session.as_mut().expect("active session");
        if let Some(p) = s.pending {
            if p.since.elapsed() >= super::net::TIMEOUT
                || network.target(s.peer).ok() != Some(p.connection)
            {
                network.close(p.connection);
                self.halt("successor reply timeout/source disconnected; no automatic retry");
            }
            return;
        }
        let snapshot = worker.snapshot().expect("available owner");
        if snapshot.tip == s.target.tip {
            s.phase = "complete";
            s.elapsed = Some(s.started.elapsed());
            return;
        }
        let base = snapshot.tip;
        if base.revision >= s.target.tip.revision {
            self.halt("unexpected canonical progress");
            return;
        }
        let next = worker
            .approvals
            .0
            .get(base.revision as usize)
            .expect("authorized target prefix");
        if next.base != base {
            self.halt("local tip differs from immutable selected base");
            return;
        }
        let base_eid = snapshot.records[base.revision as usize]
            .producer_proof()
            .map(|p| p.envelope_id())
            .unwrap_or([0; 32]);
        let Some(request_id) = self.sequence.checked_add(1) else {
            self.halt("request sequence exhausted");
            return;
        };
        self.sequence = request_id;
        let r = Request {
            request_id,
            base,
            base_eid,
            target: s.target.tip,
            target_eid: s.target.eid,
        };
        let result = network.target(s.peer).and_then(|id| {
            network
                .queue(id, Kind::GetSuccessor, &codec::request(r), None)
                .map(|_| id)
        });
        match result {
            Ok(connection) => {
                s.pending = Some(Pending {
                    connection,
                    request: r,
                    since: Instant::now(),
                });
                s.requests += 1;
            }
            Err(_) => {
                self.halt("successor request not queued; explicitly reconnect/restart catch-up")
            }
        }
    }
    /// An immediate exact duplicate response is still cold authenticated through the existing
    /// known-H reference path; it cannot execute, advance the session or permit another relay.
    pub fn accept(
        &mut self,
        worker: &mut Worker,
        connection: u64,
        request_id: u64,
        revision: u64,
        envelope: &[u8],
    ) -> Result<(bool, bool), String> {
        let pending = self
            .session
            .as_ref()
            .and_then(|s| if s.phase == "active" { s.pending } else { None });
        let normal = pending
            .is_some_and(|p| p.connection == connection && p.request.request_id == request_id);
        let p = if normal {
            pending.expect("matching pending")
        } else {
            self.last
                .filter(|p| p.connection == connection && p.request.request_id == request_id)
                .ok_or("unsolicited/reordered successor response")?
        };
        if normal && p.since.elapsed() >= super::net::TIMEOUT {
            return Err("successor arrived after the hard request deadline".into());
        }
        if revision != p.request.base.revision + 1 || revision > p.request.target.revision {
            return Err("successor does not fill the requested next slot".into());
        }
        let s = worker.snapshot()?;
        if normal
            && (s.tip != p.request.base
                || s.records[s.tip.revision as usize]
                    .producer_proof()
                    .map(|p| p.envelope_id())
                    .unwrap_or([0; 32])
                    != p.request.base_eid)
        {
            return Err("request base changed before successor application".into());
        }
        let selected = worker
            .approvals
            .0
            .get((revision - 1) as usize)
            .ok_or("missing independent successor approval")?;
        let e = SignedBlockEnvelope::from_wire_bytes(envelope).map_err(|e| e.to_string())?;
        if selected.base != p.request.base
            || selected.tip.hash != e.block().hash()
            || selected.envelope_id != e.envelope_id()
        {
            return Err("successor differs from independently selected original".into());
        }
        let decision = receive(worker, revision, envelope);
        if normal && decision.new_commit == Some(revision) {
            let session = self.session.as_mut().expect("active session");
            session.pending = None;
            session.applied += 1;
            self.last = Some(p);
            return Ok((true, false));
        }
        if !normal && decision.duplicate {
            if let Some(s) = &mut self.session {
                s.duplicates += 1;
            }
            return Ok((false, true));
        }
        Err(if worker.available() {
            "signed successor application rejected"
        } else {
            "storage outcome unavailable; explicit recovery required"
        }
        .into())
    }
    /// A matching refusal terminates the request; it does not choose another source/target.
    pub fn response_error(&mut self, connection: u64, request_id: u64, revision: u64) -> bool {
        let matches = self
            .session
            .as_ref()
            .and_then(|s| s.pending)
            .is_some_and(|p| {
                p.connection == connection
                    && p.request.request_id == request_id
                    && p.request.base.revision + 1 == revision
            });
        if matches {
            self.halt("source refused requested successor; no automatic retry");
        }
        matches
    }
    /// Diagnostic session state is never an authoritative canonical query or commit receipt.
    pub fn status(&self) -> Value {
        match &self.session {
            None => json!({"phase":"idle","new_commit":false}),
            Some(s) => {
                json!({"phase":s.phase,"reason":s.reason,"source_node":s.peer,"target":super::super::tip(s.target.tip),
                "target_envelope_id":hex::encode(s.target.eid),"requests":s.requests,"applied":s.applied,"duplicate_responses":s.duplicates,
                "in_flight":usize::from(s.pending.is_some()),"request_id":s.pending.map(|p|p.request.request_id),
                "elapsed_ms":s.elapsed.unwrap_or_else(||s.started.elapsed()).as_millis(),"new_commit":false})
            }
        }
    }
}
