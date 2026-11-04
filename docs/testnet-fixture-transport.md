# S3 — Bounded Signed Fixture Peer Exchange

`examples/testnet_fixture_peer.rs` adds an explicit loopback-only transport executable for the
approved fixture experiment. P produces controller-selected blocks, R1 authenticates/executes/
durably commits them and relays their original signed envelopes to R2. Each process retains one
serialized `AuthenticatedFixtureStore` and an independent database/directory lock.

Implementation: `examples/testnet_support/transport/{codec,net,mod}.rs`. Existing S1/S2 commands,
profiles, crypto, native execution, schemas, durability/audits and poison/exact-recovery behavior
are reused. The S1/S2 executables do not enable sockets. No prototype handlers, peer-derived
approvals, signing-key discovery, retrieval/catch-up, autonomous slots or PoAsh rules were added by
that stage. This document records S3's frozen version-1 contract and original measurements.
[S4](testnet-fixture-catchup.md) subsequently adds explicit version-2 pinned retrieval while preserving
all version-1 bytes and normal delivery semantics; it completes the finite M1 experiment.

## Executable, Configuration and Operator API

```bash
cargo build --example testnet_fixture_peer --example testnet_fixture_node --example testnet_fixture_producer
cargo build --release --example testnet_fixture_peer --example testnet_fixture_node --example testnet_fixture_producer
```

Actual CLI:

```text
testnet_fixture_peer follower init|open PROFILE APPROVALS DATA_DIR PEERS_JSON
testnet_fixture_peer producer init|open PROFILE APPROVALS DATA_DIR PEERS_JSON PRIVATE_KEY_FILE
```

Profile/approval/key and explicit init/no-create open contracts remain those of the
[worker](testnet-fixture-worker.md) and [producer/controller](testnet-fixture-producer.md). The data
directory must already exist. The private key stays in its protected external file, never the
public configuration, wire header, canonical state or literal argv. Invalid peer configuration
fails before creating an archive/lock. A later bind/socket-capability failure can leave an already
initialized archive; fix the transport cause and explicitly open it, never automatically reseed.

Strict regular config file, at most 8 KiB, mandatory fields, no duplicate/unknown fields:

```json
{
  "format": "eternix-fixture-peers-v1",
  "node_id": 2,
  "listen": "127.0.0.1:41002",
  "peers": [
    {"node_id": 1, "endpoint": "127.0.0.1:41001"},
    {"node_id": 3, "endpoint": "127.0.0.1:41003"}
  ]
}
```

Use P=1/listen 41001/peer 2, R1=2/listen 41002/peers 1+3, R2=3/listen 41003/peer 2 (operator-chosen
ports may differ). IDs are 1..3, endpoints numeric IPv4 **127.0.0.1 with nonzero port**; at most two
unique peers, no self/duplicate IDs or endpoints. Only the lower ID initiates a connection, avoiding
two sockets for one edge. Incoming identity is untrusted routing data checked against this static
set/direction, never a public-key or producer-authority binding. There is no DNS/discovery/TLS/NAT.

The local operator channel keeps S1 BE32-length JSON framing and limits. Additional exact commands:

| Command | Meaning |
|---|---|
| `{"command":"peer_connect","node_id":2}` | Explicit single connect attempt to a configured higher-ID endpoint; no automatic retry |
| `{"command":"peer_disconnect","node_id":2}` | Close that connection and discard queued deliveries; never undo a block |
| `{"command":"peer_status"}` | Non-authoritative transport/resource/control-latency diagnostics, also usable while owner unavailable |
| `{"command":"peer_observations","offset":0,"limit":16}` | Bounded page of local peer-commit timing observations, limit 1..16 |
| `{"command":"publish","revision":1}` | First-publication attempt using a permission minted only by a new local operator-observed commitment in this process |
| `{"command":"retransmit","node_id":2,"revision":1}` | Explicit resend of an already committed original envelope; `new_commit=false` |

First establish P→R1 and R1→R2 via `peer_connect`; poll `peer_status.connections[].ready`. S1
canonical status/inspection/export and S2 pool/prepare/propose/approval/commit commands still work.
Transport commands accept no approval, key, state snapshot or arbitrary peer endpoint. Extra fields
fail. A configured endpoint/handshake/advertised Tip cannot authorize an append.

## Controller Authority and Commit-Only Publication

S2 permits follower approvals only after observing producer commitment. Therefore P's first
publication is **explicit**, avoiding a race against installation of receiver authority:

1. On P: submit/prepare/propose. The trusted local controller durably retains original E and exact
   base/H/E-ID before providing the independently selected producer approval.
2. P extends approvals and `commit_prepared` confirms its existing atomic SQL/app-state installation.
   This creates a bounded in-memory first-publication permission for that revision, not a send yet.
3. The controller checks P's Ready committed exports, persists its retention observation and
   delivers complete matching follower approvals **separately over operator I/O to R1 and R2**.
4. Operator requests `publish` on P. P exports the exact retained E and queues it to established
   neighbors. Receiver R1 uses the revision only to find an **already loaded independent selection**;
   the existing signed staging path checks producer/native authority/effects and commits once.
5. Only new confirmed local commitment allows R1's first automatic relay, excluding its source
   connection. R2 follows the same path. No peer response is treated as a local canonical receipt.

The socket process checker uses the existing S2 durable controller selection/approval helpers with
three live peer processes. R2 gets the same selected-prefix artifact directly from the controller;
it never learns its authority from R1. The existing two-node S2 CLI remains operator-only, unchanged.

Publication permissions exist only for new commits observed through this process's operator
commands. They are not reconstructed from history, readiness, remote responses or recovery. A
`publish` attempt consumes its permission even if there is no established target or queues are full;
the committed envelope remains available for explicit retransmission. Cold reopen/recovery clears
these permissions; use `retransmit`, not a fabricated new first-publication receipt.

An exact/alternative-signature known H must still authenticate before a reference. Duplicate delivery
does not native-stage/execute, replace S/E-ID, advance Tip or mint relay/publication permission. R1
never relays a duplicate back into the graph. If R2 missed a failed relay, repeating P→R1 cannot
reauthorize it: explicitly retransmit R1→R2. Reconnecting does not automatically send old blocks.
These are transport operations, not a second commitment or missing-suffix synchronization service.

On any unavailable owner or explicit recovery attempt, connections/queued frames and unused
publication permissions are cleared before further peer work. No authoritative status/export or new
publication is served until full recovery and selected-prefix checks succeed. Diagnostic counters
contain no unreconciled Tip/evidence. Already-delivered/kernel-buffered bytes cannot be retracted;
no unconfirmed candidate was queued in the first place. Reconnection/retransmission is explicit.

## Frozen Binary Codec (Experimental Transport Version 1)

No JSON/text, optional fields, host endianness or normalization is used on peer sockets. Existing E
is nested **unchanged**; this framing does not change its signing domain, hash or rules. Integers
below are unsigned BE. The fixed **144-byte header** precedes payload without another prefix:

| Half-open byte offsets | Exact field |
|---|---|
| 0..4 | ASCII `ETX3` (`45545833`), separate from legacy UDP/native envelope tags |
| 4..5 | codec version u8 = 1 |
| 5..6 | type u8: 1 Status, 2 CommittedEnvelope, 3 Reference, 4 Error |
| 6..8 | reserved BE16 = 0 |
| 8..12 | payload byte length BE32, checked against the type-specific exact/range bound |
| 12..14 | sender node ID BE16, configured/direction-bound routing identity only |
| 14..15 | run-ID byte length u8, must equal the independently supplied profile |
| 15..16 | reserved u8 = 0 |
| 16..80 | exact profile run-ID ASCII bytes, zero-padded to 64; entire field compared |
| 80..112 | exact independent native network ID[32] |
| 112..144 | exact independent anchor H[32] |

Magic/version/type/flags/length are checked as their fixed bytes arrive. Full run/network/anchor,
configured sender/direction and duplicate-connection checks precede **any length-derived body Vec**.
Unknown types/versions/flags/context, inconsistent lengths, nonzero padding and invalid routing close
the connection without payload decoding or prototype dispatch. Initial frame must be Status.
Outbound sends Status first; inbound replies after validating it. Repeated Status is not echoed.

Payloads:

| Type | Exact payload fields/offsets | Payload / complete frame bytes |
|---|---|---|
| Status | H[32] at 0..32, slot BE64 at 32..40, revision BE64 at 40..48 | 48 / 192 |
| CommittedEnvelope | revision BE64 0..8; E byte length BE32 8..12; exact original E 12..end | 408..3656 / **552..3800** |
| Reference | result u8 0..1 (1 newly locally committed, 2 authenticated no-op reference); reserved zero[7] 1..8; revision BE64 8..16; H[32] 16..48; retained E-ID[32] 48..80; submitted E-ID[32] 80..112 | 112 / 256 |
| Error | code BE16 0..2; reserved zero[6] 2..8; request revision BE64 8..16; submitted E-ID[32] 16..48 | 48 / 192 |

M1's anchor is slot/revision zero, so Status slot equals revision and is ≤200. It is an unauthenticated
hint, never selection/latest-chain authority; it does not trigger requests, slot changes or catch-up.
Committed revision is 1..200, E length must equal the exact remaining payload and be ≤3,644 (the
unchanged S1 P/16-entry experiment bound). No gap/future buffer exists. Type/reference ranges and
reserved bytes are checked; new Reference requires retained=submitted. Duplicate Reference can
distinguish alternate signatures. Error codes: 1 unavailable, 2 unauthorized selection, 3 invalid,
4 order, 5 busy. Revision 0 denotes no request and requires zero submitted-ID bytes; otherwise ≤200.
The implementation normally closes unavailable/overfull connections and emits 2/3 for processed
envelope rejections; received recognized errors remain non-authoritative failed-delivery hints.

Reference/error responses carry no text or approval. They release only matching outstanding
revision/H/submitted-ID flow credit after the data frame has been written. References do not execute,
install authority, publish or relay anything; a peer-reported result is not a local commitment proof.
Malformed/unmatched responses close the connection. Version 1 has no retrieval/request/vote types.

All six complete golden frames (Status, empty signed E, new/duplicate References and two Errors) are
frozen in [`../tests/fixtures/testnet_fixture_transport.json`](../tests/fixtures/testnet_fixture_transport.json).
Independent Python explicit packing/OpenSSL reproduction, not the Rust codec:

```bash
python3 -B scripts/reproduce_testnet_fixture_transport.py
```

`--emit` prints only, never overwrites. The nested public signed envelope/producer signature is
ordinary existing wire-3/header-2 test data; no credential fixture or transport signing scheme is added.

## Resource Bounds and Operator Responsiveness

| Resource/work | Implemented bound/behavior |
|---|---|
| Active accepted/outbound sockets | 2 total, including incomplete handshakes; third accepted socket immediately closed |
| Listener queue | requested backlog 2; OS pending/SYN bookkeeping remains outside userspace frame accounting |
| Kernel buffers | request 4,096 bytes for SO_SNDBUF/SO_RCVBUF on listener and each connection; query/fail if either >16,384 or unavailable. Linux observed **8,192 each** |
| Retained frame bytes | **32,768 aggregate** for RX bodies, queued/active TX frames and one owner-dispatched body; capacity checked before allocation/encoding |
| Frames | at most **8 queued/active frames per connection** across control/data; one outstanding data delivery per connection; no retained full flight packet after writing |
| Peer work per iteration | 1 accept, at most 2 writes/4 reads; ≤2,048 read and write bytes per connection (≤4,096 each direction/node); at most 1 complete frame/owner action; rotate peers |
| Partial/slow peer deadlines | hard 2 seconds for handshake, partial frame, queued/active output or unresolved data delivery; trickles do not extend it; close/discard on expiry |
| Retry/connect | automatic retries/reconnects **0**; explicit connect only to static numeric loopback, at most 25 ms connect timeout |
| Operator I/O | fixed reader/writer threads, bounded capacity-one channels; at most bounded operator frames/responses and fixed standard buffers, no growing message queue |
| Measurements | at most 200 successful peer-commit observations (monotonic experiment budget), paginated 1..16; malformed/flood traffic retained as counters, not unbounded logs |

Only the owner thread holds/uses the archive. Peer I/O is nonblocking; partial TCP input or blocked
output never performs read_exact/write_all on the owner thread. Control/status replies are prioritized
over waiting data without interleaving partially written frames. A full publication queue fails that
attempt; a full rejection/reference queue closes the connection. Every failed attempt leaves a valid
committed prefix available for explicit retransmission. No successful sample/error is rewritten to
fit a deadline.

The event loop checks completed operator commands before one peer action. Reading a partial local
operator frame or writing a blocked local response happens on the fixed I/O threads, not in peer I/O.
A blocked operator consumer still backpressures later operator commands; it does not grow memory.
Stop does not join a peer/stdio-blocked thread: after shutting peers it gives a cooperative writer
up to 250 ms to flush its acknowledgement, then exits/drops the owner and directory lock. A lost
reply may require normal exact-request reconciliation. Peer diagnostics remain available when
canonical owner APIs are blocked.

These are explicit **transport work/resource** bounds, not a preemption/deadline on a synchronous
SQLite transaction, native stage, full recovery audit/barrier, connection close or host scheduler.
Stop/recovery can wait for at most the currently executing owner action; durability/audits are not
weakened to interrupt it. Recovery dispatch queue time and the full action/wall time are recorded
separately. Fixed headers, queue metadata, kernel bookkeeping, operator buffers, canonical caches
and bounded encoding temporaries are outside the 32-KiB retained-transport-byte counter; this is
not a whole-process allocator cap. Fixture-only dev dependency libc is the already-locked 0.2.186,
not a package upgrade. Verified on Unix/Linux; unsupported socket-capability setups fail closed.

## Actual Verification and Measurements

Focused commands completed in debug and release:

```bash
cargo test --example testnet_fixture_peer
cargo test --release --example testnet_fixture_peer
cargo test --lib worker_s2 -- --nocapture
cargo test --release --lib worker_s2 -- --nocapture
python3 -B scripts/test_testnet_fixture_transport.py target/debug/examples/testnet_fixture_peer target/debug/examples/testnet_fixture_node target/debug/examples/testnet_fixture_producer
python3 -B scripts/test_testnet_fixture_transport.py target/release/examples/testnet_fixture_peer target/release/examples/testnet_fixture_node target/release/examples/testnet_fixture_producer
```

Each codec example suite: **6 passed** (three S1 units plus three codec/golden cases).
Same-source library scope: **11 passed**, including an added actual peer-dispatch counter test:
new two-entry received block yields native authentication/stage/execution (2,1,2), one producer
authentication; exact duplicate adds one producer authentication and **zero** native calls/stages/
execution and zero relay permission. Invalid signature on known H produces no reference/permission.
No declared “verified” flag replaces actual entry counters; all instrumentation is test-only.

**Ten real-socket/process cases passed per mode**, including three independent files/processes,
populated/empty production, exact controller-original exports, all canonical accounts/nonces/gas/
burns/ordered bodies/outcomes/Tip/S/E-IDs and every transaction/sender-nonce/slot/hash membership.
The eight-step trial ends with 37 transactions per node: Alice/Bob/Carol balances
999,609,999 / 10,001 / 10,000 quarks, nonces 36/1/0, gas 37,000, burns 370,000.

Additional exercised boundaries:

- Fragmented handshake and coalesced Status/data/duplicate frames, new and duplicate References;
  duplicates/explicit retransmission cannot restart R1's relay loop or create duplicate effects.
- 18 invalid header/legacy cases reject with **zero input-derived RX body allocation**; malformed
  payload/tag/range, unsigned, wrong signer, signature/body tampering, wrong embedded context,
  unauthorized selection and out-of-order delivery leave canonical state unchanged. Deliberately
  selected bad input cannot bypass the independent archive's cryptographic/execution checks.
- Nonloopback/duplicate/oversized/unknown config fails before archive creation. Partial/truncated
  frames close cleanly or time out; fabricated peer receipts cannot mutate local state/authority.
- Two socket slots and eight-frame saturation, aggregate byte-budget refusal, disconnected R2,
  explicit R1 retransmission of a missed relay; reconnect has no automatic history behavior.
- Real WouldBlock writes from a stalled reader, duplicate flood and partial senders while operator
  status/recovery/stop remain serviceable; no peer thread touches a ledger. SQL-trigger interference
  creates actual failed-abort confirmation/RecoveryRequired at R1, suppresses exports/relay/connections,
  failed recovery stays blocked, explicit successful recovery then retransmission completes all nodes.

### Bounded publication timing

Raw final logs: `target/s3-final-process-debug.log` and `target/s3-final-process-release.log`. Each
contains 8 samples, all failures/resource observations, a successful test result and completion
record. Keep modes/runs separate. Workload is **three accounts, H=0..8/T=0..37, N=0/1/3/16**, one
controlled publish at a time, real sockets/files on the existing disk-backed `target` parent.
Default DELETE/EXTRA/FK/cache_size=-2000/spill/audits remain intact. Host: Ryzen 9 9950X, Linux/Rust
1.98 environment, ext4 rotational WDC disk as in prior archive evidence; no CPU/host/cold-cache
isolation or drift correction.

Timer starts **before P's operator publish request**, ends when the test operator observes each
receiver's committed Tip. It includes local IPC/poll observation, socket/queue time, complete
receiver signed/native/SQL application and R1 relay, but excludes P preparation/signing/commit,
controller selection/approval sync and startup audits. Thus it is an observed upper elapsed time,
not isolated wire latency or the full producer-to-network execution pipeline.

All observed samples, milliseconds:

| Revision | N | Debug P→R1 | Debug P→R1→R2 | Release P→R1 | Release P→R1→R2 |
|---|---:|---:|---:|---:|---:|
| 1 | 0 | 156.475 | 312.173 | 155.476 | 311.377 |
| 2 | 1 | 154.951 | 310.776 | 144.910 | 300.770 |
| 3 | 3 | 168.473 | 335.304 | 155.240 | 311.269 |
| 4 | 16 | 188.122 | 366.214 | 155.770 | 300.655 |
| 5 | 0 | 145.099 | 301.052 | 156.325 | 323.327 |
| 6 | 1 | 144.194 | 300.056 | 155.676 | 311.633 |
| 7 | 16 | 188.688 | 355.779 | 155.992 | 311.993 |
| 8 | 0 | 188.915 | 322.665 | 155.398 | 334.265 |

Per-mode medians/ranges (n=8, not a common-N percentile study): debug R1 **162.474 [144.194,188.915]**,
R2 **317.419 [300.056,366.214]**; release R1 **155.576 [144.910,156.325]**, R2
**311.505 [300.655,334.265]** ms. Coarse complete-frame-dispatch-to-commit/response-queue medians were
debug ~159.985/154.371 ms and release ~152.932/154.429 ms for R1/R2; these include signed/native/
durable work, not raw ECDSA/TCP or isolated SQL costs. No sample/outlier is removed or pooled across
build modes. These results do not establish 3,000-transaction capacity or a protocol deadline.

Normal path retained-transport-byte high-water was **3,800 / 7,712 / 3,912 bytes** at P/R1/R2. The
slow-reader stress retained **30,400 bytes/eight maximum frames**, refused a third connection and
recorded **39 queue/budget failures** among 48 explicit retransmission attempts; all results are
retained. Socket buffers queried **8,192 bytes per direction**. Actual stalled-socket stress recorded
**4 WouldBlock writes** by the recovery observation in each final mode.

Observed control timings, debug/release: partial-sender status ~1.044/0.971 ms, stop ~4.184/4.219 ms;
queued-output recovery wall ~217.015/162.252 ms, dispatch ~0.936/0.996 ms, action ~215.877/161.109 ms.
With real blocked writes, status ~2.895/1.190 ms, stop ~4.253/4.162 ms; recovery wall
~178.721/155.382 ms, dispatch ~3.698/1.138 ms, action ~174.835/154.165 ms. These are observations;
the tests bound control dispatch/status/stop under their fixture load, not unchanged recovery I/O.

Development runs remain separate: `s3-development-process*.log`, the first `s3-process-*.log`, and
`s3-responsiveness-investigation.log`. One initial resource test alternated queues and incorrectly
expected eight frames in each peer before the aggregate cap; it was corrected to saturate one first.
An earlier release run failed the combined 1.5-second control/recovery wall-time assertion at
**2,379.685 ms**, with no component timing then recorded; its cause remains unclassified and it is
not hidden or attributed to a proven network/storage cause. Explicit dispatch/action instrumentation
was added; the responsiveness check now measures dispatch separately from full audit/sync and keeps
the entire wall/action observation (outer test watchdog remains). Two focused investigation runs
showed ~1.145/1.129 ms dispatch and ~142.783/165.384 ms action, not proof of the original cause.
No failed/development samples are mixed into the final eight-per-mode table.

### Compatibility checks and stopping boundary

All S1 **10** and S2 **12** process cases passed against both updated debug/release executables.
Full `cargo test` passed **184 tests** (140 library + 44 binary), release library **140 passed**,
with 12 ignored benchmark/controlled-child entries. Independent native/block/auth/profile/S3 golden
checkers, formatting, Clippy and tracked/new-file whitespace checks passed; local `target/s3-*`
files retain evidence. Clippy retains only existing prototype
warnings. The only new direct dependency is the pinned fixture dev use of an existing locked libc;
the user's package-version edits remain preserved.

SIGKILL/SQL interference/socket timeouts are not power loss or physical durability certification.
Existing schemas/signing formats/rules, default synchronization/audits and legacy HIST/BLOCK
rejection remain unchanged. At its review boundary S3 stopped here: **no missing-suffix retrieval, automatic catch-up,
autonomous scheduling, PoAsh eligibility/protocol blocks/finality or prototype activation**. Original
committed E remains available for explicit operator retransmission; status hints cannot fill gaps.
Local plans/handoffs remain excluded. The initial S3 implementation delivery was unstaged for review.
