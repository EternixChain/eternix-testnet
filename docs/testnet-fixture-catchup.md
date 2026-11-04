# S4 — Pinned Missing-Suffix Retrieval and Finite M1 Trial

S4 completes the approved **controller-authorized transport/execution fixture experiment**:
three separate archive owners exchange the same finite selected sequence, an offline receiver
restarts and retrieves its missing suffix from R1 with P stopped, and a fresh authorized worker
retrieves the complete history. Each append still uses the existing authenticated/native stage and
atomic schema-3 writer. The archive remains the sole mutable canonical owner.

Implementation: `examples/testnet_support/transport/catchup.rs`, explicit retrieval extensions to
`{codec,net,mod}.rs`, and `scripts/testnet_fixture_controller.py`. This builds on the
[S1 worker](testnet-fixture-worker.md), [S2 producer/controller](testnet-fixture-producer.md), and
[S3 transport](testnet-fixture-transport.md). Existing native/block/signature formats, hash domains,
schema, grants, initialization, synchronization, full audits and prototype HIST/BLOCK rejection
remain the compatibility baseline. M1 is not PoAsh leader selection, consensus or finality.

## Independent Authority and Operator Workflow

**New selections keep S2's current producer-retention gate.** `select` durably retains original E
before producer approval; `release_follower` still checks P's current Ready retained originals before
releasing a new follower prefix. Historical synchronization does not weaken this gate.

Already released historical selections have a separate keyless operation:

```bash
python3 -B scripts/testnet_fixture_controller.py history --directory CONTROLLER_DIR
python3 -B scripts/testnet_fixture_controller.py history --directory CONTROLLER_DIR --target-revision 120
```

It requires an existing controller directory and lock, not a producer/worker executable, signing
key or running P. It validates/resynchronizes the immutable original corpus, public test-genesis
descriptor, previously released follower artifacts and matching **historical** producer-retention
observations. It can derive only a prefix of already released follower history, never authorize an
unobserved selected tail. It does not launch a worker/signer, select, apply, reconcile P's current
availability or manufacture a lost commit receipt. Corrupt/partial artifacts fail; no repair or
replacement of original history is attempted.

The result names a complete `follower-approvals-NNNN.json` prefix and an immutable
`catchup-target-NNNN.json` terminal pin. Existing exact artifacts are validated and synchronized;
new derived files use exclusive creation and file/directory fsync. The target's strict schema is:

```json
{
  "format": "eternix-fixture-catchup-target-v1",
  "run_id": "s1-golden-2026",
  "network_id": "<independent lowercase network ID, 32 bytes>",
  "anchor_hash": "<independent unsigned anchor H, 32 bytes>",
  "target": {"hash": "<selected H, 32 bytes>", "slot": 120, "revision": 120},
  "envelope_id": "<selected original E-ID, 32 bytes>"
}
```

This is an illustrative schema, not a literal runnable target. The regular file is bounded to
4,096 bytes; unknown/duplicate fields, wrong context, out-of-range revisions and mismatching pins
fail. Loading a target **cannot extend approvals**. Every selected base/H/slot/E-ID must already
come from the independent complete approval prefix supplied through startup or `extend_approvals`.

Use the unchanged peer executable/CLI and static topology from S3. After explicit no-create `open`
and the full archive/selected-prefix audit, distribute the already authorized follower prefix to R2
through local operator I/O. Connect R1→R2 explicitly and wait for the connection's `ready` diagnostic.
Then use the same BE32-framed local JSON channel:

| Exact command | Behavior |
|---|---|
| `{"command":"catchup_start","node_id":2,"target_path":"TARGET_JSON"}` | Select one configured established source and independent terminal pin; already retained exact target reports completion without network work |
| `{"command":"catchup_status"}` | Bounded diagnostic `idle` / `active` / `halted` / `complete`, target/source/correlation/counts/elapsed time; never a canonical receipt |
| `{"command":"catchup_cancel"}` | Halt, invalidate response correlation, disconnect source/discard queued work; keep the committed prefix |

The session fixes its target in memory. A peer's Status, height, request, response or advertised
profile cannot change it, install authority, learn a signing key or authorize a state snapshot.
There is no peer target-selection operation. Independently authorized normal S3 data is refused
with Busy while retrieval is active, so it cannot race the request base. Operator Apply, approval
extension and prepare/propose/commit-prepared are refused until completion/cancellation; pure reads
remain available. Explicit Recover and Stop halt before acting. Disconnect, malformed response,
wrong original/prefix/order, refusal, queue failure, request timeout or owner uncertainty halt;
none silently retries, changes source, reloads authority, re-signs or restarts the session.

## Sequential Original-Envelope Retrieval

Only one requested successor is outstanding for a session. A request fixes:

- Monotonic nonzero process-local request ID, matched on the same connection.
- Exact local base Tip and retained E-ID (all-zero E-ID only for the unsigned anchor).
- Exact independently authorized terminal Tip and original E-ID, at revision 1..200.

A Ready source compares both endpoints to its own independent approvals and retained records,
requires that terminal record actually be committed, and exports **only base revision + 1** using
`export_signed_envelope`. It never serves private proposals, replacement signatures or snapshots.
Repeated requests can return identical original bytes without canonical effects or new publication
permission. Wrong base/evidence or unavailable/unretained target yields a bounded refusal.

The receiver matches connection/request ID/requested next revision, unchanged local base, selected
H/E-ID and exact requested original. Existing signed receive staging then authenticates P, checks
grant/parent/slot/native body/outcomes and commits once. Only confirmed commitment advances the
session and permits requesting its next successor. No future-envelope buffer, gap insertion,
provisional miss, second state mirror or separate native execution exists. Historical retrieval
does not mint S3 first-publication/relay permission. An immediately repeated exact response is cold
producer-authenticated through the existing known-H reference path, with no extra native stage,
execution, evidence replacement or relay. Older/unmatched responses fail closed.

Every interruption leaves a complete durable authenticated prefix. Restart always uses no-create
full reopen plus independent selected-prefix comparison, and begins with **no active session**.
After explicit reconnect/start, the next request derives from that audited retained tip, not a lost
response or old volatile request counter. Fresh-process recovery has no lost in-memory attempt to
report; already retained evidence is a reference/observation, not a new commitment.

Unavailable owners retain only diagnostics. Canonical queries, export, pool/signing/staging/commit,
connections/queued publication and fresh-publication tokens are suppressed. Explicit recovery must
complete full audit, exact present/absent reconciliation, synchronization and selected-prefix checks.
Failed recovery remains blocked. Successful recovery invalidates preparations and leaves the old
catch-up halted; reconnect/restart is explicit. These are the existing archive recovery contracts,
not shortcuts introduced by retrieval.

## Explicit Experimental Transport Version 2

S3's **version-1 types 1–4, meanings and all six golden frames remain byte-identical**. S4 adds
disjoint version-2 types 5–7; neither version reinterprets the other's kinds. The same fixed 144-byte
`ETX3` header/context/routing checks precede any input-sized allocation. Initial handshake remains
version-1 Status. There is no negotiation/downgrade fallback: an older S3-only peer rejects an
extension; it cannot silently turn it into data/authority.

Unsigned integer fields below are explicitly big-endian. Payload offsets exclude the fixed header:

| v2 type | Payload fields | Payload / complete frame bytes |
|---|---|---|
| 5 GetSuccessor | request ID u64 0..8; base H[32] 8..40, slot u64 40..48, revision u64 48..56, E-ID[32] 56..88; target H[32] 88..120, slot u64 120..128, revision u64 128..136, E-ID[32] 136..168 | 168 / 312 |
| 6 Successor | echoed request ID u64 0..8; successor revision u64 8..16; E length u32 16..20; unchanged original E 20..end | 416..3664 / **560..3808** |
| 7 RetrievalError | echoed request ID u64 0..8; existing error code u16 8..10; reserved zero[6] 10..16; requested successor revision u64 16..24 | 24 / 168 |

Request base < target ≤200, each slot equals its revision, anchor base E-ID is zero, request ID is
nonzero; response/refusal revisions are 1..200. Successor E length must equal remaining payload and
be ≤3,644. Error codes reuse 1 unavailable / 2 unauthorized / 3 invalid / 4 order / 5 busy. An error
does not carry approval, a new target or retry instruction. Correlation is flow control, not a proof
that any peer committed a block.

The additive maximum is **3,808 bytes**, while the v1 maximum stays 3,800. Existing two-socket,
eight-frame/connection, aggregate **32,768 retained bytes**, bounded per-iteration I/O/action, static
loopback/socket-buffer limits and zero automatic retries remain in force. Retrieval retains one
target, one pending request and one immediately completed response identity. The requester waits
for confirmation before issuing the next request; duplicate service replies still share the same
bounded source queues. No extra unbounded mailbox, future body collection or handler log is added.

Request expiry is a hard **two seconds from queueing**, and is checked again before applying a
response. It includes source/transport wait, not a preemptive timer inside a receiver SQL commit.
S3's partial-frame/output deadlines also apply. A finite 200-step history can legitimately take
longer than 30 seconds overall: the runner uses a separate 420-second total catch-up watchdog, the
existing 30-second local-command diagnostic watchdog, and two-second per-request stopping behavior.
Expiry stops the trial; it never changes a ledger deadline/rule or authorizes an automatic retry.

Four new vectors (anchor/nonanchor requests, Successor, refusal) are frozen separately in
`tests/fixtures/testnet_fixture_catchup.json`. Successor reuses the existing frozen S3 E as opaque
input. Independent Python explicit packing checks them without the Rust codec:

```bash
python3 -B scripts/reproduce_testnet_fixture_catchup.py
```

## Finite M1 and Actual-Path Failure Evidence

`scripts/test_testnet_fixture_catchup.py` has **six actual-process/socket acceptance cases**, passed
in debug and release. The maximum trial appends 200 blocks, with N=0/1/3/16, contiguous and
out-of-order submitted nonces, funding before Bob spends, self/zero transfers and a maturity hold
until slot 5. It takes R2 offline after revision 3, advances P/R1 to 200, then stops P and removes
the temporary signing file before invoking the keyless historical CLI. R2 restarts/retrieves, is
SIGKILLed at observed revision 5 during catch-up, fully reopens at a valid selected prefix and
explicitly resumes. A fresh authorized initialized worker retrieves all 200 from R1.

P's pre-stop snapshot and R1/resumed-R2/fresh snapshots, all bodies/outcomes, every transaction,
sender-nonce, slot/hash membership, Tip, compact S/E-IDs and exported original E match exactly.
Each final owner has **201 records / 3,140 transactions**, gas **3,140,000**, burn **31,400,000**;
Alice/Bob/Carol balances are **968,580,000 / 10,000 / 10,000**, nonces **3139 / 1 / 0**.
The terminal H is `ae30ff54e42b3c904f8a2a55ec29363eedde9057a9f83689be3bf7d9e2e02704`,
E-ID `66059867beba32c6bebb8c554c3281cb654ca7653b2d21893782884a9a0dfeb5`.

The remaining process cases exercise strict independent targets, hints with no automatic retrieval,
unloaded authority, active-session writer/recovery gates, omission/reordering/tampering/conflicting
content/wrong context/request IDs/refusal, duplicate Successors, lost responses and explicit
same-prefix resume, duplicate read-only source requests, wrong source base/E-ID/terminal evidence,
and corrupt historical/profile input. A missing response produced one request, no application or
retry, and halted at ~2,000 ms. Invalid responses preserved the exact prior snapshot.

`src/authenticated_fixture/tests/worker_s4.rs` adds **three same-source library cases**, passed in
both build modes, using the actual `Runtime::operator` / `peer_tick` paths:

1. Real COMMIT `xSync` / `SQLITE_IOERR_FSYNC`; actual rollback-restoration `xWrite` /
   `SQLITE_IOERR_WRITE`; durable-COMMIT/publication gap with withheld response. Each then encounters
   a selected **real recovery-barrier xSync failure**, stays blocked, and only an explicit fault-free
   recovery reconciles the exact attempt as absent / absent / present. Absent attempts retain both
   pool entries until explicit original replay; present recovery reconciles membership without
   fabricating new success. All stale preparations are invalidated.
2. Real commit sync failure during an actual requested Successor halts retrieval, clears sockets/
   publication and hides canonical APIs. Explicit absent recovery does not resume; explicit new
   session/replay commits once. Actual counters for its two-entry successor show one producer auth,
   one native stage, two native auth/executions; duplicate adds one producer auth and **zero** native
   auth/stage/execution, signing or relay/first-publication permission.
3. Isolated child processes run the production lock/setup/stdio/serialized-owner loop, paused by
   test-only hooks and SIGKILLed before SQL, before COMMIT and after durable COMMIT/before publication.
   Reopen yields exact old / old / new prefix. Replaying original E reports new / new / reference;
   a fresh recovery correctly reports no lost in-memory attempt.

The rollback case explicitly calls test-only `sqlite3_db_cacheflush` at the SQL hook to place dirty
pages on disk before forcing rollback and failing actual restoration. Cache_size=-2000, DELETE,
synchronous=EXTRA, FK, spill and full audits are unchanged. This is a selected **real rollback-write
error**, not evidence of natural small-fixture spill or a broad fault sweep. Test-only constructors,
hooks and real-VFS wrappers have no production CLI/operator/peer fault interface. Direct dispatch
fault tests are distinct from the isolated real-runtime SIGKILL children.

SIGKILL tests are process-interruption evidence; real callback errors are selected I/O-failure
evidence; the existing archive sector-prefix/lost-unsynced-write **declared power-loss model** is
separate. The full compatibility suite reruns that model; S4 does not relabel it as network or
physical-power-loss certification, nor repeat the ignored large capacity/profiling experiments.

## Measurements and Limitations

All S4 process samples/outliers and completion results are emitted and retained in unique
`target/s4-process-{debug,release}-*.json`; real-I/O owner action/recovery observations and exact
error responses are in `target/s4-owner-{debug,release}-*.json`. Development/subset runs stay
separate. The first five-case development report is `target/s4-process-debug.json`.

Initial complete runs, milliseconds (one finite run per mode, not percentiles):

| Boundary | Debug | Release |
|---|---:|---:|
| R2 no-create process start → Ready, retained H=3 | 172.015 | 160.161 |
| After catch-up SIGKILL: start → Ready, retained H=5 | 184.942 | 174.889 |
| Explicit resumed start → observed completion, 195 successors | 44,755.827 | 36,237.383 |
| Fresh process init → Ready | 179.965 | 171.111 |
| Explicit fresh start → observed completion, 200 successors | 40,557.262 | 35,658.094 |
| P publish request → observed R1 Tip, n=200 mixed H/N samples, min..max | 155.899..519.367 | 123.171..333.887 |

The first three production samples also wait for online R2; their reported elapsed time therefore
includes that extra observation barrier. Others wait only for R1. Do not pool them as isolated wire
or uniform-N timing. Publish timing excludes P preparation/sign/commit/controller artifact fsync;
catch-up timing includes all sequential request/response/native/SQL commits and operator observation,
but excludes prior startup audit, target export and subsequent full equivalence inspection.
Startup includes process/profile/approval load, lock, full applicable audit and initial Ready reply.

A separate release maximum-trial rerun added the previously missing **full endpoint reopen**
measurement: process start → Ready/full audit at H=200/T=3,140 was **541.270 ms**. That run also
observed H=3/H=5 startup **171.354 / 162.988 ms**, fresh init **181.163 ms**, resumed 195-step
catch-up **38,617.602 ms**, fresh 200-step catch-up **38,139.135 ms**, and its 200 mixed publish
samples **135.786..312.198 ms**. All passed with the same exact terminal identity/equivalence;
the separate raw report is retained, not pooled into the initial-run table. Its total finite test
wall time was 252.302 seconds, including input generation/controller work and equality inspection.

Release normal retained-byte high-water was P **3,800**, R1 **3,976**, resumed R2 **3,664**, fresh
**3,664**, all below the unchanged 32-KiB budget. Debug recorded source **3,976** and fresh **3,664**;
its first report read resumed R2's counter only after a cold reopen (reset to zero), so that zero is
not a measurement of its retrieval high-water. The runner now captures it before reopen. Existing
S3 saturation/slow-reader regressions also pass with the extension present.

Focused real-I/O action / failed barrier recovery / successful explicit recovery samples, ms:

| Case | Debug | Release |
|---|---|---|
| COMMIT sync failure, absent | 75.803 / 99.701 / 290.032 | 86.796 / 106.128 / 328.580 |
| Forced real rollback write, absent | 242.017 / 179.864 / 267.342 | 265.425 / 156.285 / 289.480 |
| Durable publication gap, present | 231.410 / 88.747 / 257.365 | 287.124 / 88.828 / 312.093 |

These observations include actual synchronous audit/storage work, not operator dispatch alone.
Full-suite reruns have their own unique artifacts; they are not pooled with this focused table.
An earlier development pass before the child-lock test setup fix observed fault actions
52.867 / 208.635 / 141.813 ms, successful recovery
310.545 / 167.025 / 167.182 ms and failed recovery 67.753 / 100.456 / 22.169 ms for the three cases;
these are retained here rather than discarded. That initial kill child lacked the pre-existing
lock artifact and failed before startup; the fixture setup was fixed, not no-create-open behavior.

Host/filesystem/build context is the same Linux/ext4 rotational-disk `target` parent as S3, with no
CPU/host/cold-cache isolation. All defaults/full audits remain. Whole-history catch-up exceeds one
slot and 30 seconds in these runs; it is not a slot/deadline or 3,000-entry capacity claim. Existing
retained-history copying, SQL/fsync cost and long full-audit limits remain documented in
[authenticated storage](authenticated-block-storage.md). S3's earlier unclassified 2,379.685-ms
control/recovery wall outlier remains in its historical evidence and is not explained away here.

## Reproduction and Review Boundary

```bash
cargo test
cargo test --release --lib
cargo test --example testnet_fixture_peer
cargo test --release --example testnet_fixture_peer
cargo test --lib worker_s4 -- --nocapture
cargo test --release --lib worker_s4 -- --nocapture
cargo build --example testnet_fixture_peer --example testnet_fixture_node --example testnet_fixture_producer
cargo build --release --example testnet_fixture_peer --example testnet_fixture_node --example testnet_fixture_producer
python3 -B scripts/test_testnet_fixture_catchup.py target/debug/examples/testnet_fixture_peer target/debug/examples/testnet_fixture_node target/debug/examples/testnet_fixture_producer
python3 -B scripts/test_testnet_fixture_catchup.py target/release/examples/testnet_fixture_peer target/release/examples/testnet_fixture_node target/release/examples/testnet_fixture_producer
cargo fmt --check
cargo clippy --all-targets
```

Full debug compatibility: **189 passed** (145 library + 44 binary), 13 ignored benchmark/controlled
child entries. Release library: **145 passed**, 13 ignored. Peer example: **8 passed per mode**.
All S1 **10**, S2 **12**, and S3 **10** process cases passed in both modes. Independent native,
stage-4, block-auth, public-profile, original S3 and new S4 vector checkers pass. Existing prototype
Clippy warnings remain separate from the fixture code.

S4/M1 stops at this finite review deliverable: controller-pinned replicated execution, original
evidence, bounded retrieval, interruption and selected storage-uncertainty recovery. No autonomous
retry/re-sign/failover, protocol blocks, PoAsh admission/scheduling/finality, public RPC/P2P or
prototype ingress activation follows. The initial delivery is unstaged/uncommitted for review;
local plans/handoffs and the user's package-version edits remain local.
