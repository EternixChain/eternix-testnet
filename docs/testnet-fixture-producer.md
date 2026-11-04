# S2 — Bounded Local Fixture Producer and Controller

S2 extends the reviewed [S1 worker](testnet-fixture-worker.md) with a separate opt-in producer,
bounded native pool and durable local controller. The existing `AuthenticatedFixtureStore` remains
the **only authoritative mutable canonical owner**. Its preparation/sealing/application, schema 3,
crypto/native formats, full audits, poison gates and exact recovery are reused unchanged.

New implementation areas:

- `examples/testnet_fixture_producer.rs`: producer executable entrypoint.
- `examples/testnet_support/producer.rs`: private signer, pool, deterministic selection and owned
  preparation/proposal. The shared `mod.rs` adds explicit operator lifecycle commands.
- `scripts/testnet_fixture_controller.py`: finite local controller, immutable selected originals,
  separate retention observations/approval artifacts and explicit restart/replay operations.
- `src/authenticated_fixture/tests/worker_s2.rs`: actual same-source orchestration tests against
  private function-entry counters; `scripts/test_testnet_fixture_producer.py`: actual OS processes.

The default `testnet_fixture_node` remains the follower/S1 role and never loads a key or enables a
pool. No peer sockets, autonomous slots, eligibility, protocol blocks, schema changes, consensus-rule
changes or prototype-node activation are introduced. Controller authority is the approved experiment,
not PoAsh consensus, a quorum or finality.

S3 subsequently adds a separate opt-in [fixture peer executable](testnet-fixture-transport.md).
The original S1/S2 executables and controller CLI remain local/operator-only. S3 reuses their
authoritative owner, private signer and independent approvals without enabling sockets implicitly.
S4's [pinned catch-up](testnet-fixture-catchup.md) adds a keyless controller `history` operation for
already released follower prefixes. New selections still require the current producer-retention gate
described here; historical reuse does not require P or its key to authorize the same steps again.

## Build and Private Signing Input

```bash
cargo build --example testnet_fixture_node --example testnet_fixture_producer
cargo build --release --example testnet_fixture_node --example testnet_fixture_producer
```

Actual producer invocation:

```text
testnet_fixture_producer init|open PROFILE_JSON APPROVALS_JSON EXISTING_DATA_DIR PRIVATE_KEY_FILE
```

S1's four-argument follower invocation and explicit init/no-create open behavior remain supported.
Both roles share its directory lock, bounded local framing, pure canonical reads and recovery gates.

`PRIVATE_KEY_FILE` is a **file path, never literal signing material in argv**. The external operator
supplies exactly 32 raw bytes representing a valid secp256k1 key. No hex/newline/password default is
accepted. The regular file must be outside the node data directory and, on Unix, grant no group/
other permissions (for example owner-read-only or mode 0600). The controller additionally requires
it outside the entire controller artifact directory. The full derived public key must match the
independently supplied profile's P binding before the archive opens. A zeroizing bounded read buffer
is used, including failed reads/length checks; `SigningKey` retains its existing secret handling.

The key is not put in a profile, controller corpus, canonical accounts, command/response, source
credential fixture or log. The controller never reads its bytes; it passes only the path to the
producer process. Errors do not echo key contents. Tests generate protected temporary files from
published toy inputs or a fresh ephemeral test key at runtime. The public S1 golden binding is test
data, not a provisioned credential. No key-generation, wallet or remote signing service is added.

The existing `sign_block` API provides the same domain/prehash/canonical signature behavior. The
signer remains **experimental and stateless**, with no production crash-safe anti-equivocation
guarantee. Persisting a controller-selected request does not prove no other statement was signed.

## Pool Admission and Deterministic Selection

Pool policy is local and non-consensus. It has at most **128 entries**, indexed in ordered raw
`(sender[20], nonce:u64)` order. Each entry retains exact signed bytes, ID and authenticated payload
metadata; no admission proof is reused to skip inclusion checks.

Admission under the independent profile context:

1. Bounded lowercase-hex decoding followed by the existing cold `native_transaction::authenticate`.
   Even a duplicate submission is authenticated again. Invalid signature/context/kind/asset/gas or
   non-incrementable nonce fails before insertion.
2. Identical ID/bytes already pending returns `duplicate_id`; a canonical ID returns `already_included`.
3. Reject nonce below canonical and unrepresentable value-plus-10,000-quark exposure. Different ID
   at an occupied sender/nonce is rejected: **no replacement**. At capacity a new entry is refused;
   an authenticated identical duplicate still deduplicates.
4. Otherwise admit, including future nonces, future maturity and currently unfunded spends.

Submission does not change canonical balances, nonces, accounting, Tip or membership. Pending data
is volatile, never canonical state. No pool persistence or durable replacement/signing-intent policy
is implied across process restart.

Selection for the exact next archive slot is deliberately **conservative**:

- Iterate by raw sender bytes and ascending nonce, independent of arrival order; one candidate per
  sender/nonce removes tie ambiguity. Select at most 16.
- Require each sender's next contiguous nonce, signed maturity at or before the proposed slot and
  full value-plus-fixed-fee funding from that sender's **committed starting balance minus already
  selected debits**. Do not use wall-clock time or pending nonce trackers.
- A gap, immature entry or unfunded entry holds that candidate; later nonces for that sender cannot
  jump over it. Other senders remain selectable. Report counts as `held.nonce_gap`, `immature`,
  `funding`, `stale` and `body_limit`; holds are not canonical failures or charged operations.
- **Ignore every incoming credit, including self-transfer credits**, during reservations. Funding
  received in this candidate therefore becomes selectable only in a later committed block. This can
  defer an otherwise valid body/spend; it does not change the shared executor's body validity rules.
- No preview execution occurs: selection uses a bounded local debit reservation map, not a second
  canonical state owner, `stage_body` call or alternative transfer executor. Then the archive's
  `prepare_next` authenticates and executes the final ordered raw body exactly once. Aggregate
  preparation failure installs nothing and is not silently skipped/retried.

Rejected admission candidates are not queued. Holds remain queued until a later explicit selection,
canonical invalidation, or process exit. There is no pressure-based eviction or replacement/drop command.
An explicit committed transition or successful audited recovery reconciles included IDs and stale
nonces against canonical membership. Uncertain commitment does **not** remove selected entries.

The supplied CLI controller starts/stops nodes per operation, so unselected volatile entries disappear
at operation exit. Operators retain/resubmit the original native transaction batch explicitly on a
later `step`; exact canonical IDs return references. The controller does not silently resubmit,
replace or transform a deferred transaction. A long-lived producer supports multiple commands and
steps while retaining its pool. These choices fit the unchanged M1 200-block/16-transaction budget.

## Operator Commands and Approval Extension

All S1 commands retain their framing: BE32 length then JSON, 1..65,536 bytes, bounded responses/pages,
one synchronous command/response at a time. Producer additions are:

| Exact command | Behavior |
|---|---|
| `{"command":"submit_native","transaction":"<199 signed bytes as lowercase hex>"}` | Authenticate/admit/deduplicate; no canonical reservation or append |
| `{"command":"pool","offset":0,"limit":16}` | Pure page (limit 1..16), count/128 bound and pending-preparation summary |
| `{"command":"prepare"}` | Select and stage once against the current exact base; return H/IDs/hold counts, `new_commit=false` |
| `{"command":"propose"}` | Sign the existing preparation once, cache exact E and return **private uncommitted controller input** |
| `{"command":"extend_approvals","path":"<independent public approvals file>"}` | Explicit monotonic extension for either role; validates the complete currently loaded prefix and retained archive before installing authority |
| `{"command":"commit_prepared","selection":1}` | Check independent base/H/E-ID, seal the owned preparation, commit atomically, then cleanup/output only on confirmed success |

`prepare` while the same preparation exists returns `already_prepared` without another stage.
`propose` requires explicit preparation; repeat requests return the identical cached original E,
not deterministic re-signing. Submissions after preparation do not alter its frozen body. There is
at most one pending preparation/proposal. No command takes a private signing key.

The producer cannot prepare a new candidate while loaded selected authority is ahead of committed
progress: the original selected request must first be reconciled/replayed. A loaded unresolved
selection also prohibits newly signing an unsigned preparation. An already cached private proposal
can be inspected without signing again.

`extend_approvals` is an explicit trusted-operator action, not automatic reload or packet approval.
It reads the same bounded strict S1 approval schema, with the same independent profile/anchor/P/ticket.
All old selections, bases, H/E-IDs and order must remain identical; truncation/replacement is refused.
It leaves archive generation and the owned preparation intact, so preparing before approval extension
does not require restaging. Exact idempotent extension is allowed; stop/open with a complete matching
history still works.

Wrong/missing approval is rejected **before consuming** the non-cloneable native preparation. The
caller can correct its request without new native work or signatures, provided it has not changed
loaded authority to a different immutable decision. Sealing then uses the existing producer proof
route once; successful commit repeats neither producer nor native verification/execution.

On success `commit_prepared` returns `outcome=committed,new_commit=true`, exact Tip/E-ID, original
retained `envelope` and `pool_removed` (included IDs plus stale local invalidations). The proposal
response instead has `outcome=proposal,committed=false,new_commit=false`. A signature, preparation,
selection file or `ok=true` is never substituted for a new commitment receipt.

While a producer preparation is alive, S1 `apply` is refused: it must not restage that same candidate
through the received-block route. After explicit recovery/restart invalidates old generations,
`apply` can replay the **original selected E** as a new explicit attempt. Followers continue to use
the unchanged signed `apply` path and do not accept producer-only operations.

## Durable Local Controller and Actual CLI

The controller is `scripts/testnet_fixture_controller.py`, for the Linux/local-process experiment.
It uses the existing independent OpenSSL Keccak helper for H/E-ID checks, not a new signer. Python's
OpenSSL/cryptography environment is the same as the repository vector checkers.

Actual modes: `init`, `step`, `reconcile`, `replay`. Every invocation takes:

```text
--worker WORKER_EXECUTABLE --producer PRODUCER_EXECUTABLE
--key-file PRIVATE_KEY_FILE --directory CONTROLLER_DIRECTORY
```

`init` additionally requires `--profile PROFILE_JSON` and a **fresh nonexistent** controller directory
whose parent exists. It freezes the public profile, creates independent producer/follower data
directories, and explicitly initializes both archives. Existing controller directories fail; no
create-or-open fallback exists. Interrupted initialization can leave an unusable partial experiment;
later modes do not fill in missing node databases. Other modes use the frozen profile and no-create worker opening.
One lifetime `controller.lock` excludes concurrent coordinators for the same artifact directory.

`step` additionally requires `--transactions TRANSACTIONS_JSON`. Strict batch schema, at most 64 KiB:

```json
{"transactions":["<exact 199-byte signed native transaction hex>"]}
```

At most 128 inputs are allowed; `[]` explicitly selects an empty block. Invalid/rejected submissions
stop before preparation. An authenticated duplicate/canonical-ID reference is allowed. Each call
performs **one** controller-driven logical step; no timing loop or autonomous schedule is present.

Example command shapes (paths are operator inputs, not embedded credentials):

```bash
python3 -B scripts/testnet_fixture_controller.py init \
  --worker target/release/examples/testnet_fixture_node \
  --producer target/release/examples/testnet_fixture_producer \
  --profile tests/fixtures/testnet_fixture_profile.json \
  --key-file PRIVATE_KEY_FILE --directory NEW_RUN_DIRECTORY

python3 -B scripts/testnet_fixture_controller.py step \
  --worker target/release/examples/testnet_fixture_node \
  --producer target/release/examples/testnet_fixture_producer \
  --key-file PRIVATE_KEY_FILE --directory RUN_DIRECTORY --transactions SIGNED_BATCH_JSON
```

Use the same common options with `reconcile` or `replay`, without `--profile`/`--transactions`.
The process checker exercises these actual CLI operations as well as direct long-lived command
sessions; it generates test-only private input outside the public/artifact directories at runtime.

### Persistence and permission ordering

Artifacts, using fixed four-digit indices and public JSON contents:

| Artifact | Meaning |
|---|---|
| `profile.json` | Frozen independent public profile; not a key file |
| `selected-0001.json` | Original exact E plus format/context/anchor/P/ticket, selection index, base Tip, next slot, H/E-ID; **selection**, not node commitment |
| `producer-approvals-0001.json` | Complete append-only selected-prefix authority for P, derived only from synchronized original selection records |
| `producer-retained-0001.json` | Separate `observed_retained,new_commit=false` observation of a Ready producer archive's exact selected E |
| `follower-approvals-0001.json` | Complete authority released only after producer retention is established; no grant from a private proposal alone |
| `producer/`, `follower/` | Separate schema-3 database/lock directories |

For every step:

1. Verify both Ready node prefixes match all existing selections; unresolved progress refuses a new
   step before preparing/signing. Submit, prepare and privately propose on P.
2. Recompute existing H/E-ID and base/context association, then **exclusively create the immutable
   original selection file, write all bytes, fsync the file and fsync its directory**.
3. Only after that succeeds, durably create the complete producer approval artifact and explicitly
   extend P's loaded authority. Seal/commit the original owned preparation.
4. Check P's Ready Tip and exact committed exports against the selected corpus. Durably retain the
   separate observation, then durably create/extend follower approval and send the original E to F.
5. Verify follower retention. Output a controller step result; this is not a consensus quorum.

No file is overwritten or silently repaired. An exact existing artifact is validated and genuinely
re-synchronized; different contents fail. A partial/malformed file, sequence gap, changed historical
pin or mismatched original bytes blocks continuation. A completed file with a previous unresolved
sync may be validated and fsynced again with its directory, **without changing its original request**.
File/sync errors raise before permission is delivered. Selected files are capped at 16 KiB, approval
files at 512 KiB, selection count at 200 and directory entries at a fixed finite bound. Bounds are
experiment controls, not a global allocator cap or a new canonical persistence format.

The controller starts signers with the complete selected prefix, even if a prior crash interrupted
creation of a derived producer-approval file. This reconstructs only the identical permission from
already synchronized originals; it does not prepare, sign or commit. Historical approval artifacts
are checked against the selected corpus. Follower artifacts additionally require matching producer
observations. A historical observation never replaces a **current Ready producer retention check**
before releasing follower authority or advancing a step.

## Lost Replies, Restart and Uncertainty

Selection, observed retention and receipt delivery are separate facts. There is no atomic transaction
across controller files and two node databases, and none is claimed.

- **Lost Prepare/Propose reply, same process:** inspect/repeat the same preparation/proposal; no
  second stage or signature. Lost unselected proposals across process death cannot be recovered
  from a signer journal: no such guarantee exists. Startup never automatically prepares/signs.
- **Selected before producer commitment:** the original file survives independently. Restarted
  producer sees unresolved selected authority and refuses new preparation/signing. `reconcile`
  reports selected-but-absent without committing; explicit `replay` uses those original bytes.
- **Committed but reply lost:** no-create reopen fully audits producer history. `reconcile` checks
  exact original exports, records observed retention and can release follower authority; it does
  not fabricate the old receipt or call Prepare/Propose/Apply/Commit.
- **Explicit `replay`:** resolves only the one selected tail left unresolved by the controller's
  per-step barrier. An absent tail is applied using original E; a retained tail returns an
  authenticated `already_committed` reference. No signature is regenerated, no new H/S/E-ID is
  selected and duplicate durable effects are impossible through this route. Producer/follower
  `new_commit` results are reported separately. More than one missing tail is refused, not treated
  as a general catch-up service.
- **Node `RecoveryRequired` or failed recovery:** the existing owner gates all new admission,
  preparation, signing, commitment, authoritative queries/pool inspection and export. No new
  committed-block output or included cleanup occurs. Explicit `recover` invalidates pending
  preparations before auditing, even if recovery fails. Only successful audited recovery and exact
  selected-prefix checks permit reconciliation of the local pool/status. Recovery reports
  `new_commit=false`; reference/export is not a new receipt.

The CLI's later reconcile/replay operations reopen existing stores through full audits/barriers;
they never initialize missing node databases. Live operator sessions can request `recover`
explicitly. The controller never automatically retries a rejected/uncertain command, replaces a
selection, re-signs a selected request or fixes SQLite data/journals. Its 30-second response watchdog
stops the operation rather than selecting a miss block; unresolved commands may already be durable.
Pipes retain S1's bounded synchronous backpressure and partial-input behavior.

Pool reconciliation after explicit successful recovery derives membership/nonces from confirmed
canonical data. It is not a retroactive acknowledgement. Volatile pool entries are not restored on
restart; the operator explicitly supplies original native transactions again if still wanted.

## Verification Performed

Actual debug and release commands completed:

```bash
cargo test --lib worker_s2 -- --nocapture
cargo test --release --lib worker_s2 -- --nocapture
cargo test --example testnet_fixture_node --example testnet_fixture_producer
cargo test --release --example testnet_fixture_node --example testnet_fixture_producer
cargo build --example testnet_fixture_node --example testnet_fixture_producer
cargo build --release --example testnet_fixture_node --example testnet_fixture_producer
python3 -B scripts/test_testnet_fixture_producer.py target/debug/examples/testnet_fixture_node target/debug/examples/testnet_fixture_producer
python3 -B scripts/test_testnet_fixture_producer.py target/release/examples/testnet_fixture_node target/release/examples/testnet_fixture_producer
python3 -B scripts/test_testnet_fixture_worker.py target/debug/examples/testnet_fixture_node
python3 -B scripts/test_testnet_fixture_worker.py target/release/examples/testnet_fixture_node
```

**Seven focused library tests passed per mode**: four new S2 orchestration/counter cases plus three
same-source S1 profile/framing regressions. The same example worker code is compiled into the
library's test build using a test-only crate alias; actual native-authentication, body-entry/stage,
producer-recovery and signing API entry counters are used, not worker-declared flags. All counter
instrumentation is absent from production builds.

Normal successful pipeline evidence, with n admitted/selected transactions (tested n=0 and 2):

| Boundary | Native `authenticate` calls | Native body stages / entry auth, execution | Producer authentications | Signing calls |
|---|---:|---|---:|---:|
| After admission | n | 0 / (0,0) | 0 | 0 |
| After Prepare/Propose | 2n | 1 / (n,n) | 0 | 1 |
| After repeated Prepare/Propose | 2n | 1 / (n,n) | 0 | 1 |
| After seal/confirmed commit | 2n | 1 / (n,n) | 1 | 1 |

The first n calls are **pool admission**, the second n inclusion. Empty inclusion still calls the
body stage once. Successful commitment repeats neither phase. Recovery/reopen historical audits
are separate required work. Tests also prove selected-but-unsigned preparations cannot trigger new
signing; generation refresh invalidates preparation; explicit original replay uses one received
stage; actual durable-but-unpublished failure blocks further cryptographic/application/output work
until successful recovery. Failed recovery stays blocked, and present recovery produces no new receipt.

**Twelve separate-process S2 tests passed per mode** against actual executables, including:

- Empty, single and ordered multi-transaction production/replay, full state/accounting/body/Tip/S/
  E-ID/index equivalence and byte-for-byte original exports. Independent wire/hash/arithmetic oracles
  check all membership positions and final balances/nonces (Alice/Bob/Carol 999,940,000 / 10,000 /
  10,000 quarks, nonces 3/1/0, gas 4,000, burns 40,000 in the composed trial).
- 128-entry capacity, authenticated ID deduplication, sender/nonce alternatives, no admission-side
  canonical changes, 16-entry deterministic selection independent of arrival order, exact cleanup
  only after commit, gaps/maturity/unfunded/self-credit holds and invalid admission.
- Wrong approvals, immutable loaded-prefix replacement rejection, stale preparations, no accidental
  received-path restaging of a live producer candidate, and original-request replay after invalidation.
- Durable controller selection before authorization, controller restart, observed-retention versus
  missing request, lost commit-response payload, explicit replay and no new signing/duplicate effects.
- Injected controller file-fsync and directory-fsync failures: no producer/follower authorization
  delivered; complete originals can be validated/resynced and replayed, never re-signed. Corrupt
  originals and concurrent controller ownership fail closed.
- Actual SQL abort/failed audit confirmation using a test-only external trigger, blocking pool/
  signing/preparation/commit/export and follower-authority release. After removing interference,
  explicit absent-attempt recovery preserves the pool and permits original replay/cleanup.
- Private-file permission/key mismatch rejection and an ephemeral key excluded from public artifacts,
  status and actual `/proc` argv. All actual controller CLI modes are exercised.

**All ten S1 separate-process tests still pass in both modes**, and each example's three unit tests
pass. Existing full `cargo test` passed **180 tests** (136 library + 44 binary); release library
**136 passed**, 12 ignored benchmark/controlled-child entries. Existing UDP HIST/BLOCK rejection
remains exercised. Independent native/block/producer-auth/S1 profile vector checkers passed; all
630 original profile-genesis bytes remain unchanged. `cargo fmt --check`,
`cargo clippy --all-targets --all-features` and tracked/new-file whitespace checks passed; Clippy
reports only existing prototype warnings. Local logs are under `target/s2-*`.

Process death/SIGKILL retains OS/device caches and is **not power loss**. SQL test interference is
selected engine/control uncertainty, not a new VFS sweep. Injecting Python fsync error returns
tests controller ordering/error behavior, not loss of volatile filesystem data. Existing archive
power-model evidence is not relabeled as new S2 evidence. No throughput, heap-cap, capacity/deadline
or production anti-equivocation claim follows from these bounded tests.

## S2 Stopping Boundary

S2 ends with trusted local production, durable selected-original authority and producer/follower
replay across independent processes. Profiles/approvals remain independent caller authority, not
claims discovered from incoming packets. General peer catch-up, sockets, automated scheduling,
PoAsh selection/miss/collision/finality/economics, migrations and prototype activation remain outside
this implementation. Local plans/handoffs and user package-version changes are preserved separately.
The initial S2 implementation delivery was unstaged for review, without commit or push.
