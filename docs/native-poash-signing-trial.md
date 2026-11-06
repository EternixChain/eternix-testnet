# P2.3 — Durable Fenced Signing and Finite C1 Processes

This delivers the approved C1 signing boundary **before** integrating an isolated two-validator plus
observer experiment. It uses the unchanged [P2.1 genesis/eligibility](native-poash-eligibility.md) and
[P2.2 complete application/schema4 owner](native-poash-application-storage.md). C1 still stops at200
logical validator successors, at most16 primitive native entries each. D5–D9 remain deferred.

## Signing Authority and Fence Scope

`native_poash::signing::SigningAuthority` owns one configured producer key and a separate protection
store. Every participating local archive for the **same network/full key must use the same explicit
shared protection root**. There is no archive-specific signing-root default.

The root is canonicalized. Both filenames derive from:

```text
stem = lowercase_hex(N32) || "-" || lowercase_hex(compressed_public_key33)
fence = stem || ".lock"
protection = stem || ".sqlite"
```

Before opening/creating protection, an exclusive OS `File::try_lock` is acquired on the fence file.
Its open handle is retained through normal operation, poison and recovery, and is never unlinked.
Changing archive directory, validator label or profile cannot create another slot namespace under
that root. Validator/profile identity is checked content, not an additional fence discriminator.
The separate archive `process.lock` prevents two runtime owners of one archive; it is **not** the
key-wide fence. The distinct two configured keys can coexist under the same shared root.

**D4 limits:** locks are advisory/cooperative and scoped to the configured shared local root. Honest
participating software must use it and must not replace/unlink live fence files. An operator-created
key clone, independently provisioned replacement/alternate protection root, signing-store copy or
rollback, malicious/key-compromised signer, hostile filesystem/host, or another unconfigured signing
program invalidates this single-authority premise. This is not hardware/external monotonic fencing,
distributed key custody or rollback-resistant production anti-equivocation. Canonical archive
absence/rollback alone never releases retained signing protection.

The key is supplied externally as a private regular32-byte binary file in the example runtime,
matched against the full independent compressed genesis key. It is held in a non-cloneable authority
without Debug/Serialize/key-export APIs; input bytes use zeroizing storage. No secret is stored in
the journal, genesis, account state, peer frame, response or diagnostic. Public small-integer test
inputs are provisioned only by the finite test harness, not executable defaults or deployment keys.

## Actual Signing APIs

| API | Contract |
|---|---|
| `SigningAuthority::create(root,&genesis,producer,key,&owner)` | Acquire network/key fence, exclusively create fresh protection only against independent canonical slot0; never backfill already-signed history |
| `SigningAuthority::reopen(...)` | Acquire same fence, no-create exact schema/identity/attribution audit, reconcile with independently audited owner, establish dirty-page barrier before availability |
| `sign_prepared(&owner,&PreparedBlock)` | Accept only a real privately constructed owner preparation; check generation/full RAM and exact persisted canonical dataset, own historical selection/base, then reserve → sign → retain/sync original → return |
| `Original::{bytes,envelope_id,timings}` | Exact durable original/private-proposal value, not canonical commitment or publication permission |
| `original(&owner,slot)` | Return retained original after owner/context reconciliation, without signing or native staging; used after canonical advancement/lost replies |
| `check_application(&owner,slot,&StagedBlock)` | Compare exact retained E and expected compound candidate ID before a separately staged explicit original application; no new crypto/execution |
| `recover(&owner)` | Poison first; no-create reopen, full protection audit, exact last journal-attempt reconciliation, owner reconciliation and dirty-page synchronization; then install. No signing/application/publication/release |
| `status(&owner)` | Read-only committed/pending/incomplete slot classification after owner-generation/context checks |
| `is_ready`, `producer`, `signing_calls` | Diagnostics, never signing or canonical permission. `signing_calls` counts process-local protected prehash helper calls; reopen starts at0, rare backend nonce retries are internal |

`is_ready` describes synchronized protection availability. A retained **incomplete** reservation still
blocks all new signing and cannot be completed/released by recovery, even if no signature escaped.
The process runtime separately marks such work halted.

The owner exposes only crate-private signing checks/history derivation. They reconstruct Start(s)
from its own audited originals, never caller snapshots or `AdmissionPlan`s. A supplied preparation
from another owner/generation is rejected before reservation/signing. Exact SQL-base comparison is
inside a consistent read transaction and includes complete state, original evidence and indexes.
Canonical commitment retains its own locked exact-base comparison/CAS; no cross-file atomicity is
claimed between those checks and subsequent signing/commitment.

## Synchronization Ordering and Crash States

```text
owner-derived selection + once-staged native/compound preparation
  → EXTRA reservation COMMIT + database/directory sync
  → vetted secp256k1/Keccak prehash signing
  → EXTRA original-E/S/E-ID COMMIT + database/directory sync
  → private Original response is permitted
  → owner seal: one producer authentication, move prepared effects
  → canonical schema4 atomic COMMIT/install
  → committed-block publication / original-envelope serving
```

The original is never returned before its full synchronization, including a private proposal return.
The vetted signing primitive is factored into a crate-private helper shared with existing fixture
authentication; old public profile2/auth1 semantics and all old goldens are preserved. No new curve
arithmetic, domain mapping or signature normalization is introduced.

| Durable protection | Canonical state | Allowed result |
|---|---|---|
| No reservation; failed reservation attempt confirmed exactly absent | Exact old base | No signature was called before confirmed reservation synchronization; explicit new work may be requested after recovery |
| Reservation only | Exact still-absent successor | **Incomplete/fenced** forever through this API; no same-H retry, different-H signing, completion, release or auto-application |
| Complete original | Exact authorized old base | Pending original; explicit `apply_original` may stage/apply that same E, never create another signature |
| Complete original | Exact canonical original/candidate present | Return/reference/export that original, without another signature or economic effect |
| Any row | Different base/branch/content/S/E-ID/candidate or missing required history | Fail reconciliation and block affected work; never repair/replace or choose a newer peer tip |

Every post-reservation failure poisons the signing authority and withholds originals until explicit
successful recovery. Its in-memory journal attempt retains complete before/after maps, so uncertain
presence requires exact equality, not a matching row count/H. A failed original transaction reconciled
absent returns to the still-durable incomplete reservation, **not** to permission to re-sign.

Recovery checks every reserved slot's owner-derived historical base/selection, exact finalized inner
content and original. Every canonical own-key block must already have matching protection; no fresh
protection backfill is allowed. Present canonical originals must also match the retained compound
candidate ID. For a pending original, explicit staging derives the candidate and `check_application`
compares that ID before canonical commitment. Required ancestors/prefixes cannot come from peers'
snapshots. A restored archive behind the reservation's required parent remains blocked until its
actual audited prefix is independently restored, for example through an explicit keyless catch-up.

Canonical and signer recovery are **separate** operations: recover/audit/synchronize the canonical
owner first, then explicitly recover/reconcile/synchronize signing protection against that owner.
Owner recovery invalidates preparation generations and the signer's prior owner-generation binding.
The process hides canonical queries/export/new work during recovery uncertainty. Successful recovery
does not invent a previously delivered receipt, publish, apply pending originals, sign or restart
pacing/catch-up. A diagnostic selected-key conflict halt is not cleared by recovery.

## Exact Local Signing Formats

All integers are unsigned big-endian; text is BE16 byte length plus exact ASCII. Local schema1,
mode `c1-signing-authority`, is unrelated to canonical schema4 and is outside consensus genesis.

The **119-byte authority identity** is:

```text
b"ETERNIX_C1_SIGN_AUTHORITY\0"[26]
|| BE32(local_identity_encoding1) || N32
|| BE32(PoAsh_rules1) || BE32(header_profile3)
|| inner4:u8 || outer4:u8 || auth_encoding1:u8 || BE32(auth_rules2)
|| public_key33 || BE16(7) || exact producer7
```

### Reservation encoding1

For the independent empty slot1 control the reservation is **652 bytes**; general length is
`357 + inner_length`, at most3,900 for C1. Decoder/storage bound4,055 does not broaden the strict
inner/profile/count constraints.

| Half-open offset | Exact field |
|---|---|
| 0..28 | `b"ETERNIX_C1_SIGN_RESERVATION\0"` |
| 28..32 | BE32(reservation encoding1) |
| 32..64 | N32 |
| 64..68 / 68..72 | BE32(PoAsh_rules1) / BE32(header_profile3) |
| 72..75 / 75..79 | inner4 / outer4 / auth1 as three u8; BE32(auth_rules2) |
| 79..112 | Full compressed key33 |
| 112..121 | BE16(7) and producer7 |
| 121..129 | BE64(exact signing slot) |
| 129..161 / 161..193 | Exact H32 / parent H32 |
| 193..225 | Complete supported base-state ID32 |
| 225..257 / 257..289 | Historical header-prefix ID32 / SlotStartView ID32 |
| 289..321 | Exact original-evidence base comparison ID32 |
| 321..353 | Expected complete compound candidate state ID32 |
| 353..357 / 357..end | BE32(inner length) / exact finalized unsigned inner4 block |

Base state/prefix/view IDs retain P2.1's exact definitions. The additional local evidence pin is:

```text
Keccak256(b"ETERNIX_C1_SIGN_BASE_EVIDENCE\0" || N32 || BE16(prior_produced_count)
          || original_E_ID_at_slot1 || ... || original_E_ID_at_parent)
```

These comparison IDs bind complete base state and original history under collision resistance;
they are not signed checkpoints, header roots or another account ledger. Full finalized inner content
and candidate ID pin subsequent explicit application. Producer S stays outside H and lottery inputs.

### Exact SQLite closure

Exact DDL/triggers are in `src/native_poash/signing/journal.rs`; schema object maps, integrity and
foreign-key checks must match. No create-or-open, migration, repair or reservation deletion exists.

| Table, stored column order | Width/type |
|---|---|
| `metadata(id,version,mode,identity,barrier)` | INTEGER singleton1; BLOB4=`00000001`; TEXT exact mode; BLOB1..256 (identity119); BE64 BLOB8 |
| `reservations(slot,reservation)` | BE64 BLOB8 nonzero primary key; bounded BLOB295..4055 (strict codec imposes actual652..3900); WITHOUT ROWID |
| `originals(slot,envelope,signature,envelope_id)` | BE64 BLOB8 primary key/FK→reservations; exact outer4 BLOB402..3650; original S BLOB65; original E-ID BLOB32 unique; WITHOUT ROWID |

Reservations/originals have immutable UPDATE/DELETE and explicit INSERT replacement guards. Metadata
identity cannot be replaced/deleted/changed; only the non-consensus barrier advances. Every load
reconstructs the envelope, compares reserved content, redundant S/E-ID, independent network/key and
canonical signature attribution. Runtime persisted-base comparisons repeat neither producer crypto
nor native staging. Every reopen/recovery dirties/increments the barrier under a write lock, verifies
the exact dataset, EXTRA commits and synchronizes file/directory before publishing availability.
All connections enforce DELETE/EXTRA/foreign_keys/default cache−2000/default spill.

## Isolated Process and Peer3 Boundary

`examples/native_poash_node.rs` invokes `native_poash::trial::run` with **one explicit strict JSON
configuration file**. It is separate from the prototype and every M1 executable. Config includes
`id`, existing `archive` directory, independent raw `genesis` file, `mode` (`create`/`reopen`), loopback
`listen`, up to two explicit `{id,address}` peers, optional `producer` and optional `body_plan`.
Producer configuration requires `{id,key_file,authority_root,mode}`. Observer/keyless serving uses
`producer:null`, `body_plan:null`. There is no implicit signing root or key. Producer body plans
contain exactly200 explicit arrays of ≤16 opaque199-byte signed native hex inputs; file bound2MB.
They are finite workload input, not approvals, grants or cached authentication results.

Local trusted operator I/O is BE32 JSON length plus exact JSON, bounded65,536 bytes both directions.
Unknown/duplicate fields fail; empty commands are structs rather than permissive unit variants.

| Command | Actual behavior |
|---|---|
| `status` | Ready canonical/economic summary, next locally selected producer/ticket, protection diagnostics and process-local signing-call count |
| `advance {slot}` | Exact successor guard only; no desired producer/ticket/H parameter. Locally non-selected producer returns `not_selected` without native/economic/signing effects; selected producer prepares/protects/seals/commits then publishes |
| Repeated `advance` for own committed slot | Return exact retained committed original without another signing call or application; does not infer new progress |
| `apply_original {slot}` | Explicitly stage/check/apply an exact pending original, then publish only after confirmed canonical commitment; never create/sign implicitly |
| `publish {slot}` | Explicit retransmission of an already canonical retained original; receiver still authenticates duplicates |
| `catchup {source,target_slot,target_hash}` | Explicit configured source/target request; sequentially retrieve originals and run ordinary owner admission/application. Target is an operator checkpoint observation, not per-block authority or proof of latest/finality |
| `recover` | Separate canonical then protection audit/reconciliation/barriers; no automatic application/signing/publication/pacing/catch-up |
| `export {slot}` | Original canonical E only; no signed anchor export |
| `state {offset,length}` | Complete supported canonical payload in ≤1,024-byte pages |
| `inspect {section,offset,limit}` | Records (one per page), transaction membership or sender/nonce membership (≤16 per page) |
| `timings {offset,limit}` | ≤16 diagnostic rows; bounded last1,024 observation window, with complete finite trace captured on supervisor stderr |
| `stop` | Bounded cooperative reply opportunity then release owners/fences on process exit |

The main thread owns ledger/key/protection and handles one bounded peer connection at a time. Two
bounded one-message operator I/O channels carry bytes/JSON only. Peer operations use one absolute
two-second request/frame I/O bound, not a per-byte refreshed timeout. It is an **operational bound**,
not PoAsh execution/publication timing or an absence proof. No autonomous missed-leader outcome,
collision block, penalty or pacing timer exists. Failure to obtain the selected producer halts the
finite supervisor at its current prefix. Partial publication or explicit catch-up failure halts
affected progress for diagnosis; no zero-effect fallback or automatic retry is manufactured.

Only canonical commitment permits a new publication. Receivers use the schema4 owner's own audited
prefix/selection and ordinary once-staged compound path. A configured signing node refuses unknown
own-key incoming originals absent/different in its protection; known-H references still require
producer authentication. Invalid/non-selected packets do not acquire conflict-halt authority. A
diagnostic inspection ring cannot be exhausted by such traffic to manufacture a consensus halt.

### Exact peer3 framing

Header is128 bytes; maximum frame is3,778 bytes (128+3,650). All reserved bytes must be zero:

| Offsets | Field |
|---|---|
| 0..8 / 8..9 / 9..10 | `b"ETXC1P3\0"`, version3:u8, kind:u8 |
| 10..12 | zero2 |
| 12..16 / 16..20 / 20..24 | BE32(header_profile3/auth_rules2/PoAsh_rules1) |
| 24..32 / 32..64 | BE64(chain1162), N32 |
| 64..72 / 72..76 | nonzero BE64(request ID), BE32(exact body length) |
| 76..128 | zero52 |

Kinds:1 Status(empty),2 Tip(slot8/H32/local-comparison-digest32),3 Push(original E402..3650),4 Get
(BE64 slot1..200),5 Envelope(original E),6 Ack(slot8/H32/retained-E-ID32/new-commit flag0/1),7 Reject
(one byte1..4: unavailable/halted/invalid/reserved diagnostic). Responses must match request correlation.
Peer declarations bind routing/context, not key authority or canonical validity. Body bounds are
checked before allocation. M1 peer1/peer2 and their144-byte frames/goldens are unchanged.

The Tip digest is a **local comparison**, not an importable checkpoint: Keccak under
`b"ETERNIX_C1_PROCESS_SNAPSHOT\0"` over N, BE32 state length/state bytes, BE16 record count, each
BE32 E length/E/state-ID32, BE32 native-index count and sorted ID32/slot8/H32/index8, then BE32
sender-nonce-index count and sorted address20/nonce8/slot8/H32/index8. The acceptance path does not
trust this digest or a peer's claimed height as permission. Full comparison below reads actual pages.

## New Verification Evidence

Independent `scripts/reproduce_native_poash_signing.py` uses explicit Python packing/OpenSSL Keccak
and the independently reproduced public P2.1/P2.2 inputs, never Rust/SQLite encoders. It freezes the
119-byte identity,652-byte reservation, complete base/candidate IDs and seven exact peer frames in
`tests/fixtures/native_poash_signing.json`. Mutations/truncations, stale/foreign preparations, wrong
network/key, permanent incomplete rows, retained-repeat counts, failed recovery and actual runtime
handlers are checked in debug/release. Producer/receiver function-entry counters prove one native
inclusion stage and one producer authentication per successful append, with neither repeated by
commit; historical audit work is measured separately.

### Real I/O failures

New signing traces enumerate32 write/sync/delete callbacks for a populated reservation+original
request and14 for protection recovery. Actual SQLite VFS FULL/write/fsync/delete injections cover
**56+24=80 cases**, withholding signatures on every failed/uncertain request and blocking until explicit
recovery. Additional persistent cases cover canonical COMMIT fsync uncertainty, failed signer dirty
barrier and the requirement for two explicit recoveries. These are actual VFS faults, not semantic
hooks labeled as disk failures. Existing P2.2 storage evidence remains separate compatibility coverage.

### Process termination and lost replies

**17 new controlled signing/owner child handshakes** cover before reservation, reservation write/
COMMIT/sync, before/after signature creation, original write/COMMIT/sync, before private response,
canonical pre-BEGIN/post-COMMIT/post-install, publication gap and lost committed reply. Reopen
requires absent, fenced-incomplete, exact pending original or exact committed original as appropriate;
it never signs a replacement. A competing child using another archive is rejected by the same
network/key OS fence. These are SIGKILL tests, **not power-loss certification**.

The finite executable trial additionally leaves the slot65 operator reply unread, captures the
operation's diagnostic timing, SIGKILLs that actual producer process, reopens both stores and repeats
the request. It returns the retained original with **zero signing calls after restart**, and full
state/evidence equality proves no duplicate native/economic effects.

### Declared-model power loss

All32 new reservation/original I/O cuts run under each of two stable-image models: discard unsynced
writes, with/without early persistence of the first512-byte sector of one unsynced database write.
Each model yields14 absent reservations and18 permanently fenced incomplete reservations. No
signature response is permitted at those cuts. A separate captured image after an exposed private
original preserves the exact original on reopen without signing. These **64 cuts plus the exposed-
original retention control** use the declared VFS model, not arbitrary disk reordering, signing-store
rollback, malicious filesystem edits or physical device power-loss testing.

## Completed Finite Process Trial

Reviewed run: `target/c1-p23-review-20261106/report.json`, with every raw process stderr trace and
framed-run configuration retained in that ignored directory. The independent oracle observes E
**after** commitment/publication, then checks exact header/body commitments, producer signature and
state-derived selection, applies native monetary effects separately, and compares the complete
supported snapshot bytes/records/indexes. It never supplies H/E-ID approvals or imported state.

| Item | Observed result |
|---|---|
| Fresh run ID | `c1-p23-review-20261106` |
| Network N | `aab3b57f6f6b16e4adbc9bf6e89be77a0f0698136473c722fcd57ca6561028d9` |
| Successors / native entries | **200 /3,120**, at most16 entries per body |
| Explicit empty rewarded slots | 1,32,64,128,200 |
| Selected participation | trial-A104, trial-B96 |
| Cumulative actual gas / ETX fees | 3,120,000 /31,200,000 quarks |
| Base issuance / total held credits | 2,000,000,000 quarks /200 earning credits |
| Locked A / B | 1,040,000,000 /960,000,000 quarks; total locked equals base issuance |
| Final supply | 1,752,001,968,800,000 quarks |
| Retained year-zero reward | 10,000,000 quarks, unchanged across recovery/reopen |
| Final H | `0aefe157815b98c23d73f80c8899c1c7d9411a97a8efaadbbb15895aa4ce3b31` |
| Complete state ID | `0fee47e678d0fe9314ab5f924b7c77ae079f98247a72ccfce46da22b0e4f9e19` |

Both validators and observer agree on full canonical payload bytes (including vaults/locks/credits/
year metadata), every record's exact E/S/E-ID/outcome/post-state ID, all native and sender/nonce
memberships, accounting and tips. All three close/reopen at64, explicitly recover without automatic
actions and compare the entire projection again. Slot65 exercises the unread-reply kill/restart.
All three close/reopen and compare again at200. Requests for201 fail without effects or signing.

Before progress, stopping the selected producer leaves the other validator's request `not_selected`
and both remaining prefixes at0; no missed/collision result is invented. A separate archive's attempt
to start the same signer is excluded. Independently signed **test-only adversarial non-selected**
claims are rejected by all processes with no canonical/native/economic projection change; actual
receiver counter tests separately prove authentication-before-rejection and zero native staging.
These public-toy-key negative fixtures are not an alternative runtime signing path.

After the final comparison both validator signing processes are confirmed stopped. The retained
observer serves originals; the former validator archive also reopens in **keyless serving mode**
with identical full state. A fresh genesis-only receiver catches up200 sequential originals, compares
every supported state/evidence/index field, then closes/reopens and compares again while both
producer signing services remain stopped. Observed fresh catch-up roundtrip: **38.671087353 seconds**.

## Timing Boundaries, Outliers and Method

Release Rust1.98.0/LLVM22.1.8 on Linux7.2.7, AMD Ryzen9 9950X (16 cores/32 logical CPUs), file-backed
ext4 workload storage. SQLite uses DELETE/EXTRA/default cache−2000/default spill and explicit
protection path/directory sync; no durability relaxation, cache dropping, CPU affinity or capacity
sweep. k256/Keccak and the existing pinned rusqlite/bundled SQLite backend are reused.

Every complete finite timing row is captured on supervisor stderr and retained in `report.json`
(1,029 rows), with process/generation filename, slot, action, success and raw nanoseconds. The bounded
operator window is only an inspection convenience. The report retains **all** observations and
maximum locations, not a filtered average. It asserts200 protected signing spans,17 owner spans
(4 creates,10 reopens,3 explicit recoveries), and10 signer spans (2 creates,6 reopens,2 recoveries).

The first complete200-slot run captured live phases but omitted startup recovery spans from the
supervisor trace. Capture was corrected and the **same finite workload** rerun with a fresh run ID;
only the corrected reviewed run supplies the table below. No consensus rule or timing deadline
was changed. This was an instrumentation correction, not a capacity/performance matrix.

| Included span | Samples | Median ms | Maximum ms | Maximum location |
|---|---:|---:|---:|---|
| Initial owner selection/view | 401 | 0.238828 | 0.603905 | A slot154 |
| Native/compound producer preparation | 200 | 2.293078 | 3.284135 | A slot179 |
| Full signer base/history validation | 200 | 39.380174 | 182.580516 | A slot198 |
| Reservation transaction + sync | 200 | 170.742531 | 332.480569 | A slot50 |
| Protected prehash signing helper | 200 | 0.044365 | 0.206378 | A slot65 |
| Original transaction + sync | 200 | 166.962014 | 233.411176 | B slot33 |
| Producer seal + exact application check | 200 | 37.011287 | 168.824541 | A slot198 |
| Receiver stage/reference/rejection handling | 608 | 2.797464 | 5.356689 | B slot164 |
| Canonical exact-base/SQL/EXTRA/install | 800 | 198.074737 | **1,177.587789** | A receiving slot15 |
| Post-commit publication + peer acknowledgements | 200 | 422.866414 | **1,788.373849** | B producing slot15 |
| Live frame read / catch-up Get exchange | 609 | 0.008090 | 1.239671 | fresh slot191 |
| Owner create/reopen/recovery | 17 | 292.799823 | 645.539671 | observer reopen at200 |
| Signer create/reopen/recovery | 10 | 167.012544 | 377.624747 | A reopen at200 |
| Whole-operation total, mixed action rows | 1,029 | 199.809194 | **2,369.856665** | B producing slot15 |

Selection is the explicit initial derivation; repeated required checks remain included in later
spans. Preparation includes native authentication/execution/compound effects. Seal includes producer
authentication and moving owned effects, not another native stage. Commit includes complete base,
history/index/state comparison, SQL writes, EXTRA commit and installation. Publication begins only
after canonical success and includes both receivers' work and ack waits; those spans overlap with
receiver timings and **must not be summed across processes**. Receiver totals begin after the frame
is available; live frame timing starts at accept, whereas catch-up frame timing is the complete
outbound Get/E exchange. Whole catch-up roundtrip is separately reported above. Startup/recovery
totals include full required audits/barriers; retained-year validation is not omitted as warm work.
The608 receiver-stage samples include600 successful new receiver inclusions,6 authenticated duplicate
references and2 authenticated non-selected rejections; the latter eight execute no native body stage.

The2.370-second producer-operation outlier includes post-commit publication. It is retained, not
excluded or used to relax rules. This experiment has no assigned real-time slot origin or autonomous
absence/evidence mechanism, and **establishes no execution/publication deadline, capacity, liveness
or finality guarantee**. SIGKILL/model results likewise do not certify hardware power-loss behavior.

## Commands and Completed Checks

```bash
cargo test --lib native_poash -- --nocapture
cargo test --release --lib native_poash
python3 -B scripts/reproduce_native_poash_signing.py
cargo build --release --example native_poash_node
python3 -B scripts/native_poash_process_trial.py --executable target/release/examples/native_poash_node --output target/c1-p23-review-20261106 --run-id c1-p23-review-20261106
cargo test -- --test-threads=4
cargo fmt --check
cargo clippy --all-targets
git diff --check
```

The finite harness exclusively creates its output directory; a repeat must explicitly choose a new
output/run ID, never erase/reset protection. It writes only public test keys to external private
runtime input files. To run an independently provisioned node, use
`cargo run --release --example native_poash_node -- CONFIG.json` and the exact framed commands above.
The reviewed configurations and opaque workload are retained beside the report; no approval file
is generated. Artifacts and keys remain ignored local outputs, not source fixtures.

Completed verification: **49 focused C1 tests passed per mode**,2 controlled children ignored by
default and exercised by their parents. This includes18 new passing P2.3 tests. Full compatibility:
**238 passed** (194 library +44 binary),15 ignored benchmark/controlled-child entries; the full library
run completed in300.86 seconds. All **nine independent checkers** pass: native, stage4, block auth,
S1 profile, S3 transport, S4 catch-up, P2.1 eligibility, P2.2 application and new P2.3 signing/peer bytes.
Formatting, Clippy and tracked/new-file whitespace checks pass; only existing prototype Clippy
warnings remain. Old native/profile/genesis/peer fixtures and all M1 executable sources are unchanged.
The only old authentication implementation change extracts the unchanged vetted prehash primitive
into a crate-private shared helper; old golden/phase/entropy/retry tests pass unchanged.

No concrete consensus-contract gap required a semantic change. Signing storage is not account state,
protection availability is not commit authority, and peer timing/status is not consensus evidence.
D5–D9, timed miss/collision progression, membership/lifecycle/PBM, boundary settlement, finality/reorgs,
prototype activation and public deployment remain outside this deliverable. **Stop for P2.3 review.**
