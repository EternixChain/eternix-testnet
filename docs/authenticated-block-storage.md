# Offline Authenticated Block Archive — Schema 3

`src/authenticated_fixture.rs` implements a **fresh, separate offline archive** whose canonical
SQLite transaction includes producer evidence and all native block effects. Reopening reconstructs
the originally retained signed envelopes from compact SQL constituents and authenticates every
appended producer under independently supplied policy, then audits native history from the trusted
post-anchor seeds. The live node does not use this owner.

Local storage schema 3 and mode `offline-authenticated-native-blocks` are independent of signed
outer wire 3, auth encoding/rules 1, and existing native wire/header profile 2. Schema-1/schema-2
files and production behavior remain separate; opening an incompatible schema fails without conversion.

## Independent Policy and Record Kinds

`AuthenticatedFixtureManifest::new(fixture, auth_context, bindings)` requires:

- The complete trusted `canonical_fixture::FixtureManifest`: exact native context, unsigned empty
  anchor, complete post-anchor accounts/nonces/gas/burn baseline, and provenance.
- A matching explicit `BlockAuthenticationContext`.
- A nonempty static set of exact producer IDs and canonical compressed public keys. Duplicate IDs
  and key aliases are rejected. Names retain their raw UTF-8 bytes and deterministic ordering.

Creation, reopen and recovery receive this policy independently. Stored declarations must match
field for field, including unused configured bindings; a file cannot authorize its own changed keys,
network, anchor or seeds. Signatures do not authenticate the initialization manifest or supplied state.
There is no key discovery, registration, rotation, eligibility or consensus-selection mechanism here.

Revision zero is an explicit `ArchiveRecord::TrustedAnchor`: the supplied unsigned empty checkpoint
and post-anchor state, never replayed or promoted into authenticated history. Its proposer need not
be an appended-history binding. All positive revisions are `AuthenticatedAppend`, with immutable
producer proof and the checked native outcome. The anchor has no signed-envelope export.

## Compact Durable Representation and Frozen Cryptography

The schema is in `src/authenticated_fixture/schema.rs`. It preserves the original block/body/native
transaction/index/tip relationships and adds:

| Location | Stored additions |
|---|---|
| `metadata` | BE32(3) schema, new mode, fixed outer/auth descriptors, BE64 producer count |
| `producer_bindings` | Exact UTF-8 producer BLOB, canonical 33-byte key; unique names and keys |
| Every positive-revision `blocks` row | Exact `producer_signature` BLOB[65], checked `signed_envelope_id` BLOB[32] |
| Revision-zero anchor | Both evidence columns NULL, required by its distinct record-kind constraint |

The logical evidence payload is **97 bytes per appended block**; SQLite page/index overhead and
static declarations are additional. No whole signed envelope, duplicate inner body, signing digest,
per-block recovered key, or persisted verification flag is stored. Existing 199-byte signed native
entries remain the sole durable transaction-body copy. SQL integer arithmetic is not used for
balances, fees, slots or revisions; existing explicit unsigned BE BLOB widths remain in force.

An in-memory appended record's `AuthenticatedProducerBlock` owns its typed inner block/body. It
also retains the original authentication proof/context/binding and evidence identities. There is
no separate cached serialized envelope; export reconstructs one on request. Full cache/attempt
cloning remains explicit work, rather than an unrelated history-ownership optimization.

Reconstruction uses the checked existing header/proposer/protocol/body constituents and S:

```text
L = 288 + proposer_byte_len + 203 * transaction_count
E = 03 || 01 || BE32(1) || trusted_network_id[32] || BE32(L)
 || exact existing native wire-2 block[L] || S[65]
E-ID = Keccak256(b"\x19ETERNIX\x00BLOCK_ENVELOPE_ID\x00" || E)
```

All framing/resource limits, canonical signature validation, domains and hash identities remain
those of [`block-authentication.md`](block-authentication.md). In particular, producer signatures
remain **outside the historical 229-byte header hash H**. Parent/tip identity remains H, not E-ID.
The existing 20-byte signing domain, 82-byte payload, 102-byte signing preimage, 27-byte E-ID domain,
secp256k1/Keccak prehash, low-s/parity-only signature representation, x=r recovery and fresh-nonce
overflow retry are unchanged. Native transaction rules, reserved roots and V1 bytes/hashes are unchanged.

Exact table/constraint/trigger definitions, SQLite integrity and foreign keys are checked on load.
Immutable triggers prohibit committed evidence/body/index/seed/key mutations and archive replacement;
initialized policy cannot change through the writer. These are application guards, not independent
authority against an adversary rewriting both data and schema offline. Bounded borrowed BLOB reads
check widths before allocation, and a LEFT JOIN exposes missing required body rows instead of hiding them.

## APIs and Once-Only Staging

| API | Meaning |
|---|---|
| `create_authenticated_fixture(path, &policy)` | Exclusive fresh-path reservation; policy/seeds/anchor/tip/marker initialize in one durable transaction |
| `reopen(path, &policy)` / `recover_existing(path, &policy)` | No CREATE; complete attribution/native audit and synchronization barrier before readiness |
| `prepare_next(producer, ticket, signed_native_body)` | One native body stage and finalized inner header; returns privately constructed non-cloneable `PreparedAuthenticatedBody` |
| `seal_prepared(prepared, exact_E, independent_grant)` | Check owner/base first, authenticate producer once, require exact prepared inner identity, move existing effects into `StagedAuthenticatedBlock` |
| `stage_received(exact_E, independent_grant)` | Signed framing/context/producer checks, append gates, one ordered native stage, checked outcome and uniqueness |
| `commit(stage)` / `commit_profiled(stage)` | Consume sealed candidate; no producer/native authentication or execution repetition on successful append |
| `recover()` | Immediately invalidate overlays; fully reload, reconcile exact known evidence/effects, synchronize, install coherent caches |
| `snapshot()` / `export_signed_envelope(revision)` | Ready-only coherent state/evidence and reconstructed exact E; no signed export for anchor |
| `settings()` / `load_timings()` / `is_ready()` | Diagnostics, never commitment or publication permission |

The producer controller signs `prepared.block()` using existing `sign_block`, then supplies the
exact envelope to sealing. Signing alone cannot commit. The receiver authenticates producer evidence
before native user application. A preliminary structural parse dispatches the exact proposer to the
independent binding map; existing authentication may repeat structural work, not producer recovery.
Native staging authenticates all entries in body order before executing any entry, preserving the
original first phase/index/cause.

Both successful producer and receiver routes perform **one producer authentication and one
`stage_body` invocation**, including empty bodies; populated bodies perform exactly N native
authentications and N executions. Successful commitment repeats none. Test-only thread-local counters
count actual empty-body invocations as well as per-entry calls; they are not protocol inputs.

There is no public unsigned admission, arbitrary effects installation, evidence attachment, raw
connection exposure, or conversion from an old schema-2 prepared/staged object. Independently supplied
fixture grants still bind context/anchor/base/content/slot; producer attribution does not establish
leader/ticket eligibility. Unchanged live HIST/BLOCK rejection does not become signed live admission.

## Atomic Writer, Duplicates and Recovery

Private base tokens retain unique owner generation, immutable full policy, complete native state,
tip and ordered `(Tip, S, E-ID)` identities. Prior body bytes are not copied again just for this
identity list. The writer prepares next cache/exact attempt before SQL and then, under BEGIN IMMEDIATE:

1. Compares independently expected declarations, stored revision, tip, complete accepted-evidence
   prefix, native state/accounting and uniqueness before any candidate write.
2. Writes changed accounts/accounting, **one block row including evidence**, one body, native entries/
   indexes, revision CAS and canonical-tip CAS in the same transaction.
3. Confirms EXTRA COMMIT, installs the complete preallocated projection, destroys old caches and
   returns success. No evidence-sidecar transaction or fallible publication allocation is added.

The prior-evidence comparison is a declared O(H) byte-read cost, not repeated historical producer
authentication. Full cache/attempt preparation still scales with retained accounts/body/indexes.
An external stored-base change is rejected before candidate writes and requires explicit refresh.

A submitted known H is authenticated before any reference result. An exact duplicate or different
legitimate low-s S for the same inner block returns `AlreadyCommitted`, exposing **retained and
submitted E-IDs**. It does not stage the native body, change retained evidence/state/tip/revision,
or permit new acknowledgement/cleanup. The **first committed evidence stays immutable**. Another H
at an occupied slot is `SlotConflict`; the unsigned checkpoint yields separate `TrustedAnchorReference`.
Conflicting-statement inspection remains the existing pure read-only authentication operation, not
a canonical replacement, offense update or anti-equivocation journal.

| Outcome | Publication boundary |
|---|---|
| `Committed` | Exact accepted evidence and all effects durably committed and coherently installed; only this permits new success/emission/cleanup |
| `Aborted` | No new committed effects; rollback failures require full old-prefix confirmation, not autocommit alone |
| `RecoveryRequired` | Evidence/effects/durability/publication unresolved; owner poisoned until explicit successful recovery |

Poison blocks state, records, evidence export, settings/timings, preparation, staging and installation.
The exact attempt retains captured base/prefix/state, original new block/body/outcome/S/E-ID and
candidate effects. Audited recovery accepts exact present (including valid descendants) or exact
absent old prefix. Another H, or the same H with different valid S/E-ID, does not establish that
attempt and remains unresolved. A Ready refresh without an attempt also preserves this owner's
already-known accepted-evidence prefix; valid descendants are allowed, substitution is not.

Reopen/recovery uses one consistent load, checks the entire independent policy/seeds/anchor/archive,
authenticates each positive-revision E once with its stored claimed E-ID, stages each suffix body
once from separate seeds, and compares final materialized state. It never executes the anchor or
replays onto loaded RAM. A writer barrier rechecks policy/revision/tip/evidence identities, advances
a real checked barrier page, confirms EXTRA COMMIT and synchronizes database/directory before Ready.
Any failed audit/reconciliation/barrier/installation stays unavailable, and all old overlays remain stale.

## Attribution Versus Original Choice, Selection and Freshness

The caller's independent context/bindings establish producer attribution of retained content.
**They do not independently pin which legitimate signature was originally accepted.** H excludes S,
and E-ID is an unkeyed hash in the same database. A database adversary possessing another legitimate
signature can replace both S/E-ID consistently and preserve valid attribution on a fresh unpinned
loader. A valid different selected prefix, fork or older archive also needs independent selection/
freshness authority.

Application immutability, known prefix/exact-attempt comparisons and independent original-packet/
acknowledged-prefix test oracles enforce the bounded retention contract. Tests honestly distinguish
S-only substitution (E-ID mismatch), consistent S/E-ID substitution accepted by fresh attribution,
and rejection by the original attempt or known-prefix owner. Stronger adversarial exact-choice/
selection/freshness claims require caller-trusted pins; no stored checksum or new signing domain
provides that authority. Signing remains stateless and abort does not revoke an already-made signature.

## Executed Correctness and Distinct Persistence Evidence

`src/authenticated_fixture/tests.rs` and `tests/storage_evidence.rs` add **23 active tests** plus
two parent-controlled ignored child entries and one ignored release measurement entry. Tests cover
separate producer/receiver files, two producer bindings, unsigned anchor separation, signed-only
admission, native ordering, once-only empty/populated/3,000-entry staging/commit, exact exported bytes,
duplicates/alternate S, stale/foreign owner/preparation, external revision and valid append changes,
SQL immutability, corrupt/missing/mis-sized/swapped evidence and canonical fields, wrong independent
policy, consistently re-signed attacker key replacement, exact present/absent/descendant/different
content/evidence attempts, all poison gates and failed recovery transitions, and unsigned field maxima.

The committed independent `single`/`empty` signed goldens reconstruct byte-for-byte after SQL reopen,
with exactly 194 logical evidence bytes. Existing crypto/native/V1 goldens are preserved. Wider crypto,
UTF-8, signature canonicality and malformed-wire tests continue to exercise the reused primitives.

### New Schema-3 Real SQLite Fault Traces

These operation counts are newly enumerated, not inherited schema-2 evidence. Each nth case uses a
fresh fixture and exact prior evidence/effects oracle. After fault reset, explicit full recovery returns
the old complete prefix; uncertain owners hide evidence throughout.

| Trace | Newly enumerated I/O cases | Confirmed abort | RecoveryRequired / blocked recovery |
|---|---:|---:|---:|
| Initialization | 50 | 2 | 48 |
| Empty append | 88 | 56 | 32 |
| Populated append | 128 | 86 | 42 |
| Recovery barrier | 24 | 0 | 24 |
| **Total** | **290** | **144** | **146** |

Actual callback errors include xWrite FULL/IOERR_WRITE, xSync IOERR_FSYNC and xDelete IOERR_DELETE.
Additional cases inject real xOpen CANTOPEN and default-budget spilled initialization rollback
xTruncate IOERR_TRUNCATE. Two isolated allocation children use SQLite's hard heap limit of 1 byte,
at pre-BEGIN and post-evidence boundaries: both encounter actual NOMEM/extended code 7 and require
recovery before exact old-prefix readiness. Clearing the cap precedes recovery; Rust heap allocation
is not capped. A development allowance of `memory_used()+512` succeeded and failed its test, then was
corrected; it is not allocation-failure evidence. These are selected engine outcomes, not exhaustive OOM.

Small trace/process/allocator fixtures use real SQLite files in the host's `/tmp` tmpfs. They prove
selected engine/control behavior, not rotational-device latency or physical loss. The large-history
spill/restoration stress is performed on the same real disk parent as the matched experiment.

That separate A=1,000/H=100/T=100,000/N=3,000 stress passed with **5,907 actual cache spills** at
cache_size=-2000 and real database writes. Its journal was **17,182,216 bytes** at the post-index/
pre-rollback boundary. A sticky actual rollback xWrite IOERR_WRITE (extended code 778) prevented
confirmation and yielded RecoveryRequired; after resetting the fault, fully audited synchronized
recovery returned the exact old evidence/effects with `attempted_present=Some(false)`. This journal
observation is not a measured primary-sample peak, and the stress is excluded from performance totals.

### Handshake SIGKILL

**76 parent-controlled kills** passed with A=50,000, unchanged default cache and exact state/archive/
evidence oracles: 19 initialization, 16 each empty/populated/3,000-entry append, and 9 recovery cases.
Locations include actual journal/database write/sync/delete callbacks, block+evidence/body/index/
revision/tip SQL boundaries, pre/post actual COMMIT, installation/acknowledgement gap, and recovery
open/validation/barrier/installation. Post-COMMIT outcomes retain exact new evidence/effects; earlier
append cuts retain exact old evidence/effects. Interrupted initialization remains unusable or complete.
Recovery cuts preserve the entire acknowledged prefix. SIGKILL preserves OS/device caches and is not
power loss; no physical durability certification follows.

### Declared Power Model

The existing stable-image model was retraced for schema 3: **306 cuts**, across volatile-loss and
first-512-byte unsynced database-sector-prefix variants:

| Trace | Cuts per variant | Observed complete old / new / uninitialized per variant |
|---|---:|---|
| Initialization | 27 | 0 / 0 / 27 |
| Empty append | 46 | 46 / 0 / 0 |
| Populated append | 66 | 66 / 0 / 0 |
| Recovery | 14 | 14 / 0 / 0 |

Two additional acknowledged/durable-unpublished stable-image cases retain the exact new evidence/
effects. Every append trace begins with two acknowledged exact signed blocks. The model installs
only captured synchronized images after connection closure, discarding volatile writes independently
of SQLite cleanup. Assumptions include successful synchronization, modeled directory ordering and
surviving reserved entries. The single sector-prefix variant is not arbitrary torn/reordered hardware
write coverage, and the absence of new prefixes at pre-callback cuts is not a universal absent-attempt rule.

## Final Checks and Reproduction

Commands completed successfully:

```bash
cargo test
cargo test --release --lib
cargo test --release --lib authenticated_fixture -- --skip matched_archive_measurements --nocapture
cargo fmt --check
cargo clippy --all-targets --all-features
python3 -B scripts/reproduce_native_auth_vectors.py
python3 -B scripts/reproduce_stage4_vectors.py
python3 -B scripts/reproduce_block_auth_vectors.py
cargo run --example authenticated_fixture_replay -- target
cargo run --release --example authenticated_fixture_replay -- target
cargo run --example native_transfer_replay
cargo run --release --example native_transfer_replay
cargo run --example stage4_canonical_replay -- target
cargo run --release --example stage4_canonical_replay -- target
cargo run --example block_auth_replay -- target
cargo run --release --example block_auth_replay -- target
```

Debug: **173 passed** (129 library + 44 binary), release library: **129 passed**; 12 ignored benchmark/
controlled-child entries, no failures. Focused schema-3: 23 active passed, two child entries ignored.
Clippy completed with existing prototype warnings, no new schema-3 warning. Independent checkers
reproduced 5 native-auth vectors/262 malformed signatures, 4 native-block vectors/43 prefix headers,
and 6 block-auth vectors/262 malformed signatures/82 payload mutations. Replay harnesses retain whole
state/accounting/archive/index/tip equality; the new harness reconstructs both original signed packets
from separate producer/receiver SQL files with public independent policy only after restart.

Logs: `target/schema3-final-debug.log`, `schema3-final-release.log`, `schema3-final-clippy.log`,
`schema3-final-focused.log`. An attempted command naming a nonexistent `durable_fixture_replay` example
was corrected to the actual available replay harnesses; it is not reported as a passing harness.

## Matched Measurement Method

```bash
cargo test --release --lib authenticated_fixture::tests::measurements::matched_archive_measurements -- --exact --ignored --nocapture
python3 -B scripts/summarize_authenticated_storage.py <completed-log>
```

Driver: `src/authenticated_fixture/tests/measurements.rs`. Matrix A/H/T:
1,000/100/0; 1,000/100/100,000; 10,000/0/0 with N=0/1/3,000, plus 1,000/1,000/0 with N=0/1.
Producer/receiver, 8 phase pairs and 4 ordinary pairs per group, schema 2/3 alternation 23/32:
**528 appends in the completed run**. H counts appended blocks; anchor is separate. Representative ordinary
receiver groups provide four matched Ready-refresh and four actual durable-unpublished recovery
pairs per case. Native audits remain full before/after every sample and all canonical projections
are compared across the two backends; exact schema-3 evidence is additionally checked against its oracle.

The primary baseline is **adapted signed schema 2**, including one newly added local producer
self-authentication and the same trusted-policy structural dispatch helper. The original committed
schema-2 producer harness had zero local producer recoveries; this comparison explicitly adds one,
rather than removing schema-3 sealing verification. Reported baseline/schema-3 attribution spans
show that newly required work separately. Both measured paths assert one producer authentication,
one native stage invocation and (N,N) native per-entry calls. Neither is an unsigned authenticated baseline.

Complete producer time includes native prepare/header finalization, block signing/E encoding, local
attribution/sealing/grant, native/policy/prefix comparisons, all cache/attempt preparation, SQL indexes/
durability, installation/destruction and return. Receiver begins with available E and includes cold
signed framing/dispatch/attribution/native stage and the same writer/publication path. Native signing,
history construction, synchronized complete-file copying, external equality and printing are outside
append timing, not omitted audits or actual publication work.

Diagnostic spans are included, not subtracted. The `attribution_or_signed_staging_ms` field now
measures producer attribution only. `observations.native_stage_ms` is schema-2 native staging versus
schema-3 complete prepare/seal or receiver staging, **including attribution**; these coarse spans
are not disjoint or isolated ECDSA measurements. Schema-3 ordinary commit retains fixed boundary
clocks, although only `commit_profiled` exposes its SQL breakdown; schema-2 ordinary commit omits
optional SQL phase clocks. Both are their actual ordinary API paths. Test-only counters remain in
this release test binary. All overhead remains in totals; no production-executor timing is inferred.

Schema-2 full SQL native reopen is shown separately from re-authentication of original in-memory
envelope artifacts; their sum is **non-atomic external evidence**, not SQL producer assurance.
Schema-3 reopen/recovery includes actual SQL reconstruction, producer attribution and native audit
before its barrier/readiness. Durable-unpublished preparation forces a test-only error after actual
SQL COMMIT, then times exact attempt recovery; it is separate from Ready refresh and physical loss.

Hardware/settings: AMD Ryzen 9 9950X, 62 GiB RAM, Linux 7.2.7-arch1-1, Rust/Cargo 1.98.0/default
optimized release; rusqlite 0.38.0/bundled SQLite 3.51.1, k256 0.13.4/ecdsa 0.16.9/sha3 0.10.9.
Primary files: ext4 `rw,relatime` on WDC WD10JUCT-61CYNY0 rotational SATA disk. DELETE journaling,
EXTRA synchronous=3, foreign_keys=ON, default cache_size=-2000, enabled spill, zero busy timeout;
no `cache_spill` assignment, WAL, optional cache tuning, pruning, weaker sync or audit shortcuts.
One benchmark owner/writer at a time; CPU boost enabled, no affinity/host isolation/OS-cache flush.
Shared-process RSS/cumulative HWM are observations, not isolated backend peaks or hard caps.

Omissions: A=100,000/full Cartesian histories, H=1,000/N=3,000 optional case, cold-cache/isolated
backend peak experiments, exhaustive failure interleavings/allocator failures, production transport,
eligibility/economics and anti-equivocation. Primary sample transient journal high-water is not
instrumented; normal DELETE completion removes its journal. A separate large-base failed-restoration
stress records real spills and journal size at its pre-rollback boundary, outside performance samples.

### Measurement Results

The corrected main run completed **528 appends, zero failed samples**, all before/after audits,
cross-backend canonical equality checks, exact once-only counters, representative recovery pairs,
and the real-disk spill/restoration stress. Driver elapsed time was **4,329,466.810 ms (~72.16 minutes)**,
including construction/copies/audits/recovery/stress/printing outside append timers. The test result
was successful. The read-only helper verifies the completion/test result, declared complete matrix,
pair/backend/order identity, counts, fixture identity, recovery coverage and logical evidence growth;
it rejects partial logs and overlapping experiments. Every raw pipeline/durable observation and
within-pair difference remains in `target/schema3-matched-complete-summary.txt`.

#### Complete Pipelines — Phase Samples

**n=8 per cell**, ms **median [minimum, maximum]**; all outliers retained. Schema 2 is the adapted
signed baseline described above, not the original zero-self-verification producer:

| A/H/T | N | Schema2 producer | Schema3 producer | Schema2 receiver | Schema3 receiver |
|---|---:|---:|---:|---:|---:|
| 1000/100/0 | 0 | 3.161 [2.986, 4.686] | 3.684 [3.262, 12.980] | 3.048 [2.872, 5.014] | 3.651 [3.204, 5.039] |
| 1000/100/0 | 1 | 3.577 [3.193, 4.711] | 4.040 [3.654, 5.184] | 3.526 [3.279, 4.542] | 4.505 [3.537, 13.304] |
| 1000/100/0 | 3000 | 375.395 [370.543, 379.574] | 374.740 [370.781, 379.714] | 372.179 [368.670, 374.763] | 373.036 [367.938, 381.003] |
| 1000/100/100000 | 0 | 10.825 [9.475, 42.066] | 11.531 [10.921, 34.067] | 11.493 [9.762, 42.056] | 11.624 [10.714, 22.387] |
| 1000/100/100000 | 1 | 16.546 [12.941, 29.101] | 19.950 [14.323, 36.496] | 16.075 [12.929, 40.614] | 16.534 [13.584, 36.296] |
| 1000/100/100000 | 3000 | 1779.594 [1560.308, 1965.872] | **1901.131 [1715.920, 2154.858]** | 1827.308 [1523.406, 2033.130] | **1778.282 [1630.194, 2004.169]** |
| 10000/0/0 | 0 | 4.328 [4.057, 5.115] | 5.665 [4.960, 6.750] | 4.801 [4.276, 5.798] | 5.161 [4.838, 11.113] |
| 10000/0/0 | 1 | 5.251 [4.391, 35.527] | 6.656 [5.390, 20.259] | 4.822 [4.503, 5.267] | 5.946 [5.558, 7.712] |
| 10000/0/0 | 3000 | 392.522 [382.904, 415.044] | 389.494 [385.027, 407.673] | 386.508 [380.691, 410.838] | 387.482 [381.340, 398.925] |
| 1000/1000/0 | 0 | 3.061 [2.893, 4.169] | 4.339 [4.144, 5.034] | 2.901 [2.811, 4.229] | 4.107 [4.057, 4.294] |
| 1000/1000/0 | 1 | 4.055 [3.849, 5.565] | 4.527 [4.305, 4.892] | 4.062 [3.785, 4.590] | 4.560 [4.269, 5.549] |

#### Ordinary Controls

**n=4 per cell**, same complete boundaries/units, not pooled into phase samples:

| A/H/T | N | Schema2 producer | Schema3 producer | Schema2 receiver | Schema3 receiver |
|---|---:|---:|---:|---:|---:|
| 1000/100/0 | 0 | 3.158 [3.002, 3.435] | 3.559 [3.464, 3.705] | 3.052 [2.964, 3.569] | 3.633 [3.426, 5.177] |
| 1000/100/0 | 1 | 3.667 [3.521, 5.728] | 4.003 [3.864, 4.558] | 3.555 [3.491, 4.534] | 3.767 [3.588, 5.519] |
| 1000/100/0 | 3000 | 372.875 [371.388, 377.200] | 373.652 [370.937, 378.221] | 371.450 [367.330, 374.716] | 378.441 [374.241, 382.972] |
| 1000/100/100000 | 0 | 10.693 [10.198, 13.020] | 11.284 [10.605, 11.574] | 12.949 [9.737, 14.139] | 12.053 [10.603, 14.679] |
| 1000/100/100000 | 1 | 13.748 [13.543, 14.228] | 26.810 [13.957, 38.098] | 13.559 [13.154, 16.331] | 14.197 [13.719, 14.608] |
| 1000/100/100000 | 3000 | 1846.722 [1791.410, 2028.292] | 1860.826 [1827.491, 2122.596] | 1823.364 [1715.057, 1941.624] | **1992.721 [1898.505, 2040.897]** |
| 10000/0/0 | 0 | 4.492 [4.028, 5.115] | 5.105 [4.954, 19.180] | 5.004 [4.002, 6.083] | 5.321 [4.902, 65.325] |
| 10000/0/0 | 1 | 5.141 [4.444, 7.047] | 6.925 [5.901, 7.764] | 5.098 [4.552, 5.746] | 11.475 [5.791, 50.015] |
| 10000/0/0 | 3000 | 390.460 [386.106, 395.418] | 391.272 [387.342, 401.060] | 385.973 [380.698, 397.207] | 382.339 [381.814, 383.434] |
| 1000/1000/0 | 0 | 3.038 [2.940, 3.243] | 4.286 [4.001, 4.320] | 2.914 [2.847, 3.038] | 4.028 [4.023, 4.545] |
| 1000/1000/0 | 1 | 4.894 [4.177, 5.515] | 4.806 [4.358, 5.665] | 4.233 [3.763, 5.087] | 4.356 [4.165, 4.731] |

#### Direct Work and SQL Variance

Representative phase spans, n=8, ms median [min,max]. **Added schema2 verification** is the actual
new local producer work absent from its original committed harness; it stays in that baseline's total.
Signing and attribution include framing/preflight/owned encoding/hash/key work, not only raw ECDSA:

| A/H/T | N | Schema3 signing+E encoding | Added schema2 producer verification | Schema3 producer attribution | Schema3 receiver attribution | Schema3 receiver policy/prefix |
|---|---:|---:|---:|---:|---:|---:|
| 1000/100/0 | 0 | .068 [.067, .088] | .118 [.116, .177] | .116 [.115, .123] | .125 [.117, .136] | .061 [.051, .126] |
| 1000/100/0 | 3000 | 1.470 [1.465, 2.265] | 3.769 [3.724, 3.858] | 3.789 [3.738, 4.387] | 3.777 [3.754, 4.243] | .121 [.118, .131] |
| 1000/100/100000 | 0 | .079 [.078, .080] | .121 [.120, .122] | .121 [.120, .123] | .140 [.137, .144] | .123 [.117, .140] |
| 1000/100/100000 | 3000 | 1.547 [1.508, 1.710] | 4.030 [3.861, 4.286] | 3.880 [3.818, 4.121] | 3.927 [3.845, 3.992] | .135 [.126, .162] |
| 10000/0/0 | 0 | .081 [.077, .112] | .122 [.120, .188] | .127 [.123, .179] | .142 [.138, .159] | .039 [.028, .062] |
| 10000/0/0 | 3000 | 1.482 [1.475, 1.631] | 3.764 [3.716, 4.177] | 3.764 [3.755, 4.076] | 3.837 [3.787, 3.962] | .085 [.080, .092] |
| 1000/1000/0 | 0 | .071 [.068, .129] | .123 [.120, .164] | .118 [.116, .238] | .120 [.118, .125] | .409 [.339, .448] |
| 1000/1000/0 | 1 | .067 [.066, .099] | .118 [.117, .142] | .117 [.116, .175] | .122 [.119, .128] | .380 [.351, .432] |

At A=1,000/H=100/T=100,000/N=3,000, **within-pair schema3 minus schema2** complete-pipeline deltas
were **107.135 [-1.471, 366.524] ms producer** and **-26.168 [-216.846, 248.982] ms receiver** in
phase samples; ordinary deltas were **-15.171 [-142.252, 331.186]** and
**153.321 [-11.049, 325.841] ms** respectively. These are medians of actual differences, not
differences of group medians. Order is balanced within groups, but group/time drift is not removed.
Changing sign across modes and the large SQL variance do not establish a speedup or precise feature
overhead bound. Rare forced signing retry/entropy-failure paths were behavior-tested, not benchmarked.

Large-history/maximum-body **receiver phase** attribution, n=8, ms median [min,max]:

| Included span | Adapted schema2 | Schema3 |
|---|---:|---:|
| Coarse staging (schema3 includes attribution) | 350.045 [346.075, 362.127] | 354.435 [351.677, 358.533] |
| Full cache/attempt preparation | 6.879 [6.471, 7.205] | 7.076 [6.829, 7.589] |
| Old-cache destruction | 3.366 [3.165, 3.612] | 3.499 [3.212, 3.715] |
| Persisted-state comparison inside SQL | .148 [.138, .196] | .210 [.204, .352] |
| Uniqueness probes | 15.264 [14.701, 17.139] | 15.203 [14.764, 15.993] |
| Changed-account writes | 3.624 [3.448, 3.717] | 3.526 [3.438, 3.695] |
| Block (schema3 includes evidence) insertion | .057 [.051, .065] | .092 [.081, .123] |
| Transaction/index insertion | 260.908 [209.745, 317.421] | 315.771 [257.825, 363.078] |
| COMMIT return | 1147.369 [916.944, 1399.639] | 1087.416 [934.265, 1287.318] |
| Complete durable SQL | 1465.046 [1146.489, 1668.484] | 1414.987 [1265.237, 1637.777] |

All **nine observations above 2,000 ms** occurred at the large-history/maximum-body point; seven
were schema 3 and two adapted schema 2. Schema-3 producer phase values above the reference were
**2,154.858 / 2,007.153 / 2,073.407 ms**, and ordinary producer **2,122.596 ms**. Schema-3 receiver
was **2,004.169 ms** in phases and **2,021.138 / 2,040.897 ms** in ordinary controls. The two baseline
exceedances were **2,028.292 ms** ordinary producer and **2,033.130 ms** phase receiver. Smaller-body
outliers, including 65.325 ms and 50.015 ms controls, are retained too. No sample is dropped to fit
the execution reference, and neither a near-2-second median nor a lower median than the baseline
establishes a deadline bound.

#### Authenticated Reopen and Recovery

Receiver phase **full post-append reopen**, n=8, ms median [min,max]. External artifacts are a
separate in-memory authentication pass after SQL reopening; do not interpret SQL-only as equal assurance:

| A/H/T | N | Schema2 SQL native reopen | Separate original-artifact pass | Schema3 integrated authenticated reopen |
|---|---:|---:|---:|---:|
| 1000/100/0 | 0 | 4.341 [4.093, 5.636] | 11.592 [11.502, 12.174] | 16.674 [16.148, 18.486] |
| 1000/100/0 | 3000 | 358.374 [353.463, 363.502] | 15.219 [15.146, 15.346] | 365.404 [361.758, 371.383] |
| 1000/100/100000 | 0 | 12020.648 [11919.484, 12099.324] | 134.296 [133.252, 135.483] | 11835.339 [11749.074, 11959.383] |
| 1000/100/100000 | 3000 | 12782.918 [12731.717, 13106.359] | 144.407 [141.079, 145.229] | **12570.096 [12536.734, 12647.498]** |
| 10000/0/0 | 0 | 8.889 [7.894, 32.398] | .143 [.141, .152] | 10.487 [9.503, 12.783] |
| 10000/0/0 | 3000 | 367.692 [362.079, 390.024] | 3.833 [3.783, 4.241] | 358.560 [355.208, 365.422] |
| 1000/1000/0 | 0 | 18.382 [18.134, 34.560] | 115.844 [114.780, 118.047] | 137.327 [135.069, 139.303] |
| 1000/1000/0 | 1 | 19.047 [18.191, 47.587] | 117.153 [115.107, 119.817] | 136.263 [134.949, 138.168] |

At T=100,000/N=3,000, schema-3 reopen includes native audit **11941.903 [11908.170, 12011.320] ms**,
producer reconstruction/attribution **145.276 [144.677, 146.221] ms**, validation/materialization
**484.659 [477.064, 492.903] ms** and barrier **1.981 [1.927, 2.194] ms**. Baseline SQL native audit
was **12289.349 [12244.693, 12586.186] ms**, validation/materialization
**492.162 [484.584, 517.878] ms**, barrier **1.946 [1.871, 2.281] ms**. These valid paired/group
observations retain drift; they do not prove the added producer audit makes native execution faster.

Four ordinary receiver pairs per representative point measured **both Ready refresh and actual
durable-unpublished exact recovery**, ms median [min,max]. Baseline combined spans are sums for each
actual observation, then summarized, not sums of independently selected medians:

| A/H/T; N | Recovery kind | Schema2 SQL | Separate artifact | Combined non-atomic/external | Schema3 integrated |
|---|---|---:|---:|---:|---:|
| 1000/100/0; 3000 | Ready | 361.688 [355.848, 362.563] | 15.264 [15.209, 15.483] | 376.952 [371.057, 378.046] | 369.292 [365.483, 371.879] |
| 1000/100/0; 3000 | Unpublished | 358.732 [354.424, 363.558] | 15.652 [15.327, 16.156] | 374.729 [369.752, 379.024] | 369.506 [365.532, 370.360] |
| 1000/100/100000; 3000 | Ready | 12840.817 [12598.624, 13311.099] | 141.237 [139.917, 147.988] | 12982.054 [12738.541, 13459.087] | **12655.681 [12361.729, 13164.781]** |
| 1000/100/100000; 3000 | Unpublished | 12790.371 [12545.105, 13326.104] | 144.352 [138.113, 150.381] | 12934.723 [12683.219, 13476.484] | **12596.683 [12334.344, 12806.906]** |
| 10000/0/0; 3000 | Ready | 361.693 [360.684, 376.318] | 3.930 [3.807, 4.029] | 365.630 [364.491, 380.333] | 356.031 [354.510, 356.312] |
| 10000/0/0; 3000 | Unpublished | 362.500 [361.330, 366.121] | 4.038 [3.899, 4.230] | 366.538 [365.560, 370.020] | 357.983 [356.688, 359.472] |
| 1000/1000/0; 1 | Ready | 18.731 [18.168, 19.757] | 115.529 [114.963, 117.568] | 134.700 [133.131, 136.445] | 135.760 [133.725, 137.727] |
| 1000/1000/0; 1 | Unpublished | 18.459 [18.294, 19.939] | 115.558 [114.820, 117.803] | 134.823 [133.113, 136.132] | 136.237 [135.076, 138.567] |

Each unpublished recovery proves its original attempted evidence/effects present, followed by full
reopen equality. It is not a tip-only check, ordinary refresh relabeled as uncertainty, real process
crash timing or power-loss timing. Per-recovery load breakdowns are retained in raw records.

#### Actual File/Evidence Growth and Memory

Closed normally constructed bases, bytes (construction times outside append timer):

| A/H/T | Schema2 SQL | Schema3 SQL | Extra SQL bytes | Logical evidence | Separate schema2 original packets | Construction ms |
|---|---:|---:|---:|---:|---:|---:|
| 1000/100/0 | 270336 | 311296 | 40960 | 9700 | 41200 | 1146.642 |
| 1000/100/100000 | 47947776 | 47988736 | 40960 | 9700 | 20341200 | 155488.350 |
| 10000/0/0 | 1241088 | 1257472 | 16384 | 0 | 0 | 35.271 |
| 1000/1000/0 | 937984 | 1200128 | 262144 | 97000 | 412000 | 17750.171 |

After one N=3,000 phase append, schema2/schema3 sizes were **1,691,648 / 1,732,608 bytes** at
1000/100/0, **49,250,304 / 49,291,264** at 1000/100/100000, and **2,674,688 / 2,691,072** at
10000/0/0. Growth was respectively **1,421,312 / 1,302,528 / 1,433,600 bytes** for both backends at
these page-granularity points; equal growth does not eliminate the extra logical 97 bytes or index
overhead. At 1000/1000/0, an empty append grew schema3 4,096 bytes versus zero baseline growth; its
N=1 append fit existing pages for both. Ordinary representative receiver files include the extra
durable-unpublished empty append and must not be mislabeled one-append size observations.

Every appended envelope adds exactly 97 logical evidence bytes regardless of empty versus maximum
body, compared to serializing another **412 / 615 / 609,412-byte** signed envelope for the fixture's
N=0/1/3,000 inputs. The largest body's 597,000 native signed bytes are already stored once. The
baseline's in-memory original artifacts are not part of its atomic SQL transaction. Primary journal
transient peaks were not measured; the separate stress's 17,182,216-byte journal observation is
reported above without treating it as a primary maximum.

Maximum observed shared-process RSS/HWM was **430,576 KiB (~420.48 MiB)**, including both stores,
retained reference snapshots/artifacts, candidate/cache/attempt copies and allocator reuse. It is
not an isolated schema-3 peak or memory cap. T=100,000 retains ~19.9 MB raw signed native entries,
3.2 MB ordered IDs and 200,000 transaction/sender-nonce memberships per full canonical snapshot;
cache preparation copies them rather than pruning history. SQL evidence is compact, but this stage
does not solve existing retained-body/index cloning, full-audit latency or default-budget spill cost.

Development runs are retained separately and excluded: `schema3-measurement-pilot.log` (16 selected
appends), an earlier selected empty-body pilot, `schema3-matched-measurements.log` interrupted for the
literal SQLite-reserved-prefix schema fix, `schema3-matched-final.log` interrupted for revision/known-
prefix gate corrections, and `schema3-matched-reviewed.log` interrupted by the tool's 120-second
process timeout. The detached corrected full run is `target/schema3-matched-complete.log`; its validated
aggregation is `target/schema3-matched-complete-summary.txt`. No completed partial data is pooled into
the main matrix. Failed runs and all timing outliers remain disclosed.

Medians/ranges are observations, not deadlines or p95/p99 bounds. Compare complete work against the
**2,000 ms execution reference**, never the 2,100 ms publication deadline. Earlier signed schema-2
work already observed 2,004.871 ms; fresh results cannot inherit a deadline claim from that baseline.

## Review Boundary

This is an authenticated offline suffix/projection with trusted initialization and static historical
producer policy, not a complete production node checkpoint. Live RPC/P2P/slot admission, activation/
production numbering/genesis, dynamic keys, consensus selection/economics/protocol blocks, signing-
intent journals, finality/reorgs, pruning/checkpoints and automatic migration require separate work.
The initial implementation delivery was unstaged for review; local design/ignore files remain local.
