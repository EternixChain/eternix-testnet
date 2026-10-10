# Stage 4: Offline Anchored Native Block Storage

The approved bounded Stage 4 experiment is implemented in `src/native_block.rs` and
`src/canonical_fixture.rs`. **Wire value 2 and header profile value 2 are experimental offline
assignments**, not production numbering, activation, genesis, migration or a production block profile.
The result is a durable native ETX projection for an explicitly selected fixture chain, not a complete
node checkpoint or a producer-authenticated network chain.

## APIs and Ownership

| API | Contract |
|---|---|
| `FixtureManifest::new(context, anchor, initial, provenance)` | Explicit trusted empty synthetic anchor and **post-anchor** ETX accounts/committed nonces/gas/burn baseline; no prototype or genesis import |
| `CanonicalFixtureStore::create_anchored_fixture(path, &manifest)` | Exclusive new-path creation; initialized schema/seed/state/anchor/body/tip/marker commit atomically; file/directory sync before success |
| `reopen` / `recover_existing` | Open read/write without CREATE; validate the expected manifest, entire retained archive and seed audit, establish a synchronized barrier, then return Ready |
| `create_anchored_fixture_with_cache_policy` / `reopen_with_cache_policy` / `recover_existing_with_cache_policy` | Same ownership, initialization, full audit and synchronization contracts with an explicit connection-local offline memory policy |
| `prepare_next(proposer, ticket, exact_body)` | Producer uses `stage_body` once and constructs immutable header/roots from its results; returns `PreparedNativeBlock`, which alone cannot commit |
| `FixtureAdmissionGrant::explicit_offline(...)` | Trusted test code explicitly supplies context, anchor, exact base tip, block hash and slot. This is not a producer signature or live consensus authorization |
| `PreparedNativeBlock::authorize(grant)` | Consumes the prepared object and seals its existing effects with the grant; does not authenticate/execute again |
| `stage_received(exact_wire, grant)` | Strict preflight, explicit append/admission checks, one shared body stage, then exact bytes/IDs/gas/burn/uniqueness checks |
| `commit(StagedNativeBlock)` | Consumes the sealed candidate once; one SQL transaction for every canonical field, durable COMMIT before one coherent cache installation |
| `snapshot`, `settings`, `load_timings`, `cache_policy` | Ready-only results; poison hides unreconciled cached accounts, records, indexes, tip and timings |
| `recover()` | Explicit generation invalidation, no-create reopen, complete audit, exact attempted-record reconciliation, dirty-page barrier, cache refresh; failure stays blocked |

`Tip { hash, slot, revision }` keeps genuine content identity and local commit sequence separate.
Revision zero is the explicitly supplied anchor; its slot need not be zero. The implementation never
executes anchor effects on its trusted post-anchor state. `Snapshot` contains the native state, exact
`CommittedBlock` archive including the anchor, ID and sender/nonce membership indexes, slot/hash
indexes, and tip. Public access is read-only and exclusive Rust ownership gates persist/install/recover.

`AppendOutcome` retains **Committed / Aborted / RecoveryRequired**. Only Committed authorizes a new
acknowledgement/broadcast/local-pool cleanup. A fresh exact stored-block resubmission is
`Error::AlreadyCommitted(Tip)`, a no-op reference, not a new successful application. A consumed old
overlay is rejected as Stale before payload work. A changed SQL base produces an unchanged-storage
Stale rejection and blocks that stale owner's publication until explicit refresh.

Before COMMIT, account equality, records, and all publication allocations are prepared. After confirmed
COMMIT, a prepared complete cache is moved in and the old cache destroyed. Failure in this gap blocks
processing; restart loads the durable new prefix rather than executing it twice. There are no automatic
retries, queued resubmissions, ancestor replacements, economic reversals, or reorg operations.

### Explicit Offline Cache Resource Policy

`CachePolicy::ExistingDefault` remains the default for every original schema-2 API. It verifies the
pinned SQLite `cache_size=-2000` (~2 MiB) without assigning a different default. An explicit
`CachePolicy::Trial32MiB` selects and verifies `cache_size=-32768` (32 MiB). Creation, reopening and
prior-process recovery accept the policy through the suffixed APIs above; `recover()` consistently
reapplies the current owner's choice. A new owner must explicitly choose the trial again.

This is a connection-local resource preference, not persisted schema metadata or a native rule.
Either policy reads the same archive, with the same manifest checks, full audit and synchronized
barrier. The common schema-1 configuration and live configuration retain their existing behavior.
DELETE journaling, EXTRA synchronization, foreign keys, SQL/index constraints and acknowledgement
ordering remain mandatory. The code never assigns `PRAGMA cache_spill`; it checks that enabled status
is preserved. SQLite naturally reports a different numeric spill threshold with the larger budget.

`cache_size` is a suggested page-cache budget, **not a hard SQLite allocation or process-RSS cap**.
Growing Rust archive/index/candidate caches and full-audit projections consume additional memory.
The bounded two-policy release experiment and separate spill/fault/allocation evidence are documented
in the local `stage-4-storage-performance-review.md`; the trial has not become the default.

The completed paired run retained all 192 receiver samples (8 phase/4 ordinary/4 passive per policy
per matched group), 8 representative producer/reopen/recovery samples and 2 isolated memory children.
At A=1,000/H=100/T=100,000/N=3,000, phase-mode receiver medians were **1,790.781 / 1,684.436 ms**
(default/trial), with **6.321% median paired improvement**; ordinary paired improvement was 7.697%.
Cache spills fell **5,896 to 0**, page writes **6,328 to 4,507**, but trial COMMIT still took ~1.29 s.
Fresh-process peak RSS increased by ~31.05 MiB; full reopen/audit/recovery remained ~12 seconds.
These are one-host offline observations, with all outliers retained, not a deadline/resource guarantee.

Final two-policy checks passed: **130 debug tests (86 library + 44 binary)** and **86 release library
tests**, formatting, Clippy (existing prototype warnings), and both independent vector checkers.
Real I/O sweeps, actual-budget process termination, declared power modeling, SQLite hard-heap NOMEM
children and separately invoked initialization/append spill stress cover the explicit option. The
400,000-account initializer spills under both actual budgets; the 703,000-account/100,000-history-tx
append stress also spills under both budgets and poisons after a real failed restoration write.
Allocation evidence is four SQLite hard-heap cases, not Rust OOM or exhaustive malloc-failure coverage;
large-fixture power evidence is three selected trial cuts, not an exhaustive physical-outage claim.
Reproduction/complete ranges and the recommendation to retain opt-in status are in the local review.

## Exact Representation and Compatibility

`src/block_commitment.rs` narrowly extracts `BlockHeader`, `BlockKind`, `ProtocolData`, proposer/list
commitments and hashing from the V1 binary modules. `src/models.rs` re-exports those types; V1 retains
its constructors, transaction type, wire-1 decoder and version/chain/fee/gas validation. Existing V1
golden bytes/hashes and live HIST/BLOCK rejection regressions pass. No live app/network module calls
the new native block/store APIs.

The experiment accepts **validator-kind only**, including empty bodies: <=3,000 transfers, actual gas
<=16,000,000, nonempty/nonreserved proposer UTF-8 <=256 bytes with no normalization, matching nonzero
proposer commitment and nonzero ticket. Structural proposer/ticket checks do not establish eligibility.

```text
wire:u8=2 || claimed_hash:32 || canonical_header:229 ||
BE32(proposer_bytes_length) || proposer_utf8 ||
BE32(10) || protocol_data_encoding:u8=1 || BE64(burns) || missed_flag:u8=0 ||
BE64(count) || each_in_body_order(BE32(199) || exact_signed_native_bytes:199)
```

Maximum wire size is 609,544 bytes. Declared lengths/counts are bounded before allocation; every native
entry remains opaque during envelope decoding. No V1 conversion, mixed bodies, raw-Ethereum fallback,
timestamp, memo, producer signature, wallet key or pending nonce enters this format/application.

Native IDs retain `ID_DOMAIN || exact_signed_bytes`; ordered roots retain
`ETERNIX_TX_LIST_V1 || BE64(count) || ordered_ids`; block identity retains
`ETERNIX_BLOCK_HEADER_V1 || exact_229_byte_header`. Protocol-data bytes/root are unchanged. State root
is exactly 32 zero bytes and receipts root is the historical count-zero receipt-list commitment.
The experimental profile changes only the new header's profile field value; historical V1 is intact.
The header has no native network-ID field: empty blocks depend on the explicit trusted context/anchor,
not a newly invented network binding in the hash preimage.

### Fixed Error Precedence and One Body Stage

Receiver ordering follows approved design §4.3.1:

1. Ready/base-token gates.
2. Bounded envelope syntax in wire order.
3. Header profile/chain/kind/proposer/ticket/reserved roots/gas cap/protocol shape, claimed hash,
   protocol-data root and raw-byte ordered transaction root.
4. Exact stored-block reference or occupied-slot conflict; checked tip-plus-one, exact parent,
   checked revision and explicit fixture grant.
5. `stage_body` authentication left-to-right, stopping at its first failure.
6. Inside that **same call**, execution left-to-right only after every authentication succeeds.
7. Exact staged bytes/IDs, actual gas, actual burn, then per-position ID and sender/nonce uniqueness.
8. Token/metadata/SQL rechecks and commitment.

A later authentication error wins over an earlier nonce/funding/maturity execution error. If all
authentications succeed, the first execution error wins over later execution errors and an in-range
claimed gas/burn mismatch. Duplicate transfers retain their existing nonce-rejection precedence.
Preflight raw-byte hashing is not signature verification. Tests count real authentication/execution
calls: no pre-authentication pass, repeated `apply_body`, or candidate authentication/execution at
successful commitment. Rollback verification and restart audit authenticate their historical bodies
once each in a separate seed projection; they do not re-execute the attempted body on materialized RAM.

## Schema 2, Initialization, and Recovery

Pinned backend remains rusqlite 0.38.0 / bundled SQLite 3.51.1 with queried/verified **DELETE,
synchronous=EXTRA/3 and foreign_keys=ON**, zero busy timeout. Schema-1 NULL-tip fixtures retain their
behavior; each API family explicitly rejects the other schema. There is no upgrade or backfill.

Schema 2 stores metadata/mode/context/provenance/seeds/baseline, materialized accounts/accounting,
`blocks`, one `bodies` row per block, exact `transactions`, and singleton `canonical_tip`. Hash and
slot/revision keys are unique; ID and sender/nonce uniqueness and original positions are constrained.
Deferred cyclic block/body FKs require both records; composite tip/FKs bind the same hash/slot/revision.
Redundant header-derived columns are checked on load. Signed bytes have one durable canonical copy,
not a competing reserialized V1 or whole-state blob.

Unsigned protocol/storage fields use checked big-endian BLOBs: addresses 20, hashes 32, headers 229,
wire/transaction encoding 1, rules/profile/schema 4, nonces/slots/revisions/positions/count/gas/body burns
8, balances/cumulative burns 16. SQL does no monetary/slot arithmetic. SQL type/length constraints and
exact Rust decoding both apply. Full-width unsigned maxima were actually committed/reopened, including
chain/slot/nonce/gas u64::MAX and balance/burn u128 boundaries.

All initialization records, anchor/body/tip at revision zero, seeds/state/baseline, provenance and the
logically-last complete marker share one transaction. Publication/cache allocations precede its COMMIT.
Durable creation also syncs the database and parent directory. Existing/empty paths are not replaced;
missing reopen does not create. Interrupted/uncertain initialization is recovered as complete or
unusable, never reseeded. Reopen checks the full immutable expected post-anchor fixture state/baseline
against stored seeds (stronger than a seed-count check), then audits the suffix against current state.

An uncertain attempt retains its **exact block/body/outcome and expected base tip**, not just revision.
Recovery accepts the exact attempted row in a valid prefix or the exact unchanged old prefix; a different
valid block at that revision leaves the first owner poisoned. The recovered archive is checked for
contiguous revisions/slots, exact parents/hashes/roots, bytes/positions/IDs/membership, accounting and
final tip. Each suffix body is authenticated/executed once into a fresh seed-owned audit, compared to
the materialized state, which is loaded directly and never replayed onto.

After auditing, BEGIN IMMEDIATE rechecks trusted context/anchor/revision/tip, checked-increments a real
recovery-barrier metadata page, performs EXTRA COMMIT, then database/directory sync. Only complete
reconciliation/barrier/cache refresh returns Ready with a fresh generation. Readability is not proof
of failed-sync durability. Successful SQL ROLLBACK/autocommit alone is also insufficient: full old-prefix
validation catches SQLite pager restoration failures swallowed by SQL rollback.

## Verification Actually Performed

The following commands completed successfully after the implementation fixes:

```bash
cargo fmt --check
cargo test
cargo test --release --lib
cargo clippy --all-targets --all-features
python3 -B scripts/reproduce_native_auth_vectors.py
python3 -B scripts/reproduce_stage4_vectors.py
cargo run --example stage4_canonical_replay -- target
cargo run --release --example stage4_canonical_replay -- target
```

- Full debug: **122 passed** (78 library + 44 binary); release library: **78 passed**. Three ordinary-run
  ignores are the two controlled subprocess entries (actually exercised by parent tests) and the
  explicitly invoked retained-history benchmark. All existing schema-1/native/V1/ingress tests pass.
- Clippy completed with existing prototype/dead-helper warnings; this stage's warnings were fixed.
- Whitespace checks passed for tracked changes (`git diff --check`) and every untracked/new file
  (`git diff --no-index --check` against `/dev/null`, using Git's untracked-file list). The root design
  ignore rule and absence from the Git index were separately verified.
- Independent Python struct packing/OpenSSL Keccak/RFC6979/curve arithmetic/OpenSSL-backed ECDSA
  reproduced **4 block vectors, a 43-header synthetic prefix, 3 native signatures and explicit native
  resulting-state projections** without calling Rust. The previous 5 native vectors/262 malformed
  signatures also reproduce. Frozen manifest: `tests/fixtures/stage4_native_blocks.json`.
- Debug/release producer/receiver/restart examples agree on entire state/archive/index/tip using separate
  databases: anchor slot 42, populated slot 43, empty slot 44, final revision 2, three indexed native
  entries; cumulative gas 3,007 and burns 30,013 include the explicitly supplied 7/13 baseline.
- Correctness covers zero/nonzero/max-slot anchors, exclusive creation/no-create reopen, exact grants,
  wrong parent/slot, exact duplicates/conflicts, stale owner/recovery/SQL overlays, malformed/commitment
  errors, compound native-phase error precedence, later-transaction/accounting failures, unsigned
  boundaries, exact uncertain identity and corrupt schema/context/seed/header/body/tip/index/widths.

### Distinct Storage Evidence

These are real executed evidence classes, not one undifferentiated crash-recovery claim:

| Class | Actual Stage 4 evidence | Limits |
|---|---|---|
| Normal close/reopen | Separate file-backed producer/receiver/restart; complete archive/index/state/tip equality; marker/corruption/seed authority and no-reseed checks | Orderly reload, not interrupted storage |
| Application failpoints/constraints | 13 initialization positions; 8 append SQL/control phases plus real transaction-index and tip trigger/constraint failures; all recovery gates; post-COMMIT/install hooks | Control/SQL atomicity coverage; flags alone are not physical I/O faults |
| Process termination | **50 handshake-controlled SIGKILL locations per suite run**: 18 initialization, 16 empty append, 16 populated append. 50,000 seeded accounts, actual journal/database write/sync/delete callbacks, hot-journal presence checked at database-sync cuts | OS/device caches survive SIGKILL; not power loss |
| Real SQLite I/O | **266 nth-operation sweep cases**: initialization 42, empty append 80, populated append 120, recovery barrier 24. FULL=13, IOERR_WRITE=778, IOERR_FSYNC=1034, IOERR_DELETE=2570. Additional real spilled-page rollback write (2,048 transfers), initializer rollback truncate (1546), and reopen xOpen/CANTOPEN (14) tests | Selected engine error/abort/poison behavior; returned errors alone do not discard/reorder volatile data |
| Declared power model | **282 operation-boundary cuts** (both volatile-loss-only/sector-prefix variants): 23 initialization, 42 empty append, 62 populated append, 14 barrier boundaries per variant; plus stable-image retention after both acknowledged and durable-but-unacknowledged COMMIT | Conditional on the declared model, not physical storage certification |

I/O sweeps observed 132 unchanged-prefix/pre-application aborts and 134 blocked uncertain outcomes;
after successful explicit recovery every selected append-error case recovered the old complete prefix.
Separate post-COMMIT publication failure tests recover the exact new prefix, and a different block at
the attempted revision is never guessed committed. Successful rollback does not run cleanup/ack hooks.
The verbose tests print operation/ordinal, SQLite extended result, coordinator outcome and recovered tip.

Power-model cuts before writes/sync/delete recovered uninitialized initialization (46 cuts), old empty/
populated prefixes (84/124 cuts), and retained acknowledged new data through interrupted barrier work
(28 cuts). The two post-COMMIT stable-image tests separately recovered complete new prefixes.
The shared real SQLite VFS stabilizes prior file writes/truncation at successful xSync and journal
deletion at successful xDelete(syncDir=1). Selected cuts restore only captured stable images, dropping
other writes and post-cut cleanup. The optional variant destages a first 512-byte sector/prefix of an
unsynced database page. Reserved directory entry survival is assumed; arbitrary sub-sector corruption,
all reorderings, dishonest sync/device firmware and real outages are not certified. xOpen fault counters
are separate so prior schema-1 write/sync/delete model traces remain unchanged.

## Complete Pipeline and Retained-History Measurements

Environment: AMD Ryzen 9 9950X, 16 cores/32 logical CPUs, 62 GiB RAM; Linux 7.2.7-arch1-1 x86_64;
Rust 1.98.0/LLVM 22.1.8, default optimized release; rusqlite 0.38.0 / SQLite 3.51.1. Workload files
are under disk-backed `target` on ext4 (`rw,relatime`), WDC WD10JUCT-61CYNY0 rotational 931.5 GiB SATA
disk, not tmpfs. One writer per run, boost enabled, no affinity/isolation, warm CPU/OS caches without
flushing; reopen uses fresh SQLite owners. Three samples per row, no meaningful p95/p99 claim; every
outlier is retained. Required PRAGMAs remain DELETE/EXTRA/foreign keys; page 4,096/cache -2,000 KiB,
zero busy timeout. The driver reports bundled compile options (same options as the stage-3 report;
DEFAULT_SYNCHRONOUS=2 is explicitly overridden/queried as 3).

Driver: `examples/stage4_support/bench.rs`; CLI:

```text
cargo run --release --example stage4_canonical_bench -- <existing-disk-parent> [samples] [case] [body-count]
```

The full `target 3` run reached its **1,800-second command timeout after 37 completed rows**. It was
not reported as a successful complete command. Targeted commands completed the two remaining rows:

```bash
cargo run --release --example stage4_canonical_bench -- target 3 12 1
cargo run --release --example stage4_canonical_bench -- target 3 12 3000
```

Thus all **39 workload rows** in the declared 13-point A/H/T matrix have actual results, with the last
two in fresh processes. The separate case-0 pilot is not mixed into the table. History construction
is outside sample timing but not hidden: the largest H=1,000/T=100,000 construction took approximately
242–285 seconds per database. The default run timeout can leave disposable benchmark artifacts under
the ignored target directory. No full Cartesian matrix, A=100,000/H=10,000, larger H/T, cold-disk flush,
minimum-hardware or production economics/authentication/transport benchmark is claimed.

### Boundaries and Copy/Rebuild Costs

- **Receiver pipeline:** already available exact bytes/grant through commit return, including complete
  decode/preflight/grant/root/native authentication/execution/post-checks, cache preparation, SQL sync,
  installation, old-cache destruction and return/overlay teardown. No authenticated-result cache.
- **Producer pipeline:** supplied exact signed body through preparation/header finalization/grant sealing
  and commit return. Signing/input/history generation is outside both paths. Staging is timed as a
  combined ordered validation/authentication/execution phase, not an authentication-only estimate.
- **Durable commit:** BEGIN IMMEDIATE through confirmed EXTRA COMMIT, including metadata/tip/index checks,
  full account/accounting decode/equality, changed-row scan and all writes. Stored comparison remains
  included and is separately reported. Cache copies are outside this timer and **inside** the pipeline.
- **Cache preparation:** clones all retained `CommittedBlock` constituents/signed bytes/ordered IDs,
  both T-entry transaction/sender-nonce maps, both H-entry slot/hash maps, and candidate state before
  SQL. Stage already clones candidate/base. No incremental-cache optimization was substituted.
- **Cache destruction:** explicit prior complete-cache drop after COMMIT; additional overlay/call drops
  stay in pipeline elapsed. Installation separately measures the owned move.
- **Reopen/recovery:** open-to-Ready includes configuration, schema/integrity/FK checks, both seed/current
  state reads, full block/body/index reconstruction, one seed audit per archived appended body, equality,
  synchronized barrier and publication. Interleaved validation/read/cache rebuild is combined rather
  than double-counted; audit is separately timed and included in total. Full audit clones accounts twice
  per body, including empty bodies: work can grow with sum of audit account counts over H, not just T.

H/T below are pre-workload retained appended blocks/transactions, anchor counted separately. Each
workload starts from its own database/history, then alternates producer and receiver on consecutive
fresh requests: before producer samples H is H0/H0+2/H0+4, T is T0/T0+2N/T0+4N; receiver copying sees
one intervening producer block, and after samples the audit sees H0+6 / T0+6N. No histories/indexes are
pruned/reset. A remains fixed by recipient reuse; touched counts are 0 for empty, 2 for single,
min(A,3,001) for 3,000 entries. Signed-body bytes are 0/199/597,000; envelope bytes 305/508/609,305.

### Actual Results (ms, median / maximum)

`Copy` = full-cache preparation; `Drop` = old-cache destruction; `Compare` = SQL state comparison,
already included in COMMIT. `Recover` in this table is explicit Ready refresh; unpublished recovery
is measured separately below. Reopen includes the entire post-sample archive audit.

| A | H0 | T0 | N | Receiver | Producer | COMMIT | Copy | Drop | Compare | Reopen | Recover |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 100 | 0 | 0 | 0 | 2.109/3.268 | 2.085/3.451 | 2.098/3.256 | .002/.002 | .001/.001 | .017/.021 | 2.023/2.089 | 1.941/1.968 |
| 100 | 0 | 0 | 1 | 2.666/3.542 | 2.569/2.656 | 2.535/3.409 | .003/.003 | .001/.001 | .021/.021 | 2.618/4.282 | 2.715/2.717 |
| 100 | 0 | 0 | 3000 | 492.445/553.052 | 437.741/518.578 | 150.423/213.861 | 1.341/1.945 | .192/.286 | .038/.040 | 2059.476/2065.991 | 2067.063/2076.077 |
| 1000 | 0 | 0 | 0 | 2.194/2.284 | 2.193/3.415 | 2.162/2.257 | .004/.006 | .003/.003 | .104/.105 | 2.535/2.555 | 2.545/2.605 |
| 1000 | 0 | 0 | 1 | 2.754/2.941 | 3.295/3.859 | 2.593/2.760 | .014/.017 | .005/.005 | .109/.135 | 3.445/3.700 | 3.217/4.664 |
| 1000 | 0 | 0 | 3000 | 544.035/627.847 | 486.403/578.186 | 205.178/282.247 | 1.132/1.321 | .202/.294 | .135/.151 | 2047.823/2048.509 | 2065.377/2109.114 |
| 10000 | 0 | 0 | 0 | 3.834/4.055 | 4.222/5.935 | 3.654/3.820 | .037/.038 | .018/.019 | 1.020/1.226 | 8.211/9.141 | 8.059/8.862 |
| 10000 | 0 | 0 | 1 | 4.405/4.910 | 5.138/5.673 | 4.083/4.347 | .033/.058 | .031/.040 | 1.026/1.086 | 8.680/8.953 | 9.876/12.120 |
| 10000 | 0 | 0 | 3000 | 539.224/575.975 | 580.580/624.649 | 203.866/240.354 | 1.114/1.433 | .261/.351 | 1.157/1.272 | 2056.088/2063.152 | 2066.524/2076.053 |
| 100000 | 0 | 0 | 0 | 26.556/27.371 | 25.964/30.002 | 21.091/22.179 | 1.129/1.135 | .749/.778 | 13.078/13.924 | 64.518/66.216 | 64.407/65.360 |
| 100000 | 0 | 0 | 1 | 29.291/35.383 | 26.842/27.633 | 23.228/29.115 | 1.200/1.268 | .793/.845 | 12.486/14.080 | 68.083/70.058 | 64.761/65.281 |
| 100000 | 0 | 0 | 3000 | 629.463/662.267 | 480.037/594.354 | 287.406/319.482 | 1.958/2.311 | .929/1.047 | 14.067/14.272 | 2136.298/2140.450 | 2110.536/2121.191 |
| 1000 | 100 | 0 | 0 | 2.673/3.141 | 2.988/4.189 | 2.637/3.098 | .008/.009 | .005/.007 | .106/.111 | 3.969/4.004 | 4.223/4.385 |
| 1000 | 100 | 0 | 1 | 3.843/13.241 | 3.515/4.959 | 3.684/13.068 | .011/.012 | .006/.012 | .111/.117 | 4.895/4.980 | 5.068/5.124 |
| 1000 | 100 | 0 | 3000 | 534.236/586.694 | 480.382/575.161 | 197.588/247.741 | 1.043/1.357 | .215/.310 | .132/.134 | 2065.989/2069.279 | 2058.228/2062.481 |
| 1000 | 1000 | 0 | 0 | 3.288/3.557 | 3.557/3.579 | 3.200/3.456 | .043/.044 | .018/.028 | .132/.162 | 19.915/20.084 | 19.465/19.632 |
| 1000 | 1000 | 0 | 1 | 3.518/4.151 | 4.082/4.956 | 3.308/3.772 | .048/.085 | .021/.022 | .112/.228 | 18.247/18.585 | 19.438/19.499 |
| 1000 | 1000 | 0 | 3000 | 511.640/597.600 | 460.136/579.088 | 168.208/260.470 | 1.104/1.463 | .274/.371 | .136/.137 | 2072.641/2080.937 | 2078.654/2102.992 |
| 1000 | 10000 | 0 | 0 | 17.100/28.141 | 13.985/14.223 | 16.233/27.207 | .547/.552 | .334/.349 | .130/.132 | 158.641/169.755 | 154.731/161.984 |
| 1000 | 10000 | 0 | 1 | 12.535/20.735 | 20.168/23.816 | 11.320/19.329 | .587/.623 | .356/.594 | .136/.142 | 161.389/161.494 | 157.940/163.300 |
| 1000 | 10000 | 0 | 3000 | 571.061/616.563 | 483.776/588.089 | 228.514/277.796 | 1.875/2.272 | .848/.878 | .145/.171 | 2207.263/2232.698 | 2212.906/2215.845 |
| 1000 | 100 | 1000 | 0 | 2.704/2.909 | 3.076/3.506 | 2.638/2.825 | .027/.035 | .013/.014 | .111/.176 | 123.393/124.098 | 119.250/121.674 |
| 1000 | 100 | 1000 | 1 | 3.348/3.933 | 3.542/3.624 | 3.169/3.744 | .029/.034 | .015/.015 | .110/.115 | 122.174/126.992 | 117.423/117.626 |
| 1000 | 100 | 1000 | 3000 | 537.645/664.198 | 470.750/628.005 | 200.643/328.144 | 1.143/1.398 | .229/.328 | .134/.135 | 2164.313/2178.616 | 2160.594/2163.953 |
| 1000 | 1000 | 1000 | 0 | 2.719/15.956 | 2.683/2.949 | 2.560/15.810 | .068/.087 | .042/.046 | .109/.112 | 130.927/131.816 | 135.788/136.426 |
| 1000 | 1000 | 1000 | 1 | 4.352/4.590 | 4.025/4.718 | 4.098/4.338 | .073/.111 | .043/.043 | .108/.181 | 136.022/144.334 | 132.579/132.792 |
| 1000 | 1000 | 1000 | 3000 | 612.649/684.940 | 477.832/683.293 | 275.627/340.770 | 1.336/1.488 | .362/.397 | .140/.140 | 2196.580/2197.692 | 2188.960/2201.299 |
| 1000 | 100 | 10000 | 0 | 3.417/3.786 | 3.244/3.317 | 2.954/3.481 | .214/.333 | .056/.087 | .119/.124 | 1144.142/1155.649 | 1144.410/1158.888 |
| 1000 | 100 | 10000 | 1 | 10.534/25.130 | 4.798/11.600 | 10.015/24.482 | .304/.310 | .075/.127 | .116/.184 | 1139.344/1152.488 | 1155.322/1155.566 |
| 1000 | 100 | 10000 | 3000 | 738.179/858.106 | 662.695/755.400 | 402.053/517.120 | 1.634/1.888 | .386/.464 | .140/.143 | 3222.731/3229.699 | 3191.473/3211.950 |
| 1000 | 1000 | 10000 | 0 | 4.104/4.456 | 3.472/11.684 | 3.481/3.663 | .377/.709 | .109/.189 | .119/.148 | 1158.508/1161.973 | 1161.507/1166.583 |
| 1000 | 1000 | 10000 | 1 | 5.575/48.181 | 4.687/4.754 | 4.948/47.195 | .471/.479 | .108/.328 | .117/.118 | 1182.701/1192.439 | 1161.180/1171.679 |
| 1000 | 1000 | 10000 | 3000 | 685.802/754.689 | 642.678/758.534 | 348.173/417.329 | 1.864/2.032 | .516/.609 | .142/.163 | 3218.526/3234.257 | 3226.372/3227.521 |
| 1000 | 100 | 100000 | 0 | 9.226/20.434 | 8.539/8.593 | 3.191/14.743 | 4.302/4.601 | 1.338/1.383 | .141/.145 | 11523.587/11556.387 | 11549.256/11565.214 |
| 1000 | 100 | 100000 | 1 | 10.370/11.607 | 9.991/18.652 | 4.245/5.879 | 4.585/4.617 | 1.386/1.396 | .150/.156 | 11561.135/11568.907 | 11394.865/11455.659 |
| 1000 | 100 | 100000 | 3000 | 1705.593/1745.958 | 1642.511/1814.768 | 1364.912/1398.510 | 5.805/6.053 | 1.739/1.897 | .151/.166 | 13494.037/13535.018 | 13540.453/13586.521 |
| 1000 | 1000 | 100000 | 0 | 17.759/39.047 | 19.074/30.376 | 10.875/32.881 | 4.408/5.161 | 1.643/1.675 | .154/.155 | 11495.495/11532.003 | 11496.155/11552.692 |
| 1000 | 1000 | 100000 | 1 | 40.742/48.631 | 25.856/30.197 | 33.771/42.121 | 4.567/4.955 | 1.742/1.823 | .144/.145 | 11904.937/11917.891 | 11920.328/11959.092 |
| 1000 | 1000 | 100000 | 3000 | 1668.258/1684.149 | 1638.415/1870.681 | 1311.747/1326.977 | 6.492/6.766 | 1.940/1.979 | .139/.139 | 14061.151/14094.279 | 14048.792/14049.570 |

At T0=100,000/N=0, the receiver copies 19,900,000 signed bytes, 3,200,000 ordered-ID bytes and 200,000
transaction/sender-nonce memberships even though the new body is empty. Slot/hash maps and canonical
header/proposer/protocol metadata add H-dependent copying. Estimates exclude allocator/node overhead.
At N=3,000, receiver pre-copy T grows to 103,000/109,000/115,000 across samples; each database ends with
118,000 entries. Largest measured current RSS/cumulative process HWM was **212,212 KiB (~207 MiB)**;
it is not a row-local peak measurement. Largest regular workloads' database size before producer
samples grew approximately 48.5–54.2 MB; all raw row outputs report actual byte ranges/copy estimates.

Full reopen audit is the dominant retained-T cost: H0=100/T0=100,000/N=0 has audit median 11,106.530 ms
inside 11,523.587 ms total. With N=3,000 the final 118,000-entry archive needs roughly 13–14 seconds
to audit/reopen. Empty-history growth alone is measurable: A=1,000/H0=10,000/T0=0/N=0 audit median
48.621 ms and total 158.641 ms, reflecting per-body account cloning plus metadata/index reconstruction.
These costs are not removed from totals or replaced with a tip-only load.

### Actual Durable-but-Unpublished Recovery Benchmark

The test-only release benchmark uses an **application post-COMMIT publication failpoint**, not a
physical I/O fault, to poison the owner after an additional empty block is durable. Its recover-to-Ready
timer includes full retained-history audit, exact attempted-block reconciliation, sync barrier and RAM
refresh. It is separate from both Ready-refresh timing and real I/O-failure evidence. Three samples
at each listed point; each recovered the exact new attempted record. Subsequent samples grow H by one.

```text
ETX_STAGE4_BENCH_CASE=<3|11> ETX_STAGE4_BENCH_BODY=<0|3000> cargo test --release --lib canonical_fixture::tests::uncertain_history_benchmark -- --exact --ignored --nocapture
```

| A | H0 | T0 | N | Recover total ms med/max | Audit med/max | Validation/read/rebuild med/max | Barrier med/max |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 100000 | 0 | 0 | 0 | 67.456/68.355 | 3.779/4.180 | 58.117/58.297 | 3.467/4.397 |
| 100000 | 0 | 0 | 3000 | 2125.143/2128.730 | 2008.851/2011.037 | 112.878/113.352 | 2.174/2.193 |
| 1000 | 100 | 100000 | 0 | 11550.555/11561.538 | 11123.855/11131.305 | 423.605/424.932 | 1.843/1.871 |
| 1000 | 100 | 100000 | 3000 | 13708.599/13720.431 | 13190.938/13203.496 | 511.114/511.316 | 1.827/2.189 |

Across regular completed rows the worst receiver/producer pipelines were **1,745.958 / 1,870.681 ms**,
87.30% / 93.53% of the **2,000 ms execution reference**. Maximum observed is not a hard bound and
does not prove the production deadline safe. Durable commitment itself reached 1,398.510 ms;
header/transaction checks, authentication/execution and cache work add real costs. The 2,100 ms
publication deadline is not used as an execution budget. No failures/lock waits occurred in completed
benchmark samples; the whole-run timeout is explicitly reported above, not discarded.

## Scaling Limits, Deviations, and Integration Dependencies

- Full archive/body/index copies and destruction on every append are intentional baseline costs,
  with unbounded retained-cache memory and growing work. Full reopen revalidates all retained signed
  entries and repeatedly clones audit account state. An optimized change-set/cache/checkpoint design
  is a separate project; this task did not weaken correctness or durability to improve results.
- The implementation follows the approved experimental format, fixture grants, schema separation,
  append/recovery ownership and §4.3.1 phase precedence. Routine choices include a separate coordinator
  sharing crate-private disk helpers and complete expected-seed comparison on reopen. No protocol
  format/rules deviations were needed. Resource-driven benchmark splitting/omissions are disclosed.
- Only ETX balance/nonces and native gas/burn accounting are checkpointed along with block metadata.
  Validator/ticket/vault/rewards/issuance/burn-offset/epoch/liveness/economic transition state remains
  outside the projection. Proposer/ticket fields and fixture grants do not authenticate a producer.
- Live RPC/P2P, BLOCK/HIST acceptance, HELLO/STATE imports, slot-engine integration, block signatures,
  protocol blocks/economics, production genesis/chain ID/profile numbering/activation, migrations,
  FCTs/VM/Ethereum, real state/receipt roots and reorgs need separate review/authorization.

Implementation and evidence are complete for this bounded offline experiment. Existing version,
schema-1 and other user changes are preserved. The root design remains ignored/untracked.
No commit or push was performed.
