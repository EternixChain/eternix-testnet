# Offline Durable Fixture Storage — Stages 1–3

`src/durable_fixture.rs` implements the fixture-only SQLite backend and coordinator using explicit
synthetic accounts, accounting baseline, trusted network/rules context, and provenance. Canonical tip
is always absent; slots/revisions never become block identity. The library has no prototype importer
or live node call site. Consensus bytes/hashes/rules and live RPC/P2P behavior are unchanged.

## Frozen Storage Contract

- Pinned `rusqlite 0.38.0`, bundled `libsqlite3-sys 0.36.0`, SQLite **3.51.1** (lockfile).
- Single serialized owner, with exclusive Rust access through persist/install/recovery. Multiple
  active writers are outside the operating model; persisted revision/base checks also reject stale
  candidates when another connection advances storage.
- Each connection sets and queries **DELETE, synchronous=EXTRA/3, foreign_keys=ON** and fails if
  unavailable. Zero busy timeout; lock errors are surfaced without automatic retries. Durability
  assumes a local storage stack honoring SQLite locking, sync, and directory sync.
- Local schema **1** is independent of encoding 2 and native rules 1. Arithmetic stays in the checked
  Rust executor, never SQL monetary casts/arithmetic.
- `create_fixture` exclusively reserves with `create_new`: any existing database, empty artifact,
  directory, or symlink fails. Schema/indexes, context, seed/materialized accounts, accounting baseline,
  provenance, revision zero, NULL tip, and logically-last complete marker share **one SQL transaction**.
  Only EXTRA COMMIT plus database and parent-directory `sync_all` returns Ready. Uncertain COMMIT or
  directory sync returns `RecoveryRequired`; replacing an artifact requires a separate caller decision.
- `reopen` / `recover_existing` open read/write **without CREATE**. Missing paths fail without creating
  files. No seeding, filling gaps, resubmission, or manual journal deletion. Public reopen also runs
  the durability barrier: a new process cannot know whether the last caller saw a failed sync.

### Schema and Codecs

| Table | Content / invariants |
|---|---|
| `metadata` | Singleton schema/mode/context/provenance, seed baseline/count, revision, recovery-barrier counter, NULL tip, complete marker |
| `seed_accounts` | Immutable fixture audit snapshot, never applied onto materialized accounts |
| `accounts` | Materialized ETX balance/committed nonce, raw-address primary key |
| `accounting` | Singleton cumulative gas and ETX burns |
| `bodies` | Local revision primary key, slot, encoding/rules, count, actual gas/burns |
| `transactions` | Exact bytes/ID, revision-position index, unique ID and sender/nonce, body foreign key |

Fixed big-endian BLOB widths: address 20, hash 32, chain/nonce/slot/gas/revision/position/count/barrier
8, balance/cumulative burn 16, schema/rules 4, signed transaction 199. SQL type/length constraints and
exact Rust decoding both apply. Singleton tags, marker, and fixed encoding descriptor use constrained
local SQL values. This is fixture storage, not consensus serialization.

Load verifies exact schema definitions/constraints/implicit indexes, integrity and foreign keys,
then reads all fields/records/indexes in one transaction. A separate owned seed audit authenticates
and applies archived bytes, checking contiguous revisions (including empty bodies), counts/outcomes,
sender/nonce/ID/position indexes, and exact final-state equality. Seed count detects missing initial
rows. Materialized state is loaded directly; audit never re-executes on it or reseeds it. Current
balances/accounting need not still match original fixture values.

### Commit and Explicit Recovery

The coordinator does **not** implement `AtomicBodyStore`, whose ordinary errors cannot express
uncertain commitment. Non-cloneable overlays capture generation, revision, complete base, candidate,
and exact body. Commit checks Ready/generation/revision/in-memory equality, preallocates caches,
takes BEGIN IMMEDIATE, verifies context/NULL tip/revision/full persisted base, then writes changed
accounts, accounting, body/indexes, and revision together. Durable COMMIT precedes one installation.

`Committed` alone authorizes caller acknowledgement/cleanup. `Aborted` means pre-effect rejection or
confirmed unchanged storage. SQL ROLLBACK/autocommit alone are insufficient: SQLite can swallow a
pager restoration error. Complete old-state validation is required after SQL-phase rollback.
COMMIT errors and unconfirmed rollback/publication are conservative `RecoveryRequired` outcomes.
Poison blocks snapshot/settings/staging/commit success, with diagnostics available and no auto-retry.

Explicit `recover` invalidates the generation immediately, closes/reopens without CREATE, allows
SQLite hot-journal recovery, verifies the complete dataset, and runs this frozen barrier:

1. BEGIN IMMEDIATE and recheck loaded context/revision against intervening changes.
2. Checked-increment an eight-byte recovery-barrier counter, dirtying a real metadata page.
3. Successful EXTRA COMMIT, database sync, and parent-directory sync.
4. Replace RAM and issue fresh generation/base tokens before returning Ready.

The barrier is a real write, not a read/no-op. Its counter is local recovery metadata, not a body
revision/block height/accounting mutation. Failure stays poisoned; a newly opened owner does not
clear the old owner's poison. `RecoveryReport` resolves stored revision/attempt membership without
retroactive acknowledgement or automatic body retry. Every pre-recovery overlay is invalidated.

## Verification Evidence (2026-10-06)

Sources: `src/durable_fixture/tests.rs`, test-only `src/durable_fixture/tests/vfs.rs`.

| Evidence class | Executed coverage | Limits |
|---|---|---|
| Normal close/reopen | Separate producer/replay files; exact bytes/state/accounting/revision/records/indexes/NULL tip; no reseeding; missing/existing paths; unsigned boundaries; stale tokens/empty commits; both duplicate constraints; corrupt/schema/context/width/marker/index/missing-row rejection | Orderly restart, not crash/power-loss evidence. |
| Application failpoints | 10 initialization locations, 6 SQL-write phases, rollback/post-COMMIT/publication, all 4 recovery phases | Coordinator control coverage, not real I/O evidence. |
| Process termination | **29 handshake-controlled SIGKILL locations per run: 15 initialization + 14 commitment**, 50,001 seed accounts; actual journal/database callbacks; journal presence checked at database-sync cuts | Hot-journal and persist/install-gap recovery; OS/device caches survive SIGKILL. |
| Injected SQLite I/O | Every nth normal-trace xWrite twice (FULL=13, IOERR_WRITE=778), xSync (1034), xDelete (2570), for initialization and commitment; spilled-page rollback write failure (2,048 transfers); initialization rollback truncate failure (1546); recovery-barrier sync failure | Real SQLite abort/uncertainty/poison/recovery behavior; returned errors alone do not model volatile loss. |
| Declared power model | All initialization/subsequent-body write/sync/delete cuts, volatile-loss and sector-prefix variants; acknowledged empty prefix and separately acknowledged transfer retained | Model-conditional valid-prefix/acknowledgement retention, not physical certification. |

Process initialization cuts: schema, context, first/all accounts, accounting, provenance, marker,
before COMMIT, journal/database write, journal/database sync, journal deletion, after COMMIT, before
directory sync. Body cuts: before BEGIN, accounts, accounting, body row, indexes, revision, before
COMMIT, journal/database write, journal/database sync, journal deletion, after COMMIT, and after
installation before caller cleanup/success return. Handshakes select exact callbacks, not sleeps.

The normal-trace I/O sweep uses **34 initialization and 80 commitment cases** (114 selected faults),
plus the separate initialization/body rollback and poisoned-recovery faults. Each case records the
injected operation/ordinal, SQLite extended result, coordinator outcome, and verifies the recovered
complete dataset or uninitialized artifact. The declared power-model sweep uses **15 initialization
and 38 body boundaries per variant: 106 cuts total**, one repetition per boundary per suite run,
plus the independent acknowledged-transfer retention test. Initialization cuts recovered complete
or uninitialized, and all body cuts retained the acknowledged prefix with an audited old/new outcome.
An additional real SQLite trigger/constraint failure at transaction-index insertion confirms that
earlier account, accounting, and body writes roll back together, independently of phase hooks.

### Power-Model Assumptions

SQLite operates on real files while the VFS records stable images. Successful xSync stabilizes
preceding file writes/truncation; xDelete(syncDir=1) durably removes the journal. A selected cut
captures stable images; after connections close, restoring precisely those images discards other
volatile writes and post-cut cleanup. The optional variant destages the first 512-byte sector/prefix
of an unsynced database write early and loses the rest of its page/write. This exercises partial-page
persistence against synchronized journal data. The reserved database directory entry survives as an
empty file in this model; the oracle also allows missing initialization but does not inject entry loss.

The model does not enumerate arbitrary permutations, sub-sector corruption, dishonest fsync,
controller firmware failures, or every directory/device scenario. Initialization must be complete
or missing/uninitialized; later recovery retains the acknowledged prefix and may include/exclude the
unacknowledged body. Every usable result passes complete state/history/index audit, preventing mixed
prefixes. SIGKILL and error-return injection are separately reported and not labeled power loss.

Successful commands:

```bash
cargo fmt --check
cargo test
cargo test --release --lib
cargo test --lib durable_fixture
cargo test --release --lib durable_fixture
cargo clippy --all-targets --all-features
cargo run --release --example durable_fixture_bench -- target 7
```

Full debug: **102 passed** (59 library + 43 binary). Full release library: **59 passed**. One controlled
child entry is ignored by the ordinary runner but explicitly invoked by the process test. Final
focused durable suites: **15 passed each** in debug/release, including all child cuts. Clippy completes
with existing prototype/dead-helper warnings and no new storage/library/test/example warnings.

## Release File-Backed Benchmark

`examples/durable_fixture_bench.rs` requires release mode and an existing parent directory. It creates
exclusive fixtures, verifies workload settings, keeps all samples, surfaces failures, and checks final
complete close/reopen equality outside timing.

Environment: AMD Ryzen 9 9950X (16 cores/32 logical CPUs), 62 GiB RAM; Linux 7.2.7-arch1-1 x86_64;
Rust 1.98.0 / LLVM 22.1.8, default optimized release. Workspace `target` on ext4 (`rw,relatime`),
**WDC WD10JUCT-61CYNY0 rotational 931.5 GiB SATA disk**, not tmpfs. Single writer thread, boost enabled,
no affinity, warm connection/OS caches without flushing, host activity not isolated. Seven samples per
row; zero failures/lock waits, zero busy timeout, outliers retained. No meaningful p95/p99 claim with
seven samples. Maximum is worst observed, not a hard real-time bound.

Verified settings: DELETE, EXTRA/3, foreign keys, page 4,096, cache -2,000 KiB. Counts are exact total
accounts (sender plus synthetic recipients); sequential nonces, one-quark values, existing fixed fee.
Recipient reuse allows small fixtures to execute 3,000 entries without increasing account counts.

Timings: **durable commit** is before BEGIN IMMEDIATE through confirmed COMMIT, including checks,
full persisted-state read/decode/equality, changed-account determination, all writes, and SQLite sync.
**Stored comparison** stays included in that total, never subtracted. **Memory comparison** is full
base equality before BEGIN. **Stage** combines authentication/execution/cloning, excluding signing/
fixture generation. **Cache preparation** is publication/state/index/history allocation before SQL.
**Installation** is owned cache replacement after COMMIT. Pipeline includes residual call/destruction
overhead; there is no pool cleanup in this workload. Initialization is separately timed through
file/directory sync, one sample per size, outside steady state.

Milliseconds, **median / maximum**:

| Accounts | Entries | Touched | Body bytes | Durable commit | Stored comparison | Memory comparison | Stage | Cache preparation | Installation | Complete pipeline |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 100 | 0 | 0 | 0 | 1.827 / 3.423 | .019 / .035 | .000 / .001 | .002 / .004 | .001 / .002 | .001 / .001 | 1.833 / 3.428 |
| 100 | 1 | 2 | 199 | 2.262 / 2.342 | .016 / .022 | .000 / .000 | .119 / .128 | .002 / .002 | .001 / .001 | 2.382 / 2.468 |
| 100 | 3,000 | 100 | 597,000 | 170.307 / 1127.599 | .036 / .040 | .001 / .001 | 337.012 / 362.226 | .627 / .893 | .086 / .142 | 506.799 / 1473.703 |
| 1,000 | 0 | 0 | 0 | 2.094 / 3.229 | .101 / .114 | .002 / .002 | .009 / .018 | .004 / .007 | .003 / .004 | 2.120 / 3.255 |
| 1,000 | 1 | 2 | 199 | 2.349 / 2.605 | .099 / .186 | .002 / .004 | .129 / .246 | .004 / .008 | .003 / .007 | 2.617 / 2.745 |
| 1,000 | 3,000 | 1,000 | 597,000 | 151.496 / 346.090 | .126 / .130 | .002 / .002 | 339.708 / 358.265 | .507 / .716 | .099 / .145 | 486.131 / 682.227 |
| 10,000 | 0 | 0 | 0 | 3.396 / 3.813 | .927 / 1.186 | .022 / .040 | .070 / .251 | .030 / .103 | .018 / .027 | 3.608 / 4.100 |
| 10,000 | 1 | 2 | 199 | 3.607 / 4.424 | .939 / 1.109 | .022 / .032 | .195 / .244 | .029 / .053 | .020 / .046 | 3.954 / 4.717 |
| 10,000 | 3,000 | 3,001 | 597,000 | 167.269 / 315.475 | 1.013 / 1.196 | .023 / .039 | 338.877 / 346.177 | .603 / .829 | .176 / .286 | 514.452 / 652.142 |
| 100,000 | 0 | 0 | 0 | 20.100 / 21.813 | 10.904 / 12.761 | .673 / .913 | 1.745 / 4.032 | .971 / 2.219 | .789 / .925 | 25.228 / 30.150 |
| 100,000 | 1 | 2 | 199 | 20.828 / 39.662 | 11.128 / 13.447 | .629 / .806 | 1.856 / 2.204 | .967 / 2.169 | .790 / 1.663 | 27.030 / 46.790 |
| 100,000 | 3,000 | 3,001 | 597,000 | 219.986 / 350.438 | 11.306 / 12.538 | .724 / .952 | 339.384 / 344.469 | 1.584 / 1.931 | .927 / 1.224 | 568.797 / 695.898 |

Initialization samples: **4.118 / 6.576 / 44.527 / 511.198 ms** for the four account sizes.
Before samples the rollback journal is absent (0 bytes). Existing history counts grow **0–6** (empty),
**7–13** (single), **14–20** (3,000); corresponding index counts **0**, **0–6**, **7–18,007**. Each database
ends with 21 bodies and 21,007 signed/indexed entries, exercising growing history/indexes.

| Accounts | Database bytes before empty/single rows | Bytes before 3,000-transfer samples |
|---:|---:|---:|
| 100 | 53,248 | 53,248–8,663,040 |
| 1,000 | 151,552 | 151,552–8,671,232 |
| 10,000 | 1,208,320 | 1,208,320–9,748,480 |
| 100,000 | 11,751,424 | 11,751,424–20,291,584 |

Against the **2,000 ms execution reference**, the largest-account/3,000-transfer storage median uses
11.00%, complete pipeline median 28.44%. Worst observed storage/pipeline across sizes uses 56.38% /
73.69%. These are host/workload observations, not activation or deadline guarantees; the 2,100 ms
publication deadline is not used as an execution budget.

SQLite compile options (compiler string spaces represented by underscore):

```text
ATOMIC_INTRINSICS=1 COMPILER=gcc-16.2.1_20260810 DEFAULT_AUTOVACUUM
DEFAULT_CACHE_SIZE=-2000 DEFAULT_FILE_FORMAT=4 DEFAULT_FOREIGN_KEYS
DEFAULT_JOURNAL_SIZE_LIMIT=-1 DEFAULT_MMAP_SIZE=0 DEFAULT_PAGE_SIZE=4096
DEFAULT_PCACHE_INITSZ=20 DEFAULT_RECURSIVE_TRIGGERS DEFAULT_SECTOR_SIZE=4096
DEFAULT_SYNCHRONOUS=2 DEFAULT_WAL_AUTOCHECKPOINT=1000 DEFAULT_WAL_SYNCHRONOUS=2
DEFAULT_WORKER_THREADS=0 DIRECT_OVERFLOW_READ ENABLE_API_ARMOR ENABLE_COLUMN_METADATA
ENABLE_DBSTAT_VTAB ENABLE_FTS3 ENABLE_FTS3_PARENTHESIS ENABLE_FTS5 ENABLE_LOAD_EXTENSION
ENABLE_MEMORY_MANAGEMENT ENABLE_RTREE ENABLE_STAT4 HAVE_ISNAN MALLOC_SOFT_LIMIT=1024
MAX_ATTACHED=10 MAX_COLUMN=2000 MAX_COMPOUND_SELECT=500 MAX_DEFAULT_PAGE_SIZE=8192
MAX_EXPR_DEPTH=1000 MAX_FUNCTION_ARG=1000 MAX_LENGTH=1000000000 MAX_LIKE_PATTERN_LENGTH=50000
MAX_MMAP_SIZE=0x7fff0000 MAX_PAGE_COUNT=0xfffffffe MAX_PAGE_SIZE=65536
MAX_SQL_LENGTH=1000000000 MAX_TRIGGER_DEPTH=1000 MAX_VARIABLE_NUMBER=32766
MAX_VDBE_OP=250000000 MAX_WORKER_THREADS=8 MUTEX_PTHREADS SOUNDEX SYSTEM_MALLOC
TEMP_STORE=1 THREADSAFE=1 USE_URI
```

Compiled DEFAULT_SYNCHRONOUS=2 is overridden and queried as **3** on workload connections; no
synchronization or full-state comparison was weakened for measurement.

Stages 1–3 are implemented and verified. Canonical block/tip metadata, migration authority, production
genesis/final chain ID, and activation are separately reviewed tasks. The live node's volatile
persistence hook is not replaced. No commit or push was performed.
