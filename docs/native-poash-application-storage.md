# P2.2 — Complete C1 Application and Fresh Authoritative Storage

This implements the **bounded C1 transition and schema-4 owner** authorized for P2.2. It builds on
the frozen [P2.1 eligibility inputs and vectors](native-poash-eligibility.md). C1 remains the explicitly
approved synthetic two-validator/two-ticket, reserved-root, **200-slot / 16-entry** experiment.

The new public modules are `native_poash::application` and `native_poash::storage`. Existing native
encoding2/rules1, fixture header2/inner2/outer3/auth1, schemas1–3, M1 transport and old goldens retain
their meanings. No dependency, prototype execution, ingress or activation change is required.

## Authority and Actual APIs

| API | Actual contract |
|---|---|
| `application::Block::from_parts` | Immutable profile3 C1 header/body object; validates count, producer, reserved roots, gas/fee/protocol/root commitments; native entries remain opaque |
| `Block::{from_wire_bytes,wire_bytes,claim,hash,transactions,protocol_data}` | Strict inner4 codec and read-only constituents; no old-wire fallback or implicit rehash of a false received H |
| `application::Envelope::{from_parts,from_wire_bytes,wire_bytes,id}` | Exact outer4/auth1/rules2 wrapper, network claim and original compact signature; construction/decoding is not attribution |
| `Envelope::{block,network_id,signature_bytes,authenticate}` | One full-key header authentication against independent `Genesis`; returns private-constructor `AuthenticatedEnvelope` |
| `AuthenticatedEnvelope::{envelope,header}` | Attribution only. No conversion to a fixture grant, execution seal or canonical commit token |
| `storage::PoashTrialStore::create(path,&genesis)` | Exclusive fresh-path creation; schema/genesis/year/accounts/accounting/anchor-state/tip/completion marker in one transaction, then filesystem/directory sync |
| `PoashTrialStore::{reopen,recover_existing}` | No-create independent genesis check, full historical authentication/selection/native/economic replay, exact complete materialization equality, then synchronization barrier |
| `PoashTrialStore::{snapshot,settings,export_envelope}` | Coherent Ready state/index/evidence views and exact original appended envelopes. Slot0 is unsigned and cannot be exported as a signed block |
| `PoashTrialStore::slot_start` | Derive `SlotStartView` from this owner's current complete audited prefix; no caller snapshot/view/plan parameter |
| `PoashTrialStore::prepare_next(producer,ticket,body)` | Require the locally selected producer/ticket first; stage native once, construct finalized unsigned C1 block, apply the compound reward/state once |
| `PreparedBlock::{block,candidate}` | Read-only finalized unsigned content and already-computed compound candidate; non-cloneable, bound to unique owner generation and exact complete base |
| `PoashTrialStore::seal_prepared(prepared,bytes)` | Check generation/base before packet work; authenticate producer once, compare exact finalized block, privately seal the already-owned effects |
| `PoashTrialStore::stage_received(bytes)` | Ready/framing/context → producer authentication → authenticated known-H reference or historical selection/parent checks → one native stage → complete compound candidate |
| `StagedBlock::{proof,candidate}` | Immutable private-constructor one-use owner seal; no public snapshot/plan constructor |
| `PoashTrialStore::commit(stage)` | Exact RAM and SQL-base/prefix checks; one atomic SQL transaction for every effect and original evidence; install once; no producer authentication/native stage/reward replay |
| `PoashTrialStore::recover` | Poison first, invalidate all preparations, no-create reopen, full replay, exact attempt/base/evidence reconciliation, real synchronization barrier, then coherent installation |
| `PoashTrialStore::{is_ready,is_halted}` | Diagnostics only; neither is permission to sign, acknowledge or schedule |

`Snapshot` includes complete `ClosedState`, chronological `Record`s, native-ID membership and
sender/nonce membership. Its `tip()` is the exact post-state `Position`. Each record retains the
original authenticated envelope, native `BodyOutcome` and complete supported post-state. Snapshot
clones are values for inspection; mutating a clone cannot authorize or install effects.

**The independent genesis and the owner's audited prefix are authority.** Public P2.1 trusted-input
constructors intentionally remain usable for pure comparisons; no owner API accepts their snapshots
or `AdmissionPlan`s as canonical authority. `Snapshot::prefix`, compound application, base tokens and
sealing constructors are private. Neither `FixtureAdmissionGrant` nor prototype state is used.

This is offline application infrastructure. `prepare_next` supplies no signing service, reservation,
intent log or durable signer protection. Tests sign only published small-integer toy inputs outside
the owner. **P2.3's fenced durable signing lifecycle is still required before the producer-process
trial.** There are no C1 sockets, queues, scheduling, wall-clock acceptance or prototype integration.

P2.3 now supplies the separate protected signer and isolated process experiment described in
[`native-poash-signing-trial.md`](native-poash-signing-trial.md). The P2.2 codecs, schema and application
semantics below retain their meanings; signer protection remains outside canonical genesis/state.

## Exact New Codecs and Authentication

All integers are unsigned, explicit big-endian, without alignment or serialization defaults. Both
closed producer IDs are seven exact ASCII bytes. Syntax/resource bounds precede input-derived copies.

### Inner wire4

| Half-open offset | Exact field |
|---|---|
| 0..1 | `04` |
| 1..33 | Claimed header-derived H, compared to recomputed H |
| 33..262 | Shared canonical header[229], **profile3**, chain1162, validator-kind only |
| 262..266 | BE32(7) |
| 266..273 | Exact `trial-A` or `trial-B` ASCII producer ID |
| 273..277 | BE32(10) |
| 277..287 | Existing encoding1 protocol data: `01 || BE64(native_fee_burn) || 00` |
| 287..295 | BE64(native count), 0..16 |
| 295..end | In body order: `BE32(199) || exact signed native[199]` for every entry |

Length is exactly `295 + 203*count`: **295..3,543 bytes**. There are no trailing/optional fields.
Header H retains the shared `ETERNIX_BLOCK_HEADER_V1` domain and 229-byte layout. Proposer and ordered
native-ID roots retain their existing domains/widths. The state root is reserved zero and receipts
root is the existing empty-list commitment: these are not claims of authenticated state checkpoints.

Structural checks require slot1..200, nonzero ticket, exact closed producer commitment,
gas=`count*1,000`, protocol fees=`count*10,000`, matching protocol root and ordered transaction root.
Native IDs commit exact signed199-byte entries; structural hashing is not native authentication.
Unsupported protocol kinds, extra witness fields, old wire/profile interpretations and malformed
lengths fail before effects. A supported-looking opaque native body still must pass shared staging.

### Signed outer4

| Half-open offset | Exact field |
|---|---|
| 0..1 | Outer wire `04` |
| 1..2 | Authentication encoding `01` |
| 2..6 | BE32(authentication rules2) |
| 6..38 | Network N, compared with independently expected full canonical-genesis N |
| 38..42 | BE32(exact inner byte length) |
| 42..42+length | Exact inner4 block |
| 42+length..107+length | Original canonical `r[32] || s[32] || y_parity[1]` |

Length is exactly inner length+107: **402..3,650 bytes**. Outer3/inner2 authentication and existing
profile2 APIs continue to reject C1; C1 rejects the old encodings rather than promoting them.

```text
preimage[102] = b"\x19ETERNIX\0BLOCK_SIGN\0"[20]
             || 04 || 01 || BE32(2) || BE64(1162) || N32 || BE32(3) || H32
digest = Keccak256(preimage)
E-ID = Keccak256(b"\x19ETERNIX\0BLOCK_ENVELOPE_ID\0" || complete_exact_outer4_bytes)
```

Canonical parsing/recovery/full compressed-key matching reuse `NativeSignature` and P2.1's
`HeaderClaim::authenticate`; low-s, scalar ranges and parity0/1 are enforced, never normalized.
H excludes producer S; parent and randomness identities remain H, never E-ID. A correctly signed
non-selected producer is attributed successfully and then rejected as `NotSelected` before staging.

## One Compound Transition

For each accepted successor s:

1. Capture the owner's complete post-parent Start(s), exact parent and prefix. Reference=N for1..31;
   from32 require the actual H(s−32). Missing history is a blocked/invalid history, not no tickets,
   a genesis fallback or permission to skip a slot.
2. Authenticate the exact envelope against independent full keys, require selected producer/ticket,
   exact slot/parent and supported C1 pre-state. Only the fixed active registry/tickets is executable;
   misses, offenses, cooldown, registration, retirement, slash/FCT/VM/protocol outcomes are unsupported.
3. Invoke the **existing `native_transfer::stage_body` once**. It authenticates all entries before
   body-ordered execution; exact nonce/maturity/funding and checked primitive arithmetic apply.
   A later failure discards all earlier candidate effects and produces no SQL/reward/count changes.
4. Move the already-staged native accounts and **already-updated cumulative gas/fee totals** into the
   compound candidate. Do not add the per-body totals again. Fee accounting is native burn only;
   period eligible ETX burn equals those fees because C1 admits no other burn-producing operation.
5. Add one participation to the selected validator. Credit the **retained year-zero reward
   10,000,000 quarks** once to its total vault, locked subset and base issuance, including empty
   validator blocks. Record one earning credit for s, earning epoch0 and confirmed hold4. Miss/offense
   counters remain their initialized zero values; no success-decay/qualification rule is inferred.
6. Revalidate complete state: supply, locked-credit/count/issuance equality, collateral, identity,
   nonces/gas/fees, earning slots and supported metadata. All changes remain owned candidate values.
7. Persist state/body/indexes/reward/accounting/tip/original S/E-ID atomically; install once after
   confirmed commitment. Only `AppendOutcome::Committed` allows new success/cleanup/publication.

```text
S = sum(native balances) + sum(total validator vaults)
S = S0 + cumulative_base_issuance - cumulative_native_fees
V[v] = initial_vault[v] + locked[v]
locked[v] = sum(retained credits[v]) = produced[v] * retained_R0
sum(produced[v]) = produced slots = number of earning credits
cumulative_base_issuance = produced_slots * retained_R0
```

Locked rewards are a **subset** of vault supply, not a second balance. Ticket-burn baseline2*T is
retained, not debited again. Unsupported burn/offset fields and period indices retain the frozen
supported snapshot encoding; they are not executable zero-effect defaults for deferred outcomes.
Four-epoch hold metadata is retained without implementing unlock/release or maturity ordering.

The year record is `BE64(year0) || BE64(boundary0) || BE64(effective_first1)` followed by six BE128
values: original S0, rate numerator3, denominator50, retained reward10,000,000, remainder0,
division denominator525,600,000. This **120-byte historical record** is separately retained and
compared on audit, as well as included in each complete state payload. Replay uses its original
genesis-boundary meaning, never current supply. At the65-slot control, recalculation from current
supply would produce a different whole-quark amount; reopen still retains10,000,000.

## Exact Local Schema4

The separately named mode is `native-poash-c1`, local schema version BE32(4). Schema numbers are
**not** part of consensus genesis. No create-or-open, schema1/2/3 migration, backfill, checkpoint
promotion, partial reset, automatic repair or journal deletion is implemented.

Exact DDL and trigger strings are in `src/native_poash/storage/sql.rs`; loads/commit bases/barriers
compare the entire non-SQLite schema object map, including unexpected objects with names such as
`sqliteX...`. SQLite integrity and foreign-key checks must pass. All consensus quantities are BLOBs
with checked SQLite `typeof`/length, not SQLite signed numeric arithmetic:

| Table | Columns in exact stored order / encoding |
|---|---|
| `metadata` | `id` singleton INTEGER1; `version` BLOB4=`00000004`; `mode` TEXT=`native-poash-c1`; exact canonical `genesis` BLOB1..16384; `revision` BLOB8; `barrier` BLOB8; `initialized` INTEGER0/1 |
| `accounts` | `address` BLOB20 primary key, `balance` BLOB16, canonical `nonce` BLOB8; `WITHOUT ROWID` |
| `accounting` | INTEGER singleton1, `gas`8, `fees`16, `issuance`16, reconstructed `supply`16, `participation`8, `eligible_fee_burn`16; all quantities BE BLOBs |
| `year_zero` | INTEGER singleton1, exact `record` BLOB120 |
| `blocks` | `slot`8 primary key/nonzero, `hash`32 unique, `parent`32, exact `header`229, `producer`7, exact `protocol`10, original `signature`65, original `envelope_id`32 unique; `WITHOUT ROWID` |
| `bodies` | `slot`8 primary key, `count`8, body actual `gas`8, native `fees`8; `WITHOUT ROWID` |
| `transactions` | signed `id`32 primary key, `slot`8, `position`8, `sender`20, `nonce`8, original `signed`199; unique(slot,position) and unique(sender,nonce); `WITHOUT ROWID` |
| `rewards` | earning `slot`8 primary key, `validator`7, `amount`16, `earning_epoch`8, `hold_epochs`8; `WITHOUT ROWID` |
| `states` | `slot`8 primary key, `hash`32 unique, complete canonical `payload`610..200000, network-scoped `state_id`32; unique(slot,hash); `WITHOUT ROWID` |
| `canonical_tip` | INTEGER singleton1, `slot`8, `hash`32 |

Foreign keys: `blocks.slot` ↔ `bodies.slot` deferred; `(blocks.slot,blocks.hash)` → `states(slot,hash)`
deferred; transactions → bodies; rewards → blocks; canonical tip → states(slot,hash). They are
checked as one compound write. A block cannot leave an orphan body, reward or post-state unnoticed.

`blocks`, `bodies`, `transactions`, `rewards`, `states`, `year_zero` have immutable UPDATE/DELETE
triggers and explicit INSERT replacement guards covering their unique keys. Metadata policy cannot
be replaced/deleted, or changed once initialized; only revision/barrier advance. Native accounts,
accounting and tip are materialized mutable rows whose exact values must match replay. These guards
are local write invariants, not a claim of adversarial filesystem tamper-proofing.

Slot0 has an immutable independently supplied genesis state in `states`, with tip0 and revision0;
it has **no** appended block/body/reward/signature. Produced slot s has revision s in this contiguous
bounded profile. `states.payload` is the unchanged complete P2.1 snapshot codec, including validators,
tickets, status/counters, vault/locked values, ordered earning metadata, burns/issuance/period/year
metadata and native accounts. Keys/initial policy are in the exact independent genesis. Thus all
supported fields are materialized or reconstructible and compared, rather than storing an eligible
list or trusting a verification flag. Maximum permitted C1 payload is151,210 bytes; the decoder's
200,000-byte SQL bound leaves explicit headroom without widening the actual validated domain.

Original bodies are stored once as ordered indexed signed entries. Blocks retain compact original
producer S/E-ID; exact envelopes reconstruct deterministically. Per-slot full state bytes permit
exact intermediate-state comparison and uncertain-attempt reconciliation, not imported state authority.

## Commitment, Audit and Recovery

Connections retain **DELETE / synchronous=EXTRA / foreign_keys=ON / cache_size=-2000 / default spill**.
`BEGIN IMMEDIATE` serializes the writer. Before any candidate write, the owner compares independently
expected genesis, revision, every retained state payload/ID, every block/body/native index/original
S/E-ID, year record, reward row, current native/accounting rows and tip with the captured full base.
No crypto or native replay is hidden in this comparison. A foreign owner/generation is rejected
before packet/SQL work; an externally changed SQL base aborts without candidate writes and blocks
that stale owner until explicit refresh. Publication data/attempt state/E-ID are prepared before COMMIT.

The transaction writes accounts, accounting, block/evidence, body, native indexes, reward, complete
state, revision and tip. Failure before commitment is `Aborted` only after confirmed rollback and
exact previous materialization equality. Any COMMIT error, failed rollback, uncertain old-state
verification or post-COMMIT/pre-publication failure returns `RecoveryRequired` and poisons the owner.
Poison hides snapshot, settings, export, slot-start derivation, staging and commitment success.

Every reopen/recovery audits in a consistent read transaction:

1. Verify exact schema, integrity, independent full genesis and explicit initialization.
2. Start from independent genesis state/anchor, not stored current state or stored post-state rows.
3. For every contiguous slot, reconstruct exact body/envelope, authenticate full historical producer,
   derive its own Start(s)/lookback/selection, stage native once and execute the compound transition.
4. Rebuild all memberships and compare **every** stored per-slot post-state, all original evidence,
   rewards, retained historical year record and final native/accounting/tip values. Wrong/missing/
   extra/tampered rows fail without repair. Old profile anchors cannot supply C1 authority.
5. Acquire a write transaction, recheck the complete audited dataset against concurrent changes,
   increment the non-consensus barrier counter to dirty a page, EXTRA COMMIT, then sync the database
   path and containing directory. Only after that barrier can audited RAM be installed/exposed.

Recovery invalidates preparation generations **before** reopen. A failed reopen/audit/reconciliation/
barrier/install leaves poison and the exact uncertain attempt intact. The next recovery starts by
closing the prior connection; it never automatically resubmits an envelope or recreates a receipt.

For a locally uncertain attempt, compare the exact base prefix and full base state first. **Present**
requires the exact original attempted record, S/E-ID and full candidate state; valid audited
descendants may follow it. **Absent** requires exact equality with the entire old base snapshot.
Different valid content or a consistently authenticated alternate signature at the attempted slot
is unresolved, not inferred present from a revision/H. A known owner without an attempt also pins
its complete accepted state/original-evidence prefix during refresh.

Authenticated exact/alternate-S duplicates return `AlreadyCommitted` before native staging and do
not replace retained originals or repeat any effect. An invalid signature cannot get a reference.
A fresh process with no independent original-evidence pin can establish attribution/replay consistency,
not prove which valid alternate S was historically retained against a malicious database rewrite,
latest network tip or delivery of a previous receipt. The live/uncertain owner does retain that pin.

A distinct-H statement by the historically selected key with the historical ticket/parent produces
`ConflictHalt` before native staging. A non-selected packet does not cause that halt. This is C1's
diagnostic, **not** the full-master body/evidence-validity/slashing/neutralization predicate. The halt
preserves the accepted prefix and readable originals, prevents further work on that instance and
survives its `recover()`; it is an in-memory diagnostic, not a durable conflict-evidence journal.
Fresh process reopen remains an explicit operator operation. No scheduler automatically resumes.

## Independent Vectors and Verification

`scripts/reproduce_native_poash_application.py` packs new bytes independently, runs OpenSSL Keccak
and the separate public-test ECDSA/recovery/OpenSSL verification reference, and executes a separate
body-ordered balance/nonce/supply calculation. It invokes **no Rust codec, selector, executor, signer
or SQL** and never overwrites fixtures. It checks the unchanged independently encoded P2.1 genesis.

`tests/fixtures/native_poash_application.json` freezes10 codec/signature/transition controls at
slots1/2/3/4/5/31/32/33/64/65: full empty inner bytes, exact inner lengths/Keccak, signing digests/S,
E-IDs, complete post-state lengths/IDs, accounts, counts, gas/fees/issuance/supply and ordered native IDs.
The first five include an empty block, four sequential funding/self/zero transfers, another zero
transfer, a funded self-transfer and another empty block; later empty controls cross lookback edges.
All native totals remain6,000 gas /60,000 fees after the six entries, while every empty block earns R0.

The actual-owner test compares producer and receiver after every one of65 slots, then normal reopen
and a third fresh owner replaying original envelopes. Reopen phase counters are separate audit work.
It compares complete states, records, native memberships, original envelopes/signatures/IDs and
retained year metadata. Another test reaches slot200 and rejects further progression; a16-entry
new-recipient block checks both exact wire maxima, all memberships, conservation and restart equality.

Negative tests cover old profiles/schemas, every empty-envelope truncation, bad lengths/tails/
commitments/signatures, selected/non-selected producers, wrong ticket/parent/network, history holes,
later signature/nonce/maturity/funding/combined-debit-overflow/kind/asset failures, private checked
reward overflow and unsupported states. The impossible internal reward-overflow fixture is explicitly
test-only, not a supported imported checkpoint. Native primitive overflow controls remain intact.
Foreign/stale/mismatched producer preparations, generation invalidation, exact SQL-base changes,
changed retained-year/reward/lock/state/index/evidence fields, exact/alternate-S duplicates, exact
absent/present-with-descendants and different-valid-attempt/original-choice failures are exercised.

### New C1 storage-failure evidence

These are **new schema4 actual-owner traces**, using the unchanged VFS machinery. They are not old
fixture measurements relabeled C1 and do not include a performance sweep.

| Phase | Newly observed write/sync/delete events | Nth-operation real error cases | Confirmed aborts | Recovery-required |
|---|---:|---:|---:|---:|
| Atomic initialization | 26 | 48 | 2 | 46 |
| Empty rewarded append | 54 | 104 | 68 | 36 |
| Populated rewarded append | 70 | 136 | 92 | 44 |
| Full replay + recovery barrier | 14 | 24 | 0 | 24 |

The312 cases inject SQLite FULL/write, fsync and delete errors at newly enumerated callbacks. Further
controls inject persistent rollback database-write, failed no-create reopen and actual dirty-barrier
fsync errors. For the small rollback control, a **test-only `sqlite3_db_cacheflush` before requesting
rollback** forces real pager playback under the unchanged cache/durability settings; the failure is
then injected into actual rollback I/O. The first draft merely requested rollback before any dirty
page playback and did not reach that failure; it was corrected rather than counted as I/O evidence.
Separate semantic hooks cover every compound SQL phase and failed recovery/installation gates.

**Process termination:**42 child/parent handshakes kill actual C1 initialization, empty/populated
append and recovery paths, including new year/state/reward/evidence points and journal/database sync
boundaries. Reopen must yield a complete permitted prefix and exact evidence. SIGKILL does **not**
simulate removal of the OS page cache or certify power-loss survival.

**Declared-model power loss:** all164 new write/sync/delete event cuts are rerun for each of two
models (328 cuts): loss of unsynchronized writes, and optional early persistence of the first512-byte
sector of one unsynchronized database write. Synchronized journal/database images are retained.
Initialization cuts produced unusable/uninitialized artifacts; append/recovery cuts yielded exact
old complete prefixes. Separate post-COMMIT image controls, both acknowledged and lost-response,
retain the entire new state and original evidence. This is the VFS's declared sector-prefix/stable-
image model, not physical-device/filesystem certification or proof against every reorder/torn-write
model. No hot journal is deleted to make a recovery pass.

### Commands and Results

```bash
cargo test --lib native_poash -- --nocapture
cargo test --release --lib native_poash -- --nocapture
python3 -B scripts/reproduce_native_poash_application.py
python3 -B scripts/reproduce_native_poash_eligibility.py
cargo test -- --test-threads=4
cargo fmt --check
cargo clippy --all-targets
git diff --check
```

Completed results:

- Focused suites: **31 passed per mode**, one controlled child ignored by default and exercised by
  its parent. This includes20 new passing P2.2 tests plus the11 frozen P2.1 tests.
- Full `cargo test -- --test-threads=4`: **220 passed** (176 library +44 binary),14 ignored benchmark/
  controlled-child entries. The library run completed in296.79 seconds; the initial default-parallel
  run hit the240-second command limit in an existing schema3 crash test, with no reported assertion
  failure. The longer reduced-contention rerun completed, including that test, native/authentication/
  storage/M1 compatibility and prototype HIST/BLOCK rejection.
- All **eight independent reproduction checkers** pass: native5/262 malformed signatures; stage4
  four/43 prefix headers; block-auth six/262 malformed signatures/82 payload mutations; S1's unchanged
  630-byte genesis; six S3/four S4 frames; P2.1's unchanged1,367-byte genesis/65 H/four views/eight
  header proofs/four selector kernels; P2.2's10 vectors over65 slots/six native entries.
- `cargo fmt --check`, `cargo clippy --all-targets`, tracked and new-file whitespace checks pass.
  Clippy has only existing prototype warnings; the new C1 code has none.

Independent compatibility commands, in addition to the two C1 checkers above:

```bash
python3 -B scripts/reproduce_native_auth_vectors.py
python3 -B scripts/reproduce_stage4_vectors.py
python3 -B scripts/reproduce_block_auth_vectors.py
python3 -B scripts/reproduce_testnet_fixture_profile.py
python3 -B scripts/reproduce_testnet_fixture_transport.py
python3 -B scripts/reproduce_testnet_fixture_catchup.py
```

The existing primitive/authentication/archive implementations and all preexisting fixtures are
unchanged. P2.1 source changes beyond its new submodule exports are scope/documentation comments;
its prior golden bytes and public planning semantics remain intact. Local designs/handoffs remain
excluded and the user's package-version edits are preserved. Nothing is staged, committed or pushed.

## Review Boundary

This completes application/storage only within C1's approved supported domain. D5–D9 remain deferred:
no unlocks, boundary settlement, offset qualification/distribution, lifecycle/PBM, miss/collision
progression, fault economics, reorganization or full evidence/finality mechanism is supplied. Missing
history, unsupported outcomes and slot201 cannot become zero-effect blocks. The confirmed20-slot
finality parameter is unchanged, without claiming implemented finality.

Full-state comparison and replay are deliberately bounded/simple; this stage makes no capacity,
deadline, benchmark or power-loss hardware guarantee. Reserved roots cannot authenticate peer
snapshots. Original-evidence storage is not a signer fence. **Stop for P2.2 review; P2.3 remains the
required signing/process milestone.**
