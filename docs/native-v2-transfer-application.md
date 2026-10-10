# Offline Native V2 Transfer Application

`src/native_transfer.rs` adds one shared native rules-1 application path, exported by the isolated
library. The live node binary does not import it. It does not alter RPC/P2P admission, remote block
acceptance, `HELLO`/`STATE`, production activation, genesis, FCT/validator/vault/ticket operations,
raw Ethereum, or historical V1 bytes/hashes/roots.

## Inputs and State Boundary

Application depends on exactly the supplied native account snapshot, trusted explicit
`AuthenticationContext`, inclusion slot, and signed body bytes. Persistence success/failure controls
installation but not the deterministic candidate calculation. There are no wallet keys, mempool,
pending nonce reservations, host clock, locale, or map-iteration choices in this calculation.

`TransferState` is an owned offline ETX account/accounting projection:

- A `BTreeMap` of raw twenty-byte addresses to `TransferAccount { balance_quarks: u128, nonce: u64 }`.
- Cumulative `gas_used_total: u64` and `fees_burned_total: u128`, checked on each update.
- Missing accounts read as balance zero and initial nonce zero without being inserted on reads.

These are Rust snapshots for the offline harness, not a newly frozen production storage format,
state-root encoding, or genesis allocation scheme. Cumulative gas is offline committed accounting;
per-body actual gas and burns are returned separately. No conversion from prototype `Account`,
`ProtocolState`, wallet keys, or `nonce_tracker` is implemented or inferred.

## Shared Stage/Persist/Install Path

1. `stage_body` authenticates every exact signed V2 entry using the supplied chain/genesis/rules
   context. Unknown kinds/assets, insufficient intrinsic gas, exhausted transaction nonces,
   malformed bytes, and invalid signatures fail explicitly before state execution.
2. It clones the input snapshot into an independently owned candidate; it never temporarily swaps
   a candidate into live state. Authentication and execution failures therefore discard all effects.
3. The private primitive-transfer function processes authenticated entries in exact body order.
   Prior entries' balances and nonces are visible to later entries; no invalid entry is skipped.
4. `StagedBody::commit` checks the complete live snapshot against the captured base, then calls the
   fallible `AtomicBodyStore::persist` boundary with base, candidate, and exact body record.
5. Only after persistence succeeds is the candidate moved into live state once. Committing an
   already-executed producer overlay does not execute or charge its transactions again.

`apply_body` is the shared synchronous wrapper for stage/persist/install. An offline producer may
prepare/inspect a `StagedBody` and consume it at commit; an independent receiver may use `apply_body`
on the same bytes. Both use the same authentication and application function.

Failure ordering is deterministic by phase and body index: complete-body authentication first,
then body-ordered state execution. Any failure rejects the whole body. Error indexes are body
positions, never mempool positions.

## Primitive ETX Rules

- Native rules 1 and primitive-transfer kind only; value asset ETX ID 0 only.
- Declared `gas_limit >= 1000`; actual gas is exactly 1,000, irrespective of a larger limit.
- Fee is exactly 10,000 quarks, debited and burned in ETX; no proposer/recipient fee credit.
- Declared nonce must equal the current staged sender nonce exactly.
- Inclusion slot must be at least `valid_after_slot`, including equality.
- Value plus fee, balances, nonce increments, body totals, and cumulative accounting use checked
  arithmetic. No wrapping, saturation, or debug/release-dependent behavior is permitted.
- Full combined debit must be representable and funded before credit, including self-transfers.
- A self-transfer debits and credits one consistent staged sender record. Its net balance change is
  only the fee, and its nonce increments exactly once; a stale recipient copy cannot overwrite it.
- A zero-value transfer still consumes 1,000 gas, burns 10,000 quarks, and increments sender nonce.
  Zero credit leaves the recipient record untouched, including an absent/default one. This sparse
  representation does not prescribe production account pruning or a state-commitment encoding.
- Nonces advance in a candidate, but become canonical only with successful atomic installation.

Consumed canonical nonces reject duplicate entries and reapplication of committed transfer bodies,
including re-signed/different-ID transactions at the same sender nonce. No new block identity,
slot-progression, finality, reorg, or block-level exactly-once rule is invented. An empty body has no
canonical account or accounting effects; any future block-level duplicate gate remains upstream.

## Persistence Contract and Architectural Limits

`AtomicBodyStore` must atomically persist the candidate snapshot and `AppliedBody` record. The record
contains trusted context, explicit slot, exact authenticated bytes, ordered transaction IDs, gas,
and burns; it is an in-memory offline record, not a native block or prescribed database schema.
Returning `Err` must leave committed storage unchanged. The applicator preserves live state on Err
and rejects stale prepared overlays before calling persistence.

The harness/tests provide an atomic in-memory store with injected failure after preparing its
pending storage update but before publishing it. This demonstrates rollback of state and records;
it is not crash-safe disk persistence. A backend that writes partially or reports an indeterminate
error after committing cannot satisfy this contract without transactional/recovery work.

The separate [`durable fixture coordinator`](durable-fixture-storage.md) now provides file-backed
SQLite state/body/index storage for explicit offline fixtures. It reuses this staged executor but
has a richer Committed/Aborted/RecoveryRequired contract, poisoned publication gates, atomic fixture
initialization, and explicit synchronized recovery. It does not implement `AtomicBodyStore` or turn
an uncertain disk outcome into an ordinary applicator error. Its canonical tip remains absent.

There is no architectural blocker for this offline stage. Live integration still requires an
explicit native state adapter/migration, durable transactional storage, and separately approved
block validation/activation. The current live state mixes wallet data and pending nonce tracking;
its no-op persistence hook cannot substitute for this storage contract. Body/transport limits and
parent/producer/tip checks remain upstream block-integration responsibilities.

## Offline Harness and Tests

Run:

```bash
cargo test --lib native_transfer
cargo test --release --lib native_transfer
cargo run --example native_transfer_replay
cargo run --release --example native_transfer_replay
```

The harness uses published toy keys solely to build signed bytes, drops them before application,
and starts producer and receiver from identical explicit synthetic snapshots. Their mempools and
pending nonce reservations differ; none are passed to application. Local producer pool cleanup
runs only after commit and never changes canonical nonce fields.

Its four-entry body includes a transfer funding the next sender, sequential Alice nonces, a
self-transfer, and a zero-value transfer. Expected committed results are:

| Account | ETX balance in quarks | Canonical nonce |
|---|---:|---:|
| Alice | 40,000 | 3 |
| Bob | 15,000 | 1 |
| Carol | 5,000 | 0 |

Actual gas is 4,000 and ETX burns are 40,000 quarks. Producer and receiver compare complete state,
body outcomes, and exact persisted body records. The harness also rejects a later immature entry,
rolls back an injected persistence failure, and rejects duplicate application.

The 23 regressions additionally cover stale/future nonces, nonce exhaustion, combined-funds
insufficiency, absent accounts, self-transfer at maximum balance, recipient nonce preservation,
combined-debit/credit/accounting overflow, tampered/truncated bytes, unknown kinds/assets, gas bounds,
duplicate body entries and changed-ID nonce replay, stale overlays, preservation of previous stored
commits, keyless replay from archived bytes, and empty-body behavior. Both debug and release suites
exercise the same checked failure semantics.
