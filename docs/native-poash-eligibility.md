# P2.1 — Pure C1 Closed-State and Historical Eligibility

`src/native_poash.rs` exports a separate **pure C1 planning boundary**, with support in
`src/native_poash/{genesis,state,history,selection,admission}.rs`. Luna approved D1–D4 of the reconciled
local design for the bounded synthetic C1 trial and authorized **P2.1 only**. D5–D9 remain deferred.

The module supplies immutable validated initialization/snapshot/header inputs, deterministic bytes,
the exact two-stage selector, independent producer-header authentication, and a privately constructed
eligibility plan bound to the complete supplied view. The code imports no prototype `ProtocolState`,
`Ticket`, selector or legacy admission route. It does not construct fixture grants.

**Planning is not canonical application.** There is no SQL owner, body execution, economic application,
year/epoch transition, signing API/journal, socket, timer, receipt or live-node activation in P2.1.
Existing native/authentication/M1 APIs, schemas, domains and golden bytes retain their meanings.

## Actual APIs and Trust Boundary

| API | Contract |
|---|---|
| `Genesis::new(GenesisInput)` | Validate explicit approved public seeds, two exact producer/key/owner/reward associations, collateral and initial tickets; normalize semantic map inputs into one byte order; derive N |
| `Genesis::from_bytes(&[u8])` | Strict bounded decoder for this new descriptor only; reconstruct and require exact byte equality; no fixture/V1 fallback, alternate map order or trailing fields |
| `Genesis::{canonical_bytes,network_id,anchor,initial_state,validators,year_zero}` | Read-only independent policy. `YearZero` is returned by value; editing a copy cannot change genesis/state |
| `ClosedState::from_trusted_snapshot(&genesis, SnapshotInput)` | Validate position/resource bounds, duplicates, fixed identities, lifecycle/bucket/ACTIVE collateral, native totals, supply and unreleased-credit invariants; canonicalize all provided rows |
| `ClosedState::{input,canonical_bytes,id,position}` | Immutable complete **supported C1 snapshot projection**; comparison ID includes N and every encoded field, not just eligible tickets |
| `HistoricalHeader::new(header, claimed_H)` | Recompute H and check new profile/chain/kind/slot range; a bare advertised H or E-ID is insufficient |
| `PrefixContext::from_trusted_history(&genesis, headers, state)` | Require every linked header0..parent, exact independent anchor, closed header/ticket associations, terminal position and snapshot earning/gas/fee/participation metadata |
| `PrefixContext::{initial,historical_hash,slot_start}` | Genesis-only context or explicit complete lookup; missing rows are `MissingHistory(slot)`, never zero/genesis/NoEligibleTickets |
| `SlotStartView::{id,state,parent,genesis,slot,reference,select}` | Frozen complete post-parent view; pure selection under its own state, distinct randomness reference and independent keys |
| `HeaderClaim::new(header, producer, transaction_count)` | Validate C1 profile3/validator kind, reserved roots, count/gas/fee commitments, exact producer commitment and empty-body root; populated transaction root remains opaque |
| `HeaderClaim::{signing_preimage,signing_digest,authenticate}` | Inspect C1 signing bytes; independently check network, canonical signature, recovery and full known key. A correctly authenticated non-selected producer still gets an attribution proof |
| `SlotStartView::plan(&AuthenticatedHeader)` | Match network/slot/parent, derive selection from the view, compare producer/ticket, and privately construct an `AdmissionPlan`; otherwise `NotSelected` or an earlier contextual failure |
| `AdmissionPlan::{view,proof,selection,check}` | Read-only binding to the exact view and attributed claim/signature. `check` refuses another state/history/parent/network/claim. No conversion to an execution seal or commit token exists |

The independent caller supplies trusted initialization and historical state. **Validation here does
not prove execution provenance.** In particular, a complete linked header list is not an audit of
historical signatures, native transaction bodies, historical selection, finality or snapshot
reachability. The later owner/application stage must obtain these inputs from its authoritative
audited prefix and enforce transitions. Do not call the trusted constructors with a peer's state
snapshot or manufacture a context from candidate eligibility claims.

This explicit boundary is necessary in a pure stage without a ledger/application engine. Snapshot
invariants reject malformed or inconsistent inputs; they do not implement the deferred lifecycle
operations that could cause statuses. Tests with independently supplied alternative status views
are input-comparison tests, not claims that C1 has executed a mute/jail/retirement transition.

Typical API composition, with independent inputs supplied by the caller:

```rust,ignore
let genesis = Genesis::from_bytes(&independent_genesis_bytes)?;
let state = ClosedState::from_trusted_snapshot(&genesis, independent_post_parent_snapshot)?;
let prefix = PrefixContext::from_trusted_history(&genesis, independent_headers, state)?;
let view = prefix.slot_start()?;
let expected = view.select()?;
let proof = claim.authenticate(&genesis, claimed_network, &signature_bytes)?;
let plan = view.plan(&proof)?;
plan.check(&view, &proof)?;
```

The example is an API shape, not a signer, executable block receiver or runnable node. Immutable
objects own their data; getters expose shared references or copies. Mutating a cloned input/header
does not change a checked object. A non-forgeable plan constructor is useful for composition, but
its ID is an unkeyed comparison hash, **not a state root or independently authenticated checkpoint**.

## Closed Inputs and Validation

The public genesis supports exactly the approved synthetic fixture, with a fresh supplied run label:

- `trial-A` → public compressed point
  `02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5`, owner/reward Alice
  `7e5f4552091a69125d5dfcb7b8c2659029395bdf`, active ticket1/home bucket3.
- `trial-B` → public compressed point
  `022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4`, owner/reward Bob
  `6813eb9362372eef6200f3b1dbc3f819671cba69`, active ticket255/home bucket3.
- Each vault60,000,000,000,000 quarks, locked0; minimum55,000,000,000,000 for one live ticket.
- Alice liquid1,600,000,000,000,000; Bob32,000,000,000,000; Carol0 at
  `1eff47bc3a10a45d4b230b5d10e37751fe6aa718`; canonical nonces0.
- Post-initialization supply1,752,000,000,000,000, ticket-burn baseline2*T and native/issuance
  counters0. This is the explicitly approved **test fixture**, not the master's public genesis supply.
- Run label1..64 ASCII alphanumeric/`-`/`_`; no normalization. No secret key input/default exists.

`ClosedState` retains exactly the two validator identities and ticket ID/owner associations. Runtime
status, position, full accounts, counters and unreleased credits are explicit input. It checks:

- Unique accounts/validators/tickets, known owners and one consistent lifecycle/bucket category;
  home bucket `2+(id mod254)`, MUTED/retiring1, DEAD0, jailed owners' tickets DEAD.
- ACTIVE owners must have an active ticket and sufficient collateral. `locked <= vault`, consistent
  cooldown/retirement metadata shape; no automatic promotion, punishment or retirement is applied.
- Slot<=200, accounts<=3+200*16, credits<=200. Native gas<=3,200,000, divisible by1,000;
  fees=gas*10; sum canonical nonces=gas/1,000, with checked totals.
- Participation sums to the supplied parent slot; base issuance is that count times the retained
  year0 amount. Exactly one credit per earning slot, amountR0, closed recipient; locked sums reconcile,
  and each vault equals initial vault plus its still-held credits. All original seed accounts remain.
- ETX account/vault supply equals S0+base issuance−fees. No other C1 burn/issuance operation is
  represented as an executable fallback. Serialized zero components are the restricted unsupported
  domain, not production rules for offset/slash/FCT effects.

Genesis normalizes semantic input row permutations, but byte decoding rejects a noncanonical wire
permutation. State input rows/credits are canonicalized with duplicates rejected before they can be
overwritten. Prefix **order is significant**: swapped/duplicate/missing rows fail instead of sorting
an advertised height into a different history.

The public C1 state does not admit new tickets. Multi-bucket/unequal-count vectors exercise the same
private checked selection kernel with explicit synthetic four-ticket inputs; those checks do not
authorize a four-ticket C1 genesis, ticket creation or a new lifecycle transition.

## Exact New Bytes

All integers below are unsigned big-endian, without alignment/default serialization. `T(s)` is BE16
byte length followed by exact ASCII ID/run bytes. Options encode tag0 for None or tag1 then BE64.
Native rules1 already bind intrinsic gas/fee semantics; they are not wrapper price overrides.

### Genesis descriptor, encoding1

Golden run `c1-eligibility-golden-2026` is **1,367 bytes**:

| Half-open absolute offsets | Bytes |
|---|---|
| 0..25 | Literal `b"ETERNIX_POASH_C1_GENESIS\0"`, including final zero |
| 25..29 | BE32(genesis encoding1) |
| 29..57 | T(run label): length26 and26 ASCII bytes in the golden |
| 57..326 | Fixed269-byte parameter block below |
| 326..555 | Exact unsigned trusted anchor header[229] |
| 555..557 | BE16(registry count2) |
| 557..655 / 655..753 | trial-A / trial-B config: T(ID), key[33], owner[20], reward[20], initial vault BE128 |
| 753..757 | BE32(initial snapshot payload length610) |
| 757..1367 | Exact initial snapshot payload |

Parameter block, in this exact sequence:

```text
BE64(chain1162)
native_encoding:u8=2 || BE32(native_rules1) || BE32(poash_rules1)
BE32(header_profile3) || inner_descriptor:u8=4 || outer_descriptor:u8=4
auth_encoding:u8=1 || BE32(auth_rules2)
BE32(slot_ms3000) || BE32(execution_cutoff2000) || BE32(publication_deadline2100)
BE64(each of: sub_epoch_slots1200, epoch_sub_epochs24, lookback32, finality20,
             registration_delay20, reward_hold_epochs4, year_slots10512000)
BE128(each of: ticket_cost10000000000000, vault_base_multiplier5,
              vault_per_ticket_denominator2, initial_rate_numerator3, denominator50,
              annual_decay_numerator9, denominator10, floor_numerator1, denominator200)
BE64(run_slot_bound200) || BE64(run_entry_bound16)
BE32(native_hard_transaction_cap3000) || BE64(native_hard_gas_cap16000000)
supported_operation_mask:u8=1               # bit0: primitive ETX transfer
```

No SQLite schema, peer configuration, local clock, private key or computed N/G field is encoded.
Deferred k/penalty/retirement/qualification policies are not silently assigned values. The open
canonical2-MB definition is not resolved by this smaller experiment descriptor. Inner/outer
descriptor4 fields bind C1 identity/signing interpretation; **no full block wire4 codec** is supplied
by P2.1. Existing fixture profile2/wire2/outer3/auth1 codecs are unchanged.

The trusted unsigned anchor uses shared header layout/hash domain, profile3/chain1162/slot0,
kind0, zero parent, `proposer_id("c1-anchor")`, ticket1, empty transaction/receipt commitments,
zero reserved state root/gas and encoding1 empty protocol-data commitment. It is NOT a produced
validator block or proof of post-anchor state. Only the independent descriptor supplies that authority;
`HeaderClaim::new` refuses slot0. Genesis stores the header rather than a fabricated producer signature.

```text
N = G = Keccak256(exact canonical genesis bytes)
golden N = 2a673342d02b9917ad907154503759ed24dc4e33334f3936c620740faeabbe65
anchor H0 = 859cf8f303560dc5d9a39182fb79dd5e2105a677662ac7da33aefceb9a54bfd8
```

Initial snapshot bytes have no N field: the embedded payload therefore does not introduce a
genesis self-hash cycle. Comparison IDs separately include the computed N.

### Snapshot payload, encoding1

The initial payload is610 bytes. In exact order:

```text
BE32(1) || BE64(post_parent_slot) || post_parent_H[32]
BE32(account_count); each by raw address:
    address[20] || BE128(balance) || BE64(nonce)
BE16(validator_count); each by exact ID:
    T(ID) || status:u8 || BE128(vault) || BE128(locked)
    BE32(misses) || BE32(offenses) || BE64(produced) || optional(cooldown_until)
BE16(ticket_count); each by numeric ticket ID:
    BE64(ID) || T(owner) || bucket:u8 || lifecycle:u8
    optional(retire_start) || optional(retire_effective)
BE16(credit_count); each by earning slot:
    BE64(earning_slot) || T(validator) || BE128(amount)
    BE64(earning_epoch0) || BE64(confirmed_hold4)
BE64(cumulative_actual_gas)
BE128(each of: fee_burn, ticket_burn_baseline2*T, base_issuance,
              unsupported_offset0, slash0, FCT_creation0, other_ETX_burn0)
BE64(year0) || BE64(epoch0) || BE64(sub_epoch0)
BE64(year_record_index0) || BE64(boundary_slot0) || BE64(effective_first_slot1)
BE128(each of: initial_supply1752000000000000, rate_numerator3, denominator50,
              retained_reward10000000, remainder0, division_denominator525600000)
```

Validator tags: Active0 / PausedLowVault1 / Cooldown2 / Inactive3 / Jailed4. Ticket tags:
Active0 / Muted1 / Dead2 / Retiring3. This is the pure snapshot comparison codec, not a SQL schema
or mutable checkpoint loader; only genesis decoding is public in this stage. Retirement metadata
shape is checked, without inventing D9's effective-time rule. Four-epoch hold metadata is retained,
without executing a maturity/release transition. Only initialization of the approved year0 record
is calculated; current snapshot supply never recalculates its amount.

### Historical-view identities and selection

The following exact domains include their displayed final zero. They are **local comparison
identities**, not signed authority or replacements for the reserved header state root:

```text
state_id = Keccak256(b"ETERNIX_POASH_C1_SNAPSHOT\0" || N || snapshot_payload)
prefix_id = Keccak256(b"ETERNIX_POASH_C1_PREFIX\0" || N || BE16(header_count)
                     || header0[229] || ... || header_parent[229])
view_id = Keccak256(b"ETERNIX_POASH_C1_SLOT_START\0" || N || prefix_id || state_id
                   || BE64(next_slot) || parent_H || randomness_reference)
```

For s1..31 reference=N; at32 reference=H0, at33 H1, at64 H32. **Start(s) is post-state(s−1)**,
not state(s−32). Missing context fails before even a genuinely empty eligibility set is considered.
The selector uses the unchanged approved literal domains (no terminators):

```text
seed = Keccak256(b"eternix:leader-selection:v1" || reference || BE64(slot))
total = checked sum of eligible ticket counts in buckets2..255
threshold = 2^64 mod total
raw = BE64(first8(Keccak256(b"eternix:bucket-selection:v1" || seed || BE64(retry))))
accept raw >= threshold, offset = raw mod total; otherwise checked retry++
choose bucket by increasing cumulative count; score only within that bucket
score = Keccak256(b"eternix:ticket-selection:v1" || seed || BE64(ticket_ID))
minimum (score bytes, numeric ticket_ID) wins
```

Invalid state/overflow/missing history do not return `NoEligibleTickets`. Input permutations do not
change canonical bytes/scores; duplicate ticket IDs are invalid, not tie candidates. A selection
plan includes the full view/proof and cannot be rebound to an altered account allocation even at
the same parent H and with the same winner.

### C1 producer-header attribution bytes

`HeaderClaim` uses shared exact header[229], profile3. Count<=16, actual-gas claim=count*1,000,
fee claim=count*10,000 and encoding1 protocol-data root are checked. Empty count requires the
canonical empty transaction root. For nonempty claims the root is opaque: body validity is later work.

```text
preimage = existing b"\x19ETERNIX\0BLOCK_SIGN\0"[20]
         || outer_descriptor4:u8 || auth_encoding1:u8 || BE32(auth_rules2)
         || BE64(header.chain_id) || N[32] || BE32(header_profile3) || H[32]
length = 102 bytes
digest = Keccak256(preimage)
signature = canonical r[32] || s[32] || y_parity[1]
```

Canonical signature/recovery reuses `native_transaction::NativeSignature`: low-s, parity0/1,
prehash recovery/verification and exact full compressed-key comparison. The candidate cannot
install a binding. Header identity H still excludes producer S. Changing network/profile/auth
descriptors changes the signed statement. A valid non-selected signature is **successfully
authenticated**, then rejected by `plan` as `NotSelected`. It is not mislabeled as a bad signature.

No complete signed envelope E/E-ID, body sealing or publication permission is created here. In
particular, an old profile2 `BlockAuthenticationContext` still rejects profile3/auth2; P2.1 does
not broaden it. There is no new production signing method or claim of signing-journal protection.

## Independent Vectors and Actual Checks

`tests/fixtures/native_poash_eligibility.json` freezes the complete1,367-byte genesis as concatenated
64-byte hex chunks, exact anchor header/H0, initial state ID,65 synthetic linked-prefix H values,
four boundary views and eight actual producer-header signatures/preimages/digests/public keys.
It also freezes four two-ticket/four-ticket selector-kernel cases, including unequal bucket weights.
Chunk segmentation is JSON fixture presentation only, not part of canonical genesis bytes.

The independent checker packs fields with Python `struct`/integer widths, uses OpenSSL Keccak,
the existing separate public-test RFC6979/curve reference and OpenSSL ECDSA verification, and
calls **no Rust encoder/selector/signer**. It never writes/replaces a golden. The synthetic history
uses explicit empty headers and earning metadata as fixture construction, not canonical execution
evidence. Multi-bucket kernel fixtures do not bypass public C1's closed two-ticket validation.

| Planned slot | Randomness reference | Snapshot bytes | Independent winner |
|---:|---|---:|---|
| 31 | Full genesis N | 2,080 | trial-B / 255 |
| 32 | Actual anchor H0 | 2,129 | trial-A / 1 |
| 33 | H1=`6453370f88b450ba5280e142fb52035486505e54443b5dd9249c5fdee1eac7ad` | 2,178 | trial-A / 1 |
| 64 | H32=`69d5f0b9d72583c4ca43cc0d899103a278264ba6d22318fd8c0580d396844006` | 3,697 | trial-A / 1 |

Focused debug/release module suites: **11 passed per mode**, covering:

- Exact independent bytes/IDs/selection/signature vectors and all genesis truncations/fixed-byte
  mutations; closed seeds, aliases/duplicate identities, reset identities, noncanonical/trailing bytes.
- State/map/credit permutations; malformed/duplicate/unknown state, insufficient ACTIVE collateral,
  missing credits, locked/supply/native-total errors; strict prefix claim-H/link/order/anchor/network/
  ticket/position checks and holes0/1/32/63; explicit slot200 stop.
- Slot31/32/33/64 lookback versus complete post-parent state, historical status-view changes,
  genuine `NoEligibleTickets` distinguished from a missing ancestor even with an empty eligible set.
- Correctly authenticated selected/non-selected producers; old-profile/network-domain/signature/
  ticket/parent failures and exact plan/state binding. Actual native entry counters prove **zero
  native authentication/body-stage/execution calls** during producer-header planning.
- Multiple buckets/unequal counts/permutation invariance; forced raw0→raw1 rejection branch and
  equal mocked-score ticket-ID tie. No natural Keccak collision/rare draw is falsely claimed.

Development found an extra-zero transcription in the first long literal genesis golden. It was
corrected against the independent calculation and split into fixed-size chunks before freezing;
the checker and Rust exact-byte tests now agree. No existing golden was changed.

Reproduction/check commands:

```bash
cargo test --lib native_poash
cargo test --release --lib native_poash
python3 -B scripts/reproduce_native_poash_eligibility.py
cargo test
cargo test --release --lib
cargo test --example testnet_fixture_peer
cargo test --release --example testnet_fixture_peer
cargo fmt --check
cargo clippy --all-targets
```

The existing independent native, stage4, block-authentication, S1 profile, S3 transport and S4
retrieval checkers also form the byte-compatibility checks. Their fixtures and implementations
remain unchanged; this task adds a library module/export, new vectors/checker/tests and this document.

Completed verification:

- Full `cargo test`: **200 passed** (156 library +44 binary),13 ignored benchmark/controlled-child
  entries; includes existing native/authentication/storage and actual worker/recovery regressions
  plus prototype HIST/BLOCK rejection. Release library: **156 passed**,13 ignored.
- Peer example suites: **8 passed per mode**, retaining all fixture profile/framing/vector checks.
- All seven independent checkers completed: native5/262 malformed signatures; stage4 four vectors/
  43 prefix headers; producer-auth six/262 malformed signatures/82 payload mutations; unchanged630-byte
  S1 genesis; six S3/four S4 frames; new1,367-byte C1 genesis/65 H values/four views/eight attributed
  headers/four selector kernels. Native/producer checkers use their original contexts, not relabeled C1.
- `cargo fmt --check`, `cargo clippy --all-targets` and tracked/new-file whitespace checks pass.
  Clippy reports only the existing prototype warnings, with no new C1 warning.

Exact independent commands, in addition to the C1 checker above:

```bash
python3 -B scripts/reproduce_native_auth_vectors.py
python3 -B scripts/reproduce_stage4_vectors.py
python3 -B scripts/reproduce_block_auth_vectors.py
python3 -B scripts/reproduce_testnet_fixture_profile.py
python3 -B scripts/reproduce_testnet_fixture_transport.py
python3 -B scripts/reproduce_testnet_fixture_catchup.py
```

The new module, vectors and pure tests establish P2.1's stated boundary, not a new multi-process
PoAsh trial or storage/power-loss/performance result. Existing full-suite storage evidence is
compatibility coverage, not relabeled evidence of a new C1 owner.

## Review Boundary and Limits

This delivers the approved pure P2.1 boundary. Source-state authority, linkage and body execution
are different facts; only the first two inputs/invariants are represented here. The later owner must
establish audited historical-state provenance, native body validity, complete state transitions,
duplicate/commit/recovery generation behavior and signed-evidence persistence. A plan or producer
header proof is not a commit receipt, consensus-finality certificate or substitute for those checks.

D1–D4 are recorded in the ignored local design, while D5–D9 remain deferred. This implementation
does not add their mechanisms or the approved-but-later SQL/economic/signing-journal contracts.
M1 remains the separately compatible controller-granted baseline. No public deployment, timed
PoAsh liveness/finality or performance guarantee follows from these pure tests. Stop for P2.1 review.
