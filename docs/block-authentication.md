# Offline Block Producer Authentication

`src/block_authentication.rs` implements the approved A–G contracts from the local
`block-authentication-design.md`, solely for its bounded offline stage. The library is exported by
`src/lib.rs`; no live RPC/P2P/slot-engine acceptance is enabled. Producer attribution is distinct
from leader/ticket eligibility, native user authority, execution validity and durable application.

## APIs and Trust

| API | Contract |
|---|---|
| `BlockAuthenticationContext::new(native_context, header_profile, auth_rules)` | Explicit caller-trusted chain/genesis/native context; supports only header 2/native encoding 2/rules 1/block-auth rules 1; no defaults or incoming-policy discovery |
| `ProducerBinding::new(exact_id, compressed_key)` | Nonempty/nonreserved exact UTF-8 <=256 bytes, canonical finite compressed SEC1 key of exactly 33 bytes; no identity normalization or address/key discovery |
| `BlockSignature::from_bytes` / `as_bytes` | Reuses `native_transaction::NativeSignature`; exact 65-byte evidence, parity then scalar then low-s checks |
| `SignedBlockEnvelope::from_parts` / `from_wire_bytes` / `wire_bytes` | Bounded syntax-only owned object, evidence opaque until authentication; no claim of producer/native/state validity |
| Envelope `signing_payload` / `signing_preimage` / `signing_digest` / `envelope_id` | Read-only exact inspection bytes/hashes; computing them alone does not authenticate anything |
| `sign_block(block, key, context, binding)` | Preflight immutable finalized block, match exact producer and full signing key, sign only the approved block domain; state-free and without a signing-intent journal |
| `authenticate_block(bytes, context, binding, optional_claimed_envelope_id)` | Cold exact framing/network/preflight/reconstruction/producer/canonical-signature/claimed-ID/recovery/full-key checks, one producer recovery |
| `AuthenticatedProducerBlock` | Private construction, immutable envelope/context/binding/signature/digest/IDs; attribution proof only, never a receipt, eligibility claim or append token |

Producer identity matches the inner proposer **exactly**, including UTF-8 bytes, and its existing
`block_commitment::proposer_id` commitment. The recovered full compressed key must equal the
caller-supplied binding; a successfully recovered arbitrary key or twenty-byte address is insufficient.
Keys are not learned from envelopes, HELLO, transaction senders, owner/reward addresses or prototype
validator fields. The harness uses one explicitly selected static binding, not a key registry/map
with aliases, rotations or dynamic discovery.

## Exact Frozen Bytes

These values are **experimental offline assignments**, not production numbering or activation.

```text
outer wire = 3:u8
auth encoding = 1:u8
block-auth rules = 1:u32
inner wire = existing 2:u8
header profile = existing 2:u32

D_SIGN = b"\x19ETERNIX\x00BLOCK_SIGN\x00"                     # 20 bytes
hex = 19455445524e495800424c4f434b5f5349474e00
H = Keccak256("ETERNIX_BLOCK_HEADER_V1" || exact header[229])

U = wire[1] || encoding[1] || BE32(auth_rules) || BE64(header.chain_id)
 || network_id[32] || BE32(header.protocol_version) || H[32]  # 82 bytes
signing_preimage = D_SIGN || U                              # 102 bytes
signing_digest = Keccak256(signing_preimage)

S = BE256(r) || BE256(s) || y_parity:u8                      # 65 bytes
E = wire[1] || encoding[1] || BE32(auth_rules) || network_id[32]
 || BE32(L) || unchanged inner wire-2 bytes[L] || S[65]

D_ENVELOPE_ID = b"\x19ETERNIX\x00BLOCK_ENVELOPE_ID\x00"       # 27 bytes
hex = 19455445524e495800424c4f434b5f454e56454c4f50455f494400
envelope_id = Keccak256(D_ENVELOPE_ID || E)
```

U offsets, half-open: wire 0..1, encoding 1..2, rules 2..6, chain 6..14, network 14..46,
profile 46..50, H 50..82. Preimage offsets add 20. Outer offsets: wire 0..1, encoding 1..2,
rules 2..6, network 6..38, L 38..42, inner 42..42+L, S 42+L..107+L.

Integers are unsigned fixed-width big-endian; hashes and keys are raw bytes, not display hex.
Domains include exactly the zero bytes shown. No SHA3-256, text/JSON encoding, optional fields,
Ethereum prefix, secondary message hash or verification-domain fallback is used.

Overhead is **107 bytes**, maximum **609,651 bytes**. L must be 289..609,544, with exact checked total
length before allocation; one signature and no tails/extensions. Original inner limits remain
3,000 entries/256 proposer bytes and actual-gas cap 16,000,000. The 17-byte fixture proposer yields
empty/single/3,000-entry signed sizes **412 / 615 / 609,412** versus unsigned **305 / 508 / 609,305**.

Network ID is the existing native definition, Keccak of the caller-approved canonical genesis bytes
excluding their own computed hash. The library does not establish that genesis codec/authority and
never substitutes prototype `consensus_hash::GENESIS_HASH`. Chain, profile and H come from the inner
block, not duplicated untrusted claims. Network is explicit and compared to caller policy even when
the body is empty. Authentication rules 1 freeze the entire profile mapping; they cannot silently
change native execution rules.

## Cryptography and Identity

Backend: existing k256 secp256k1 ECDSA prehash APIs. Require `1 <= r < n`, `1 <= s <= floor(n/2)`,
parity 0/1. Recovery uses x=r, never x=r+n, rejects invalid/infinite points and verifies the original
32-byte prehash. Received high-s is rejected, not rewritten. Ordinary signing is RFC6979/HMAC-SHA-256
(SHA-256 is internal nonce generation only). Rare x-overflow candidates retry with fresh OS entropy
through the vetted randomized prehash signer; ID 2/3 is never masked into parity. The block adapter
fallibly seeds the existing `StdRng` CSPRNG from OS entropy before calling that backend (whose RNG
convenience call is infallible), so entropy failure returns `SigningFailed` without a panic or reuse.
Controlled tests
exercise both overflow IDs, real fresh retry calls and signing failure. No bespoke secret arithmetic.

The producer signature remains **outside H**. Parent/tip identities, all V1/unsigned native header
bytes/hashes/roots, native 199-byte transaction rules and storage formats remain intact. Multiple
legitimate low-s signatures for one U/H have distinct envelope IDs, the same block identity and no
second application. Native transaction signatures still affect transaction IDs/root/H. Identical
empty headers in different networks may share H; their block digests/envelopes differ, so raw H alone
is not a globally network-unique authenticated identity.

A key can sign conflicting H at the same slot, an ineligible ticket or execution-invalid content.
Two independently authenticated same-context/same-producer/same-key/same-slot different-H statements
can be inspected as an offline conflicting-statement candidate. Different signatures for the same H
are duplicates, not that candidate. No eligibility, fault/slashing rule, evidence transaction,
penalty, fork choice or protocol-block authorization is inferred. The signer is stateless: an abort
or poisoned commit does not revoke a signature or supply crash-safe anti-equivocation protection.

## Admission, Error Order and Once-Only Application

`examples/block_auth_support/mod.rs::SignedFixtureReceiver` privately owns the fixture store. Its
create/reopen methods compare the explicit authentication context to the trusted manifest. Its only
staging entry requires a signed outer envelope and an **independently supplied trusted fixture grant**;
it never creates a grant or key binding from received claims. Its non-forgeable `SignedFixtureStage`
is consumed by ordinary/profiled commitment. These are example/test helpers, not live library admission.

Order:
1. Owner Ready; poison wins over even malformed packets.
2. Outer framing/version/length and bounded inner syntax.
3. Network match, existing inner preflight predicate order, exact canonical reconstruction.
4. Exact producer binding; parity/scalars/low-s; digest/optional envelope-ID claim; one recovered-key
   verification and full-key comparison.
5. Existing store preflight again, stored-block/conflict/successor/parent/revision/grant gates, one
   native `stage_body`: authenticate all entries left-to-right, then execute left-to-right.
6. Existing outcome/uniqueness/token/SQL checks and one durable COMMIT/coherent installation.

The reused store route repeats structural preflight, **not** producer verification or native staging.
Successful commit repeats neither authentication nor execution. Counter tests cover both producer and
receiver, empty and 3,000-entry bodies, ordinary/profiled commitment and poisoned/duplicate failures.
Rollback confirmation and fixture reopen/recovery retain their original separate native archive audit.

Framing/context/inner `BlockError`/producer mismatch/signature canonicality/recovery/key mismatch/
claimed-envelope-ID errors remain distinct. Grant/native-body/base/storage errors retain their original
causes. Invalid signatures on known H are rejected before the stored-block no-op reference. Altering
roots/H after body/protocol tampering does not preserve producer authorization. Protocol kinds remain
unsupported even with known keys. Signature proofs do not bypass actual gas/burn/funding/parent checks.

## Harness and Restart Evidence

```bash
cargo run --example block_auth_replay -- target
cargo run --release --example block_auth_replay -- target
```

Both commands completed successfully. Single and ordered-three-entry cases each use separate real
producer/receiver files from the explicit synthetic anchor/post-anchor state. A following signed empty
block advances tip/revision. Producer preparation runs once, then block signing/outbound encoding is
preallocated before commitment. Receiver independently verifies and stages; mock pools are separate.
Whole state/accounting/archive/index/tip equality, unsigned-input rejection and duplicate no-op checks
pass. Ready refresh and close/reopen verify the existing fixture audit and synchronization barrier.

Exact signed envelopes are written/read as **separate binary test artifacts** and independently
re-authenticated after stores close. They are not a second canonical journal or part of SQL COMMIT.
Schema 1/2, `CommittedBlock`, SQL attempted-record reconciliation and native history audit contain no
producer signature evidence. **Fixture-store reopen/recovery cannot establish authenticated producer
history from SQL alone.** Missing artifacts cannot be filled with a guessed signature or “checked” flag.
The trusted empty anchor's supplied post-anchor state is still fixture authority, not a signed state root.

## Independent Vectors and Adversarial Evidence

`tests/fixtures/block_authentication.json` freezes six independent vectors: empty, single, ordered
three-entry, same-header/different-network empty, maximum chain/slot/ticket and 256-byte UTF-8 producer,
and alternative-signature empty. Literal outer prefixes plus existing frozen inner bytes plus literal
signatures freeze complete packets without copying/changing the unsigned goldens; the extreme inner
is literal hex chunks. Payload/preimage/digest/block/envelope IDs and normalization evidence are frozen.

```bash
python3 -B scripts/reproduce_block_auth_vectors.py
```

The checker completed: **6 vectors**, **262 malformed signatures**, **82 payload-byte mutations**,
both parities, low-s normalization/parity correction and alternative-S identity separation. It packs
bytes with independent Python `struct`, builds native/header commitments independently, uses separate
public-test RFC6979/curve arithmetic, and cross-checks Keccak/points/ECDSA with OpenSSL-backed providers.
It invokes no Rust codec or signer. Only published toy producer scalar 2/native sender scalar 1 and
explicit opaque test genesis inputs are used.

`src/block_authentication/tests.rs` and `src/canonical_fixture/tests/block_authentication.rs` cover
exact golden bytes, all truncations/forbidden parity values/payload/signature/header mutations,
zero/order/half-order/high-s/DER/recovery-point/infinite-key cases, alternate domains, malformed SEC1/
UTF-8/length/version/identity/context, recomputed tampered roots/H, signature-required duplicates,
conflicting headers, unsupported protocol kinds, grants, ordered native failures, actual gas/burn/
funding checks, max valid/opaque-invalid bodies, failed signing, rollback/poison/recovery/stale overlays,
ordinary/profiled equality, unsigned rejection after reopen, and explicit entropy failure without an
infallible OS-RNG call. **20 new tests pass in the full debug/release suites** (11 stateless + 9 composition).

## Complete-Pipeline Measurement Method

Driver:

```text
cargo run --release --example block_auth_bench -- <existing-disk-parent> [phase-pairs=8] [ordinary-pairs=4] [case] [body-size]
python3 -B scripts/summarize_block_auth_bench.py <completed-main-log>
```

Default matrix: A/H/T **1,000/100/0**, **1,000/100/100,000**, **10,000/0/0**, N **0/1/3,000**, both
producer/receiver, signed/unsigned, 8 phase pairs plus 4 ordinary pairs: **432 appends**. US on even
pairs/SU on odd pairs gives equal order positions. Each sample synchronizes a complete independent
copy of a closed trusted base, uses fresh owners and full pre/post archive audits, and compares entire
signed/unsigned results. No retained history is pruned/rewound. A bounded selected 2/2-pair pilot was
used for driver verification and is excluded from main statistics.

Inputs/native transaction signing/history/copying/external equality/printing are outside append
timing. **Producer block signing and outgoing signed/unsigned encoding/preallocation are inside the
producer timer.** Receiver starts with available exact bytes and includes cold attribution, repeated
structural preflight, native execution, all cache copies, SQL comparisons/index/tip/sync, installation,
old-cache destruction and return. Coarse signing+encoding and attribution (decode/preflight/hash/
recovery/binding) spans are labeled combined costs, not isolated raw ECDSA cost. No result cache or
preauthenticated receiver proof is reused; extra clocks remain in totals and are never subtracted.

Ordinary receiver 3,000-entry samples also measure separate **fixture Ready-refresh** recovery; these
are not interrupted/unpublished recovery timings. Full post-append reopen includes the entire native
history audit/barrier. Four separate passes over retained producer-envelope **in-memory test artifacts**
measure their re-authentication, not SQL producer evidence or cold-disk reads. Shared-process RSS/HWM
is reported as cumulative observations, not an isolated per-admission peak or hard memory cap.

All samples retain **DELETE / EXTRA (3) / foreign keys / default cache -2000 KiB**. No 32 MiB option,
WAL, audit bypass or weaker synchronization is used to claim an authentication improvement. Results
must retain all outliers, modes and within-pair differences. Larger A=100,000/full Cartesian histories,
cold-cache flushing, host isolation, concurrent admission, production economics/transport and durable
producer-evidence recovery are omitted and explicitly outside these measurements. The existing
2,000 ms execution reference is not the 2,100 ms publication deadline or a hard observed bound.

## Actual Measurement Results

The complete main matrix finished successfully: **432 appends, no failed samples, all pre/post audits
and signed/unsigned snapshot comparisons passed**. Raw records and read-only aggregation are retained
at `target/block-auth-measurements.log` and `target/block-auth-measurements-summary.txt`. The helper
checks completion, declared counts, every US/SU pair and duplicate inputs before reporting. The
selected 16-append pilot is separate; no pilot data is mixed into main statistics.

Host: AMD Ryzen 9 9950X, 62 GiB RAM, Linux 7.2.7-arch1-1, Rust 1.98.0/default optimized release;
rusqlite 0.38.0/bundled SQLite 3.51.1, k256 0.13.4/ecdsa 0.16.9/sha3 0.10.9. Real files on ext4
`rw,relatime`, WDC WD10JUCT-61CYNY0 rotational SATA disk, one owner/writer at a time, boost enabled,
no CPU affinity/isolation or OS-cache flushing. Connection/audit/barrier and dataset copying are
outside append timers, not bypassed. Groups/modes run sequentially; only paired admission order is
balanced. Host/disk drift is retained rather than corrected or attributed to cryptography.

Construction times, outside append measurements: **596.108 / 78,841.115 / 15.434 ms** for the three
cases. Closed database sizes: **270,336 / 47,947,776 / 1,241,088 bytes**; separately retained signed
history artifacts: **41,200 / 20,341,200 / 0 bytes**. No full-run wall-time instrument was included;
the completion record and individual timings establish executed samples, not an inferred duration.

### Complete Pipelines: Main Phase Samples

**n=8 per cell**, ms **median [minimum, maximum]**. H counts appended blocks, anchor separate:

| A/H/T | N | Unsigned producer | Signed producer | Unsigned receiver | Signed receiver |
|---|---:|---:|---:|---:|---:|
| 1000/100/0 | 0 | 2.908 [2.757, 4.534] | 2.962 [2.889, 4.698] | 3.179 [2.824, 4.221] | 3.427 [3.032, 4.311] |
| 1000/100/0 | 1 | 4.071 [3.053, 49.959] | 4.561 [2.961, 43.319] | 3.344 [3.103, 5.809] | 4.229 [3.318, 49.871] |
| 1000/100/0 | 3000 | 366.523 [362.551, 378.691] | 368.668 [366.253, 390.053] | 360.771 [359.228, 362.792] | 362.191 [360.830, 373.319] |
| 1000/100/100000 | 0 | 10.667 [9.616, 19.433] | 10.316 [9.103, 23.500] | 15.160 [9.686, 37.556] | 10.738 [9.546, 30.748] |
| 1000/100/100000 | 1 | 11.222 [10.889, 15.804] | 12.060 [10.702, 37.316] | 11.235 [10.309, 31.661] | 11.554 [10.061, 40.021] |
| 1000/100/100000 | 3000 | **1800.945 [1652.774, 1846.063]** | **1800.414 [1619.555, 1915.551]** | **1814.822 [1663.699, 1871.552]** | **1803.744 [1721.087, 2004.871]** |
| 10000/0/0 | 0 | 3.866 [3.608, 4.923] | 3.956 [3.782, 5.015] | 4.075 [3.782, 7.234] | 4.139 [3.851, 4.636] |
| 10000/0/0 | 1 | 5.536 [4.303, 5.819] | 4.619 [4.206, 4.968] | 4.707 [4.190, 38.018] | 4.596 [4.137, 20.673] |
| 10000/0/0 | 3000 | 371.318 [368.381, 377.139] | 376.671 [371.456, 383.137] | 370.849 [367.513, 377.991] | 371.889 [369.939, 383.579] |

### Ordinary Controls

**n=4 per cell**, same units/boundaries and every outlier retained; not pooled into phase samples:

| A/H/T | N | Unsigned producer | Signed producer | Unsigned receiver | Signed receiver |
|---|---:|---:|---:|---:|---:|
| 1000/100/0 | 0 | 25.947 [2.967, 48.304] | 3.263 [3.024, 25.453] | 3.317 [2.952, 44.309] | 3.442 [3.070, 7.627] |
| 1000/100/0 | 1 | 3.867 [3.146, 11.736] | 3.653 [3.118, 3.903] | 3.317 [3.128, 26.290] | 6.223 [3.306, 14.181] |
| 1000/100/0 | 3000 | 363.877 [359.959, 366.649] | 365.700 [364.633, 373.200] | 360.447 [359.116, 361.684] | 361.970 [361.356, 365.856] |
| 1000/100/100000 | 0 | 12.977 [10.224, 27.807] | 10.517 [9.712, 11.106] | 10.280 [10.190, 35.235] | 12.327 [9.950, 14.712] |
| 1000/100/100000 | 1 | 12.119 [11.450, 16.440] | 11.500 [11.299, 13.409] | 11.276 [10.954, 29.932] | 11.458 [11.192, 12.456] |
| 1000/100/100000 | 3000 | 1705.916 [1522.660, 1759.381] | 1807.842 [1602.042, 1851.841] | 1776.675 [1744.066, 1811.852] | 1834.557 [1754.698, 1894.775] |
| 10000/0/0 | 0 | 3.758 [3.724, 3.786] | 4.668 [3.745, 5.553] | 3.690 [3.682, 3.829] | 3.978 [3.818, 4.228] |
| 10000/0/0 | 1 | 4.515 [4.287, 5.634] | 4.585 [4.325, 13.770] | 5.249 [4.568, 41.803] | 4.628 [4.338, 4.727] |
| 10000/0/0 | 3000 | 373.676 [370.342, 374.011] | 375.092 [371.400, 382.419] | 370.858 [368.793, 382.407] | 371.563 [370.756, 375.314] |

### Direct Added Work Versus Paired Pipeline Noise

Phase samples, **n=8**, median [min,max] ms. Deltas are **within-pair signed minus unsigned**, not
differences of separately computed medians:

| A/H/T | N | Signed producer signing+encoding | Signed receiver attribution | Paired producer pipeline delta | Paired receiver pipeline delta |
|---|---:|---:|---:|---:|---:|
| 1000/100/0 | 0 | .042 [.040, .071] | .126 [.119, .174] | .092 [-1.422, 1.747] | .325 [-1.155, 1.065] |
| 1000/100/0 | 1 | .034 [.033, .037] | .120 [.118, .132] | -.005 [-45.482, 39.775] | .851 [-.233, 46.621] |
| 1000/100/0 | 3000 | 1.464 [1.445, 1.552] | 2.438 [2.347, 2.456] | 3.509 [.901, 23.632] | 2.013 [-.398, 12.662] |
| 1000/100/100000 | 0 | .043 [.042, .044] | .120 [.119, .121] | -.102 [-9.370, 13.220] | .665 [-27.597, 12.174] |
| 1000/100/100000 | 1 | .034 [.033, .036] | .122 [.120, .148] | -.375 [-2.471, 26.195] | -.546 [-18.639, 28.753] |
| 1000/100/100000 | 3000 | **1.432 [1.427, 1.463]** | **2.365 [2.355, 2.376]** | **-6.400 [-200.514, 170.663]** | **31.344 [-123.843, 215.611]** |
| 10000/0/0 | 0 | .044 [.042, .056] | .122 [.120, .233] | .054 [-1.107, 1.243] | .231 [-3.383, .808] |
| 10000/0/0 | 1 | .041 [.036, .046] | .121 [.120, .126] | -.794 [-1.586, .445] | -.058 [-33.408, 14.354] |
| 10000/0/0 | 3000 | 1.438 [1.433, 1.794] | 2.386 [2.365, 2.483] | 4.015 [-.085, 11.090] | 1.584 [-5.751, 10.614] |

Signing+encoding includes preflight/digest/owned envelope construction and serialization; attribution
includes decode/reconstruction/root checks/E-ID hash/recovery/full-key comparison. Both spans grow
with packet size; **2.365 ms is not an isolated ECDSA recovery measurement**. Unsigned producer
encoding alone was ~.014 ms in the large-history/large-body phase case. Rare forced overflow/entropy
failure latency was not benchmarked; its behavior is tested separately. The fallible entropy adapter
was tightened during the run; the ordinary RFC6979 and verification/application paths are unchanged.

Large-history ordinary paired deltas were **82.304 [21.407, 189.679] ms producer**,
**47.465 [-16.928, 131.316] ms receiver**. In the main phase pairs, producer was slower in 4/8 pairs,
receiver in 6/8; SQL deltas track most of the large variance. Neither near-equal policy medians nor
occasional negative deltas establish an authentication speedup or a precise total overhead bound.

Large-history/3,000-entry phase attribution, ms median [min,max], unsigned/signed receiver:

| Included phase | Unsigned | Signed |
|---|---:|---:|
| Native staging | 332.336 [330.464, 346.901] | 331.695 [330.261, 334.610] |
| Full cache preparation | 6.568 [6.123, 7.008] | 6.495 [6.114, 7.152] |
| Old-cache destruction | 3.069 [2.978, 4.758] | 3.042 [2.917, 3.167] |
| Full persisted-state comparison (inside SQL) | .145 [.133, .166] | .142 [.132, .163] |
| All uniqueness probes | 13.928 [13.488, 14.124] | 13.665 [13.517, 14.240] |
| Changed-account writes | 3.287 [3.256, 3.348] | 3.290 [3.270, 3.696] |
| Transaction/all-index insertion | 295.640 [267.557, 338.860] | 287.262 [262.848, 330.970] |
| COMMIT return | **1144.330 [966.564, 1227.397]** | **1168.524 [1076.140, 1355.399]** |
| Durable SQL total | **1471.714 [1322.649, 1529.719]** | **1458.923 [1378.052, 1660.037]** |

Every raw/paired pipeline and durable observation is printed by the helper. All reported ranges
include every outlier, including ~40–50 ms low-body spikes and the **2,004.871 ms signed receiver**
maximum. That sample exceeds the **2,000 ms execution reference** before any deferred live costs;
this host/workload measurement cannot justify a production deadline or minimum-hardware guarantee.
No sample is discarded to fit the reference, and the 2,100 ms publication deadline is not substituted.

### Fixture Reopen/Recovery and Separate Test-Artifact Costs

At A=1,000/H=100/T=100,000/N=3,000, receiver phase samples' full post-append fixture reopening was
**11,789.174 [11,759.869, 11,791.449] ms unsigned** versus
**11,824.605 [11,772.560, 11,845.287] ms signed**, n=8. Included native audits were
**11,340.313 / 11,377.289 ms median**; validation/read/rebuild ~443–445 ms and synchronized barriers
~1.84–1.89 ms. The loader rechecks all native history, not a producer-authenticated archive.

Separate ordinary receiver Ready-refresh recovery, n=4:
**11,804.705 [11,797.916, 11,826.648] ms unsigned**, **11,810.716 [11,793.780, 11,836.890] ms signed**;
included audits **11,361.271 / 11,362.743 ms median**. Test-only poisoned/unpublished recovery was
verified by composition tests, not relabeled as these Ready-refresh measurements.

Re-authenticating 100 retained signed **in-memory test envelopes**, n=4, separately cost
**12.046 [11.504, 12.113] ms** for empty-body history and **87.363 [85.654, 89.311] ms** for the
100,000-transaction history. No native execution or SQL audit is replaced by these signature passes.
At T=100,000 each append still prepares copies of ~19.9 MB signed bodies, 3.2 MB ordered IDs,
200,000 transaction/sender-nonce memberships and both retained slot/hash maps. Maximum observed
shared-process RSS/HWM was **300,228 KiB (~293 MiB)**, including retained snapshots/artifacts and
allocator reuse; this is not an isolated signed-versus-unsigned memory comparison or a hard cap.

### Supplementary Cold Rejection Costs

`cargo run --release --example block_auth_reject_bench -- target` completed **24 batches / 2,400
rejections / zero unexpected acceptances**. Four 100-operation batches per class/body, raw input,
context and binding passed through `black_box`, no verified-result cache, warm CPU/OS. Includes
attribution and exact-error checking only, **no native execution or SQL append**. Final records:
`target/block-auth-rejection-final.log`; an earlier un-black-boxed development pilot is retained
separately at `target/block-auth-rejection-measurements.log` and excluded from final costs.

Canonical wrong-full-key rejection averaged ~**.109 ms per empty packet** (observed batch means
.108–.115 ms) and ~**2.460 ms per 3,000-entry packet** (2.456–2.464 ms). Wrong-network rejection was
~.000063 ms / .0112 ms, respectively: large framing still decodes before network comparison under
the approved error order. Empty/truncated-frame rejection was ~.000013 ms; nanosecond-scale loop
observations are secondary diagnostics, not an isolated causal ingress/network throughput estimate.

## Final Verification and Stop

Successful checks after the final library/test changes:

```bash
cargo test
cargo test --release --lib
cargo fmt --check
cargo clippy --all-targets --all-features
python3 -B scripts/reproduce_native_auth_vectors.py
python3 -B scripts/reproduce_stage4_vectors.py
python3 -B scripts/reproduce_block_auth_vectors.py
cargo run --example block_auth_replay -- target
cargo run --release --example block_auth_replay -- target
cargo run --example stage4_canonical_replay -- target
cargo run --release --example stage4_canonical_replay -- target
```

Full debug **150 passed (106 library + 44 binary)**; release library **106 passed**, nine controlled
subprocess/stress/benchmark ignores retained. The new stage adds 20 tests. Existing process/I/O/model/
allocation/recovery tests and historical V1/native/ingress compatibility tests pass in both suites;
the earlier separate larger-cache stress/benchmark results are not falsely claimed as rerun here.
Clippy completes with existing prototype warnings only; no new library/test/example warnings.
Native independent checking reproduces 5 vectors/262 malformed signatures; Stage 4 reproduces 4
blocks/43 prefix headers/3 native signatures; new independent checking reproduces the six producer
vectors and rejection controls above. Broad check logs are `target/block-auth-final-*.log`.

Tracked whitespace checks passed, as did all 35 new/untracked files and the two local design/review
documents (37 checks). Git separately confirms the exact root design/review ignore entries and zero
index entries for either document. The paired-analysis helper successfully processes the complete
main log and rejects partial output and duplicated input experiments. Existing package-version,
source, fixture, schema, ignore rules and other user changes were preserved; no files were staged.

Implementation follows the approved contracts. Routine choices include a syntax-only opaque-signature
envelope, new block-specific signature wrapper over the existing primitive, private signed fixture
stage tokens, full structural preflight repeated when reusing the old public store, fallible OS-seeded
CSPRNG for rare signing retry, and literal-component golden reuse. No persistent schema, validation/
transaction-rule/durability/cache-default change or production authorization was needed. Stop for
review of this bounded offline stage and its actual measurements.

## Remaining Boundaries

Experimental numbering only. Canonical production genesis/chain ID/profile/activation, producer-key
registry/history/rotation/revocation, leader/eligibility/time/economics, protocol miss/no-ticket/
collision authorization, consensus equivocation/evidence/slashing rules, production signing-intent
journal, authenticated persistent schema/migration/backfill, live acceptance/transport, real state/
receipt roots and reorgs remain separate decisions. Native transaction and storage rules and current
HIST/BLOCK ingress rejection remain in force. No commit or push accompanies this offline stage.
