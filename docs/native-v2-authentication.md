# Isolated Native V2 Authentication

Stage B implements the approved native authentication target in
`src/native_transaction.rs`, exported only by the new protocol-primitives library `src/lib.rs`.
The live node binary does not import this module. There is no live V2 admission, execution, activation,
production genesis definition, final chain-ID default, or change to `HELLO`/`STATE` behavior.
Existing V1 codecs, hashes, roots, historical vectors, and execution code are not modified.

## API Boundary

- `UnsignedTransaction` encodes/decodes the exact 134-byte native V2 layout and computes its
  158-byte domain-separated signing preimage and Keccak digest. It has no data, gas-price, or
  fee-asset wrapper fields.
- `NativeSignature` admits exactly 65 bytes of `r || s || y_parity`, with nonzero in-range scalars,
  mandatory low-s, and parity `0/1`. Received high-s and recovery IDs `2/3/27/28` are rejected.
- `SignedTransaction` encodes/decodes exactly 199 bytes and hashes the complete signed object under
  the native ID domain, distinct from the signing digest. Neither V1 nor raw Ethereum is a fallback.
- `AuthenticationContext::new(chain_id, network_id, native_rules_version)` requires explicit trusted
  caller policy. It has no defaults and currently supports native rules 1 only. The context must not
  be derived from the incoming transaction's own claims.
- `network_id_from_genesis_bytes` computes Keccak of a caller-supplied canonical preimage. It does
  not define a genesis schema or establish that the preimage excludes its own hash; the future
  canonical genesis codec must establish those properties.
- `authenticate` checks the stateless rules-1 profile and an optional claimed ID before recovery,
  then uses k256's prehash recovery/verification and matches the recovered twenty-byte address to
  the signed sender. It has no node state, clock input, or authentication-result cache.
- `sign` checks explicit context and sender/key identity, then uses k256's vetted signing APIs.
  Ordinary signing is deterministic RFC6979. A rare x-overflow candidate retries with fresh
  OS-generated additional entropy through the library's randomized prehash signer; it is never
  converted to a native signature by stripping the overflow bit. SHA-256 inside RFC6979 is nonce
  generation only; all transaction/genesis/address commitments and signing prehashes use Keccak.

`AuthenticatedTransaction` is an immutable identity proof, not a receipt or execution success.
Authentication rejects structurally non-incrementable nonces, gas limits below 1,000, and unsupported
value assets under rules 1. Exact canonical nonce equality, maturity at the inclusion slot, balances,
checked value-plus-fee exposure, atomic fee burning, and block/state transitions remain outside this
module. A test deliberately authenticates a representable `u128::MAX` value and future maturity to
guard against confusing authentication with stateful includability.

The separate [`offline transfer applicator`](native-v2-transfer-application.md) now exercises these
stateful checks through shared staged application. Authentication itself remains state-free and the
live node remains disconnected from both modules.

The rules-1 constants are exposed for later integration: intrinsic/actual primitive transfer gas is
1,000, fixed price is 10 quarks/gas, and the fee is exactly 10,000 quarks, burned in ETX. This module
does not charge or burn anything. Larger signed gas limits do not imply a higher fee. ETX token ID 0
is the only supported value asset until FCT transfer semantics are separately implemented.

## Tests and Independent Vector Reproduction

`src/native_transaction/tests.rs` contains 21 native regressions covering:

- Full unsigned/preimage/signed golden bytes, explicit offsets and big-endian widths.
- All truncations, trailing fields, the obsolete 207-byte draft, and V1 rejection.
- Every unsigned-byte and signature-byte mutation, with signature bytes committed into the ID.
- Both valid parities, every other parity byte, zero/order scalar bounds, and high-s rejection.
- Invalid recovery points and an infinite recovered key.
- Explicit context mismatch and claimed-ID rejection before curve recovery.
- Unsupported kinds/assets, gas and nonce bounds, zero/max integer representations.
- Sender spoofing and non-native signing-domain rejection.
- Synthetic x-overflow candidates exercising real fresh-nonce backend retries.
- Authentication/codec distinction from economic execution.

The fixture `tests/fixtures/native_auth_v2.json` is explicitly test-only. It uses the published
scalar-one key and an opaque synthetic genesis preimage, not production configuration or allocations.
Its five vectors include the base transfer, valid gas-limit 1,001 transfer, and cryptographically
valid negative controls for gas 999, unsupported token 1, and nonce exhaustion.

Run:

```bash
cargo test --lib native_transaction
cargo test --release --lib native_transaction
python3 -B scripts/reproduce_native_auth_vectors.py
```

The Python checker independently packs the payload with `struct`, hashes through OpenSSL's
`KECCAK-256` provider, reproduces RFC6979/signatures and recovery using separate Python curve
arithmetic, and cross-checks points and ECDSA verification through the OpenSSL-backed `cryptography`
package. It does not import the Rust module or use copied signed bytes to produce the result.
It reproduces all five vectors and rejects 262 malformed signatures. The arithmetic is a
variable-time checker for public test data, not a production wallet implementation.

Verification environment: Python 3.14.7, `cryptography` 50.0.1, OpenSSL 3.6.4.

## Release Cold-Authentication Measurement

Run:

```bash
cargo run --release --example native_auth_bench
```

The standalone example does not start the node. It generates 3,000 distinct test transactions
outside the timed section, then performs exact decoding, profile/context checks, both transaction
hashes, recovery/verification, address derivation, and sender matching on every transaction.
No transaction is preauthenticated, and there is no verified-result cache or verification warmup.
The measurement is single-threaded and consumes the results with `black_box` plus an ID checksum.
OS/CPU caches are not flushed; "cold" means no prior authenticated-object result is reused.
Dataset construction/signing is excluded from the authentication timing.

Measured hardware/backend:

- AMD Ryzen 9 9950X, 16 cores / 32 logical CPUs available; one authentication thread.
- Linux 7.2.7, x86_64; frequency boost enabled, CPU affinity not pinned.
- Rust 1.98.0, LLVM 22.1.8, Cargo default optimized release profile.
- RustCrypto `k256` 0.13.4 / `ecdsa` 0.16.9, `sha3` 0.10.9 Keccak-256.
- Three fresh-process samples. The execution-budget reference is **2,000 ms**, not the 2,100 ms
  publication deadline. Neither node deadline is changed by this benchmark.

| Sample | Transactions | Total ms | Microseconds/transaction | Share of 2,000 ms |
|---|---:|---:|---:|---:|
| 1 | 3,000 | 335.527 | 111.842 | 16.78% |
| 2 | 3,000 | 336.364 | 112.121 | 16.82% |
| 3 | 3,000 | 350.173 | 116.724 | 17.51% |

Median: **336.364 ms**, or **112.121 microseconds per transaction**. All samples returned the same
checksum. These are this host's authentication-only results, not a minimum-hardware guarantee or a
measurement of complete block execution, transport, persistence, or slot scheduling.

## Remaining Integration Dependencies

1. Canonical production genesis schema/bytes, final chain ID, and explicit activation schedule.
2. Reviewed native RPC/P2P admission and V1-new-inclusion migration policy without changing
   historical V1 identities or treating Ethereum signatures as native authorization.
3. Reviewed mapping of the offline canonical nonce/maturity/balance/overflow application to live
   native state, without reinterpreting prototype nonce trackers.
4. Durable transactional execution/persistence and derived block gas/fee validation. The offline
   applicator implements shared checked ETX transfer and burn accounting; declared gas limits must
   still not be summed as actual V2 transfer gas at the later block-integration boundary.
5. Separately specified FCT/native-operation semantics; no placeholder transfer fallback.
6. Independently approved block authentication/synchronization/reorg work. Stage A's inbound
   `HIST`/`BLOCK` rejection remains in force; this module does not open remote block acceptance.

Production activation and any of these integrations require separate approval.
