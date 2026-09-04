# Consensus Hashing V1

Eternix consensus hashes are raw 32-byte values. Lowercase `0x`-prefixed hexadecimal is used only at RPC, TUI, log, and UDP framing boundaries.

## Domains

The following ASCII byte strings are fixed protocol constants. No terminator is appended.

| Commitment | Domain bytes |
| --- | --- |
| Block header | `ETERNIX_BLOCK_HEADER_V1` |
| Transaction ID | `ETERNIX_TX_V1` |
| Ordered transaction list | `ETERNIX_TX_LIST_V1` |
| Protocol data | `ETERNIX_PROTOCOL_DATA_V1` |
| Empty receipt list | `ETERNIX_RECEIPT_LIST_V1` |
| Proposer ID | `ETERNIX_PROPOSER_ID_V1` |
| Genesis lookback value | `ETERNIX_GENESIS_V1` |
| Legacy bootstrap ticket ID | `ETERNIX_LEGACY_TICKET_ID_V1` |
| Epoch seed | `ETERNIX_EPOCH_SEED_V1` |

Every integer below uses unsigned big-endian encoding. Byte strings use their raw bytes, never their hexadecimal display text.

## Block Header

The canonical `BlockHeader` is exactly 229 bytes with this mandatory field order:

| Field | Encoding |
| --- | --- |
| `protocol_version` | `u32`, currently `1` |
| `chain_id` | `u64`, currently `1162` |
| `slot` | `u64` |
| `block_kind` | `u8` |
| `parent_hash` | 32 raw bytes |
| `proposer_id` | 32 raw bytes |
| `ticket_id` | `u64` |
| `transaction_root` | 32 raw bytes |
| `state_root` | 32 raw bytes |
| `receipts_root` | 32 raw bytes |
| `gas_used` | `u64` |
| `protocol_data_root` | 32 raw bytes |

The block hash is:

```text
Keccak-256("ETERNIX_BLOCK_HEADER_V1" || canonical_header_bytes)
```

The hash excludes signatures, its own hash, arrival time, peer data, and wall-clock timestamps. Blocks currently have no block signature.

Block-kind values are fixed independently of Rust enum declaration order:

| Value | Kind |
| --- | --- |
| `0` | Validator |
| `1` | Missed-leader protocol |
| `2` | Zero-eligibility/no-ticket protocol |
| `3` | Conflict/collision protocol |

Validator IDs are currently strings such as `val-0001`. Their fixed header commitment is:

```text
Keccak-256("ETERNIX_PROPOSER_ID_V1" || utf8_length_u64 || validator_id_utf8)
```

Ticket IDs are native `u64` values. Validator blocks use the exact selected ticket ID. Protocol blocks serialize 32 zero proposer bytes and ticket ID zero; these fields are never omitted.

## Transaction IDs

The V1 canonical transaction payload order is:

```text
encoding_version:u8 (=1)
kind:u8
chain_id:u64
from:bytes
nonce:u64
to:bytes
token_id:u64
value:u128
gas:u64
fee_quarks:u64
max_fee_per_gas:u64
valid_after_slot:u64
fee_token_id:u64
data_encoding:u8
data:bytes
signature:bytes
```

Every `bytes` field has a `u32` big-endian byte-length prefix and contains UTF-8 unless stated otherwise. Signatures are decoded from their hexadecimal representation and committed as raw bytes. Registration transaction data uses `data_encoding = 1` followed by separately length-prefixed canonical validator public key and reward address fields. Other transaction data uses `data_encoding = 0` followed by one length-prefixed UTF-8 field.

Transaction-kind values are fixed: transfer `0x00`, contract `0x01`, system `0x02`, PBM `0x03`, register validator `0x10`, buy ticket `0x11`, wallet-to-vault `0x12`, vault-to-wallet `0x13`, and burn ticket `0x14`.

The full transaction ID is:

```text
Keccak-256("ETERNIX_TX_V1" || canonical_transaction_bytes)
```

It commits to the currently available signature bytes. This full transaction ID is distinct from the existing signable payload hash. Adding or changing transaction signature rules must keep those concepts separate.

## Transaction Root

Transactions are committed in block order without a Merkle tree:

```text
Keccak-256(
    "ETERNIX_TX_LIST_V1" ||
    transaction_count:u64 ||
    transaction_hash_0 ||
    transaction_hash_1 ||
    ...
)
```

`EMPTY_TX_ROOT` is exactly this algorithm with count zero. It is not an unrelated constant. Transaction content, order, and count therefore affect the root.

## Reserved Roots

`state_root` is mandatory and currently equals `PLACEHOLDER_STATE_ROOT`, exactly 32 zero bytes, for every block. A real deterministic state commitment will require a protocol-versioned consensus change unless introduced before V1 is frozen.

Receipts are not implemented. `receipts_root` is mandatory and currently equals:

```text
Keccak-256("ETERNIX_RECEIPT_LIST_V1" || 0_u64)
```

This is the canonical commitment to an empty receipt list.

## Protocol Data

Protocol data V1 serializes:

```text
encoding_version:u8 (=1)
fees_burned:u64
has_missed_proposer:u8
[missed_proposer_length:u32 || missed_proposer_utf8]
```

The bracketed field is present only when `has_missed_proposer` is `1`. The protocol-data root is `Keccak-256("ETERNIX_PROTOCOL_DATA_V1" || canonical_protocol_data)`. Validator and no-ticket blocks commit fee burns. Miss blocks additionally commit the expected missed validator. Empty conflict metadata uses the canonical empty protocol-data commitment. Local runtime bookkeeping is excluded.

## Parent And Genesis Rules

Slot zero uses `ZERO_HASH` as `parent_hash`. Every later accepted block references the computed hash of the canonical block at `slot - 1`. Missing or mismatched parents are rejected. Wall-clock catch-up processes missed slots sequentially rather than synthesizing IDs or creating gaps.

There is no separately stored genesis block in this prototype. The pre-lookback genesis value is explicitly:

```text
Keccak-256("ETERNIX_GENESIS_V1" || protocol_version:u32 || chain_id:u64)
```

PoAsh leader selection uses this value before slot 32. Starting at slot 32 it uses the actual canonical block hash from `slot - 32`, including validator and protocol blocks. It never hashes an RPC hexadecimal string.

## Time

No timestamp is part of the canonical header. RPC timestamps are derived from the node's slot anchor plus `slot * slot_duration` and do not affect consensus identity.
