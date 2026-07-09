# Eternix Testnet

![Rust](https://img.shields.io/badge/language-Rust-orange) ![Status](https://img.shields.io/badge/status-0.x%20prototype-yellow) ![License](https://img.shields.io/badge/license-MIT-blue)

This repository contains the early 0.x implementation of an Eternix testnet node written in Rust.

Eternix is a Layer-1 blockchain built around deterministic execution, irreversible consensus weight, and explicit monetary policy.

It implements a deterministic slot engine with PoAsh-style ticket-based leader selection, protocol-generated fallback blocks, fee burn accounting, sub-epoch/epoch boundaries, and a terminal UI dashboard.

---

> [!WARNING]
> This is an early 0.x testnet prototype intended for protocol experimentation.
> Consensus rules, RPC methods, transaction formats, and validator mechanics may change without notice.
> Do not use with real funds.

## Current Status

Implemented:

- Slot engine
- Validator selection
- RPC
- Basic P2P gossip
- Mempool
- Protocol blocks

In progress:

- Internet networking
- Full signature validation
- Persistent database
- XVM integration
- Improved Ethereum wallet compatibility (experimental)

Planned:

- FCTs
- Wallet software
- Explorer

## Implemented Protocol Areas

- 3-second slots with 2100ms leader deadline behavior
- Sub-epoch (1200 slots) and epoch (24 sub-epochs) boundaries
- Ticket-weighted bucket selection and deterministic scoring
- Same-slot collision neutralization to protocol block
- Protocol block fallback for missed leader and no eligible tickets
- Separate PBM queue with delayed validity and deterministic inclusion
- Fee burning and burn-offset accumulator accounting
- Basic validator miss/offense tracking and state transitions
- Hard-finality window surfaced in UI

## Node TUI

The TUI follows the design layout:

- Top row: validator panel, slot view, network/node panel
- Bottom row: rewards/economy, slot history, mempool panel
- Liveness bar
- Events panel

Controls:

- `q`: quit
- `n`: add standard mempool transaction
- `b`: add a PBM validator-registration transaction

## Screenshot

![Node TUI](docs/screenshot.png)

## Requirements

- Rust stable toolchain
- Cargo

Install:

```bash
curl https://sh.rustup.rs -sSf | sh
```

## Run

```bash
cargo run
```

Start as a validator node on custom port:

```bash
cargo run -- --mode validator --p2p-port 30333
```

Start as a validator with an explicit owner account:

```bash
cargo run -- --mode validator --p2p-port 30333 --validator-account 0xYOUR_ADDRESS
```

Start as a validator process for an already registered validator ID, without synthetic startup vault/tickets:

```bash
cargo run -- --mode validator --validator-id val-0001 --validator-account 0xYOUR_ADDRESS --p2p-port 30334 --rpc-port 8546 --peers 127.0.0.1:30333
```

Run with custom RPC port:

```bash
cargo run -- --mode validator --p2p-port 30333 --rpc-port 8545
```

Run with a custom genesis file:

```bash
cargo run -- --genesis ./genesis.json
```

Validator startup behavior for this prototype:

- No validators are preloaded in genesis.
- Starting a validator node without `--validator-id` auto-registers one legacy bootstrap validator ID (`val-<p2p-port>`) with synthetic startup vault/ticket state.
- Starting a validator node with `--validator-id` binds the process to that validator ID without synthetic vault/ticket state; use this for testing registered validators.
- `--validator-id` requires `--validator-account`.
- `--validator-account` binds an account address as the owner account for that validator.
- `register_validator` enqueues a fixed-fee transaction that creates an inactive validator with a sequential ID (`val-0001`, `val-0002`, ...).
- `buy_ticket` takes `validator_id` and enqueues a fixed-fee transaction that burns ETX from the validator's configured owner account.
- `wallet_to_vault` and `vault_to_wallet` take `validator_id` and enqueue signed transactions that move ETX between the validator's configured owner account and vault.
- A validator with no tickets has a vault minimum of `0`; once it owns tickets, it is active only when its vault is at least `5 * ticket_cost + (ticket_cost / 2) * ticket_count`, where `ticket_count` is the number of non-dead tickets it owns.
- `vault_to_wallet` is rejected if the withdrawal would leave the validator below that dynamic vault minimum.
- Base block rewards and burn-offset rewards are credited to the validator vault immediately but remain locked until the start of `current_epoch + 4`; locked rewards count in vault balance but are not withdrawable.
- Legacy bootstrap validators are auto-provisioned with:
  - 1 ticket
  - 50,000 ETX vault (stored in quarks internally)
- RPC-submitted transactions are gossiped to peers so validator registration, vault funding, and ticket buys can be processed by connected nodes.

## PBM Bootstrap Mode

PBM is active when there are no eligible tickets. While PBM is active, protocol no-ticket blocks may include one eligible PBM transaction per slot.

- Allowed PBM transaction types are `registerValidator`, `walletToVault`, and `buyTicket`.
- `vaultToWallet` and generic `send_tx` PBM transactions are not PBM-allowed.
- PBM transactions are delayed by at least 20 slots via `valid_after_slot`.
- Each account may have at most 3 pending PBM transactions.
- Same-account PBM transactions are assigned staggered `valid_after_slot` values so `registerValidator`, `walletToVault`, and `buyTicket` can be submitted as an ordered bootstrap sequence.
- Eligible PBM transactions are selected deterministically by `(valid_after_slot, tx_hash)`.
- PBM deactivates once a validator has an eligible ticket; remaining PBM transactions are moved into the normal mempool.

## Genesis

Startup account allocations are loaded from `genesis.json` by default.

Each account entry may use either `private_key_hex` or `address`. Accounts with `private_key_hex` are available through `eth_accounts`; address-only accounts are funded but do not have a local private key.

Balances are keyed by token ID. Token `"0"` is ETX.

Example:

```json
{
  "accounts": [
    {
      "id": "acct-1",
      "private_key_hex": "0x...",
      "balances": {
        "0": "10000000000000"
      }
    },
    {
      "address": "0x1111111111111111111111111111111111111111",
      "balances": {
        "0": "50000000000000"
      }
    }
  ]
}
```

Use string values for large balance amounts to avoid JSON number precision limits in external tooling.

Start as a standard node and connect to a peer:

```bash
cargo run -- --mode standard --p2p-port 30334 --peers 127.0.0.1:30333
```

Multiple peers can be passed as comma-separated `host:port` entries.

## RPC (HTTP JSON)

RPC listens on `127.0.0.1:<rpc-port>` (default `8545`) and accepts `POST /` with JSON body:

```json
{"method":"send_tx","params":{"chain_id":1162,"from":"0x...","nonce":1,"to":"0x...","value":1000,"gas_limit":1000,"max_fee_per_gas":10,"data":"","tx_type":"normal_transfer"}}
```

Supported methods:

- `list_accounts` `{}`
- `create_account` `{ account_id? }`
- `import_private_key` `{ private_key_hex, account_id? }`
- `etx_faucet` `{ to, amount_quarks? }`
- `send_tx` `{ chain_id, from, nonce, to, token_id?, value, gas_limit, max_fee_per_gas, fee_token_id?, data, tx_type, signature? }`
- `register_validator` `{ from, validator_pubkey, reward_address?, nonce?, signature? }` (gas limit and fee are fixed)
- `buy_ticket` `{ validator_id, count?, nonce?, signature? }` (gas limit and fee are fixed)
- `wallet_to_vault` `{ validator_id, amount_quarks, nonce?, signature? }` (gas limit and fee are fixed)
- `vault_to_wallet` `{ validator_id, amount_quarks, nonce?, signature? }` (gas limit and fee are fixed)
- `get_account` `{ account_id }`

Example:

```bash
curl -s -X POST http://127.0.0.1:8545/ -H 'content-type: application/json' -d '{"method":"list_accounts","params":{}}'
curl -s -X POST http://127.0.0.1:8545/ -H 'content-type: application/json' -d '{"method":"create_account","params":{"account_id":"alice"}}'
curl -s -X POST http://127.0.0.1:8545/ -H 'content-type: application/json' -d '{"method":"import_private_key","params":{"account_id":"my-eth","private_key_hex":"0xYOUR_PRIVATE_KEY"}}'
curl -s -X POST http://127.0.0.1:8545/ -H 'content-type: application/json' -d '{"method":"etx_faucet","params":{"to":"0xYOUR_ADDRESS","amount_quarks":10000000000000}}'
curl -s -X POST http://127.0.0.1:8545/ -H 'content-type: application/json' -d '{"method":"etx_faucet","params":{"to":"0xYOUR_ADDRESS","amount_quarks":"100000000000000000000"}}'
curl -s -X POST http://127.0.0.1:8545/ -H 'content-type: application/json' -d '{"method":"get_account","params":{"account_id":"0x..."}}'
curl -s -X POST http://127.0.0.1:8545/ -H 'content-type: application/json' -d '{"method":"send_tx","params":{"chain_id":1162,"from":"0x1111111111111111111111111111111111111111","nonce":1,"to":"0x2222222222222222222222222222222222222222","value":1000,"gas_limit":1000,"max_fee_per_gas":10,"data":"","tx_type":"normal_transfer"}}'
```

## Quickstart

### Start validator

```bash
cargo run -- --mode validator --p2p-port 30333 --rpc-port 8545
```

### Create account

```bash 
curl -s -X POST http://127.0.0.1:8545/ -H 'content-type: application/json' -d '{"method":"create_account","params":{"account_id":"alice"}}'
```

### Get faucet funds

```bash
curl -s -X POST http://127.0.0.1:8545/ -H 'content-type: application/json' -d '{"method":"etx_faucet","params":{"to":"0xYOUR_ADDRESS","amount_quarks":10000000000000}}'
```

### Send transaction

```bash
curl -s -X POST http://127.0.0.1:8545/ -H 'content-type: application/json' -d '{"method":"send_tx","params":{"chain_id":1162,"from":"0xYOUR_ADDRESS","nonce":1,"to":"0xRECIPIENT_ADDRESS","value":1000,"gas_limit":1000,"max_fee_per_gas":10,"data":"","tx_type":"normal_transfer"}}'
```

### Register Then Start Validator

This flow tests the chain without a pre-funded validator. Use an owner account funded by the same genesis file on both nodes, or import the same private key on each node before submitting signed owner-account transactions.

Start a standard node:

```bash
cargo run -- --mode standard --p2p-port 30333 --rpc-port 8545
```

Register a validator from the standard node. The `validator_pubkey` can be the `public_key_hex` returned by `create_account` or `import_private_key`.

```bash
curl -s -X POST http://127.0.0.1:8545/ -H 'content-type: application/json' -d '{"method":"register_validator","params":{"from":"0xOWNER_ADDRESS","validator_pubkey":"0xVALIDATOR_PUBLIC_KEY"}}'
```

Wait until PBM includes the registration, then start a validator process bound to the returned `validator_id`:

```bash
cargo run -- --mode validator --validator-id val-0001 --validator-account 0xOWNER_ADDRESS --p2p-port 30334 --rpc-port 8546 --peers 127.0.0.1:30333
```

Fund the validator vault and buy tickets from the validator node RPC:

```bash
curl -s -X POST http://127.0.0.1:8546/ -H 'content-type: application/json' -d '{"method":"wallet_to_vault","params":{"validator_id":"val-0001","amount_quarks":"500000000000000"}}'
curl -s -X POST http://127.0.0.1:8546/ -H 'content-type: application/json' -d '{"method":"buy_ticket","params":{"validator_id":"val-0001","count":1}}'
```

The vault and ticket transactions are gossiped to peers. Once the ticket is active, PBM deactivates and the validator can be selected as leader.

## Notes

- This is a testnet prototype focused on protocol mechanics and observability.
- P2P networking, full EVM execution, persistent state DB, and cryptographic transaction validation are not fully implemented in this version.
- P2P in this version is UDP-based gossip for peer hello and transaction propagation (mempool sync).
- Hello gossip is sent immediately at boot and then every 500ms to reduce peer-discovery delay.
- On startup, a node performs one-time slot bootstrap from peers (`slot` + `slot-start timestamp`) so late joiners align to current network slot.
- Validator discovery is propagated via hello metadata; validator nodes are added to the local validator registry with one deterministic ticket.
- Tested on:
  - Linux (Arch)
  - Windows: Untested
  - macOS: Untested

## Documentation

Protocol specifications and docs will be published at:

https://docs.eternix.dev

(Currently under construction.)

## License

MIT
