use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sha2::{Digest, Sha256};
use serde_json::{json, Value};
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::rand_core::OsRng;
use k256::ecdsa::signature::Signer;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use rlp::{Rlp, RlpStream};
use sha3::Keccak256;

use crate::models::*;
use crate::p2p::{encode_slot_result, parse_hello, parse_slot_result, parse_tx_msg, tx_id, P2p};
use crate::leader_selection::select_leader_owner;
use crate::rpc::RpcRequest;
const GENESIS_EPOCH_SEED: [u8; 32] = [0x45; 32];
const TOKEN_ETX_ID: u64 = 0;
const TICKET_COST_QUARKS: u128 = 10_000_000_000_000;
const WEI_PER_QUARK: u64 = 100_000_000;

pub struct Protocol {
    rng: StdRng,
    pub state: ProtocolState,
    pub p2p: P2p,
}

impl Protocol {
    pub fn new(cfg: Config) -> Result<Self> {
        let p2p = P2p::new(cfg.p2p_port, &cfg.peers)?;
        let local_validator_id = if cfg.mode == NodeMode::Validator {
            Some(format!("val-{}", cfg.p2p_port))
        } else {
            None
        };

        let mut validators = vec![];
        let mut tickets = vec![];
        if let Some(id) = &local_validator_id {
            validators.push(Validator {
                id: id.clone(),
                state: ValidatorState::Active,
                vault_quarks: 5_000_000_000_000_000,
                miss_counter: 0,
                double_sign_offenses: 0,
                blocks_this_sub_epoch: 0,
                cooldown_until_epoch: None,
            });
            tickets.push(Ticket {
                id: 1,
                owner: id.clone(),
                bucket: 2,
                muted: false,
                dead: false,
                retiring: false,
                retire_requested_epoch: None,
                retire_effective_epoch: None,
            });
        }

        let mut this = Self {
            rng: StdRng::seed_from_u64(cfg.p2p_port as u64 + 42),
            state: ProtocolState {
                slot: 0,
                slot_started: Instant::now(),
                prev_hash: [0; 32],
                validators,
                tickets,
                mempool: Default::default(),
                pbm_pool: Default::default(),
                history: Default::default(),
                events: Default::default(),
                sync_pct: 99.9,
                burn_this_sub_epoch: 0,
                fees_burned_total: 0,
                base_issuance_total: 0,
                burn_offset_total: 0,
                annual_inflation_ppm: 60_000,
                burn_offset_k_permille: 500,
                epoch_validator_blocks: 0,
                epoch_total_slots: 0,
                mode: Mode::Normal,
                current_leader: "protocol".to_string(),
                exec_status: ExecStatus::Idle,
                current_result: None,
                nonce_tracker: HashMap::new(),
                mode_local: cfg.mode,
                local_validator_id,
                accounts: HashMap::new(),
                wallet_addresses: Vec::new(),
                anchor_time: SystemTime::now(),
                bootstrapped_from_peer: false,
                validator_peers: HashMap::new(),
                remote_slot_results: Default::default(),
                history_synced: false,
                liveness_epoch: 0,
                liveness_counted_slots: Default::default(),
                liveness_total_slots: 0,
                liveness_validator_slots: 0,
                epoch_index: 0,
                sub_epoch_index: 0,
                epoch_seed: GENESIS_EPOCH_SEED,
                blocks_this_sub_epoch: Vec::new(),
                retire_per_epoch_limit: 2,
                retire_schedule: Default::default(),
                retire_finalize: Default::default(),
                raw_txs: HashMap::new(),
                raw_tx_pending: Default::default(),
                block_transactions: HashMap::new(),
                blocks: HashMap::new(),
                block_hash_to_number: HashMap::new(),
            },
            p2p,
        };
        this.state.current_leader = this.select_leader();
        this.state.exec_status = ExecStatus::Executing;
        this.bootstrap_accounts();
        this.state.events.push_front(format!("node started on p2p port {}", cfg.p2p_port));
        Ok(this)
    }

    fn bootstrap_accounts(&mut self) {
        let test_private_keys = [
            "0x59c6995e998f97a5a0044966f0945382d3f8f9a89c8f6d9f2baf6a6c57b8b12a",
            "0x8b3a350cf5c34c9194ca3a545d2f8f14de6f7e2a7bc01db57a97dc0b1819b735",
            "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc5f2f8f0f85b8e7d8f5f6e9aa",
            "0x90f79bf6eb2c4f870365e785982e1f101e93b9069d6d8f5d0e7c3b2a1f4e5d6c",
            "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65d4f5a6b7c8d9e0f1a2b3c4d5",
            "0x9965507d1a55bcc2695c58ba16fb37d819b0a4dcf6a4e2d1c8b7a6f5e4d3c2b1",
            "0x976ea74026e726554db657fa54763abd0c3a0aa9b0a1b2c3d4e5f60718293a4b",
            "0x14dc79964da2c08b23698b3d3cc7ca32193d9955f7f6e5d4c3b2a1908f7e6d5c",
        ];

        for (i, pk) in test_private_keys.iter().enumerate() {
            if let Some(account) = account_from_private_key_hex(&format!("acct-{}", i + 1), pk) {
                self.state.wallet_addresses.push(account.address.clone());
                self.state
                    .accounts
                    .insert(account.address.clone(), account.clone());
                self.credit_balance(&account.address, TOKEN_ETX_ID, 10_000_000_000_000);
            }
        }
    }

    pub fn tick(&mut self) {
        self.p2p_pump();
        self.maybe_resync_slot_from_anchor();

        while self.state.slot_started.elapsed() >= Duration::from_millis(SLOT_MS) {
            self.finish_slot();
            self.start_next_slot();
        }

        if self.state.slot_started.elapsed() >= Duration::from_millis(LEADER_DEADLINE_MS) {
            self.state.exec_status = ExecStatus::Posted;
        } else {
            self.state.exec_status = ExecStatus::Executing;
        }
    }

    fn p2p_pump(&mut self) {
        let hello = self.hello_payload();
        self.p2p.tick_hello(&hello);
        for (from, msg) in self.p2p.recv_all() {
            if let Some(hello) = parse_hello(&msg) {
                self.p2p.add_peer(hello.addr);
                self.learn_validator_from_hello(&hello.mode, hello.validator_id.as_deref());
                if let Some(vid) = hello.validator_id {
                    self.state.validator_peers.insert(vid, hello.addr);
                }
                let snap = encode_history_snapshot(&self.state);
                self.p2p.send_to(&snap, hello.addr);
                if !self.state.bootstrapped_from_peer {
                    self.bootstrap_slot_from_peer(hello.slot, hello.slot_started_unix_ms);
                }
                continue;
            }
            if let Some((epoch_validator_blocks, epoch_total_slots, mut entries)) = parse_history_snapshot(&msg) {
                if !self.state.history_synced || epoch_total_slots > self.state.epoch_total_slots {
                    self.state.epoch_validator_blocks = epoch_validator_blocks;
                    self.state.epoch_total_slots = epoch_total_slots;
                    self.state.history.clear();
                    entries.sort_by_key(|e| std::cmp::Reverse(e.slot));
                    for e in entries.into_iter().take(64) {
                        self.state.history.push_back(e);
                    }
                    self.rebuild_liveness_from_history();
                    self.state.history_synced = true;
                    self.state.events.push_front("history synced from peer".to_string());
                }
                continue;
            }
            if let Some(res) = parse_slot_result(&msg) {
                self.state.remote_slot_results.entry(res.slot).or_insert(res);
                continue;
            }
            if let Some((id, tx)) = parse_tx_msg(&msg) && self.p2p.mark_seen(id) {
                self.state.mempool.push_back(tx);
                self.p2p.broadcast_raw_except(&msg, from);
            }
        }
    }

    pub fn seed_normal_tx(&mut self, gossip: bool) {
        if self.state.wallet_addresses.is_empty() {
            return;
        }
        let from = self.state.wallet_addresses[self.rng.gen_range(0..self.state.wallet_addresses.len())].clone();
        let nonce = self.state.nonce_tracker.get(&from).copied().unwrap_or(0);
        self.state.nonce_tracker.insert(from.clone(), nonce.saturating_add(1));
        let kind = if self.rng.gen_bool(0.2) { "contract" } else { "transfer" };
        let tx = Tx {
            chain_id: 1162,
            from,
            nonce,
            to: "0x0000000000000000000000000000000000000000".to_string(),
            token_id: 0,
            value: 0,
            gas: self.rng.gen_range(21_000..60_000),
            fee_quarks: self.rng.gen_range(250_000..1_000_000),
            max_fee_per_gas: 10,
            kind,
            valid_after_slot: 0,
            fee_token_id: TOKEN_ETX_ID,
            data: String::new(),
            signature_hex: String::new(),
        };
        if self.p2p.mark_seen(tx_id(&tx)) {
            if gossip {
                self.p2p.broadcast_tx(&tx);
            }
            self.state.mempool.push_back(tx);
        }
    }

    pub fn seed_pbm_tx(&mut self) {
        if self.state.wallet_addresses.is_empty() {
            return;
        }
        let from = self.state.wallet_addresses[self.rng.gen_range(0..self.state.wallet_addresses.len())].clone();
        let pending = self.state.pbm_pool.iter().filter(|t| t.from == from).count();
        if pending >= 2 {
            return;
        }
        let nonce = self.state.nonce_tracker.get(&from).copied().unwrap_or(0);
        self.state.nonce_tracker.insert(from.clone(), nonce.saturating_add(1));
        self.state.pbm_pool.push_back(Tx {
            chain_id: 1162,
            from,
            nonce,
            to: "0x0000000000000000000000000000000000000000".to_string(),
            token_id: 0,
            value: 0,
            gas: 25_000,
            fee_quarks: 200_000,
            max_fee_per_gas: 8,
            kind: "burnTicket",
            valid_after_slot: self.state.slot + 20,
            fee_token_id: TOKEN_ETX_ID,
            data: String::new(),
            signature_hex: String::new(),
        });
    }

    pub fn request_local_ticket_retire(&mut self, count: usize) {
        let Some(local_id) = &self.state.local_validator_id else {
            self.state
                .events
                .push_front("retire rejected: not a validator node".to_string());
            return;
        };

        let mut eligible: Vec<u64> = self
            .state
            .tickets
            .iter()
            .filter(|t| {
                t.owner == *local_id && !t.dead && !t.muted && !t.retiring && self.validator_active(&t.owner)
            })
            .map(|t| t.id)
            .collect();
        eligible.sort_unstable();
        eligible.truncate(count);

        if eligible.is_empty() {
            self.state
                .events
                .push_front("retire request: no eligible local tickets".to_string());
            return;
        }

        let request_epoch = self.state.epoch_index;
        let finalize_epoch = request_epoch + 2;

        for tid in &eligible {
            if let Some(t) = self.state.tickets.iter_mut().find(|t| t.id == *tid) {
                t.retiring = true;
                t.muted = true;
                t.bucket = 1;
                t.retire_requested_epoch = Some(request_epoch);
                t.retire_effective_epoch = Some(finalize_epoch);
            }
            self.state.retire_finalize.entry(finalize_epoch).or_default().push(*tid);
        }

        self.state.events.push_front(format!(
            "retire started: {} ticket(s), finalize at epoch {}",
            eligible.len(), finalize_epoch
        ));
    }

    pub fn handle_rpc(&mut self, req: RpcRequest) -> Value {
        match req {
            RpcRequest::JsonRpc { id, method, params } => self.handle_jsonrpc(id, &method, &params),
            RpcRequest::SendTx {
                chain_id,
                from,
                nonce,
                to,
                token_id,
                value,
                gas_limit,
                max_fee_per_gas,
                fee_token_id,
                data,
                tx_type,
                signature_hex,
            } => {
                if chain_id != 1162 {
                    return json!({"ok": false, "error": "invalid chain_id"});
                }
                if tx_type != "normal_transfer" && tx_type != "pbm_tx" {
                    return json!({"ok": false, "error": "invalid tx_type"});
                }
                if gas_limit < 1000 {
                    return json!({"ok": false, "error": "gas_limit must be >= 1000"});
                }
                self.ensure_account_exists(&from);
                let expected_nonce = self.state.nonce_tracker.get(&from).copied().unwrap_or(0);
                if nonce < expected_nonce {
                    return json!({"ok": false, "error": format!("invalid nonce, expected >= {}", expected_nonce)});
                }
                let sig = match signature_hex {
                    Some(s) => s,
                    None => {
                        let Some(signed) = self.derive_signature_for_sender(
                            chain_id,
                            &from,
                            nonce,
                            &to,
                            token_id,
                            value,
                            gas_limit,
                            max_fee_per_gas,
                            fee_token_id,
                            &data,
                            &tx_type,
                        ) else {
                            return json!({"ok": false, "error": "cannot derive signature for sender"});
                        };
                        signed
                    }
                };
                self.state.nonce_tracker.insert(from.clone(), nonce.saturating_add(1));
                let fee_per_gas_quarks = max_fee_per_gas_to_quarks(max_fee_per_gas);
                let fee_quarks = gas_limit.saturating_mul(fee_per_gas_quarks);
                let tx = Tx {
                    chain_id,
                    from,
                    nonce,
                    to,
                    token_id,
                    value,
                    gas: gas_limit,
                    fee_quarks,
                    max_fee_per_gas,
                    kind: if tx_type == "pbm_tx" { "pbm_tx" } else { "transfer" },
                    valid_after_slot: if tx_type == "pbm_tx" { self.state.slot + 20 } else { 0 },
                    fee_token_id,
                    data,
                    signature_hex: sig,
                };
                if tx.kind == "pbm_tx" {
                    self.state.pbm_pool.push_back(tx);
                } else {
                    self.state.mempool.push_back(tx);
                }
                json!({"ok": true, "fee_quarks": fee_quarks})
            }
            RpcRequest::BuyTicket {
                validator_id,
                count,
            } => {
                let cost = TICKET_COST_QUARKS.saturating_mul(count as u128);
                if !self.debit_balance(&validator_id, TOKEN_ETX_ID, cost) {
                    return json!({"ok": false, "error": "insufficient wallet balance"});
                }
                self.burn_and_mint_tickets(&validator_id, count);
                json!({"ok": true, "tickets_bought": count, "cost_quarks": cost})
            }
            RpcRequest::WalletToVault {
                validator_id,
                amount_quarks,
            } => {
                if !self.debit_balance(&validator_id, TOKEN_ETX_ID, amount_quarks) {
                    return json!({"ok": false, "error": "insufficient wallet balance"});
                }
                if let Some(v) = self.state.validators.iter_mut().find(|v| v.id == validator_id) {
                    v.vault_quarks += amount_quarks;
                    json!({"ok": true, "vault_quarks": v.vault_quarks})
                } else {
                    self.credit_balance(&validator_id, TOKEN_ETX_ID, amount_quarks);
                    json!({"ok": false, "error": "validator not found"})
                }
            }
            RpcRequest::VaultToWallet {
                validator_id,
                amount_quarks,
            } => {
                if let Some(v) = self.state.validators.iter_mut().find(|v| v.id == validator_id) {
                    if v.vault_quarks < amount_quarks {
                        return json!({"ok": false, "error": "insufficient vault balance"});
                    }
                    v.vault_quarks -= amount_quarks;
                    let new_vault = v.vault_quarks;
                    let _ = v;
                    self.credit_balance(&validator_id, TOKEN_ETX_ID, amount_quarks);
                    json!({"ok": true, "vault_quarks": new_vault})
                } else {
                    json!({"ok": false, "error": "validator not found"})
                }
            }
            RpcRequest::GetAccount { account_id } => {
                let key = normalize_address(&account_id);
                self.ensure_account_exists(&key);
                let acct = self.state.accounts.get(&key);
                match acct {
                    Some(a) => json!({
                        "ok": true,
                        "account_id": a.id,
                        "address": a.address,
                        "public_key_hex": a.public_key_hex,
                        "private_key_hex": a.private_key_hex,
                        "nonce": a.nonce,
                        "balances": a.balances
                    }),
                    None => json!({"ok": false, "error": "internal account error"}),
                }
            }
            RpcRequest::ListAccounts => {
                let list: Vec<Value> = self
                    .state
                    .accounts
                    .values()
                    .map(|a| {
                        json!({
                            "id": a.id,
                            "address": a.address,
                            "public_key_hex": a.public_key_hex,
                            "private_key_hex": a.private_key_hex,
                            "balances": a.balances
                        })
                    })
                    .collect();
                json!({"ok": true, "accounts": list})
            }
            RpcRequest::CreateAccount { account_id } => {
                let signing_key = SigningKey::random(&mut OsRng);
                let pk_hex = format!("0x{}", hex::encode(signing_key.to_bytes()));
                let id = account_id.unwrap_or_else(|| format!("acct-{}", self.state.accounts.len() + 1));
                match account_from_private_key_hex(&id, &pk_hex) {
                    Some(account) => {
                        let addr = account.address.clone();
                        self.state.accounts.insert(addr.clone(), account.clone());
                        self.state.wallet_addresses.push(addr.clone());
                        json!({
                            "ok": true,
                            "account_id": account.id,
                            "address": account.address,
                            "public_key_hex": account.public_key_hex,
                            "private_key_hex": account.private_key_hex,
                            "balances": account.balances
                        })
                    }
                    None => json!({"ok": false, "error": "failed to create account"}),
                }
            }
            RpcRequest::ImportPrivateKey {
                account_id,
                private_key_hex,
            } => {
                let id = account_id.unwrap_or_else(|| format!("acct-{}", self.state.accounts.len() + 1));
                match account_from_private_key_hex(&id, &private_key_hex) {
                    Some(account) => {
                        let addr = account.address.clone();
                        self.state.accounts.insert(addr.clone(), account.clone());
                        if !self.state.wallet_addresses.iter().any(|a| a == &addr) {
                            self.state.wallet_addresses.push(addr.clone());
                        }
                        json!({
                            "ok": true,
                            "account_id": account.id,
                            "address": account.address,
                            "public_key_hex": account.public_key_hex,
                            "private_key_hex": account.private_key_hex,
                            "balances": account.balances
                        })
                    }
                    None => json!({"ok": false, "error": "invalid private key"}),
                }
            }
            RpcRequest::Faucet { to, amount_quarks } => {
                let amount = amount_quarks.unwrap_or(10_000_000_000_000);
                let to_norm = normalize_address(&to);
                self.credit_balance(&to_norm, TOKEN_ETX_ID, amount);
                let bal = self
                    .state
                    .accounts
                    .get(&to_norm)
                    .and_then(|a| a.balances.get(&TOKEN_ETX_ID).copied())
                    .unwrap_or(0);
                self.state
                    .events
                    .push_front(format!("faucet: funded {} with {} q", to_norm, amount));
                json!({"ok": true, "to": to_norm, "amount_quarks": amount, "balance_quarks": bal})
            }
        }
    }

    fn start_next_slot(&mut self) {
        self.state.slot += 1;
        self.state.slot_started = Instant::now();
        self.state.current_result = None;
        self.state.mode = if self.total_eligible_tickets() == 0 { Mode::Pbm } else { Mode::Normal };
        self.state.current_leader = self.select_leader();
        self.state.exec_status = ExecStatus::Executing;
    }

    fn finish_slot(&mut self) {
        if let Some(remote) = self.state.remote_slot_results.remove(&self.state.slot) {
            self.record_hash(&remote);
            self.record_slot(remote);
            self.run_boundaries();
            return;
        }

        let no_tickets = self.total_eligible_tickets() == 0;
        let result = if no_tickets {
            self.protocol_no_tickets_block()
        } else if self.is_local_leader() {
            self.validator_block()
        } else {
            // No remote leader block observed by slot close.
            self.protocol_miss_block()
        };

        self.p2p.broadcast_message(&encode_slot_result(&result));
        self.record_hash(&result);
        self.record_slot(result);
        self.run_boundaries();
    }

    fn is_local_leader(&self) -> bool {
        let Some(local_id) = &self.state.local_validator_id else {
            return false;
        };
        self.state.current_leader == *local_id
    }

    fn total_eligible_tickets(&self) -> usize {
        self.state.tickets.iter().filter(|t| !t.dead && !t.muted && self.validator_active(&t.owner)).count()
    }

    fn validator_active(&self, id: &str) -> bool {
        self.state.validators.iter().any(|v| v.id == id && v.state == ValidatorState::Active)
    }

    fn select_leader(&mut self) -> String {
        let eligible: Vec<&Ticket> = self
            .state
            .tickets
            .iter()
            .filter(|t| !t.dead && !t.muted && self.validator_active(&t.owner))
            .collect();
        select_leader_owner(self.state.epoch_seed, self.state.slot, &eligible)
            .unwrap_or_else(|| "protocol".to_string())
    }

    fn validator_block(&mut self) -> SlotResult {
        let mut gas = 0_u64;
        let mut tx_count = 0_u32;
        let mut fees = 0_u64;
        while let Some(tx) = self.state.mempool.front() {
            if tx_count >= 3000 || gas + tx.gas > 16_000_000 {
                break;
            }
            let tx = tx.clone();
            if !self.can_pay_value(&tx.from, tx.token_id, tx.value) {
                self.state.mempool.pop_front();
                continue;
            }
            if !self.can_pay_fee(&tx.from, tx.fee_token_id, tx.fee_quarks as u128) {
                self.state.mempool.pop_front();
                continue;
            }
            self.state.mempool.pop_front();
            let value_ok = self.debit_balance(&tx.from, tx.token_id, tx.value);
            if !value_ok {
                continue;
            }
            self.credit_balance(&tx.to, tx.token_id, tx.value);
            self.debit_balance(&tx.from, tx.fee_token_id, tx.fee_quarks as u128);
            gas += tx.gas;
            fees += tx.fee_quarks;
            tx_count += 1;
            if self.rng.gen_bool(0.07) {
                break;
            }
        }
        self.state.fees_burned_total += fees as u128;
        self.state.burn_this_sub_epoch += fees as u128;
        if let Some(v) = self.state.validators.iter_mut().find(|v| v.id == self.state.current_leader) {
            v.blocks_this_sub_epoch += 1;
            if v.miss_counter > 0 {
                v.miss_counter -= 1;
            }
            v.vault_quarks += 30_000_000;
        }
        self.state.base_issuance_total += 30_000_000;

        if let Some(hash) = self.state.raw_tx_pending.pop_front()
            && let Some(rec) = self.state.raw_txs.get_mut(&hash)
        {
            rec.block_number = Some(self.state.slot);
            rec.block_hash = Some(format!("0x{}", hex::encode(hash_bytes(format!("block:{}", self.state.slot).as_bytes()))));
            rec.tx_index = Some(0);
            rec.success = Some(true);
            self.state
                .block_transactions
                .entry(self.state.slot)
                .or_default()
                .push(hash);
        }

        SlotResult { slot: self.state.slot, leader: self.state.current_leader.clone(), kind: BlockKind::Validator, tx_count, gas_used: gas, fees_burned: fees }
    }

    fn protocol_miss_block(&mut self) -> SlotResult {
        if let Some(v) = self.state.validators.iter_mut().find(|v| v.id == self.state.current_leader) {
            v.miss_counter += 1;
            if v.miss_counter >= 10 {
                v.state = ValidatorState::PunishedCooldown;
                v.cooldown_until_epoch = Some(self.state.epoch_index + 1);
            }
        }
        SlotResult { slot: self.state.slot, leader: self.state.current_leader.clone(), kind: BlockKind::ProtocolMiss, tx_count: 0, gas_used: 0, fees_burned: 0 }
    }

    fn protocol_collision_block(&mut self) -> SlotResult {
        SlotResult { slot: self.state.slot, leader: self.state.current_leader.clone(), kind: BlockKind::ProtocolCollision, tx_count: 0, gas_used: 0, fees_burned: 0 }
    }

    fn protocol_no_tickets_block(&mut self) -> SlotResult {
        SlotResult { slot: self.state.slot, leader: "protocol".to_string(), kind: BlockKind::ProtocolNoTickets, tx_count: 0, gas_used: 0, fees_burned: 0 }
    }

    fn run_boundaries(&mut self) {
        if self.state.slot > 0 && self.state.slot.is_multiple_of(SUB_EPOCH_SLOTS) {
            let produced = self
                .state
                .blocks_this_sub_epoch
                .iter()
                .filter(|p| p.is_some())
                .count() as u64;
            if produced > 0 {
                let k = self.state.burn_offset_k_permille as u128;
                let opb = k * self.state.burn_this_sub_epoch / 1000 / produced as u128;
                for proposer in &self.state.blocks_this_sub_epoch {
                    if let Some(pid) = proposer
                        && let Some(v) = self.state.validators.iter_mut().find(|v| &v.id == pid)
                    {
                        v.vault_quarks += opb;
                        self.state.burn_offset_total += opb;
                    }
                }
            }
            for v in &mut self.state.validators {
                v.blocks_this_sub_epoch = 0;
            }
            self.state.burn_this_sub_epoch = 0;
            self.state.blocks_this_sub_epoch.clear();
            self.state.sub_epoch_index += 1;
            self.state
                .events
                .push_front(format!("sub-epoch transition {}", self.state.sub_epoch_index));
        }
        if self.state.slot > 0 && self.state.slot.is_multiple_of(SUB_EPOCH_SLOTS * EPOCH_SUB_EPOCHS) {
            self.state.epoch_index += 1;
            self.state.annual_inflation_ppm = (self.state.annual_inflation_ppm * 9 / 10).max(5_000);
            self.finalize_retire_for_epoch(self.state.epoch_index);
            self.rotate_epoch_seed();
            self.process_epoch_validator_transitions();
            self.state
                .events
                .push_front(format!("epoch transition {}", self.state.epoch_index));
        }
    }

    fn record_hash(&mut self, r: &SlotResult) {
        self.state.prev_hash = hash_bytes(format!("{}-{}-{}", r.slot, r.leader, r.tx_count).as_bytes());
    }

    fn record_slot(&mut self, result: SlotResult) {
        self.state.current_result = Some(result.clone());
        self.update_liveness(&result);
        self.state.blocks_this_sub_epoch.push(match result.kind {
            BlockKind::Validator => Some(result.leader.clone()),
            _ => None,
        });
        self.record_block(&result);
        self.state.history.push_front(result);
        if self.state.history.len() > 20 {
            self.state.history.pop_back();
        }
    }

    fn record_block(&mut self, result: &SlotResult) {
        let number = result.slot;
        let hash = format!("0x{}", hex::encode(hash_bytes(format!("block:{}", number).as_bytes())));
        let parent_hash = if number == 0 {
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string()
        } else {
            format!(
                "0x{}",
                hex::encode(hash_bytes(format!("block:{}", number - 1).as_bytes()))
            )
        };
        let timestamp_ms = unix_ms_now() as u64;
        let tx_hashes = self
            .state
            .block_transactions
            .get(&number)
            .cloned()
            .unwrap_or_default();
        let rec = BlockRecord {
            number,
            hash: hash.clone(),
            parent_hash,
            timestamp_ms,
            gas_used: result.gas_used,
            tx_hashes,
        };
        self.state.block_hash_to_number.insert(hash, number);
        self.state.blocks.insert(number, rec);
    }

    fn update_liveness(&mut self, result: &SlotResult) {
        let epoch = result.slot / (SUB_EPOCH_SLOTS * EPOCH_SUB_EPOCHS);
        if epoch != self.state.liveness_epoch {
            self.state.liveness_epoch = epoch;
            self.state.liveness_counted_slots.clear();
            self.state.liveness_total_slots = 0;
            self.state.liveness_validator_slots = 0;
        }
        if !self.state.liveness_counted_slots.insert(result.slot) {
            return;
        }
        self.state.liveness_total_slots += 1;
        if result.kind == BlockKind::Validator {
            self.state.liveness_validator_slots += 1;
        }
        self.state.epoch_total_slots = self.state.liveness_total_slots;
        self.state.epoch_validator_blocks = self.state.liveness_validator_slots;
    }

    fn rebuild_liveness_from_history(&mut self) {
        self.state.liveness_counted_slots.clear();
        self.state.liveness_total_slots = 0;
        self.state.liveness_validator_slots = 0;

        let mut entries: Vec<SlotResult> = self.state.history.iter().cloned().collect();
        entries.sort_by_key(|e| e.slot);
        if let Some(last) = entries.last() {
            self.state.liveness_epoch = last.slot / (SUB_EPOCH_SLOTS * EPOCH_SUB_EPOCHS);
        }
        for e in &entries {
            let epoch = e.slot / (SUB_EPOCH_SLOTS * EPOCH_SUB_EPOCHS);
            if epoch != self.state.liveness_epoch {
                continue;
            }
            if self.state.liveness_counted_slots.insert(e.slot) {
                self.state.liveness_total_slots += 1;
                if e.kind == BlockKind::Validator {
                    self.state.liveness_validator_slots += 1;
                }
            }
        }
        self.state.epoch_total_slots = self.state.liveness_total_slots;
        self.state.epoch_validator_blocks = self.state.liveness_validator_slots;
    }

    fn rotate_epoch_seed(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(&self.state.epoch_seed);
        data.extend_from_slice(&self.state.epoch_index.to_be_bytes());
        self.state.epoch_seed = hash_bytes(&data);
    }

    fn process_epoch_validator_transitions(&mut self) {
        for v in &mut self.state.validators {
            if v.state == ValidatorState::Jailed {
                continue;
            }
            if v.state == ValidatorState::PunishedCooldown
                && let Some(until) = v.cooldown_until_epoch
                && self.state.epoch_index >= until
            {
                v.cooldown_until_epoch = None;
                if v.vault_quarks > 0 {
                    v.state = ValidatorState::Active;
                } else {
                    v.state = ValidatorState::PausedLowVault;
                }
            }
        }
    }

    fn finalize_retire_for_epoch(&mut self, epoch: u64) {
        let Some(ticket_ids) = self.state.retire_finalize.remove(&epoch) else {
            return;
        };
        for tid in ticket_ids {
            if let Some(t) = self.state.tickets.iter_mut().find(|t| t.id == tid) {
                t.dead = true;
                t.muted = false;
                t.retiring = false;
                t.bucket = 0;
            }
        }
    }

    fn ensure_account_exists(&mut self, id: &str) {
        let key = normalize_address(id);
        if self.state.accounts.contains_key(&key) {
            return;
        }
        self.state.accounts.insert(
            key.clone(),
            Account {
                id: key.clone(),
                private_key_hex: String::new(),
                public_key_hex: String::new(),
                address: key,
                nonce: 0,
                balances: HashMap::new(),
            },
        );
    }

    fn credit_balance(&mut self, account_id: &str, token_id: u64, amount: u128) {
        let k = normalize_address(account_id);
        self.ensure_account_exists(&k);
        if let Some(acct) = self.state.accounts.get_mut(&k) {
            *acct.balances.entry(token_id).or_insert(0) += amount;
        }
    }

    fn debit_balance(&mut self, account_id: &str, token_id: u64, amount: u128) -> bool {
        let k = normalize_address(account_id);
        self.ensure_account_exists(&k);
        let Some(acct) = self.state.accounts.get_mut(&k) else {
            return false;
        };
        let bal = acct.balances.entry(token_id).or_insert(0);
        if *bal < amount {
            return false;
        }
        *bal -= amount;
        true
    }

    fn burn_and_mint_tickets(&mut self, validator_id: &str, count: u64) {
        self.state.burn_this_sub_epoch += TICKET_COST_QUARKS.saturating_mul(count as u128);
        for _ in 0..count {
            let next_id = self
                .state
                .tickets
                .iter()
                .map(|t| t.id)
                .max()
                .unwrap_or(0)
                .saturating_add(1);
            self.state.tickets.push(Ticket {
                id: next_id,
                owner: validator_id.to_string(),
                bucket: ((next_id % 254) as u8) + 2,
                muted: false,
                dead: false,
                retiring: false,
                retire_requested_epoch: None,
                retire_effective_epoch: None,
            });
        }
        if !self.state.validators.iter().any(|v| v.id == validator_id) {
            self.state.validators.push(Validator {
                id: validator_id.to_string(),
                state: ValidatorState::Active,
                vault_quarks: 0,
                miss_counter: 0,
                double_sign_offenses: 0,
                blocks_this_sub_epoch: 0,
                cooldown_until_epoch: None,
            });
        }
    }

    fn can_pay_fee(&self, account_id: &str, token_id: u64, amount: u128) -> bool {
        let k = normalize_address(account_id);
        self.state
            .accounts
            .get(&k)
            .and_then(|a| a.balances.get(&token_id).copied())
            .is_some_and(|bal| bal >= amount)
    }

    fn can_pay_value(&self, account_id: &str, token_id: u64, value: u128) -> bool {
        let k = normalize_address(account_id);
        self.state
            .accounts
            .get(&k)
            .and_then(|a| a.balances.get(&token_id).copied())
            .is_some_and(|bal| bal >= value)
    }

    fn handle_jsonrpc(&mut self, id: Value, method: &str, params: &Value) -> Value {
        match method {
            "eth_chainId" => json!({"jsonrpc":"2.0","id":id,"result":"0x48a"}),
            "net_version" => json!({"jsonrpc":"2.0","id":id,"result":"1162"}),
            "web3_clientVersion" => json!({"jsonrpc":"2.0","id":id,"result":"eternix-testnet/0.1"}),
            "eth_accounts" | "eth_requestAccounts" => {
                json!({"jsonrpc":"2.0","id":id,"result":self.state.wallet_addresses})
            }
            "eth_getBalance" => {
                let addr = params.get(0).and_then(|v| v.as_str()).unwrap_or_default();
                let _tag = params.get(1).and_then(|v| v.as_str()).unwrap_or("latest");
                let key = normalize_address(addr);
                self.ensure_account_exists(&key);
                let bal_quarks = self
                    .state
                    .accounts
                    .get(&key)
                    .and_then(|a| a.balances.get(&TOKEN_ETX_ID).copied())
                    .unwrap_or(0);
                let bal_wei_style = bal_quarks.saturating_mul(WEI_PER_QUARK as u128);
                json!({"jsonrpc":"2.0","id":id,"result":to_hex_qty_u128(bal_wei_style)})
            }
            "eth_getTransactionCount" => {
                let addr = params.get(0).and_then(|v| v.as_str()).unwrap_or_default();
                let tag = params.get(1).and_then(|v| v.as_str()).unwrap_or("latest");
                let base = self.state.nonce_tracker.get(&normalize_address(addr)).copied().unwrap_or(0);
                let n = if tag == "pending" { base } else { base };
                json!({"jsonrpc":"2.0","id":id,"result":to_hex_qty(n)})
            }
            "eth_getCode" => json!({"jsonrpc":"2.0","id":id,"result":"0x"}),
            "eth_call" => json!({"jsonrpc":"2.0","id":id,"result":"0x"}),
            "eth_estimateGas" => json!({"jsonrpc":"2.0","id":id,"result":"0x3e8"}),
            "eth_gasPrice" => json!({"jsonrpc":"2.0","id":id,"result":"0x3b9aca00"}),
            "eth_maxPriorityFeePerGas" => json!({"jsonrpc":"2.0","id":id,"result":"0x0"}),
            "eth_syncing" => json!({"jsonrpc":"2.0","id":id,"result":false}),
            "eth_blockNumber" => json!({"jsonrpc":"2.0","id":id,"result":to_hex_qty(self.state.slot)}),
            "eth_sendRawTransaction" => {
                let raw = params.get(0).and_then(|v| v.as_str()).unwrap_or_default().to_string();
                eprintln!("[rpc] eth_sendRawTransaction received len={} prefix={}", raw.len(), &raw.chars().take(10).collect::<String>());
                let decoded = decode_raw_eip1559_tx(&raw).or_else(|| decode_raw_legacy_tx(&raw));
                let Some(tx) = decoded else {
                    eprintln!("[rpc] raw tx decode failed (type not supported or invalid)");
                    return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":"unsupported or invalid raw tx"}});
                };
                eprintln!("[rpc] decoded tx chain_id={} from={} nonce={} gas={} to={}", tx.chain_id, tx.from, tx.nonce, tx.gas, tx.to);
                if tx.chain_id != 1162 {
                    eprintln!("[rpc] reject raw tx: invalid chain id {}", tx.chain_id);
                    return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":"invalid chain id"}});
                }
                let expected_nonce = self.state.nonce_tracker.get(&tx.from).copied().unwrap_or(0);
                if tx.nonce < expected_nonce {
                    eprintln!("[rpc] reject raw tx: nonce {} expected >= {}", tx.nonce, expected_nonce);
                    return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":format!("invalid nonce expected >= {}", expected_nonce)}});
                }
                if tx.gas < 1000 {
                    eprintln!("[rpc] reject raw tx: gas {} < 1000", tx.gas);
                    return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":"gas_limit must be >= 1000"}});
                }
                let total_cost = tx.value.saturating_add(tx.fee_quarks as u128);
                if !self.can_pay_value(&tx.from, tx.token_id, tx.value)
                    || !self.can_pay_fee(&tx.from, tx.fee_token_id, tx.fee_quarks as u128)
                {
                    eprintln!("[rpc] reject raw tx: insufficient funds total_cost={}", total_cost);
                    return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":"insufficient funds for value + fee"}});
                }
                let hash = format!("0x{}", hex::encode(keccak256_hex_bytes(&raw)));
                let (tx_type_hex, v_hex, r_hex, s_hex) = extract_raw_signature_parts(&raw)
                    .unwrap_or_else(|| ("0x0".to_string(), "0x0".to_string(), "0x0".to_string(), "0x0".to_string()));
                self.state.nonce_tracker.insert(tx.from.clone(), tx.nonce.saturating_add(1));
                self.state.mempool.push_back(tx.clone());
                self.state.raw_txs.insert(
                    hash.clone(),
                    RawTxRecord {
                        hash: hash.clone(),
                        raw,
                        from: tx.from,
                        to: Some(tx.to),
                        nonce: tx.nonce,
                        gas: tx.gas,
                        input: tx.data,
                        value: tx.value,
                        fee_quarks: tx.fee_quarks,
                        chain_id: tx.chain_id,
                        tx_type: tx_type_hex,
                        v: v_hex,
                        r: r_hex,
                        s: s_hex,
                        block_number: None,
                        block_hash: None,
                        tx_index: None,
                        success: None,
                    },
                );
                self.state.raw_tx_pending.push_back(hash.clone());
                json!({"jsonrpc":"2.0","id":id,"result":hash})
            }
            "eth_getTransactionByHash" => {
                let h = params.get(0).and_then(|v| v.as_str()).unwrap_or_default();
                let tx = self.state.raw_txs.get(h);
                let result = tx.map(|r| {
                    let pending = r.block_number.is_none();
                    let is_type2 = r.tx_type == "0x2";
                    json!({
                        "hash": r.hash,
                        "from": r.from,
                        "to": r.to,
                        "nonce": to_hex_qty(r.nonce),
                        "gas": to_hex_qty(r.gas),
                        "gasPrice": "0x3b9aca00",
                        "type": r.tx_type,
                        "chainId": to_hex_qty(r.chain_id),
                        "maxFeePerGas": if is_type2 { json!("0x3b9aca00") } else { Value::Null },
                        "maxPriorityFeePerGas": if is_type2 { json!("0x0") } else { Value::Null },
                        "accessList": if is_type2 { json!([]) } else { Value::Null },
                        "yParity": if is_type2 { json!(r.v.clone()) } else { Value::Null },
                        "v": r.v,
                        "r": r.r,
                        "s": r.s,
                        "value": to_hex_qty_u128(r.value.saturating_mul(WEI_PER_QUARK as u128)),
                        "input": r.input,
                        "blockNumber": if pending { Value::Null } else { json!(r.block_number.map(to_hex_qty).unwrap_or_default()) },
                        "blockHash": if pending { Value::Null } else { json!(r.block_hash) },
                        "transactionIndex": if pending { Value::Null } else { json!(r.tx_index.map(to_hex_qty).unwrap_or_default()) }
                    })
                });
                json!({"jsonrpc":"2.0","id":id,"result":result})
            }
            "eth_getTransactionReceipt" => {
                let h = params.get(0).and_then(|v| v.as_str()).unwrap_or_default();
                let result = self.state.raw_txs.get(h).and_then(|r| {
                    r.block_number.map(|bn| {
                        json!({
                            "transactionHash": r.hash,
                            "blockNumber": to_hex_qty(bn),
                            "blockHash": r.block_hash,
                            "transactionIndex": r.tx_index.map(to_hex_qty).unwrap_or_else(|| "0x0".to_string()),
                            "from": r.from,
                            "to": r.to,
                            "status": if r.success.unwrap_or(false) { "0x1" } else { "0x0" },
                            "gasUsed": "0x3e8",
                            "cumulativeGasUsed": "0x3e8",
                            "effectiveGasPrice": "0x3b9aca00",
                            "contractAddress": Value::Null,
                            "type": r.tx_type,
                            "logsBloom": format!("0x{}", "00".repeat(256)),
                            "logs": []
                        })
                    })
                });
                json!({"jsonrpc":"2.0","id":id,"result":result})
            }
            "eth_getBlockByNumber" => {
                let n = params.get(0).and_then(|v| v.as_str()).unwrap_or("latest");
                let full_txs = params.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
                let slot = resolve_block_tag(n, self.state.slot);
                let block = self.state.blocks.get(&slot).cloned().unwrap_or_else(|| BlockRecord {
                    number: slot,
                    hash: format!("0x{}", hex::encode(hash_bytes(format!("block:{}", slot).as_bytes()))),
                    parent_hash: if slot == 0 {
                        "0x0000000000000000000000000000000000000000000000000000000000000000".to_string()
                    } else {
                        format!("0x{}", hex::encode(hash_bytes(format!("block:{}", slot - 1).as_bytes())))
                    },
                    timestamp_ms: unix_ms_now() as u64,
                    gas_used: 0,
                    tx_hashes: vec![],
                });
                let tx_hashes = block.tx_hashes.clone();
                let txs = if full_txs {
                    let mut out = Vec::new();
                    for h in tx_hashes {
                        if let Some(r) = self.state.raw_txs.get(&h) {
                            out.push(json!({
                                "hash": r.hash,
                                "from": r.from,
                                "to": r.to,
                                "nonce": to_hex_qty(r.nonce),
                                "gas": to_hex_qty(r.gas),
                                "gasPrice": "0x3b9aca00",
                                "value": to_hex_qty_u128(r.value.saturating_mul(WEI_PER_QUARK as u128)),
                                "input": r.input,
                                "blockNumber": r.block_number.map(to_hex_qty),
                                "blockHash": r.block_hash,
                                "transactionIndex": r.tx_index.map(to_hex_qty)
                            }));
                        }
                    }
                    json!(out)
                } else {
                    json!(tx_hashes)
                };
                json!({"jsonrpc":"2.0","id":id,"result":{
                    "number": to_hex_qty(block.number),
                    "hash": block.hash,
                    "parentHash": block.parent_hash,
                    "nonce": "0x0000000000000000",
                    "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                    "logsBloom": format!("0x{}", "00".repeat(256)),
                    "transactionsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "stateRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "receiptsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "miner": "0x0000000000000000000000000000000000000000",
                    "difficulty": "0x0",
                    "totalDifficulty": "0x0",
                    "extraData": "0x",
                    "size": "0x200",
                    "gasLimit": "0xf4240",
                    "gasUsed": to_hex_qty(block.gas_used),
                    "timestamp": to_hex_qty(block.timestamp_ms / 1000),
                    "transactions": txs,
                    "uncles": [],
                    "baseFeePerGas": "0x3b9aca00"
                }})
            }
            "eth_getBlockByHash" => {
                let h = params.get(0).and_then(|v| v.as_str()).unwrap_or_default();
                let full_txs = params.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
                let slot = self
                    .state
                    .block_hash_to_number
                    .get(&normalize_address(h))
                    .copied()
                    .or_else(|| {
                        self.state
                            .block_hash_to_number
                            .get(h)
                            .copied()
                    })
                    .unwrap_or(self.state.slot);
                let block = self.state.blocks.get(&slot).cloned().unwrap_or_else(|| BlockRecord {
                    number: slot,
                    hash: h.to_string(),
                    parent_hash: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                    timestamp_ms: unix_ms_now() as u64,
                    gas_used: 0,
                    tx_hashes: vec![],
                });
                let tx_hashes = block.tx_hashes.clone();
                let txs = if full_txs {
                    let mut out = Vec::new();
                    for hh in tx_hashes {
                        if let Some(r) = self.state.raw_txs.get(&hh) {
                            out.push(json!({
                                "hash": r.hash,
                                "from": r.from,
                                "to": r.to,
                                "nonce": to_hex_qty(r.nonce),
                                "gas": to_hex_qty(r.gas),
                                "gasPrice": "0x3b9aca00",
                                "value": to_hex_qty_u128(r.value.saturating_mul(WEI_PER_QUARK as u128)),
                                "input": r.input,
                                "blockNumber": r.block_number.map(to_hex_qty),
                                "blockHash": r.block_hash,
                                "transactionIndex": r.tx_index.map(to_hex_qty)
                            }));
                        }
                    }
                    json!(out)
                } else {
                    json!(tx_hashes)
                };
                json!({"jsonrpc":"2.0","id":id,"result":{
                    "number": to_hex_qty(block.number),
                    "hash": block.hash,
                    "parentHash": block.parent_hash,
                    "nonce": "0x0000000000000000",
                    "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                    "logsBloom": format!("0x{}", "00".repeat(256)),
                    "transactionsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "stateRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "receiptsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "miner": "0x0000000000000000000000000000000000000000",
                    "difficulty": "0x0",
                    "totalDifficulty": "0x0",
                    "extraData": "0x",
                    "size": "0x200",
                    "gasLimit": "0xf4240",
                    "gasUsed": to_hex_qty(block.gas_used),
                    "timestamp": to_hex_qty(block.timestamp_ms / 1000),
                    "transactions": txs,
                    "uncles": [],
                    "baseFeePerGas": "0x3b9aca00"
                }})
            }
            "eth_getBlockTransactionCountByNumber" => {
                let n = params.get(0).and_then(|v| v.as_str()).unwrap_or("latest");
                let slot = resolve_block_tag(n, self.state.slot);
                let c = self
                    .state
                    .blocks
                    .get(&slot)
                    .map(|b| b.tx_hashes.len() as u64)
                    .unwrap_or(0);
                json!({"jsonrpc":"2.0","id":id,"result":to_hex_qty(c)})
            }
            "eth_getBlockTransactionCountByHash" => {
                let h = params.get(0).and_then(|v| v.as_str()).unwrap_or_default();
                let slot = self
                    .state
                    .block_hash_to_number
                    .get(&normalize_address(h))
                    .copied()
                    .or_else(|| self.state.block_hash_to_number.get(h).copied());
                let c = slot
                    .and_then(|s| self.state.blocks.get(&s).map(|b| b.tx_hashes.len() as u64))
                    .unwrap_or(0);
                json!({"jsonrpc":"2.0","id":id,"result":to_hex_qty(c)})
            }
            "eth_getTransactionByBlockNumberAndIndex" => {
                let n = params.get(0).and_then(|v| v.as_str()).unwrap_or("latest");
                let idx = params
                    .get(1)
                    .and_then(|v| v.as_str())
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                    .unwrap_or(0);
                let slot = if n == "latest" {
                    self.state.slot
                } else {
                    u64::from_str_radix(n.trim_start_matches("0x"), 16).unwrap_or(self.state.slot)
                };
                let tx_hash = self
                    .state
                    .blocks
                    .get(&slot)
                    .and_then(|b| b.tx_hashes.get(idx as usize))
                    .cloned();
                let result = tx_hash
                    .as_ref()
                    .and_then(|h| tx_json_by_hash(&self.state.raw_txs, h));
                json!({"jsonrpc":"2.0","id":id,"result":result})
            }
            "eth_getTransactionByBlockHashAndIndex" => {
                let bh = params.get(0).and_then(|v| v.as_str()).unwrap_or_default();
                let idx = params
                    .get(1)
                    .and_then(|v| v.as_str())
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                    .unwrap_or(0);
                let slot = self
                    .state
                    .block_hash_to_number
                    .get(bh)
                    .copied()
                    .or_else(|| self.state.block_hash_to_number.get(&normalize_address(bh)).copied());
                let tx_hash = slot
                    .and_then(|s| self.state.blocks.get(&s))
                    .and_then(|b| b.tx_hashes.get(idx as usize))
                    .cloned();
                let result = tx_hash
                    .as_ref()
                    .and_then(|h| tx_json_by_hash(&self.state.raw_txs, h));
                json!({"jsonrpc":"2.0","id":id,"result":result})
            }
            "eth_getUncleCountByBlockNumber" | "eth_getUncleCountByBlockHash" => {
                json!({"jsonrpc":"2.0","id":id,"result":"0x0"})
            }
            "eth_getStorageAt" => json!({"jsonrpc":"2.0","id":id,"result":"0x0"}),
            "eth_getLogs" => json!({"jsonrpc":"2.0","id":id,"result":[]}),
            "eth_feeHistory" => {
                json!({"jsonrpc":"2.0","id":id,"result":{
                    "oldestBlock": to_hex_qty(self.state.slot.saturating_sub(1)),
                    "baseFeePerGas": ["0x3b9aca00","0x3b9aca00"],
                    "gasUsedRatio": [0.0],
                    "reward": [["0x0"]]
                }})
            }
            _ => json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"method not found"}}),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn derive_signature_for_sender(
        &self,
        chain_id: u64,
        from: &str,
        nonce: u64,
        to: &str,
        token_id: u64,
        value: u128,
        gas_limit: u64,
        max_fee_per_gas: u64,
        fee_token_id: u64,
        data: &str,
        tx_type: &str,
    ) -> Option<String> {
        let key = normalize_address(from);
        let acct = self.state.accounts.get(&key)?;
        if acct.private_key_hex.is_empty() {
            return None;
        }
        let raw = acct.private_key_hex.strip_prefix("0x").unwrap_or(&acct.private_key_hex);
        let pk = hex::decode(raw).ok()?;
        let signing_key = SigningKey::from_slice(&pk).ok()?;
        let msg = tx_message_bytes(
            chain_id,
            from,
            nonce,
            to,
            token_id,
            value,
            gas_limit,
            max_fee_per_gas,
            fee_token_id,
            data,
            tx_type,
        );
        let sig: Signature = signing_key.sign(&msg);
        Some(format!("0x{}", hex::encode(sig.to_bytes())))
    }

    fn hello_payload(&self) -> String {
        let slot_started_ms = unix_ms_now().saturating_sub(self.state.slot_started.elapsed().as_millis());
        format!(
            "{}|{}|{}|{}",
            self.state.slot,
            slot_started_ms,
            match self.state.mode_local {
                NodeMode::Validator => "validator",
                NodeMode::Standard => "standard",
            },
            self.state.local_validator_id.clone().unwrap_or_default()
        )
    }

    fn bootstrap_slot_from_peer(&mut self, slot: u64, slot_started_unix_ms: u128) {
        let now = unix_ms_now();
        if now < slot_started_unix_ms {
            return;
        }
        let elapsed = now - slot_started_unix_ms;
        if elapsed > SLOT_MS as u128 {
            return;
        }
        self.state.slot = slot;
        self.state.epoch_index = slot / (SUB_EPOCH_SLOTS * EPOCH_SUB_EPOCHS);
        self.state.sub_epoch_index = slot / SUB_EPOCH_SLOTS;
        self.state.epoch_seed = derive_epoch_seed(self.state.epoch_index);
        self.state.slot_started = Instant::now() - Duration::from_millis(elapsed as u64);
        self.state.anchor_time = UNIX_EPOCH + Duration::from_millis(slot_started_unix_ms as u64) - Duration::from_millis(slot.saturating_mul(SLOT_MS));
        self.state.bootstrapped_from_peer = true;
        self.state.events.push_front(format!("bootstrapped slot from peer: {}", slot));
        let hello = self.hello_payload();
        self.p2p.send_hello_now(&hello);
    }

    fn maybe_resync_slot_from_anchor(&mut self) {
        let now = SystemTime::now();
        if let Ok(since_anchor) = now.duration_since(self.state.anchor_time) {
            let target_slot = since_anchor.as_millis() as u64 / SLOT_MS;
            if target_slot > self.state.slot + 1 {
                self.state.slot = target_slot;
                self.state.epoch_index = target_slot / (SUB_EPOCH_SLOTS * EPOCH_SUB_EPOCHS);
                self.state.sub_epoch_index = target_slot / SUB_EPOCH_SLOTS;
                self.state.epoch_seed = derive_epoch_seed(self.state.epoch_index);
                let elapsed_ms = (since_anchor.as_millis() as u64) % SLOT_MS;
                self.state.slot_started = Instant::now() - Duration::from_millis(elapsed_ms);
                self.state.current_leader = self.select_leader();
                self.state.current_result = None;
                self.state.events.push_front(format!("slot resync to {}", target_slot));
            }
        }
    }

    fn learn_validator_from_hello(&mut self, mode: &str, validator_id: Option<&str>) {
        if mode != "validator" {
            return;
        }
        let Some(id) = validator_id else {
            return;
        };
        if self.state.validators.iter().any(|v| v.id == id) {
            return;
        }
        self.state.validators.push(Validator {
            id: id.to_string(),
            state: ValidatorState::Active,
            vault_quarks: 5_000_000_000_000_000,
            miss_counter: 0,
            double_sign_offenses: 0,
            blocks_this_sub_epoch: 0,
            cooldown_until_epoch: None,
        });
        let ticket_id = deterministic_ticket_id(id);
        self.state.tickets.push(Ticket {
            id: ticket_id,
            owner: id.to_string(),
            bucket: ((ticket_id % 254) as u8) + 2,
            muted: false,
            dead: false,
            retiring: false,
            retire_requested_epoch: None,
            retire_effective_epoch: None,
        });
        self.state.events.push_front(format!("discovered validator {}", id));
    }
}

fn hash_bytes(input: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(input);
    let out = h.finalize();
    let mut arr = [0_u8; 32];
    arr.copy_from_slice(&out[..32]);
    arr
}

fn deterministic_ticket_id(validator_id: &str) -> u64 {
    let h = hash_bytes(validator_id.as_bytes());
    let mut arr = [0_u8; 8];
    arr.copy_from_slice(&h[..8]);
    u64::from_be_bytes(arr)
}

fn unix_ms_now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis()
}

fn encode_history_snapshot(state: &ProtocolState) -> String {
    let mut parts = vec![format!(
        "HIST|{}|{}",
        state.epoch_validator_blocks, state.epoch_total_slots
    )];
    for h in state.history.iter().take(64) {
        let kind = match h.kind {
            BlockKind::Validator => "validator",
            BlockKind::ProtocolMiss => "protocol_miss",
            BlockKind::ProtocolCollision => "protocol_collision",
            BlockKind::ProtocolNoTickets => "protocol_notickets",
        };
        parts.push(format!(
            "{}:{}:{}:{}:{}:{}",
            h.slot, h.leader, kind, h.tx_count, h.gas_used, h.fees_burned
        ));
    }
    parts.join("|")
}

fn parse_history_snapshot(msg: &str) -> Option<(u64, u64, Vec<SlotResult>)> {
    let p: Vec<&str> = msg.split('|').collect();
    if p.len() < 3 || p[0] != "HIST" {
        return None;
    }
    let evb: u64 = p[1].parse().ok()?;
    let ets: u64 = p[2].parse().ok()?;
    let mut out = vec![];
    for chunk in p.iter().skip(3) {
        let f: Vec<&str> = chunk.split(':').collect();
        if f.len() != 6 {
            continue;
        }
        let kind = match f[2] {
            "validator" => BlockKind::Validator,
            "protocol_miss" => BlockKind::ProtocolMiss,
            "protocol_collision" => BlockKind::ProtocolCollision,
            "protocol_notickets" => BlockKind::ProtocolNoTickets,
            _ => continue,
        };
        let slot = match f[0].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let tx_count = match f[3].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let gas_used = match f[4].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let fees_burned = match f[5].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        out.push(SlotResult {
            slot,
            leader: f[1].to_string(),
            kind,
            tx_count,
            gas_used,
            fees_burned,
        });
    }
    Some((evb, ets, out))
}

fn derive_epoch_seed(epoch_index: u64) -> [u8; 32] {
    let mut seed = GENESIS_EPOCH_SEED;
    for i in 1..=epoch_index {
        let mut data = Vec::new();
        data.extend_from_slice(&seed);
        data.extend_from_slice(&i.to_be_bytes());
        seed = hash_bytes(&data);
    }
    seed
}

fn normalize_address(input: &str) -> String {
    let s = input.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        format!("0x{}", s[2..].to_lowercase())
    } else {
        s.to_lowercase()
    }
}

fn account_from_private_key_hex(id: &str, private_key_hex: &str) -> Option<Account> {
    let raw = private_key_hex.strip_prefix("0x").unwrap_or(private_key_hex);
    let bytes = hex::decode(raw).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let signing_key = SigningKey::from_slice(&bytes).ok()?;
    let verify = signing_key.verifying_key();
    let pub_uncompressed = verify.to_encoded_point(false);
    let pub_bytes = pub_uncompressed.as_bytes();
    if pub_bytes.len() != 65 {
        return None;
    }

    let mut hasher = Keccak256::new();
    hasher.update(&pub_bytes[1..]);
    let digest = hasher.finalize();
    let address = format!("0x{}", hex::encode(&digest[12..]));

    Some(Account {
        id: id.to_string(),
        private_key_hex: format!("0x{}", raw.to_lowercase()),
        public_key_hex: format!("0x{}", hex::encode(pub_bytes)),
        address,
        nonce: 0,
        balances: HashMap::new(),
    })
}

#[allow(clippy::too_many_arguments)]
fn tx_message_bytes(
    chain_id: u64,
    from: &str,
    nonce: u64,
    to: &str,
    token_id: u64,
    value: u128,
    gas_limit: u64,
    max_fee_per_gas: u64,
    fee_token_id: u64,
    data: &str,
    tx_type: &str,
) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        chain_id,
        normalize_address(from),
        nonce,
        normalize_address(to),
        token_id,
        value,
        gas_limit,
        max_fee_per_gas,
        fee_token_id,
        data,
        tx_type
    )
    .into_bytes()
}

fn to_hex_qty(v: u64) -> String {
    format!("0x{:x}", v)
}

fn to_hex_qty_u128(v: u128) -> String {
    format!("0x{:x}", v)
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn keccak256_hex_bytes(raw_hex: &str) -> [u8; 32] {
    let bytes = hex::decode(raw_hex.trim_start_matches("0x")).unwrap_or_default();
    keccak256(&bytes)
}

fn decode_raw_eip1559_tx(raw_hex: &str) -> Option<Tx> {
    let raw = raw_hex.trim_start_matches("0x");
    let bytes = hex::decode(raw).ok()?;
    if bytes.is_empty() || bytes[0] != 0x02 {
        eprintln!("[rpc][decode] unsupported tx type byte: {}", bytes.first().copied().unwrap_or_default());
        return None;
    }
    let payload = &bytes[1..];
    let rlp = Rlp::new(payload);
    if !rlp.is_list() || rlp.item_count().ok()? < 12 {
        return None;
    }

    let chain_id: u64 = rlp.val_at(0).ok()?;
    let nonce: u64 = rlp.val_at(1).ok()?;
    let _max_priority_fee_per_gas: u64 = rlp.val_at(2).ok()?;
    let max_fee_per_gas: u64 = rlp.val_at(3).ok()?;
    let gas_limit: u64 = rlp.val_at(4).ok()?;
    let to_bytes: Vec<u8> = rlp.val_at(5).ok()?;
    let to = if to_bytes.is_empty() {
        "0x0000000000000000000000000000000000000000".to_string()
    } else {
        format!("0x{}", hex::encode(&to_bytes))
    };
    let value_wei_u128: u128 = rlp_u128_at(&rlp, 6)?;
    let data_bytes: Vec<u8> = rlp.val_at(7).ok()?;
    let data_hex = format!("0x{}", hex::encode(&data_bytes));

    let y_parity: u64 = rlp.val_at(9).ok()?;
    let r_bytes: Vec<u8> = rlp.val_at(10).ok()?;
    let s_bytes: Vec<u8> = rlp.val_at(11).ok()?;
    let sig_bytes = rs_64(&r_bytes, &s_bytes)?;
    let sig = Signature::from_slice(&sig_bytes).ok()?;
    let recid = RecoveryId::from_byte(y_parity as u8)?;

    let access_list_raw = rlp.at(8).ok()?.as_raw().to_vec();

    let mut stream = RlpStream::new_list(9);
    stream.append(&chain_id);
    stream.append(&nonce);
    stream.append(&_max_priority_fee_per_gas);
    stream.append(&max_fee_per_gas);
    stream.append(&gas_limit);
    stream.append(&to_bytes);
    stream.append(&value_wei_u128);
    stream.append(&data_bytes);
    stream.append_raw(&access_list_raw, 1);
    let signing_payload = stream.out().to_vec();
    let mut preimage = vec![0x02u8];
    preimage.extend_from_slice(&signing_payload);
    let msg_hash = keccak256(&preimage);
    let vk = VerifyingKey::recover_from_prehash(&msg_hash, &sig, recid).ok()?;
    let from = pubkey_to_eth_address(&vk);

    let fee = gas_limit.saturating_mul(max_fee_per_gas_to_quarks(max_fee_per_gas));
    Some(Tx {
        chain_id,
        from,
        nonce,
        to,
        token_id: 0,
        value: wei_to_quarks(value_wei_u128),
        gas: gas_limit,
        fee_quarks: fee,
        max_fee_per_gas,
        kind: "transfer",
        valid_after_slot: 0,
        fee_token_id: 0,
        data: data_hex,
        signature_hex: format!("0x{}", hex::encode(sig_bytes)),
    })
}

fn decode_raw_legacy_tx(raw_hex: &str) -> Option<Tx> {
    let raw = raw_hex.trim_start_matches("0x");
    let bytes = hex::decode(raw).ok()?;
    if bytes.is_empty() {
        return None;
    }
    if bytes[0] <= 0x7f || bytes[0] == 0x01 || bytes[0] == 0x02 {
        return None;
    }

    let rlp = Rlp::new(&bytes);
    if !rlp.is_list() || rlp.item_count().ok()? < 9 {
        return None;
    }

    let nonce: u64 = rlp_u64_at(&rlp, 0)?;
    let gas_price: u64 = rlp_u64_at(&rlp, 1)?;
    let gas_limit: u64 = rlp_u64_at(&rlp, 2)?;
    let to_bytes: Vec<u8> = rlp_bytes_at(&rlp, 3)?;
    let to = if to_bytes.is_empty() {
        "0x0000000000000000000000000000000000000000".to_string()
    } else {
        format!("0x{}", hex::encode(&to_bytes))
    };
    let value_wei_u128: u128 = rlp_u128_at(&rlp, 4)?;
    let data_bytes: Vec<u8> = rlp_bytes_at(&rlp, 5)?;
    let data_hex = format!("0x{}", hex::encode(&data_bytes));
    let v: u64 = rlp_u64_at(&rlp, 6)?;
    let r_bytes: Vec<u8> = rlp_bytes_at(&rlp, 7)?;
    let s_bytes: Vec<u8> = rlp_bytes_at(&rlp, 8)?;

    let (chain_id, parity, eip155) = if v >= 35 {
        ((v - 35) / 2, (v - 35) % 2, true)
    } else if v == 27 || v == 28 {
        (1162_u64, v - 27, false)
    } else {
        return None;
    };
    let recid = RecoveryId::from_byte(parity as u8)?;
    let sig_bytes = rs_64(&r_bytes, &s_bytes)?;
    let sig = Signature::from_slice(&sig_bytes).ok()?;

    let mut stream = if eip155 {
        RlpStream::new_list(9)
    } else {
        RlpStream::new_list(6)
    };
    stream.append(&nonce);
    stream.append(&gas_price);
    stream.append(&gas_limit);
    stream.append(&to_bytes);
    stream.append(&value_wei_u128);
    stream.append(&data_bytes);
    if eip155 {
        stream.append(&chain_id);
        stream.append(&0u8);
        stream.append(&0u8);
    }
    let preimage = stream.out().to_vec();
    let msg_hash = keccak256(&preimage);
    let vk = VerifyingKey::recover_from_prehash(&msg_hash, &sig, recid).ok()?;
    let from = pubkey_to_eth_address(&vk);

    let fee = gas_limit.saturating_mul(max_fee_per_gas_to_quarks(gas_price));
    Some(Tx {
        chain_id,
        from,
        nonce,
        to,
        token_id: 0,
        value: wei_to_quarks(value_wei_u128),
        gas: gas_limit,
        fee_quarks: fee,
        max_fee_per_gas: gas_price,
        kind: "transfer",
        valid_after_slot: 0,
        fee_token_id: 0,
        data: data_hex,
        signature_hex: format!("0x{}", hex::encode(sig_bytes)),
    })
}

fn rlp_bytes_at(rlp: &Rlp, idx: usize) -> Option<Vec<u8>> {
    let item = rlp.at(idx).ok()?;
    if item.is_empty() {
        return Some(vec![]);
    }
    item.data().ok().map(|d| d.to_vec())
}

fn be_bytes_to_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.len() > 8 {
        return None;
    }
    let mut out = 0u64;
    for b in bytes {
        out = (out << 8) | (*b as u64);
    }
    Some(out)
}

fn be_bytes_to_u128(bytes: &[u8]) -> Option<u128> {
    if bytes.len() > 16 {
        return None;
    }
    let mut out = 0u128;
    for b in bytes {
        out = (out << 8) | (*b as u128);
    }
    Some(out)
}

fn rlp_u64_at(rlp: &Rlp, idx: usize) -> Option<u64> {
    let bytes = rlp_bytes_at(rlp, idx)?;
    if bytes.is_empty() {
        return Some(0);
    }
    be_bytes_to_u64(&bytes)
}

fn rlp_u128_at(rlp: &Rlp, idx: usize) -> Option<u128> {
    let bytes = rlp_bytes_at(rlp, idx)?;
    if bytes.is_empty() {
        return Some(0);
    }
    be_bytes_to_u128(&bytes)
}

fn rs_64(r: &[u8], s: &[u8]) -> Option<[u8; 64]> {
    if r.len() > 32 || s.len() > 32 {
        return None;
    }
    let mut out = [0u8; 64];
    out[32 - r.len()..32].copy_from_slice(r);
    out[64 - s.len()..64].copy_from_slice(s);
    Some(out)
}

fn pubkey_to_eth_address(vk: &VerifyingKey) -> String {
    let pub_uncompressed = vk.to_encoded_point(false);
    let bytes = pub_uncompressed.as_bytes();
    let mut h = Keccak256::new();
    h.update(&bytes[1..]);
    let out = h.finalize();
    format!("0x{}", hex::encode(&out[12..]))
}

fn extract_raw_signature_parts(raw_hex: &str) -> Option<(String, String, String, String)> {
    let bytes = hex::decode(raw_hex.trim_start_matches("0x")).ok()?;
    if bytes.is_empty() {
        return None;
    }
    if bytes[0] == 0x02 {
        let rlp = Rlp::new(&bytes[1..]);
        let y: u64 = rlp_u64_at(&rlp, 9)?;
        let r = rlp_bytes_at(&rlp, 10)?;
        let s = rlp_bytes_at(&rlp, 11)?;
        return Some((
            "0x2".to_string(),
            to_hex_qty(y),
            format!("0x{}", hex::encode(r)),
            format!("0x{}", hex::encode(s)),
        ));
    }
    let rlp = Rlp::new(&bytes);
    let v: u64 = rlp_u64_at(&rlp, 6)?;
    let r = rlp_bytes_at(&rlp, 7)?;
    let s = rlp_bytes_at(&rlp, 8)?;
    Some((
        "0x0".to_string(),
        to_hex_qty(v),
        format!("0x{}", hex::encode(r)),
        format!("0x{}", hex::encode(s)),
    ))
}

fn tx_json_by_hash(raw_txs: &HashMap<String, RawTxRecord>, h: &str) -> Option<Value> {
    let r = raw_txs.get(h)?;
    let pending = r.block_number.is_none();
    let is_type2 = r.tx_type == "0x2";
    Some(json!({
        "hash": r.hash,
        "from": r.from,
        "to": r.to,
        "nonce": to_hex_qty(r.nonce),
        "gas": to_hex_qty(r.gas),
        "gasPrice": "0x3b9aca00",
        "type": r.tx_type,
        "chainId": to_hex_qty(r.chain_id),
        "maxFeePerGas": if is_type2 { json!("0x3b9aca00") } else { Value::Null },
        "maxPriorityFeePerGas": if is_type2 { json!("0x0") } else { Value::Null },
        "accessList": if is_type2 { json!([]) } else { Value::Null },
        "yParity": if is_type2 { json!(r.v.clone()) } else { Value::Null },
        "v": r.v,
        "r": r.r,
        "s": r.s,
        "value": to_hex_qty_u128(r.value.saturating_mul(WEI_PER_QUARK as u128)),
        "input": r.input,
        "blockNumber": if pending { Value::Null } else { json!(r.block_number.map(to_hex_qty).unwrap_or_default()) },
        "blockHash": if pending { Value::Null } else { json!(r.block_hash) },
        "transactionIndex": if pending { Value::Null } else { json!(r.tx_index.map(to_hex_qty).unwrap_or_default()) }
    }))
}

fn resolve_block_tag(tag: &str, latest: u64) -> u64 {
    match tag {
        "latest" | "pending" | "safe" | "finalized" => latest,
        "earliest" => 0,
        _ => u64::from_str_radix(tag.trim_start_matches("0x"), 16).unwrap_or(latest),
    }
}

fn max_fee_per_gas_to_quarks(max_fee_per_gas: u64) -> u64 {
    // MetaMask/EVM values are wei-style 18-decimal units.
    // Eternix fee accounting is in quarks (1 quark = 1e-10 ETX),
    // therefore 1 quark = 1e8 wei-like units.
    let q = max_fee_per_gas / WEI_PER_QUARK;
    q.max(1)
}

fn wei_to_quarks(value_wei: u128) -> u128 {
    value_wei / WEI_PER_QUARK as u128
}
