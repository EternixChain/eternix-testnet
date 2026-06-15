use super::*;

impl Protocol {
    pub fn new(cfg: Config) -> Result<Self> {
        let p2p = P2p::new(cfg.p2p_port, &cfg.peers)?;
        let local_validator_id = if cfg.mode == NodeMode::Validator {
            Some(format!("val-{}", cfg.p2p_port))
        } else {
            None
        };
        let local_validator_account = cfg.validator_account.as_deref().map(normalize_address);

        let mut validators = vec![];
        let mut tickets = vec![];
        if let Some(id) = &local_validator_id {
            validators.push(Validator {
                id: id.clone(),
                owner_account: local_validator_account.clone(),
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
        this.bootstrap_accounts(&cfg.genesis_path);
        this.state.events.push_front(format!("node started on p2p port {}", cfg.p2p_port));
        Ok(this)
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
                let Some(owner_account) = self
                    .state
                    .validators
                    .iter()
                    .find(|v| v.id == validator_id)
                    .and_then(|v| v.owner_account.clone())
                else {
                    return json!({"ok": false, "error": "validator account not configured"});
                };
                if !self.debit_balance(&owner_account, TOKEN_ETX_ID, cost) {
                    return json!({"ok": false, "error": "insufficient validator account balance"});
                }
                self.burn_and_mint_tickets(&validator_id, count);
                json!({"ok": true, "validator_id": validator_id, "burned_from": owner_account, "tickets_bought": count, "cost_quarks": cost})
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
}
