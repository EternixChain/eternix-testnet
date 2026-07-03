use super::*;

impl Protocol {
    pub fn new(cfg: Config) -> Result<Self> {
        let p2p = P2p::new(cfg.p2p_port, &cfg.peers)?;
        // Explicit validator IDs attach to registered validators; omitted IDs keep the legacy bootstrap path.
        let local_validator_bootstrap =
            cfg.mode == NodeMode::Validator && cfg.validator_id.is_none();
        let local_validator_id = if cfg.mode == NodeMode::Validator {
            Some(
                cfg.validator_id
                    .clone()
                    .unwrap_or_else(|| format!("val-{}", cfg.p2p_port)),
            )
        } else {
            None
        };
        let local_validator_account = cfg.validator_account.as_deref().map(normalize_address);

        let mut validators = vec![];
        let mut tickets = vec![];
        if let Some(id) = &local_validator_id {
            // Non-bootstrap validators start empty and learn registration/vault/ticket state from peers or txs.
            validators.push(Validator {
                id: id.clone(),
                owner_account: local_validator_account.clone(),
                validator_pubkey: None,
                reward_address: local_validator_account.clone(),
                state: if local_validator_bootstrap {
                    ValidatorState::Active
                } else {
                    ValidatorState::Inactive
                },
                vault_quarks: if local_validator_bootstrap {
                    INITIAL_VALIDATOR_VAULT_QUARKS
                } else {
                    0
                },
                miss_counter: 0,
                double_sign_offenses: 0,
                blocks_this_sub_epoch: 0,
                cooldown_until_epoch: None,
            });
            if local_validator_bootstrap {
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
                ticket_burned_total: 0,
                base_issuance_total: 0,
                burn_offset_total: 0,
                sub_epoch_issued_quarks: 0,
                sub_epoch_burned_quarks: 0,
                epoch_issued_quarks: 0,
                epoch_burned_quarks: 0,
                annual_inflation_ppb: 60_000_000,
                base_reward_per_block_quarks: 0,
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
                local_validator_bootstrap,
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
        this.recompute_base_reward_per_block();
        this.state
            .events
            .push_front(format!("node started on p2p port {}", cfg.p2p_port));
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
        let from = self.state.wallet_addresses
            [self.rng.gen_range(0..self.state.wallet_addresses.len())]
        .clone();
        let nonce = self.state.nonce_tracker.get(&from).copied().unwrap_or(0);
        self.state
            .nonce_tracker
            .insert(from.clone(), nonce.saturating_add(1));
        let kind = if self.rng.gen_bool(0.2) {
            "contract"
        } else {
            "transfer"
        };
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
        let from = self.state.wallet_addresses
            [self.rng.gen_range(0..self.state.wallet_addresses.len())]
        .clone();
        // The TUI PBM shortcut now exercises the real registration transaction path.
        let validator_key = SigningKey::random(&mut OsRng);
        let validator_pubkey = format!(
            "0x{}",
            hex::encode(
                validator_key
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
            )
        );
        let _ = self.enqueue_register_validator_tx(&from, &validator_pubkey, None, None, None);
    }

    pub fn enqueue_validator_system_tx(
        &mut self,
        validator_id: &str,
        value: u128,
        kind: &'static str,
        nonce: Option<u64>,
        _gas_limit: Option<u64>,
        _max_fee_per_gas: Option<u64>,
        signature_hex: Option<String>,
    ) -> Value {
        if kind != "walletToVault" && kind != "vaultToWallet" && kind != "buyTicket" {
            return json!({"ok": false, "error": "invalid validator system tx type"});
        }
        if value == 0 {
            return json!({"ok": false, "error": "value must be greater than zero"});
        }
        if !self.state.validators.iter().any(|v| v.id == validator_id) {
            return json!({"ok": false, "error": "validator not found"});
        }
        let Some(owner_account) = self.validator_owner_account(validator_id) else {
            return json!({"ok": false, "error": "validator account not configured"});
        };

        let nonce = nonce.unwrap_or_else(|| {
            self.state
                .nonce_tracker
                .get(&owner_account)
                .copied()
                .unwrap_or(0)
        });
        let expected_nonce = self
            .state
            .nonce_tracker
            .get(&owner_account)
            .copied()
            .unwrap_or(0);
        if nonce < expected_nonce {
            return json!({"ok": false, "error": format!("invalid nonce, expected >= {}", expected_nonce)});
        }

        let gas_limit = 1000_u64;
        let max_fee_per_gas = 10_u64;
        let fee_quarks = gas_limit.saturating_mul(max_fee_per_gas_to_quarks(max_fee_per_gas));

        // Fixed-fee validator system txs make vault/ticket flows predictable during PBM bootstrap.
        let required_owner_balance = match kind {
            "walletToVault" => value.saturating_add(fee_quarks as u128),
            "buyTicket" => TICKET_COST_QUARKS
                .saturating_mul(value)
                .saturating_add(fee_quarks as u128),
            _ => fee_quarks as u128,
        };
        if !self.can_pay_fee(&owner_account, TOKEN_ETX_ID, required_owner_balance) {
            return json!({"ok": false, "error": "insufficient validator account balance"});
        }
        if kind == "vaultToWallet"
            && !self
                .state
                .validators
                .iter()
                .find(|v| v.id == validator_id)
                .is_some_and(|v| v.vault_quarks >= value)
        {
            return json!({"ok": false, "error": "insufficient vault balance"});
        }

        let sig = match signature_hex {
            Some(sig) => sig,
            None => {
                let Some(sig) = self.derive_signature_for_sender(
                    1162,
                    &owner_account,
                    nonce,
                    validator_id,
                    TOKEN_ETX_ID,
                    value,
                    gas_limit,
                    max_fee_per_gas,
                    TOKEN_ETX_ID,
                    "",
                    kind,
                ) else {
                    return json!({"ok": false, "error": "cannot derive signature for validator account"});
                };
                sig
            }
        };

        let tx = Tx {
            chain_id: 1162,
            from: owner_account.clone(),
            nonce,
            to: validator_id.to_string(),
            token_id: TOKEN_ETX_ID,
            value,
            gas: gas_limit,
            fee_quarks,
            max_fee_per_gas,
            kind,
            valid_after_slot: 0,
            fee_token_id: TOKEN_ETX_ID,
            data: String::new(),
            signature_hex: sig,
        };
        let (tx_hash, valid_after_slot, accepted_tx) = match self.enqueue_standard_or_pbm(tx) {
            Ok(result) => result,
            Err(error) => return json!({"ok": false, "error": error}),
        };
        self.state
            .nonce_tracker
            .insert(owner_account.clone(), nonce.saturating_add(1));
        if self.p2p.mark_seen(tx_hash.clone()) {
            self.p2p.broadcast_tx(&accepted_tx);
        }

        if kind == "buyTicket" {
            json!({
                "ok": true,
                "tx_hash": tx_hash,
                "validator_id": validator_id,
                "account": owner_account,
                "count": value,
                "ticket_cost_quarks": TICKET_COST_QUARKS.saturating_mul(value),
                "fee_quarks": fee_quarks,
                "valid_after_slot": valid_after_slot,
                "tx_type": kind
            })
        } else {
            json!({
                "ok": true,
                "tx_hash": tx_hash,
                "validator_id": validator_id,
                "account": owner_account,
                "amount_quarks": value,
                "fee_quarks": fee_quarks,
                "valid_after_slot": valid_after_slot,
                "tx_type": kind
            })
        }
    }

    pub fn enqueue_register_validator_tx(
        &mut self,
        from: &str,
        validator_pubkey: &str,
        reward_address: Option<String>,
        nonce: Option<u64>,
        signature_hex: Option<String>,
    ) -> Value {
        let from = normalize_address(from);
        self.ensure_account_exists(&from);
        let Some(validator_pubkey) = self.normalize_validator_pubkey(validator_pubkey) else {
            return json!({"ok": false, "error": "invalid validator_pubkey"});
        };
        if self.validator_pubkey_registered(&validator_pubkey)
            || self
                .state
                .mempool
                .iter()
                .chain(self.state.pbm_pool.iter())
                .filter(|tx| tx.kind == "registerValidator")
                .filter_map(|tx| decode_register_validator_data(&tx.data))
                .any(|(pending_pubkey, _)| pending_pubkey == validator_pubkey)
        {
            return json!({"ok": false, "error": "validator_pubkey already registered"});
        }

        let reward_address = reward_address
            .map(|addr| normalize_address(&addr))
            .unwrap_or_else(|| from.clone());
        let nonce =
            nonce.unwrap_or_else(|| self.state.nonce_tracker.get(&from).copied().unwrap_or(0));
        let expected_nonce = self.state.nonce_tracker.get(&from).copied().unwrap_or(0);
        if nonce < expected_nonce {
            return json!({"ok": false, "error": format!("invalid nonce, expected >= {}", expected_nonce)});
        }

        let gas_limit = 1000_u64;
        let max_fee_per_gas = 10_u64;
        let fee_quarks = gas_limit.saturating_mul(max_fee_per_gas_to_quarks(max_fee_per_gas));
        if !self.can_pay_fee(&from, TOKEN_ETX_ID, fee_quarks as u128) {
            return json!({"ok": false, "error": "insufficient account balance"});
        }

        let validator_id = self.next_pending_validator_id();
        let data = encode_register_validator_data(&validator_pubkey, &reward_address);
        // Registration encodes metadata in tx.data so it can travel through the existing Tx gossip format.
        let sig = match signature_hex {
            Some(sig) => sig,
            None => {
                let Some(sig) = self.derive_signature_for_sender(
                    1162,
                    &from,
                    nonce,
                    &validator_id,
                    TOKEN_ETX_ID,
                    0,
                    gas_limit,
                    max_fee_per_gas,
                    TOKEN_ETX_ID,
                    &data,
                    "registerValidator",
                ) else {
                    return json!({"ok": false, "error": "cannot derive signature for sender"});
                };
                sig
            }
        };

        let tx = Tx {
            chain_id: 1162,
            from: from.clone(),
            nonce,
            to: validator_id.clone(),
            token_id: TOKEN_ETX_ID,
            value: 0,
            gas: gas_limit,
            fee_quarks,
            max_fee_per_gas,
            kind: "registerValidator",
            valid_after_slot: 0,
            fee_token_id: TOKEN_ETX_ID,
            data,
            signature_hex: sig,
        };
        let (tx_hash, valid_after_slot, accepted_tx) = match self.enqueue_standard_or_pbm(tx) {
            Ok(result) => result,
            Err(error) => return json!({"ok": false, "error": error}),
        };
        self.state
            .nonce_tracker
            .insert(from.clone(), nonce.saturating_add(1));
        if self.p2p.mark_seen(tx_hash.clone()) {
            self.p2p.broadcast_tx(&accepted_tx);
        }

        json!({
            "ok": true,
            "tx_hash": tx_hash,
            "validator_id": validator_id,
            "operator": from,
            "reward_address": reward_address,
            "fee_quarks": fee_quarks,
            "valid_after_slot": valid_after_slot,
            "tx_type": "registerValidator"
        })
    }

    pub fn request_local_ticket_retire(&mut self, count: usize) {
        let Some(local_id) = self.state.local_validator_id.clone() else {
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
                t.owner == local_id
                    && !t.dead
                    && !t.muted
                    && !t.retiring
                    && self.validator_active(&t.owner)
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

        // Retirement mutes tickets immediately, then finalizes them after the cooldown epoch window.
        for tid in &eligible {
            if let Some(t) = self.state.tickets.iter_mut().find(|t| t.id == *tid) {
                t.retiring = true;
                t.muted = true;
                t.bucket = 1;
                t.retire_requested_epoch = Some(request_epoch);
                t.retire_effective_epoch = Some(finalize_epoch);
            }
            self.state
                .retire_finalize
                .entry(finalize_epoch)
                .or_default()
                .push(*tid);
        }
        self.refresh_validator_activation(&local_id);

        self.state.events.push_front(format!(
            "retire started: {} ticket(s), finalize at epoch {}",
            eligible.len(),
            finalize_epoch
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
                if tx_type != "normal_transfer" {
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
                self.state
                    .nonce_tracker
                    .insert(from.clone(), nonce.saturating_add(1));
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
                    kind: "transfer",
                    valid_after_slot: 0,
                    fee_token_id,
                    data,
                    signature_hex: sig,
                };
                let tx_hash = tx_id(&tx);
                if self.p2p.mark_seen(tx_hash.clone()) {
                    self.p2p.broadcast_tx(&tx);
                }
                self.state.mempool.push_back(tx);
                json!({"ok": true, "tx_hash": tx_hash, "fee_quarks": fee_quarks})
            }
            RpcRequest::BuyTicket {
                validator_id,
                count,
                nonce,
                signature_hex,
            } => self.enqueue_validator_system_tx(
                &validator_id,
                count as u128,
                "buyTicket",
                nonce,
                None,
                None,
                signature_hex,
            ),
            RpcRequest::RegisterValidator {
                from,
                validator_pubkey,
                reward_address,
                nonce,
                signature_hex,
            } => self.enqueue_register_validator_tx(
                &from,
                &validator_pubkey,
                reward_address,
                nonce,
                signature_hex,
            ),
            RpcRequest::WalletToVault {
                validator_id,
                amount_quarks,
                nonce,
                gas_limit,
                max_fee_per_gas,
                signature_hex,
            } => self.enqueue_validator_system_tx(
                &validator_id,
                amount_quarks,
                "walletToVault",
                nonce,
                gas_limit,
                max_fee_per_gas,
                signature_hex,
            ),
            RpcRequest::VaultToWallet {
                validator_id,
                amount_quarks,
                nonce,
                gas_limit,
                max_fee_per_gas,
                signature_hex,
            } => self.enqueue_validator_system_tx(
                &validator_id,
                amount_quarks,
                "vaultToWallet",
                nonce,
                gas_limit,
                max_fee_per_gas,
                signature_hex,
            ),
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
                let id =
                    account_id.unwrap_or_else(|| format!("acct-{}", self.state.accounts.len() + 1));
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
                let id =
                    account_id.unwrap_or_else(|| format!("acct-{}", self.state.accounts.len() + 1));
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
