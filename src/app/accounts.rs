use super::*;

impl Protocol {
    pub fn total_supply_quarks(&self) -> u128 {
        let account_supply = self
            .state
            .accounts
            .values()
            .filter_map(|a| a.balances.get(&TOKEN_ETX_ID).copied())
            .fold(0_u128, |acc, bal| acc.saturating_add(bal));
        let vault_supply = self
            .state
            .validators
            .iter()
            .map(|v| v.vault_quarks)
            .fold(0_u128, |acc, bal| acc.saturating_add(bal));

        account_supply.saturating_add(vault_supply)
    }

    pub fn base_reward_per_block_quarks(&self) -> u128 {
        self.state.base_reward_per_block_quarks
    }

    pub(super) fn recompute_base_reward_per_block(&mut self) {
        self.state.base_reward_per_block_quarks = self
            .total_supply_quarks()
            .saturating_mul(self.state.annual_inflation_ppb as u128)
            / INFLATION_RATE_DENOMINATOR
            / SLOTS_PER_YEAR;
    }

    pub(super) fn bootstrap_accounts(&mut self, genesis_path: &str) {
        let raw = match std::fs::read_to_string(genesis_path) {
            Ok(raw) => raw,
            Err(e) => {
                self.state
                    .events
                    .push_front(format!("genesis load failed: {} ({})", genesis_path, e));
                return;
            }
        };
        let genesis: GenesisFile = match serde_json::from_str(&raw) {
            Ok(genesis) => genesis,
            Err(e) => {
                self.state
                    .events
                    .push_front(format!("genesis parse failed: {} ({})", genesis_path, e));
                return;
            }
        };

        let mut loaded = 0_u64;
        for (index, entry) in genesis.accounts.into_iter().enumerate() {
            let Some(balances) = parse_genesis_balances(&entry.balances) else {
                self.state.events.push_front(format!(
                    "genesis account {} skipped: invalid balances",
                    index
                ));
                continue;
            };

            let address = if let Some(private_key_hex) = entry.private_key_hex {
                let id = entry.id.unwrap_or_else(|| format!("acct-{}", index + 1));
                let Some(account) = account_from_private_key_hex(&id, &private_key_hex) else {
                    self.state.events.push_front(format!(
                        "genesis account {} skipped: invalid private key",
                        index
                    ));
                    continue;
                };
                let address = account.address.clone();
                self.state.accounts.insert(address.clone(), account);
                if !self.state.wallet_addresses.iter().any(|a| a == &address) {
                    self.state.wallet_addresses.push(address.clone());
                }
                address
            } else if let Some(address) = entry.address {
                normalize_address(&address)
            } else {
                self.state.events.push_front(format!(
                    "genesis account {} skipped: missing address/private_key_hex",
                    index
                ));
                continue;
            };

            for (token_id, amount) in balances {
                self.ensure_account_exists(&address);
                self.credit_balance(&address, token_id, amount);
            }
            loaded += 1;
        }

        self.state
            .events
            .push_front(format!("genesis loaded: {} funded account(s)", loaded));
    }
    pub(super) fn ensure_account_exists(&mut self, id: &str) {
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

    pub(super) fn credit_balance(&mut self, account_id: &str, token_id: u64, amount: u128) {
        let k = normalize_address(account_id);
        self.ensure_account_exists(&k);
        if let Some(acct) = self.state.accounts.get_mut(&k) {
            *acct.balances.entry(token_id).or_insert(0) += amount;
        }
    }

    pub(super) fn debit_balance(&mut self, account_id: &str, token_id: u64, amount: u128) -> bool {
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

    pub(super) fn validator_owner_account(&self, validator_id: &str) -> Option<String> {
        self.state
            .validators
            .iter()
            .find(|v| v.id == validator_id)
            .and_then(|v| v.owner_account.clone())
    }

    pub(super) fn normalize_validator_pubkey(&self, pubkey: &str) -> Option<String> {
        let raw = pubkey.trim().strip_prefix("0x").unwrap_or(pubkey.trim());
        let bytes = hex::decode(raw).ok()?;
        if VerifyingKey::from_sec1_bytes(&bytes).is_err() {
            return None;
        }
        Some(format!("0x{}", hex::encode(bytes)))
    }

    pub(super) fn validator_pubkey_registered(&self, pubkey: &str) -> bool {
        self.state
            .validators
            .iter()
            .any(|v| v.validator_pubkey.as_deref() == Some(pubkey))
    }

    pub(super) fn next_pending_validator_id(&self) -> String {
        let validator_ids = self.state.validators.iter().map(|v| v.id.as_str());
        let pending_ids = self
            .state
            .mempool
            .iter()
            .chain(self.state.pbm_pool.iter())
            .filter(|tx| tx.kind == "registerValidator")
            .map(|tx| tx.to.as_str());
        let next = validator_ids
            .chain(pending_ids)
            .filter_map(|id| {
                let suffix = id.strip_prefix("val-")?;
                if suffix.len() != 4 || !suffix.chars().all(|c| c.is_ascii_digit()) {
                    return None;
                }
                suffix.parse::<u64>().ok()
            })
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        format!("val-{next:04}")
    }

    pub(super) fn register_validator_record(
        &mut self,
        validator_id: String,
        owner_account: &str,
        validator_pubkey: String,
        reward_address: String,
    ) -> String {
        self.state.validators.push(Validator {
            id: validator_id.clone(),
            owner_account: Some(normalize_address(owner_account)),
            validator_pubkey: Some(validator_pubkey),
            reward_address: Some(normalize_address(&reward_address)),
            state: ValidatorState::Inactive,
            vault_quarks: 0,
            miss_counter: 0,
            double_sign_offenses: 0,
            blocks_this_sub_epoch: 0,
            cooldown_until_epoch: None,
        });
        validator_id
    }

    pub(super) fn refresh_validator_activation(&mut self, validator_id: &str) {
        let active_tickets = self
            .state
            .tickets
            .iter()
            .any(|t| t.owner == validator_id && !t.dead && !t.muted && !t.retiring);
        if let Some(v) = self
            .state
            .validators
            .iter_mut()
            .find(|v| v.id == validator_id)
        {
            if matches!(
                v.state,
                ValidatorState::Jailed | ValidatorState::PunishedCooldown
            ) {
                return;
            }
            if v.vault_quarks == 0 {
                if v.state == ValidatorState::Active {
                    v.state = ValidatorState::PausedLowVault;
                }
            } else if active_tickets {
                if matches!(
                    v.state,
                    ValidatorState::Inactive | ValidatorState::PausedLowVault
                ) {
                    v.state = ValidatorState::Active;
                }
            } else if v.state == ValidatorState::Active {
                v.state = ValidatorState::Inactive;
            }
        }
    }

    pub(super) fn pbm_allowed_kind(kind: &str) -> bool {
        matches!(kind, "registerValidator" | "walletToVault" | "buyTicket")
    }

    pub(super) fn enqueue_standard_or_pbm(
        &mut self,
        mut tx: Tx,
    ) -> Result<(String, u64, Tx), String> {
        let pbm_active = self.total_eligible_tickets() == 0;
        if pbm_active {
            if !Self::pbm_allowed_kind(tx.kind) {
                return Err("transaction type not allowed while PBM is active".to_string());
            }
            let pending = self
                .state
                .pbm_pool
                .iter()
                .filter(|pending| pending.from == tx.from)
                .count();
            if pending >= PBM_PENDING_PER_ACCOUNT_LIMIT {
                return Err(format!(
                    "PBM per-account limit is {}",
                    PBM_PENDING_PER_ACCOUNT_LIMIT
                ));
            }
            tx.valid_after_slot = self
                .state
                .slot
                .saturating_add(PBM_VALID_AFTER_SLOTS)
                .saturating_add(pending as u64);
            let tx_hash = tx_id(&tx);
            let valid_after_slot = tx.valid_after_slot;
            let accepted_tx = tx.clone();
            self.state.pbm_pool.push_back(tx);
            return Ok((tx_hash, valid_after_slot, accepted_tx));
        }

        tx.valid_after_slot = 0;
        let tx_hash = tx_id(&tx);
        let accepted_tx = tx.clone();
        self.state.mempool.push_back(tx);
        Ok((tx_hash, 0, accepted_tx))
    }

    pub(super) fn burn_and_mint_tickets(&mut self, validator_id: &str, count: u64) {
        let burned = TICKET_COST_QUARKS.saturating_mul(count as u128);
        self.state.ticket_burned_total = self.state.ticket_burned_total.saturating_add(burned);
        self.state.sub_epoch_burned_quarks = self.state.sub_epoch_burned_quarks.saturating_add(burned);
        self.state.epoch_burned_quarks = self.state.epoch_burned_quarks.saturating_add(burned);
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
                owner_account: None,
                validator_pubkey: None,
                reward_address: None,
                state: ValidatorState::Active,
                vault_quarks: 0,
                miss_counter: 0,
                double_sign_offenses: 0,
                blocks_this_sub_epoch: 0,
                cooldown_until_epoch: None,
            });
        }
    }
    pub(super) fn can_pay_fee(&self, account_id: &str, token_id: u64, amount: u128) -> bool {
        let k = normalize_address(account_id);
        self.state
            .accounts
            .get(&k)
            .and_then(|a| a.balances.get(&token_id).copied())
            .is_some_and(|bal| bal >= amount)
    }

    pub(super) fn can_pay_value(&self, account_id: &str, token_id: u64, value: u128) -> bool {
        let k = normalize_address(account_id);
        self.state
            .accounts
            .get(&k)
            .and_then(|a| a.balances.get(&token_id).copied())
            .is_some_and(|bal| bal >= value)
    }
}

#[derive(serde::Deserialize)]
struct GenesisFile {
    accounts: Vec<GenesisAccount>,
}

#[derive(serde::Deserialize)]
struct GenesisAccount {
    id: Option<String>,
    private_key_hex: Option<String>,
    address: Option<String>,
    balances: serde_json::Map<String, serde_json::Value>,
}

fn parse_genesis_balances(
    balances: &serde_json::Map<String, serde_json::Value>,
) -> Option<Vec<(u64, u128)>> {
    let mut out = Vec::with_capacity(balances.len());
    for (token_id, amount) in balances {
        out.push((token_id.parse::<u64>().ok()?, parse_genesis_amount(amount)?));
    }
    Some(out)
}

fn parse_genesis_amount(value: &serde_json::Value) -> Option<u128> {
    if let Some(n) = value.as_u64() {
        return Some(n as u128);
    }
    value.as_str()?.parse::<u128>().ok()
}
