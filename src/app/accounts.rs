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
                self.state
                    .events
                    .push_front(format!("genesis account {} skipped: invalid balances", index));
                continue;
            };

            let address = if let Some(private_key_hex) = entry.private_key_hex {
                let id = entry.id.unwrap_or_else(|| format!("acct-{}", index + 1));
                let Some(account) = account_from_private_key_hex(&id, &private_key_hex) else {
                    self.state
                        .events
                        .push_front(format!("genesis account {} skipped: invalid private key", index));
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
                self.state
                    .events
                    .push_front(format!("genesis account {} skipped: missing address/private_key_hex", index));
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

    pub(super) fn burn_and_mint_tickets(&mut self, validator_id: &str, count: u64) {
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
                owner_account: None,
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
