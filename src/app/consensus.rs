use super::*;

impl Protocol {
    pub(super) fn start_next_slot(&mut self) {
        self.state.slot += 1;
        self.state.slot_started = Instant::now();
        self.state.current_result = None;
        self.state.mode = if self.total_eligible_tickets() == 0 { Mode::Pbm } else { Mode::Normal };
        self.state.current_leader = self.select_leader();
        self.state.exec_status = ExecStatus::Executing;
    }

    pub(super) fn finish_slot(&mut self) {
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

    pub(super) fn is_local_leader(&self) -> bool {
        let Some(local_id) = &self.state.local_validator_id else {
            return false;
        };
        self.state.current_leader == *local_id
    }

    pub(super) fn total_eligible_tickets(&self) -> usize {
        self.state.tickets.iter().filter(|t| !t.dead && !t.muted && self.validator_active(&t.owner)).count()
    }

    pub(super) fn validator_active(&self, id: &str) -> bool {
        self.state.validators.iter().any(|v| v.id == id && v.state == ValidatorState::Active)
    }

    pub(super) fn select_leader(&mut self) -> String {
        let eligible: Vec<&Ticket> = self
            .state
            .tickets
            .iter()
            .filter(|t| !t.dead && !t.muted && self.validator_active(&t.owner))
            .collect();
        select_leader_owner(self.state.epoch_seed, self.state.slot, &eligible)
            .unwrap_or_else(|| "protocol".to_string())
    }

    pub(super) fn validator_block(&mut self) -> SlotResult {
        let mut gas = 0_u64;
        let mut tx_count = 0_u32;
        let mut fees = 0_u64;
        while let Some(tx) = self.state.mempool.front() {
            if tx_count >= 3000 || gas + tx.gas > 16_000_000 {
                break;
            }
            let tx = tx.clone();
            let fee = tx.fee_quarks as u128;
            let executed = match tx.kind {
                "registerValidator" => {
                    let Some((validator_pubkey, reward_address)) = decode_register_validator_data(&tx.data) else {
                        self.state.mempool.pop_front();
                        continue;
                    };
                    let Some(validator_pubkey) = self.normalize_validator_pubkey(&validator_pubkey) else {
                        self.state.mempool.pop_front();
                        continue;
                    };
                    if self.state.validators.iter().any(|v| v.id == tx.to)
                        || self.validator_pubkey_registered(&validator_pubkey)
                        || !self.can_pay_fee(&tx.from, TOKEN_ETX_ID, fee)
                    {
                        self.state.mempool.pop_front();
                        continue;
                    }
                    self.state.mempool.pop_front();
                    if !self.debit_balance(&tx.from, TOKEN_ETX_ID, fee) {
                        false
                    } else {
                        self.register_validator_record(
                            tx.to.clone(),
                            &tx.from,
                            validator_pubkey,
                            reward_address,
                        );
                        true
                    }
                }
                "buyTicket" => {
                    let Some(count) = u64::try_from(tx.value).ok().filter(|count| *count > 0) else {
                        self.state.mempool.pop_front();
                        continue;
                    };
                    let cost = TICKET_COST_QUARKS.saturating_mul(tx.value);
                    let required = cost.saturating_add(fee);
                    if self.validator_owner_account(&tx.to).as_deref() != Some(tx.from.as_str())
                        || !self.can_pay_fee(&tx.from, TOKEN_ETX_ID, required)
                    {
                        self.state.mempool.pop_front();
                        continue;
                    }
                    self.state.mempool.pop_front();
                    if !self.debit_balance(&tx.from, TOKEN_ETX_ID, cost) {
                        false
                    } else if !self.debit_balance(&tx.from, TOKEN_ETX_ID, fee) {
                        self.credit_balance(&tx.from, TOKEN_ETX_ID, cost);
                        false
                    } else {
                        self.burn_and_mint_tickets(&tx.to, count);
                        self.refresh_validator_activation(&tx.to);
                        true
                    }
                }
                "walletToVault" => {
                    let required = tx.value.saturating_add(fee);
                    if self.validator_owner_account(&tx.to).as_deref() != Some(tx.from.as_str())
                        || !self.can_pay_fee(&tx.from, TOKEN_ETX_ID, required)
                        || !self.state.validators.iter().any(|v| v.id == tx.to)
                    {
                        self.state.mempool.pop_front();
                        continue;
                    }
                    self.state.mempool.pop_front();
                    if !self.debit_balance(&tx.from, TOKEN_ETX_ID, tx.value) {
                        false
                    } else if !self.debit_balance(&tx.from, TOKEN_ETX_ID, fee) {
                        self.credit_balance(&tx.from, TOKEN_ETX_ID, tx.value);
                        false
                    } else if let Some(v) = self.state.validators.iter_mut().find(|v| v.id == tx.to) {
                        v.vault_quarks = v.vault_quarks.saturating_add(tx.value);
                        self.refresh_validator_activation(&tx.to);
                        true
                    } else {
                        self.credit_balance(&tx.from, TOKEN_ETX_ID, tx.value);
                        false
                    }
                }
                "vaultToWallet" => {
                    if self.validator_owner_account(&tx.to).as_deref() != Some(tx.from.as_str())
                        || !self.can_pay_fee(&tx.from, TOKEN_ETX_ID, fee)
                        || !self
                            .state
                            .validators
                            .iter()
                            .find(|v| v.id == tx.to)
                            .is_some_and(|v| v.vault_quarks >= tx.value)
                    {
                        self.state.mempool.pop_front();
                        continue;
                    }
                    self.state.mempool.pop_front();
                    if !self.debit_balance(&tx.from, TOKEN_ETX_ID, fee) {
                        false
                    } else if let Some(v) = self.state.validators.iter_mut().find(|v| v.id == tx.to) {
                        v.vault_quarks -= tx.value;
                        self.credit_balance(&tx.from, TOKEN_ETX_ID, tx.value);
                        true
                    } else {
                        false
                    }
                }
                _ => {
                    let can_pay = if tx.token_id == tx.fee_token_id {
                        self.can_pay_fee(&tx.from, tx.token_id, tx.value.saturating_add(fee))
                    } else {
                        self.can_pay_value(&tx.from, tx.token_id, tx.value)
                            && self.can_pay_fee(&tx.from, tx.fee_token_id, fee)
                    };
                    if !can_pay {
                        self.state.mempool.pop_front();
                        continue;
                    }
                    self.state.mempool.pop_front();
                    if !self.debit_balance(&tx.from, tx.token_id, tx.value) {
                        false
                    } else {
                        self.credit_balance(&tx.to, tx.token_id, tx.value);
                        if !self.debit_balance(&tx.from, tx.fee_token_id, fee) {
                            self.debit_balance(&tx.to, tx.token_id, tx.value);
                            self.credit_balance(&tx.from, tx.token_id, tx.value);
                            false
                        } else {
                            true
                        }
                    }
                }
            };
            if !executed {
                continue;
            }
            gas += tx.gas;
            fees += tx.fee_quarks;
            tx_count += 1;
            if self.rng.gen_bool(0.07) {
                break;
            }
        }
        self.state.fees_burned_total += fees as u128;
        self.state.burn_this_sub_epoch += fees as u128;
        let base_reward = self.base_reward_per_block_quarks();
        if let Some(v) = self.state.validators.iter_mut().find(|v| v.id == self.state.current_leader) {
            v.blocks_this_sub_epoch += 1;
            if v.miss_counter > 0 {
                v.miss_counter -= 1;
            }
            v.vault_quarks = v.vault_quarks.saturating_add(base_reward);
            self.state.base_issuance_total = self.state.base_issuance_total.saturating_add(base_reward);
        }

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

    pub(super) fn protocol_miss_block(&mut self) -> SlotResult {
        if let Some(v) = self.state.validators.iter_mut().find(|v| v.id == self.state.current_leader) {
            v.miss_counter += 1;
            if v.miss_counter >= 10 {
                v.state = ValidatorState::PunishedCooldown;
                v.cooldown_until_epoch = Some(self.state.epoch_index + 1);
            }
        }
        SlotResult { slot: self.state.slot, leader: self.state.current_leader.clone(), kind: BlockKind::ProtocolMiss, tx_count: 0, gas_used: 0, fees_burned: 0 }
    }

    pub(super) fn protocol_collision_block(&mut self) -> SlotResult {
        SlotResult { slot: self.state.slot, leader: self.state.current_leader.clone(), kind: BlockKind::ProtocolCollision, tx_count: 0, gas_used: 0, fees_burned: 0 }
    }

    pub(super) fn protocol_no_tickets_block(&mut self) -> SlotResult {
        SlotResult { slot: self.state.slot, leader: "protocol".to_string(), kind: BlockKind::ProtocolNoTickets, tx_count: 0, gas_used: 0, fees_burned: 0 }
    }

    pub(super) fn run_boundaries(&mut self) {
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
            let next_epoch = self.state.epoch_index + 1;
            if next_epoch.is_multiple_of(EPOCHS_PER_YEAR) {
                self.state.annual_inflation_ppb = (self.state.annual_inflation_ppb * 9 / 10).max(5_000_000);
                self.recompute_base_reward_per_block();
            }
            self.state.epoch_index = next_epoch;
            self.finalize_retire_for_epoch(self.state.epoch_index);
            self.rotate_epoch_seed();
            self.process_epoch_validator_transitions();
            self.state
                .events
                .push_front(format!("epoch transition {}", self.state.epoch_index));
        }
    }

    pub(super) fn record_hash(&mut self, r: &SlotResult) {
        self.state.prev_hash = hash_bytes(format!("{}-{}-{}", r.slot, r.leader, r.tx_count).as_bytes());
    }

    pub(super) fn record_slot(&mut self, result: SlotResult) {
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

    pub(super) fn record_block(&mut self, result: &SlotResult) {
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

    pub(super) fn update_liveness(&mut self, result: &SlotResult) {
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

    pub(super) fn rebuild_liveness_from_history(&mut self) {
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

    pub(super) fn rotate_epoch_seed(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(&self.state.epoch_seed);
        data.extend_from_slice(&self.state.epoch_index.to_be_bytes());
        self.state.epoch_seed = hash_bytes(&data);
    }

    pub(super) fn process_epoch_validator_transitions(&mut self) {
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

    pub(super) fn finalize_retire_for_epoch(&mut self, epoch: u64) {
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
}
