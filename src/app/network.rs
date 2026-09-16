use super::*;

impl Protocol {
    pub(super) fn p2p_pump(&mut self) {
        let hello = self.hello_payload();
        self.p2p.tick_hello(&hello);
        for (from, msg) in self.p2p.recv_all() {
            if let Some(hello) = parse_hello(&msg) {
                // Hello messages double as lightweight discovery for validator identity and current slot timing.
                let peer_addr = if hello.addr.ip().is_unspecified() {
                    from
                } else {
                    hello.addr
                };
                self.p2p.add_peer(peer_addr);
                self.learn_validator_from_hello(
                    &hello.mode,
                    hello.validator_id.as_deref(),
                    hello.validator_account.as_deref(),
                    hello.validator_bootstrap,
                );
                if let Some(vid) = hello.validator_id {
                    self.state.validator_peers.insert(vid, peer_addr);
                }
                // Send state first so the receiver can verify historical proposer/ticket selection.
                let state_snap = encode_state_snapshot(&self.state);
                self.p2p.send_to(&state_snap, peer_addr);
                let snap = encode_history_snapshot(&self.state);
                self.p2p.send_to(&snap, peer_addr);
                if !self.state.bootstrapped_from_peer
                    && matches!(hello.mode.as_str(), "standard" | "validator")
                {
                    self.bootstrap_slot_from_peer(hello.slot, hello.slot_started_unix_ms);
                }
                continue;
            }
            if let Some((epoch_validator_blocks, epoch_total_slots, mut entries)) =
                parse_history_snapshot(&msg)
            {
                if self.state.history.is_empty() && !self.state.history_synced {
                    // Empty nodes can bootstrap history, but running nodes must not replace local history wholesale.
                    self.state.epoch_validator_blocks = epoch_validator_blocks;
                    self.state.epoch_total_slots = epoch_total_slots;
                    self.state.history.clear();
                    entries.sort_by_key(Block::slot);
                    for block in entries {
                        if self.validate_block_consensus_role(&block) && self.record_block(&block) {
                            self.state.history.push_front(block);
                            if self.state.history.len() > 50 {
                                self.state.history.pop_back();
                            }
                        }
                    }
                    self.rebuild_liveness_from_history();
                    (self.state.current_leader, self.state.current_ticket_id) =
                        self.select_leader();
                    self.state.history_synced = true;
                    self.state
                        .events
                        .push_front("history synced from peer".to_string());
                } else {
                    entries.sort_by_key(Block::slot);
                    for entry in entries {
                        if entry.kind() == BlockKind::Validator
                            && self.validate_block_consensus_role(&entry)
                        {
                            // After bootstrap, peer history is only trusted for positive validator-block corrections.
                            self.merge_slot_result(entry);
                        }
                    }
                }
                continue;
            }
            if let Some(snapshot) = parse_state_snapshot(&msg) {
                self.merge_state_snapshot(snapshot);
                continue;
            }
            if let Some(res) = parse_block(&msg) {
                // Wire decoding has already recomputed the claimed hash and commitments. Applying
                // any remote block remains disabled until transaction and producer authentication
                // have protocol definitions, so no unauthenticated block can alter canonical state.
                let reason = if !res.transactions.is_empty() {
                    "remote transaction-bearing block execution is unsupported"
                } else if res.kind() == BlockKind::Validator {
                    "remote validator block acceptance is unsupported without block authentication"
                } else {
                    "remote protocol block application is unsupported"
                };
                self.state.events.push_front(format!(
                    "rejected remote block {}: {}",
                    short_hash(&res.hash()),
                    reason
                ));
                continue;
            }
            if let Some((id, tx)) = parse_tx_msg(&msg)
                && self.p2p.mark_seen(id)
            {
                self.accept_gossiped_tx(tx);
                self.p2p.broadcast_raw_except(&msg, from);
            }
        }
    }
    pub(super) fn hello_payload(&self) -> String {
        let slot_started_ms =
            unix_ms_now().saturating_sub(self.state.slot_started.elapsed().as_millis());
        let validator_account = self
            .state
            .local_validator_id
            .as_ref()
            .and_then(|id| self.state.validators.iter().find(|v| &v.id == id))
            .and_then(|v| v.owner_account.clone())
            .unwrap_or_default();
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.state.slot,
            slot_started_ms,
            match self.state.mode_local {
                NodeMode::Validator => "validator",
                NodeMode::Standard => "standard",
            },
            self.state.local_validator_id.clone().unwrap_or_default(),
            validator_account,
            if self.state.local_validator_bootstrap {
                "1"
            } else {
                "0"
            }
        )
    }

    pub(super) fn bootstrap_slot_from_peer(&mut self, slot: u64, slot_started_unix_ms: u128) {
        if slot_started_unix_ms == 0 {
            return;
        }
        let now = unix_ms_now();
        let elapsed = now.saturating_sub(slot_started_unix_ms);
        let elapsed_slots = (elapsed / SLOT_MS as u128) as u64;
        let slot_elapsed_ms = (elapsed % SLOT_MS as u128) as u64;
        let target_slot = slot.saturating_add(elapsed_slots);
        if target_slot <= self.state.slot {
            return;
        }
        if self.canonical_parent_hash(target_slot).is_none() {
            // A later hello will retry after canonical history supplies the predecessor block.
            return;
        }
        self.state.slot = target_slot;
        // The wall-clock anchor lets the node catch up to peer slot numbers without persisting local time state.
        self.state.epoch_index = target_slot / (SUB_EPOCH_SLOTS * EPOCH_SUB_EPOCHS);
        self.state.sub_epoch_index = target_slot / SUB_EPOCH_SLOTS;
        self.state.epoch_seed = derive_epoch_seed(self.state.epoch_index);
        self.state.slot_started = Instant::now() - Duration::from_millis(slot_elapsed_ms);
        self.state.anchor_time = UNIX_EPOCH + Duration::from_millis(slot_started_unix_ms as u64)
            - Duration::from_millis(slot.saturating_mul(SLOT_MS));
        (self.state.current_leader, self.state.current_ticket_id) = self.select_leader();
        self.state.bootstrapped_from_peer = true;
        self.state
            .events
            .push_front(format!("bootstrapped slot from peer: {}", target_slot));
        let hello = self.hello_payload();
        self.p2p.send_hello_now(&hello);
    }

    pub(super) fn maybe_resync_slot_from_anchor(&mut self) {
        let now = SystemTime::now();
        if let Ok(since_anchor) = now.duration_since(self.state.anchor_time) {
            let target_slot = since_anchor.as_millis() as u64 / SLOT_MS;
            if target_slot > self.state.slot + 1 {
                // Force one sequential slot completion per tick until every canonical parent exists.
                self.state.slot_started = Instant::now() - Duration::from_millis(SLOT_MS);
                self.state
                    .events
                    .push_front(format!("catching up toward slot {}", target_slot));
            }
        }
    }

    pub(super) fn learn_validator_from_hello(
        &mut self,
        mode: &str,
        validator_id: Option<&str>,
        validator_account: Option<&str>,
        validator_bootstrap: bool,
    ) {
        if mode != "validator" {
            return;
        }
        let Some(id) = validator_id else {
            return;
        };
        let owner_account = validator_account.map(normalize_address);
        if let Some(v) = self.state.validators.iter_mut().find(|v| v.id == id) {
            if v.owner_account.is_none() {
                // Hello can fill owner metadata for legacy validators before full state sync arrives.
                v.owner_account = owner_account;
            }
            return;
        }
        let ticket_id = deterministic_ticket_id(id);
        self.state.validators.push(Validator {
            id: id.to_string(),
            owner_account,
            validator_pubkey: None,
            reward_address: None,
            state: if validator_bootstrap {
                ValidatorState::Active
            } else {
                // Non-bootstrap validators must earn activation through synced/processed vault and ticket state.
                ValidatorState::Inactive
            },
            vault_quarks: if validator_bootstrap {
                INITIAL_VALIDATOR_VAULT_QUARKS
            } else {
                0
            },
            locked_reward_quarks: 0,
            miss_counter: 0,
            double_sign_offenses: 0,
            blocks_this_sub_epoch: 0,
            cooldown_until_epoch: None,
        });
        if validator_bootstrap {
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
        }
        self.state
            .events
            .push_front(format!("discovered validator {}", id));
    }

    pub(super) fn accept_gossiped_tx(&mut self, tx: Tx) {
        if self.total_eligible_tickets() == 0 && Self::pbm_allowed_kind(tx.kind) {
            // During PBM, eligible bootstrap txs stay delayed in pbm_pool instead of normal mempool.
            let pending = self
                .state
                .pbm_pool
                .iter()
                .filter(|pending| pending.from == tx.from)
                .count();
            if pending < PBM_PENDING_PER_ACCOUNT_LIMIT {
                self.state.pbm_pool.push_back(tx);
            }
            return;
        }
        self.state.mempool.push_back(tx);
    }

    pub(super) fn merge_state_snapshot(&mut self, snapshot: StateSnapshot) {
        if snapshot.slot.saturating_add(2) < self.state.slot {
            // Very stale snapshots are more likely to regress balances than to help synchronization.
            return;
        }

        let local_progress = self.state.fees_burned_total
            + self.state.ticket_burned_total
            + self.state.base_issuance_total
            + self.state.burn_offset_total;
        let snapshot_progress = snapshot.fees_burned_total
            + snapshot.ticket_burned_total
            + snapshot.base_issuance_total
            + snapshot.burn_offset_total;
        // Account/economy state is accepted only from peers that have observed at least as much accounting progress.
        let apply_economy = snapshot_progress >= local_progress;
        let mut changed = false;

        if apply_economy {
            self.state.fees_burned_total = snapshot.fees_burned_total;
            self.state.ticket_burned_total = snapshot.ticket_burned_total;
            self.state.base_issuance_total = snapshot.base_issuance_total;
            self.state.burn_offset_total = snapshot.burn_offset_total;
            self.state.sub_epoch_issued_quarks = snapshot.sub_epoch_issued_quarks;
            self.state.sub_epoch_burned_quarks = snapshot.sub_epoch_burned_quarks;
            self.state.epoch_issued_quarks = snapshot.epoch_issued_quarks;
            self.state.epoch_burned_quarks = snapshot.epoch_burned_quarks;
            self.state.burn_this_sub_epoch = snapshot.burn_this_sub_epoch;
            self.state.reward_unlocks = snapshot.reward_unlocks.clone();
        }

        for incoming in snapshot.validators {
            if let Some(local) = self
                .state
                .validators
                .iter_mut()
                .find(|v| v.id == incoming.id)
            {
                if local.owner_account.is_none() {
                    local.owner_account = incoming.owner_account.clone();
                }
                if local.validator_pubkey.is_none() {
                    local.validator_pubkey = incoming.validator_pubkey.clone();
                }
                if local.reward_address.is_none() {
                    local.reward_address = incoming.reward_address.clone();
                }
                if incoming.vault_quarks > local.vault_quarks {
                    // Vault sync is monotonic for the current testnet flow; withdrawals are executed locally via txs.
                    local.vault_quarks = incoming.vault_quarks;
                    changed = true;
                }
                if apply_economy {
                    local.locked_reward_quarks = incoming.locked_reward_quarks;
                }
            } else {
                self.state.validators.push(incoming);
                changed = true;
            }
        }

        for incoming in snapshot.tickets {
            if let Some(local) = self.state.tickets.iter_mut().find(|t| t.id == incoming.id) {
                *local = incoming;
                changed = true;
            } else {
                self.state.tickets.push(incoming);
                changed = true;
            }
        }

        if apply_economy {
            for incoming in snapshot.accounts {
                let address = incoming.address.clone();
                let incoming_nonce = incoming.nonce;
                if let Some(local) = self.state.accounts.get_mut(&address) {
                    // Balance sync prevents late validator nodes from double-counting account balance plus vault.
                    local.balances = incoming.balances;
                    local.nonce = incoming_nonce;
                } else {
                    self.state.accounts.insert(address.clone(), incoming);
                }
                let local_nonce = self.state.nonce_tracker.get(&address).copied().unwrap_or(0);
                self.state
                    .nonce_tracker
                    .insert(address, local_nonce.max(incoming_nonce));
            }
            changed = true;
        }

        if changed {
            let ids: Vec<String> = self.state.validators.iter().map(|v| v.id.clone()).collect();
            for id in ids {
                self.refresh_validator_activation(&id);
            }
            (self.state.current_leader, self.state.current_ticket_id) = self.select_leader();
        }
    }

    pub(super) fn accept_remote_slot_result(&self, result: &Block) -> bool {
        if !self.validate_block_commitments_and_parent(result) {
            return false;
        }
        if result.slot() > self.state.slot.saturating_add(1) {
            return false;
        }
        if result.slot() < self.state.slot && result.kind() != BlockKind::Validator {
            // Past misses/no-ticket results are too weak to import; only validator blocks correct history.
            return false;
        }
        if result.slot() < self.state.slot && result.slot().saturating_add(64) < self.state.slot {
            return false;
        }
        if result.slot() == self.state.slot && self.state.current_result.is_some() {
            return false;
        }
        let Some((expected_leader, _)) = self.expected_leader_for_slot(result.slot()) else {
            return false;
        };
        if self.state.local_validator_id.as_deref() == Some(expected_leader.as_str())
            && result.kind() != BlockKind::Validator
        {
            // A local leader should produce its own block rather than accept a peer's provisional miss/PBM result.
            return false;
        }
        self.validate_block_consensus_role(result)
            || (result.kind() == BlockKind::Validator
                && self.accept_late_cooldown_correction(result))
    }

    pub(super) fn expected_leader_for_slot(&self, slot: u64) -> Option<(String, u64)> {
        if slot == self.state.slot {
            return Some((
                self.state.current_leader.clone(),
                self.state.current_ticket_id,
            ));
        }
        let eligible: Vec<&Ticket> = self
            .state
            .tickets
            .iter()
            .filter(|t| !t.dead && !t.muted && self.validator_active(&t.owner))
            .collect();
        let historical_block_hash = self.leader_selection_block_hash(slot)?;
        Some(
            select_leader_ticket(historical_block_hash, slot, &eligible)
                .unwrap_or_else(|| ("protocol".to_string(), ZERO_TICKET_ID)),
        )
    }

    pub(super) fn validate_block_consensus_role(&self, result: &Block) -> bool {
        let Some((expected_leader, expected_ticket_id)) =
            self.expected_leader_for_slot(result.slot())
        else {
            return false;
        };
        match result.kind() {
            BlockKind::Validator => {
                result.proposer.as_deref() == Some(expected_leader.as_str())
                    && result.header.ticket_id == expected_ticket_id
                    && expected_leader != "protocol"
            }
            BlockKind::ProtocolNoTickets => {
                expected_leader == "protocol"
                    && result.transactions.iter().all(|tx| {
                        Self::pbm_allowed_kind(tx.kind) && tx.valid_after_slot <= result.slot()
                    })
            }
            BlockKind::ProtocolMiss => {
                result.protocol_data.missed_proposer.as_deref() == Some(expected_leader.as_str())
                    && expected_leader != "protocol"
            }
            BlockKind::ProtocolCollision => true,
        }
    }

    pub(super) fn accept_late_cooldown_correction(&self, result: &Block) -> bool {
        // If provisional misses pushed a peer into cooldown, allow a late validator block to repair that state.
        if result.slot() >= self.state.slot {
            return false;
        }
        let Some(proposer) = result.proposer.as_deref() else {
            return false;
        };
        let Some(v) = self.state.validators.iter().find(|v| v.id == proposer) else {
            return false;
        };
        if v.state != ValidatorState::PunishedCooldown {
            return false;
        }
        self.state
            .tickets
            .iter()
            .any(|t| t.owner == proposer && t.id == result.header.ticket_id && !t.dead && !t.muted)
    }
}
