use super::*;

impl Protocol {
    pub(super) fn p2p_pump(&mut self) {
        let hello = self.hello_payload();
        self.p2p.tick_hello(&hello);
        for (from, msg) in self.p2p.recv_all() {
            if let Some(hello) = parse_hello(&msg) {
                self.p2p.add_peer(hello.addr);
                self.learn_validator_from_hello(
                    &hello.mode,
                    hello.validator_id.as_deref(),
                    hello.validator_account.as_deref(),
                );
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
    pub(super) fn hello_payload(&self) -> String {
        let slot_started_ms = unix_ms_now().saturating_sub(self.state.slot_started.elapsed().as_millis());
        let validator_account = self
            .state
            .local_validator_id
            .as_ref()
            .and_then(|id| self.state.validators.iter().find(|v| &v.id == id))
            .and_then(|v| v.owner_account.clone())
            .unwrap_or_default();
        format!(
            "{}|{}|{}|{}|{}",
            self.state.slot,
            slot_started_ms,
            match self.state.mode_local {
                NodeMode::Validator => "validator",
                NodeMode::Standard => "standard",
            },
            self.state.local_validator_id.clone().unwrap_or_default(),
            validator_account
        )
    }

    pub(super) fn bootstrap_slot_from_peer(&mut self, slot: u64, slot_started_unix_ms: u128) {
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

    pub(super) fn maybe_resync_slot_from_anchor(&mut self) {
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

    pub(super) fn learn_validator_from_hello(
        &mut self,
        mode: &str,
        validator_id: Option<&str>,
        validator_account: Option<&str>,
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
                v.owner_account = owner_account;
            }
            return;
        }
        self.state.validators.push(Validator {
            id: id.to_string(),
            owner_account,
            state: ValidatorState::Active,
            vault_quarks: INITIAL_VALIDATOR_VAULT_QUARKS,
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
