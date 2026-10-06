use super::*;

impl Protocol {
    pub(super) fn p2p_pump(&mut self) {
        let hello = self.hello_payload();
        self.p2p.tick_hello(&hello);
        for (from, msg) in self.p2p.recv_all() {
            // Reject canonical block ingress before any decoding or stateful handler. HIST must
            // not bypass the same disabled-remote-block policy by importing or correcting history.
            if self.reject_unsupported_canonical_ingress(&msg) {
                continue;
            }
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
                // Preserve read-only outbound prototype snapshots; serving history does not grant
                // permission to import peer blocks or replay their state on this node.
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
            if let Some(snapshot) = parse_state_snapshot(&msg) {
                self.merge_state_snapshot(snapshot);
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

    /// Consumes disabled HIST/BLOCK ingress with a local diagnostic and no protocol-state effects.
    /// Matching the framing tag also rejects malformed bodies without allocating or decoding them.
    fn reject_unsupported_canonical_ingress(&mut self, message: &str) -> bool {
        let reason = match message.split('|').next() {
            Some("HIST") => {
                "inbound HIST synchronization is unsupported; canonical import and replacement are disabled"
            }
            Some("BLOCK") => {
                "inbound BLOCK acceptance is unsupported; remote authentication and execution are unavailable"
            }
            _ => return false,
        };
        // Diagnostics are deliberately the only ProtocolState mutation on rejection. In particular,
        // history_synced and all canonical/economic state must survive even a valid peer body intact.
        self.state
            .events
            .push_front(format!("rejected inbound message: {reason}"));
        true
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
            // Timing bootstrap requires a predecessor already stored locally. Inbound history
            // synchronization is disabled and cannot supply that block.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    fn protocol() -> Protocol {
        Protocol::new(Config {
            mode: NodeMode::Standard,
            p2p_port: 0,
            peers: Vec::new(),
            rpc_port: 0,
            validator_id: None,
            validator_account: None,
            genesis_path: String::new(),
            no_tui: true,
        })
        .unwrap()
    }

    fn assert_state_unchanged(before: &ProtocolState, after: &ProtocolState) {
        // Compare every protocol field, including all sync flags, indexes, raw transaction status,
        // penalties, balances, and accounting. Only local rejection diagnostics may be appended.
        let mut before = before.clone();
        let mut after = after.clone();
        before.events.clear();
        after.events.clear();
        assert_eq!(before, after);
    }

    fn deliver_rejected_message(protocol: &mut Protocol, message: &str, tag: &str) {
        // Exercise the actual socket and pump so a future dispatch change cannot bypass this test.
        let peer = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let mut endpoint = protocol.p2p.test_local_addr().unwrap();
        endpoint.set_ip("127.0.0.1".parse().unwrap());
        assert_eq!(
            peer.send_to(message.as_bytes(), endpoint).unwrap(),
            message.len()
        );
        let event_count = protocol.state.events.len();
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            protocol.p2p_pump();
            if protocol.state.events.len() > event_count {
                break;
            }
            assert!(Instant::now() < deadline, "UDP ingress was not processed");
            std::thread::sleep(Duration::from_millis(1));
        }
        let diagnostic = protocol.state.events.front().unwrap();
        assert!(diagnostic.contains(tag), "{diagnostic}");
        assert!(diagnostic.contains("unsupported"), "{diagnostic}");
    }

    fn history_message(state: &ProtocolState, block: &Block) -> String {
        let mut peer_state = state.clone();
        peer_state.blocks.clear();
        peer_state.blocks.insert(block.slot(), block.clone());
        // These peer-supplied counters used to overwrite bootstrap state before block acceptance.
        peer_state.epoch_validator_blocks = 9;
        peer_state.epoch_total_slots = 11;
        let message = encode_history_snapshot(&peer_state);
        let (validator_blocks, total_slots, decoded) = parse_history_snapshot(&message).unwrap();
        assert_eq!((validator_blocks, total_slots), (9, 11));
        assert_eq!(decoded, vec![block.clone()]);
        message
    }

    fn correction_fixture() -> (Protocol, Block) {
        let mut protocol = protocol();
        let proposer = "val-test";
        let owner = "0x1111111111111111111111111111111111111111";
        protocol.learn_validator_from_hello("validator", Some(proposer), Some(owner), true);
        (
            protocol.state.current_leader,
            protocol.state.current_ticket_id,
        ) = protocol.select_leader();
        let ticket_id = protocol.state.current_ticket_id;
        let old = Block::new(
            0,
            BlockKind::ProtocolMiss,
            ZERO_HASH,
            None,
            ZERO_TICKET_ID,
            Vec::new(),
            0,
            ProtocolData {
                missed_proposer: Some(proposer.to_string()),
                fees_burned: 0,
            },
        )
        .unwrap();
        assert!(protocol.record_slot(old));
        protocol.start_next_slot();
        protocol.state.history_synced = true;
        protocol.state.bootstrapped_from_peer = true;
        protocol.state.validators[0].miss_counter = 3;
        protocol.state.validators[0].locked_reward_quarks = 20;
        protocol
            .state
            .reward_unlocks
            .insert(4, vec![(proposer.to_string(), 20)]);
        protocol.credit_balance(owner, TOKEN_ETX_ID, 10_000);
        protocol.state.nonce_tracker.insert(owner.to_string(), 7);
        protocol.state.fees_burned_total = 40;
        protocol.state.burn_this_sub_epoch = 40;

        // This deliberately unauthenticated V1 body satisfies the former HIST commitment/role
        // checks. Importing it used to overwrite the tip, reduce a penalty, and mark it as mined
        // without executing its transfer. The regression must protect all of those fields.
        let transaction = Tx {
            chain_id: CHAIN_ID,
            from: owner.to_string(),
            nonce: 0,
            to: "0x2222222222222222222222222222222222222222".to_string(),
            token_id: TOKEN_ETX_ID,
            value: 1,
            gas: 1000,
            fee_quarks: 1000,
            max_fee_per_gas: 1,
            kind: TxKind::Transfer,
            valid_after_slot: 0,
            fee_token_id: TOKEN_ETX_ID,
            data: String::new(),
            signature_hex: String::new(),
        };
        let transaction_hash = transaction.hash().unwrap();
        protocol.state.mempool.push_back(transaction.clone());
        protocol.state.raw_txs.insert(
            transaction_hash,
            RawTxRecord {
                hash: transaction_hash,
                raw: String::new(),
                from: transaction.from.clone(),
                to: Some(transaction.to.clone()),
                nonce: transaction.nonce,
                gas: transaction.gas,
                input: transaction.data.clone(),
                value: transaction.value,
                fee_quarks: transaction.fee_quarks,
                chain_id: transaction.chain_id,
                tx_type: "0x0".to_string(),
                v: "0x0".to_string(),
                r: "0x0".to_string(),
                s: "0x0".to_string(),
                block_number: None,
                block_hash: None,
                tx_index: None,
                success: None,
            },
        );
        let correction = Block::new(
            0,
            BlockKind::Validator,
            ZERO_HASH,
            Some(proposer.to_string()),
            ticket_id,
            vec![transaction],
            1000,
            ProtocolData {
                missed_proposer: None,
                fees_burned: 1000,
            },
        )
        .unwrap();
        assert!(protocol.validate_block_consensus_role(&correction));
        assert!(protocol.validate_block_commitments_and_parent(&correction));
        (protocol, correction)
    }

    #[test]
    fn hist_bootstrap_is_rejected_without_state_changes() {
        let mut protocol = protocol();
        let incoming = Block::new(
            0,
            BlockKind::ProtocolNoTickets,
            ZERO_HASH,
            None,
            ZERO_TICKET_ID,
            Vec::new(),
            0,
            ProtocolData::empty(),
        )
        .unwrap();
        assert!(protocol.state.history.is_empty());
        assert!(!protocol.state.history_synced);
        assert!(protocol.validate_block_consensus_role(&incoming));
        let message = history_message(&protocol.state, &incoming);
        let before = protocol.state.clone();

        deliver_rejected_message(&mut protocol, &message, "HIST");

        assert_state_unchanged(&before, &protocol.state);
    }

    #[test]
    fn hist_correction_is_rejected_without_state_changes() {
        let (mut protocol, correction) = correction_fixture();
        assert!(protocol.state.history_synced);
        assert_ne!(protocol.state.blocks[&0].hash(), correction.hash());
        let message = history_message(&protocol.state, &correction);
        let before = protocol.state.clone();

        deliver_rejected_message(&mut protocol, &message, "HIST");

        assert_state_unchanged(&before, &protocol.state);
    }

    #[test]
    fn block_messages_are_rejected_without_state_changes() {
        let (mut protocol, transaction_block) = correction_fixture();
        let mut empty_validator = transaction_block.clone();
        empty_validator.transactions.clear();
        empty_validator.header.transaction_root = *EMPTY_TX_ROOT;
        empty_validator.header.gas_used = 0;
        empty_validator.protocol_data = ProtocolData::empty();
        empty_validator.header.protocol_data_root = empty_validator.protocol_data.root();
        let protocol_block = protocol.state.blocks[&0].clone();

        for block in [transaction_block, empty_validator, protocol_block] {
            let message = encode_block(&block);
            assert_eq!(crate::p2p::parse_block(&message), Some(block));
            let before = protocol.state.clone();

            deliver_rejected_message(&mut protocol, &message, "BLOCK");

            assert_state_unchanged(&before, &protocol.state);
        }
    }

    #[test]
    fn malformed_hist_and_block_messages_are_rejected_without_state_changes() {
        let mut protocol = protocol();
        for (tag, message) in [
            ("HIST", "HIST"),
            ("HIST", "HIST|not-a-snapshot"),
            ("HIST", "HIST|0|0|not-hex"),
            ("BLOCK", "BLOCK"),
            ("BLOCK", "BLOCK|not-hex"),
        ] {
            let before = protocol.state.clone();

            deliver_rejected_message(&mut protocol, message, tag);

            assert_state_unchanged(&before, &protocol.state);
        }
    }

    #[test]
    fn outbound_history_serving_remains_read_only() {
        let (mut protocol, _) = correction_fixture();
        let before = protocol.state.clone();
        let expected_history = encode_history_snapshot(&protocol.state);
        assert_state_unchanged(&before, &protocol.state);

        let peer = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut endpoint = protocol.p2p.test_local_addr().unwrap();
        endpoint.set_ip("127.0.0.1".parse().unwrap());
        // A standard HELLO with no timing bootstrap or validator metadata requests the existing
        // outbound snapshot without introducing unrelated discovery/state transitions.
        let hello = format!("HELLO|{}|0|0|standard|||0", peer.local_addr().unwrap());
        peer.send_to(hello.as_bytes(), endpoint).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            protocol.p2p_pump();
            if protocol.p2p.peer_count() == 1 {
                break;
            }
            assert!(Instant::now() < deadline, "HELLO was not processed");
            std::thread::sleep(Duration::from_millis(1));
        }
        let mut received_history = None;
        for _ in 0..2 {
            let mut buffer = [0_u8; 65_507];
            let (length, _) = peer.recv_from(&mut buffer).unwrap();
            let message = std::str::from_utf8(&buffer[..length]).unwrap();
            if message.starts_with("HIST|") {
                received_history = Some(message.to_string());
            }
        }
        assert_eq!(received_history.as_deref(), Some(expected_history.as_str()));
        assert_state_unchanged(&before, &protocol.state);
    }
}
