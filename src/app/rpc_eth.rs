use super::*;

impl Protocol {
    pub(super) fn handle_jsonrpc(&mut self, id: Value, method: &str, params: &Value) -> Value {
        match method {
            "eth_chainId" => json!({"jsonrpc":"2.0","id":id,"result":to_hex_qty(CHAIN_ID)}),
            "net_version" => json!({"jsonrpc":"2.0","id":id,"result":CHAIN_ID.to_string()}),
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
                let base = self
                    .state
                    .nonce_tracker
                    .get(&normalize_address(addr))
                    .copied()
                    .unwrap_or(0);
                let n = if tag == "pending" { base } else { base };
                json!({"jsonrpc":"2.0","id":id,"result":to_hex_qty(n)})
            }
            "eth_getCode" => json!({"jsonrpc":"2.0","id":id,"result":"0x"}),
            "eth_call" => json!({"jsonrpc":"2.0","id":id,"result":"0x"}),
            "eth_estimateGas" => json!({"jsonrpc":"2.0","id":id,"result":"0x3e8"}),
            "eth_gasPrice" => json!({"jsonrpc":"2.0","id":id,"result":"0x3b9aca00"}),
            "eth_maxPriorityFeePerGas" => json!({"jsonrpc":"2.0","id":id,"result":"0x0"}),
            "eth_syncing" => json!({"jsonrpc":"2.0","id":id,"result":false}),
            "eth_blockNumber" => {
                json!({"jsonrpc":"2.0","id":id,"result":to_hex_qty(self.canonical_tip_slot())})
            }
            "eth_sendRawTransaction" => {
                let raw = params
                    .get(0)
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                eprintln!(
                    "[rpc] eth_sendRawTransaction received len={} prefix={}",
                    raw.len(),
                    raw.chars().take(10).collect::<String>()
                );
                let decoded = decode_raw_eip1559_tx(&raw).or_else(|| decode_raw_legacy_tx(&raw));
                let Some(tx) = decoded else {
                    eprintln!("[rpc] raw tx decode failed (type not supported or invalid)");
                    return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":"unsupported or invalid raw tx"}});
                };
                eprintln!(
                    "[rpc] decoded tx chain_id={} from={} nonce={} gas={} to={}",
                    tx.chain_id, tx.from, tx.nonce, tx.gas, tx.to
                );
                if tx.chain_id != CHAIN_ID {
                    eprintln!("[rpc] reject raw tx: invalid chain id {}", tx.chain_id);
                    return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":"invalid chain id"}});
                }
                let expected_nonce = self.state.nonce_tracker.get(&tx.from).copied().unwrap_or(0);
                if tx.nonce < expected_nonce {
                    eprintln!(
                        "[rpc] reject raw tx: nonce {} expected >= {}",
                        tx.nonce, expected_nonce
                    );
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
                    eprintln!(
                        "[rpc] reject raw tx: insufficient funds total_cost={}",
                        total_cost
                    );
                    return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":"insufficient funds for value + fee"}});
                }
                let Some(hash) = tx.hash() else {
                    return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":"transaction cannot be canonically encoded"}});
                };
                let display_hash = format_hash(&hash);
                let (tx_type_hex, v_hex, r_hex, s_hex) = extract_raw_signature_parts(&raw)
                    .unwrap_or_else(|| {
                        (
                            "0x0".to_string(),
                            "0x0".to_string(),
                            "0x0".to_string(),
                            "0x0".to_string(),
                        )
                    });
                self.state
                    .nonce_tracker
                    .insert(tx.from.clone(), tx.nonce.saturating_add(1));
                self.state.mempool.push_back(tx.clone());
                self.state.raw_txs.insert(
                    hash,
                    RawTxRecord {
                        hash,
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
                json!({"jsonrpc":"2.0","id":id,"result":display_hash})
            }
            "eth_getTransactionByHash" => {
                let h = params.get(0).and_then(|v| v.as_str()).unwrap_or_default();
                let result = parse_hash(h).and_then(|hash| self.transaction_json_by_hash(&hash));
                json!({"jsonrpc":"2.0","id":id,"result":result})
            }
            "eth_getTransactionReceipt" => {
                let h = params.get(0).and_then(|v| v.as_str()).unwrap_or_default();
                let result = parse_hash(h).and_then(|hash| self.transaction_receipt(&hash));
                json!({"jsonrpc":"2.0","id":id,"result":result})
            }
            "eth_getBlockByNumber" => {
                let n = params.get(0).and_then(|v| v.as_str()).unwrap_or("latest");
                let full_txs = params.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
                let slot = resolve_block_tag(n, self.canonical_tip_slot());
                let result = self
                    .state
                    .blocks
                    .get(&slot)
                    .map(|block| self.block_json(block, full_txs));
                json!({"jsonrpc":"2.0","id":id,"result":result})
            }
            "eth_getBlockByHash" => {
                let h = params.get(0).and_then(|v| v.as_str()).unwrap_or_default();
                let full_txs = params.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
                let result = parse_hash(h)
                    .and_then(|hash| self.state.block_hash_to_number.get(&hash))
                    .and_then(|slot| self.state.blocks.get(slot))
                    .map(|block| self.block_json(block, full_txs));
                json!({"jsonrpc":"2.0","id":id,"result":result})
            }
            "eth_getBlockTransactionCountByNumber" => {
                let n = params.get(0).and_then(|v| v.as_str()).unwrap_or("latest");
                let slot = resolve_block_tag(n, self.canonical_tip_slot());
                let c = self
                    .state
                    .blocks
                    .get(&slot)
                    .map(|b| b.transactions.len() as u64)
                    .unwrap_or(0);
                json!({"jsonrpc":"2.0","id":id,"result":to_hex_qty(c)})
            }
            "eth_getBlockTransactionCountByHash" => {
                let h = params.get(0).and_then(|v| v.as_str()).unwrap_or_default();
                let slot = parse_hash(h)
                    .and_then(|hash| self.state.block_hash_to_number.get(&hash).copied());
                let c = slot
                    .and_then(|s| {
                        self.state
                            .blocks
                            .get(&s)
                            .map(|b| b.transactions.len() as u64)
                    })
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
                let slot = resolve_block_tag(n, self.canonical_tip_slot());
                let result = self
                    .state
                    .blocks
                    .get(&slot)
                    .and_then(|block| self.block_transaction_json(block, idx as usize));
                json!({"jsonrpc":"2.0","id":id,"result":result})
            }
            "eth_getTransactionByBlockHashAndIndex" => {
                let bh = params.get(0).and_then(|v| v.as_str()).unwrap_or_default();
                let idx = params
                    .get(1)
                    .and_then(|v| v.as_str())
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                    .unwrap_or(0);
                let result = parse_hash(bh)
                    .and_then(|hash| self.state.block_hash_to_number.get(&hash).copied())
                    .and_then(|s| self.state.blocks.get(&s))
                    .and_then(|block| self.block_transaction_json(block, idx as usize));
                json!({"jsonrpc":"2.0","id":id,"result":result})
            }
            "eth_getUncleCountByBlockNumber" | "eth_getUncleCountByBlockHash" => {
                json!({"jsonrpc":"2.0","id":id,"result":"0x0"})
            }
            "eth_getStorageAt" => json!({"jsonrpc":"2.0","id":id,"result":"0x0"}),
            "eth_getLogs" => json!({"jsonrpc":"2.0","id":id,"result":[]}),
            "eth_feeHistory" => {
                json!({"jsonrpc":"2.0","id":id,"result":{
                    "oldestBlock": to_hex_qty(self.canonical_tip_slot().saturating_sub(1)),
                    "baseFeePerGas": ["0x3b9aca00","0x3b9aca00"],
                    "gasUsedRatio": [0.0],
                    "reward": [["0x0"]]
                }})
            }
            _ => {
                json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"method not found"}})
            }
        }
    }

    fn canonical_tip_slot(&self) -> u64 {
        self.state.blocks.keys().copied().max().unwrap_or(0)
    }

    fn find_block_transaction(&self, hash: &Hash) -> Option<(&Block, usize)> {
        self.state
            .blocks
            .values()
            .filter_map(|block| {
                block
                    .transactions
                    .iter()
                    .position(|transaction| transaction.hash().as_ref() == Some(hash))
                    .map(|index| (block, index))
            })
            .min_by_key(|(block, _)| block.slot())
    }

    fn transaction_json_by_hash(&self, hash: &Hash) -> Option<Value> {
        if let Some(raw) = tx_json_by_hash(&self.state.raw_txs, hash) {
            return Some(raw);
        }
        let (block, index) = self.find_block_transaction(hash)?;
        self.block_transaction_json(block, index)
    }

    fn transaction_receipt(&self, hash: &Hash) -> Option<Value> {
        let (block, index) = self.find_block_transaction(hash)?;
        let transaction = block.transactions.get(index)?;
        let cumulative_gas = block
            .transactions
            .iter()
            .take(index + 1)
            .try_fold(0_u64, |total, tx| total.checked_add(tx.gas))?;
        let tx_type = self
            .state
            .raw_txs
            .get(hash)
            .map(|record| record.tx_type.as_str())
            .unwrap_or("0x0");
        Some(json!({
            "transactionHash": format_hash(hash),
            "blockNumber": to_hex_qty(block.slot()),
            "blockHash": format_hash(&block.hash()),
            "transactionIndex": to_hex_qty(index as u64),
            "from": transaction.from,
            "to": transaction.to,
            "status": "0x1",
            "gasUsed": to_hex_qty(transaction.gas),
            "cumulativeGasUsed": to_hex_qty(cumulative_gas),
            "effectiveGasPrice": to_hex_qty(transaction.max_fee_per_gas),
            "contractAddress": Value::Null,
            "type": tx_type,
            "logsBloom": format!("0x{}", "00".repeat(256)),
            "logs": []
        }))
    }

    fn block_json(&self, block: &Block, full_transactions: bool) -> Value {
        let hashes = block.transaction_hashes().unwrap_or_default();
        let transactions = if full_transactions {
            Value::Array(
                (0..block.transactions.len())
                    .filter_map(|index| self.block_transaction_json(block, index))
                    .collect(),
            )
        } else {
            json!(hashes.iter().map(format_hash).collect::<Vec<_>>())
        };
        let anchor_ms = self
            .state
            .anchor_time
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_millis() as u64;
        let timestamp_ms = anchor_ms.saturating_add(block.slot().saturating_mul(SLOT_MS));
        let size = block.wire_bytes().map(|bytes| bytes.len()).unwrap_or(0);

        json!({
            "number": to_hex_qty(block.slot()),
            "hash": format_hash(&block.hash()),
            "parentHash": format_hash(&block.header.parent_hash),
            "nonce": "0x0000000000000000",
            "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            "logsBloom": format!("0x{}", "00".repeat(256)),
            "transactionsRoot": format_hash(&block.header.transaction_root),
            "stateRoot": format_hash(&block.header.state_root),
            "receiptsRoot": format_hash(&block.header.receipts_root),
            "miner": "0x0000000000000000000000000000000000000000",
            "difficulty": "0x0",
            "totalDifficulty": "0x0",
            "extraData": "0x",
            "size": to_hex_qty(size as u64),
            "gasLimit": "0xf42400",
            "gasUsed": to_hex_qty(block.gas_used()),
            "timestamp": to_hex_qty(timestamp_ms / 1000),
            "transactions": transactions,
            "uncles": [],
            "baseFeePerGas": "0x3b9aca00",
            "eternixBlockKind": block.kind().consensus_code(),
            "eternixProposerId": format_hash(&block.header.proposer_id),
            "eternixTicketId": to_hex_qty(block.header.ticket_id),
            "eternixProtocolDataRoot": format_hash(&block.header.protocol_data_root)
        })
    }

    fn block_transaction_json(&self, block: &Block, index: usize) -> Option<Value> {
        let transaction = block.transactions.get(index)?;
        let hash = transaction.hash()?;
        if let Some(raw) = tx_json_by_hash(&self.state.raw_txs, &hash) {
            return Some(raw);
        }
        Some(json!({
            "hash": format_hash(&hash),
            "from": transaction.from,
            "to": transaction.to,
            "nonce": to_hex_qty(transaction.nonce),
            "gas": to_hex_qty(transaction.gas),
            "gasPrice": to_hex_qty(transaction.max_fee_per_gas),
            "value": to_hex_qty_u128(transaction.value.saturating_mul(WEI_PER_QUARK as u128)),
            "input": transaction.data,
            "blockNumber": to_hex_qty(block.slot()),
            "blockHash": format_hash(&block.hash()),
            "transactionIndex": to_hex_qty(index as u64)
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn derive_signature_for_sender(
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
        let raw = acct
            .private_key_hex
            .strip_prefix("0x")
            .unwrap_or(&acct.private_key_hex);
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
        let digest = keccak256(&msg);
        let sig: Signature = signing_key.sign_prehash(&digest).ok()?;
        Some(format!("0x{}", hex::encode(sig.to_bytes())))
    }
}
