use super::*;

impl Protocol {
    pub(super) fn handle_jsonrpc(&mut self, id: Value, method: &str, params: &Value) -> Value {
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
                json!({"jsonrpc":"2.0","id":id,"result":to_hex_qty(self.state.slot)})
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
                    &raw.chars().take(10).collect::<String>()
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
                if tx.chain_id != 1162 {
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
                let hash = format!("0x{}", hex::encode(keccak256_hex_bytes(&raw)));
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
                let block = self
                    .state
                    .blocks
                    .get(&slot)
                    .cloned()
                    .unwrap_or_else(|| BlockRecord {
                        number: slot,
                        hash: format!(
                            "0x{}",
                            hex::encode(hash_bytes(format!("block:{}", slot).as_bytes()))
                        ),
                        parent_hash: if slot == 0 {
                            "0x0000000000000000000000000000000000000000000000000000000000000000"
                                .to_string()
                        } else {
                            format!(
                                "0x{}",
                                hex::encode(hash_bytes(format!("block:{}", slot - 1).as_bytes()))
                            )
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
                    .or_else(|| self.state.block_hash_to_number.get(h).copied())
                    .unwrap_or(self.state.slot);
                let block = self
                    .state
                    .blocks
                    .get(&slot)
                    .cloned()
                    .unwrap_or_else(|| BlockRecord {
                        number: slot,
                        hash: h.to_string(),
                        parent_hash:
                            "0x0000000000000000000000000000000000000000000000000000000000000000"
                                .to_string(),
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
                    .or_else(|| {
                        self.state
                            .block_hash_to_number
                            .get(&normalize_address(bh))
                            .copied()
                    });
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
            _ => {
                json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"method not found"}})
            }
        }
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
        let sig: Signature = signing_key.sign(&msg);
        Some(format!("0x{}", hex::encode(sig.to_bytes())))
    }
}
