use super::*;

pub(super) fn hash_bytes(input: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(input);
    let out = h.finalize();
    let mut arr = [0_u8; 32];
    arr.copy_from_slice(&out[..32]);
    arr
}

pub(super) fn deterministic_ticket_id(validator_id: &str) -> u64 {
    let h = hash_bytes(validator_id.as_bytes());
    let mut arr = [0_u8; 8];
    arr.copy_from_slice(&h[..8]);
    u64::from_be_bytes(arr)
}

pub(super) fn unix_ms_now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis()
}

pub(super) fn encode_history_snapshot(state: &ProtocolState) -> String {
    let mut parts = vec![format!(
        "HIST|{}|{}",
        state.epoch_validator_blocks, state.epoch_total_slots
    )];
    for h in state.history.iter().take(64) {
        let kind = match h.kind {
            BlockKind::Validator => "validator",
            BlockKind::ProtocolMiss => "protocol_miss",
            BlockKind::ProtocolCollision => "protocol_collision",
            BlockKind::ProtocolNoTickets => "protocol_notickets",
        };
        parts.push(format!(
            "{}:{}:{}:{}:{}:{}",
            h.slot, h.leader, kind, h.tx_count, h.gas_used, h.fees_burned
        ));
    }
    parts.join("|")
}

pub(super) fn parse_history_snapshot(msg: &str) -> Option<(u64, u64, Vec<SlotResult>)> {
    let p: Vec<&str> = msg.split('|').collect();
    if p.len() < 3 || p[0] != "HIST" {
        return None;
    }
    let evb: u64 = p[1].parse().ok()?;
    let ets: u64 = p[2].parse().ok()?;
    let mut out = vec![];
    for chunk in p.iter().skip(3) {
        let f: Vec<&str> = chunk.split(':').collect();
        if f.len() != 6 {
            continue;
        }
        let kind = match f[2] {
            "validator" => BlockKind::Validator,
            "protocol_miss" => BlockKind::ProtocolMiss,
            "protocol_collision" => BlockKind::ProtocolCollision,
            "protocol_notickets" => BlockKind::ProtocolNoTickets,
            _ => continue,
        };
        let slot = match f[0].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let tx_count = match f[3].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let gas_used = match f[4].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let fees_burned = match f[5].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        out.push(SlotResult {
            slot,
            leader: f[1].to_string(),
            kind,
            tx_count,
            gas_used,
            fees_burned,
        });
    }
    Some((evb, ets, out))
}

pub(super) fn derive_epoch_seed(epoch_index: u64) -> [u8; 32] {
    let mut seed = GENESIS_EPOCH_SEED;
    for i in 1..=epoch_index {
        let mut data = Vec::new();
        data.extend_from_slice(&seed);
        data.extend_from_slice(&i.to_be_bytes());
        seed = hash_bytes(&data);
    }
    seed
}

pub(super) fn normalize_address(input: &str) -> String {
    let s = input.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        format!("0x{}", s[2..].to_lowercase())
    } else {
        s.to_lowercase()
    }
}

pub(super) fn account_from_private_key_hex(id: &str, private_key_hex: &str) -> Option<Account> {
    let raw = private_key_hex
        .strip_prefix("0x")
        .unwrap_or(private_key_hex);
    let bytes = hex::decode(raw).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let signing_key = SigningKey::from_slice(&bytes).ok()?;
    let verify = signing_key.verifying_key();
    let pub_uncompressed = verify.to_encoded_point(false);
    let pub_bytes = pub_uncompressed.as_bytes();
    if pub_bytes.len() != 65 {
        return None;
    }

    let mut hasher = Keccak256::new();
    hasher.update(&pub_bytes[1..]);
    let digest = hasher.finalize();
    let address = format!("0x{}", hex::encode(&digest[12..]));

    Some(Account {
        id: id.to_string(),
        private_key_hex: format!("0x{}", raw.to_lowercase()),
        public_key_hex: format!("0x{}", hex::encode(pub_bytes)),
        address,
        nonce: 0,
        balances: HashMap::new(),
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn tx_message_bytes(
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
) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        chain_id,
        normalize_address(from),
        nonce,
        normalize_address(to),
        token_id,
        value,
        gas_limit,
        max_fee_per_gas,
        fee_token_id,
        data,
        tx_type
    )
    .into_bytes()
}

pub(super) fn to_hex_qty(v: u64) -> String {
    format!("0x{:x}", v)
}

pub(super) fn to_hex_qty_u128(v: u128) -> String {
    format!("0x{:x}", v)
}

pub(super) fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

pub(super) fn keccak256_hex_bytes(raw_hex: &str) -> [u8; 32] {
    let bytes = hex::decode(raw_hex.trim_start_matches("0x")).unwrap_or_default();
    keccak256(&bytes)
}

pub(super) fn decode_raw_eip1559_tx(raw_hex: &str) -> Option<Tx> {
    let raw = raw_hex.trim_start_matches("0x");
    let bytes = hex::decode(raw).ok()?;
    if bytes.is_empty() || bytes[0] != 0x02 {
        eprintln!(
            "[rpc][decode] unsupported tx type byte: {}",
            bytes.first().copied().unwrap_or_default()
        );
        return None;
    }
    let payload = &bytes[1..];
    let rlp = Rlp::new(payload);
    if !rlp.is_list() || rlp.item_count().ok()? < 12 {
        return None;
    }

    let chain_id: u64 = rlp.val_at(0).ok()?;
    let nonce: u64 = rlp.val_at(1).ok()?;
    let _max_priority_fee_per_gas: u64 = rlp.val_at(2).ok()?;
    let max_fee_per_gas: u64 = rlp.val_at(3).ok()?;
    let gas_limit: u64 = rlp.val_at(4).ok()?;
    let to_bytes: Vec<u8> = rlp.val_at(5).ok()?;
    let to = if to_bytes.is_empty() {
        "0x0000000000000000000000000000000000000000".to_string()
    } else {
        format!("0x{}", hex::encode(&to_bytes))
    };
    let value_wei_u128: u128 = rlp_u128_at(&rlp, 6)?;
    let data_bytes: Vec<u8> = rlp.val_at(7).ok()?;
    let data_hex = format!("0x{}", hex::encode(&data_bytes));

    let y_parity: u64 = rlp.val_at(9).ok()?;
    let r_bytes: Vec<u8> = rlp.val_at(10).ok()?;
    let s_bytes: Vec<u8> = rlp.val_at(11).ok()?;
    let sig_bytes = rs_64(&r_bytes, &s_bytes)?;
    let sig = Signature::from_slice(&sig_bytes).ok()?;
    let recid = RecoveryId::from_byte(y_parity as u8)?;

    let access_list_raw = rlp.at(8).ok()?.as_raw().to_vec();

    let mut stream = RlpStream::new_list(9);
    stream.append(&chain_id);
    stream.append(&nonce);
    stream.append(&_max_priority_fee_per_gas);
    stream.append(&max_fee_per_gas);
    stream.append(&gas_limit);
    stream.append(&to_bytes);
    stream.append(&value_wei_u128);
    stream.append(&data_bytes);
    stream.append_raw(&access_list_raw, 1);
    let signing_payload = stream.out().to_vec();
    let mut preimage = vec![0x02u8];
    preimage.extend_from_slice(&signing_payload);
    let msg_hash = keccak256(&preimage);
    let vk = VerifyingKey::recover_from_prehash(&msg_hash, &sig, recid).ok()?;
    let from = pubkey_to_eth_address(&vk);

    let fee = gas_limit.saturating_mul(max_fee_per_gas_to_quarks(max_fee_per_gas));
    Some(Tx {
        chain_id,
        from,
        nonce,
        to,
        token_id: 0,
        value: wei_to_quarks(value_wei_u128),
        gas: gas_limit,
        fee_quarks: fee,
        max_fee_per_gas,
        kind: "transfer",
        valid_after_slot: 0,
        fee_token_id: 0,
        data: data_hex,
        signature_hex: format!("0x{}", hex::encode(sig_bytes)),
    })
}

pub(super) fn decode_raw_legacy_tx(raw_hex: &str) -> Option<Tx> {
    let raw = raw_hex.trim_start_matches("0x");
    let bytes = hex::decode(raw).ok()?;
    if bytes.is_empty() {
        return None;
    }
    if bytes[0] <= 0x7f || bytes[0] == 0x01 || bytes[0] == 0x02 {
        return None;
    }

    let rlp = Rlp::new(&bytes);
    if !rlp.is_list() || rlp.item_count().ok()? < 9 {
        return None;
    }

    let nonce: u64 = rlp_u64_at(&rlp, 0)?;
    let gas_price: u64 = rlp_u64_at(&rlp, 1)?;
    let gas_limit: u64 = rlp_u64_at(&rlp, 2)?;
    let to_bytes: Vec<u8> = rlp_bytes_at(&rlp, 3)?;
    let to = if to_bytes.is_empty() {
        "0x0000000000000000000000000000000000000000".to_string()
    } else {
        format!("0x{}", hex::encode(&to_bytes))
    };
    let value_wei_u128: u128 = rlp_u128_at(&rlp, 4)?;
    let data_bytes: Vec<u8> = rlp_bytes_at(&rlp, 5)?;
    let data_hex = format!("0x{}", hex::encode(&data_bytes));
    let v: u64 = rlp_u64_at(&rlp, 6)?;
    let r_bytes: Vec<u8> = rlp_bytes_at(&rlp, 7)?;
    let s_bytes: Vec<u8> = rlp_bytes_at(&rlp, 8)?;

    let (chain_id, parity, eip155) = if v >= 35 {
        ((v - 35) / 2, (v - 35) % 2, true)
    } else if v == 27 || v == 28 {
        (1162_u64, v - 27, false)
    } else {
        return None;
    };
    let recid = RecoveryId::from_byte(parity as u8)?;
    let sig_bytes = rs_64(&r_bytes, &s_bytes)?;
    let sig = Signature::from_slice(&sig_bytes).ok()?;

    let mut stream = if eip155 {
        RlpStream::new_list(9)
    } else {
        RlpStream::new_list(6)
    };
    stream.append(&nonce);
    stream.append(&gas_price);
    stream.append(&gas_limit);
    stream.append(&to_bytes);
    stream.append(&value_wei_u128);
    stream.append(&data_bytes);
    if eip155 {
        stream.append(&chain_id);
        stream.append(&0u8);
        stream.append(&0u8);
    }
    let preimage = stream.out().to_vec();
    let msg_hash = keccak256(&preimage);
    let vk = VerifyingKey::recover_from_prehash(&msg_hash, &sig, recid).ok()?;
    let from = pubkey_to_eth_address(&vk);

    let fee = gas_limit.saturating_mul(max_fee_per_gas_to_quarks(gas_price));
    Some(Tx {
        chain_id,
        from,
        nonce,
        to,
        token_id: 0,
        value: wei_to_quarks(value_wei_u128),
        gas: gas_limit,
        fee_quarks: fee,
        max_fee_per_gas: gas_price,
        kind: "transfer",
        valid_after_slot: 0,
        fee_token_id: 0,
        data: data_hex,
        signature_hex: format!("0x{}", hex::encode(sig_bytes)),
    })
}

pub(super) fn rlp_bytes_at(rlp: &Rlp, idx: usize) -> Option<Vec<u8>> {
    let item = rlp.at(idx).ok()?;
    if item.is_empty() {
        return Some(vec![]);
    }
    item.data().ok().map(|d| d.to_vec())
}

pub(super) fn be_bytes_to_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.len() > 8 {
        return None;
    }
    let mut out = 0u64;
    for b in bytes {
        out = (out << 8) | (*b as u64);
    }
    Some(out)
}

pub(super) fn be_bytes_to_u128(bytes: &[u8]) -> Option<u128> {
    if bytes.len() > 16 {
        return None;
    }
    let mut out = 0u128;
    for b in bytes {
        out = (out << 8) | (*b as u128);
    }
    Some(out)
}

pub(super) fn rlp_u64_at(rlp: &Rlp, idx: usize) -> Option<u64> {
    let bytes = rlp_bytes_at(rlp, idx)?;
    if bytes.is_empty() {
        return Some(0);
    }
    be_bytes_to_u64(&bytes)
}

pub(super) fn rlp_u128_at(rlp: &Rlp, idx: usize) -> Option<u128> {
    let bytes = rlp_bytes_at(rlp, idx)?;
    if bytes.is_empty() {
        return Some(0);
    }
    be_bytes_to_u128(&bytes)
}

pub(super) fn rs_64(r: &[u8], s: &[u8]) -> Option<[u8; 64]> {
    if r.len() > 32 || s.len() > 32 {
        return None;
    }
    let mut out = [0u8; 64];
    out[32 - r.len()..32].copy_from_slice(r);
    out[64 - s.len()..64].copy_from_slice(s);
    Some(out)
}

pub(super) fn pubkey_to_eth_address(vk: &VerifyingKey) -> String {
    let pub_uncompressed = vk.to_encoded_point(false);
    let bytes = pub_uncompressed.as_bytes();
    let mut h = Keccak256::new();
    h.update(&bytes[1..]);
    let out = h.finalize();
    format!("0x{}", hex::encode(&out[12..]))
}

pub(super) fn extract_raw_signature_parts(
    raw_hex: &str,
) -> Option<(String, String, String, String)> {
    let bytes = hex::decode(raw_hex.trim_start_matches("0x")).ok()?;
    if bytes.is_empty() {
        return None;
    }
    if bytes[0] == 0x02 {
        let rlp = Rlp::new(&bytes[1..]);
        let y: u64 = rlp_u64_at(&rlp, 9)?;
        let r = rlp_bytes_at(&rlp, 10)?;
        let s = rlp_bytes_at(&rlp, 11)?;
        return Some((
            "0x2".to_string(),
            to_hex_qty(y),
            format!("0x{}", hex::encode(r)),
            format!("0x{}", hex::encode(s)),
        ));
    }
    let rlp = Rlp::new(&bytes);
    let v: u64 = rlp_u64_at(&rlp, 6)?;
    let r = rlp_bytes_at(&rlp, 7)?;
    let s = rlp_bytes_at(&rlp, 8)?;
    Some((
        "0x0".to_string(),
        to_hex_qty(v),
        format!("0x{}", hex::encode(r)),
        format!("0x{}", hex::encode(s)),
    ))
}

pub(super) fn tx_json_by_hash(raw_txs: &HashMap<String, RawTxRecord>, h: &str) -> Option<Value> {
    let r = raw_txs.get(h)?;
    let pending = r.block_number.is_none();
    let is_type2 = r.tx_type == "0x2";
    Some(json!({
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
    }))
}

pub(super) fn resolve_block_tag(tag: &str, latest: u64) -> u64 {
    match tag {
        "latest" | "pending" | "safe" | "finalized" => latest,
        "earliest" => 0,
        _ => u64::from_str_radix(tag.trim_start_matches("0x"), 16).unwrap_or(latest),
    }
}

pub(super) fn max_fee_per_gas_to_quarks(max_fee_per_gas: u64) -> u64 {
    // MetaMask/EVM values are wei-style 18-decimal units.
    // Eternix fee accounting is in quarks (1 quark = 1e-10 ETX),
    // therefore 1 quark = 1e8 wei-like units.
    let q = max_fee_per_gas / WEI_PER_QUARK;
    q.max(1)
}

pub(super) fn wei_to_quarks(value_wei: u128) -> u128 {
    value_wei / WEI_PER_QUARK as u128
}

pub(super) fn encode_register_validator_data(
    validator_pubkey: &str,
    reward_address: &str,
) -> String {
    json!({
        "validator_pubkey": validator_pubkey,
        "reward_address": reward_address,
    })
    .to_string()
}

pub(super) fn decode_register_validator_data(data: &str) -> Option<(String, String)> {
    let value: Value = serde_json::from_str(data).ok()?;
    let validator_pubkey = value.get("validator_pubkey")?.as_str()?.to_string();
    let reward_address = value.get("reward_address")?.as_str()?.to_string();
    Some((validator_pubkey, reward_address))
}
