use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

pub struct RpcEnvelope {
    pub req: RpcRequest,
    pub reply: Sender<Value>,
}

#[derive(Clone, Debug)]
pub enum RpcRequest {
    JsonRpc {
        id: Value,
        method: String,
        params: Value,
    },
    SendTx {
        chain_id: u64,
        from: String,
        nonce: u64,
        to: String,
        token_id: u64,
        value: u128,
        gas_limit: u64,
        max_fee_per_gas: u64,
        fee_token_id: u64,
        data: String,
        tx_type: String,
        signature_hex: Option<String>,
    },
    BuyTicket {
        validator_id: String,
        count: u64,
        nonce: Option<u64>,
        signature_hex: Option<String>,
    },
    RegisterValidator {
        from: String,
        validator_pubkey: String,
        reward_address: Option<String>,
        nonce: Option<u64>,
        signature_hex: Option<String>,
    },
    WalletToVault {
        validator_id: String,
        amount_quarks: u128,
        nonce: Option<u64>,
        gas_limit: Option<u64>,
        max_fee_per_gas: Option<u64>,
        signature_hex: Option<String>,
    },
    VaultToWallet {
        validator_id: String,
        amount_quarks: u128,
        nonce: Option<u64>,
        gas_limit: Option<u64>,
        max_fee_per_gas: Option<u64>,
        signature_hex: Option<String>,
    },
    GetAccount { account_id: String },
    ListAccounts,
    CreateAccount { account_id: Option<String> },
    ImportPrivateKey { account_id: Option<String>, private_key_hex: String },
    Faucet { to: String, amount_quarks: Option<u128> },
}

pub fn start_rpc_server(port: u16) -> Receiver<RpcEnvelope> {
    let (tx, rx) = mpsc::channel::<RpcEnvelope>();
    thread::spawn(move || {
        let listener = match TcpListener::bind(("127.0.0.1", port)) {
            Ok(l) => l,
            Err(_) => return,
        };
        for stream in listener.incoming().flatten() {
            let tx2 = tx.clone();
            thread::spawn(move || {
                let _ = handle_connection(stream, tx2);
            });
        }
    });
    rx
}

fn handle_connection(mut stream: TcpStream, tx: Sender<RpcEnvelope>) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut reader = BufReader::new(stream.try_clone()?);

    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 || line == "\r\n" {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }

    let mut body_bytes = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body_bytes)?;
    }
    let body = String::from_utf8_lossy(&body_bytes);

    let parsed: Result<Value, _> = serde_json::from_str(&body);
    let response = match parsed {
        Ok(v) => match parse_rpc_request(&v) {
            Ok(req) => {
                let (reply_tx, reply_rx) = mpsc::channel();
                let _ = tx.send(RpcEnvelope { req, reply: reply_tx });
                reply_rx
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap_or_else(|_| json!({"ok": false, "error": "rpc timeout"}))
            }
            Err(e) => json!({"ok": false, "error": e}),
        },
        Err(e) => json!({"ok": false, "error": format!("invalid json: {}", e)}),
    };

    let body_out = serde_json::to_string_pretty(&response).unwrap_or_else(|_| response.to_string());
    let http = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body_out.len(),
        body_out
    );
    stream.write_all(http.as_bytes())?;
    Ok(())
}

fn parse_rpc_request(v: &Value) -> Result<RpcRequest, String> {
    let method = v
        .get("method")
        .and_then(|x| x.as_str())
        .ok_or("missing method")?;

    if v.get("jsonrpc").and_then(|x| x.as_str()) == Some("2.0") || method.starts_with("eth_") || method.starts_with("net_") || method.starts_with("web3_") {
        return Ok(RpcRequest::JsonRpc {
            id: v.get("id").cloned().unwrap_or(Value::Null),
            method: method.to_string(),
            params: v.get("params").cloned().unwrap_or_else(|| Value::Array(vec![])),
        });
    }

    let p = v.get("params").cloned().unwrap_or_else(|| json!({}));
    match method {
        "send_tx" => Ok(RpcRequest::SendTx {
            chain_id: p.get("chain_id").and_then(|x| x.as_u64()).unwrap_or(1162),
            from: p.get("from").and_then(|x| x.as_str()).ok_or("missing from")?.to_string(),
            nonce: p.get("nonce").and_then(|x| x.as_u64()).ok_or("missing nonce")?,
            to: p.get("to").and_then(|x| x.as_str()).ok_or("missing to")?.to_string(),
            token_id: p.get("token_id").and_then(|x| x.as_u64()).unwrap_or(0),
            value: parse_u128_field(&p, "value")?,
            gas_limit: p.get("gas_limit").and_then(|x| x.as_u64()).ok_or("missing gas_limit")?,
            max_fee_per_gas: p
                .get("max_fee_per_gas")
                .and_then(|x| x.as_u64())
                .ok_or("missing max_fee_per_gas")?,
            fee_token_id: p.get("fee_token_id").and_then(|x| x.as_u64()).unwrap_or(0),
            data: p.get("data").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            tx_type: p
                .get("tx_type")
                .and_then(|x| x.as_str())
                .unwrap_or("normal_transfer")
                .to_string(),
            signature_hex: p.get("signature").and_then(|x| x.as_str()).map(|s| s.to_string()),
        }),
        "buy_ticket" => Ok(RpcRequest::BuyTicket {
            validator_id: p
                .get("validator_id")
                .and_then(|x| x.as_str())
                .ok_or("missing validator_id")?
                .to_string(),
            count: p.get("count").and_then(|x| x.as_u64()).unwrap_or(1),
            nonce: p.get("nonce").and_then(|x| x.as_u64()),
            signature_hex: p.get("signature").and_then(|x| x.as_str()).map(|s| s.to_string()),
        }),
        "register_validator" => Ok(RpcRequest::RegisterValidator {
            from: p.get("from").and_then(|x| x.as_str()).ok_or("missing from")?.to_string(),
            validator_pubkey: p
                .get("validator_pubkey")
                .and_then(|x| x.as_str())
                .ok_or("missing validator_pubkey")?
                .to_string(),
            reward_address: p.get("reward_address").and_then(|x| x.as_str()).map(|s| s.to_string()),
            nonce: p.get("nonce").and_then(|x| x.as_u64()),
            signature_hex: p.get("signature").and_then(|x| x.as_str()).map(|s| s.to_string()),
        }),
        "wallet_to_vault" => Ok(RpcRequest::WalletToVault {
            validator_id: p
                .get("validator_id")
                .and_then(|x| x.as_str())
                .ok_or("missing validator_id")?
                .to_string(),
            amount_quarks: parse_u128_field(&p, "amount_quarks")?,
            nonce: p.get("nonce").and_then(|x| x.as_u64()),
            gas_limit: p.get("gas_limit").and_then(|x| x.as_u64()),
            max_fee_per_gas: p.get("max_fee_per_gas").and_then(|x| x.as_u64()),
            signature_hex: p.get("signature").and_then(|x| x.as_str()).map(|s| s.to_string()),
        }),
        "vault_to_wallet" => Ok(RpcRequest::VaultToWallet {
            validator_id: p
                .get("validator_id")
                .and_then(|x| x.as_str())
                .ok_or("missing validator_id")?
                .to_string(),
            amount_quarks: parse_u128_field(&p, "amount_quarks")?,
            nonce: p.get("nonce").and_then(|x| x.as_u64()),
            gas_limit: p.get("gas_limit").and_then(|x| x.as_u64()),
            max_fee_per_gas: p.get("max_fee_per_gas").and_then(|x| x.as_u64()),
            signature_hex: p.get("signature").and_then(|x| x.as_str()).map(|s| s.to_string()),
        }),
        "get_account" => Ok(RpcRequest::GetAccount {
            account_id: p
                .get("account_id")
                .and_then(|x| x.as_str())
                .ok_or("missing account_id")?
                .to_string(),
        }),
        "list_accounts" => Ok(RpcRequest::ListAccounts),
        "create_account" => Ok(RpcRequest::CreateAccount {
            account_id: p.get("account_id").and_then(|x| x.as_str()).map(|s| s.to_string()),
        }),
        "import_private_key" => Ok(RpcRequest::ImportPrivateKey {
            account_id: p.get("account_id").and_then(|x| x.as_str()).map(|s| s.to_string()),
            private_key_hex: p
                .get("private_key_hex")
                .and_then(|x| x.as_str())
                .ok_or("missing private_key_hex")?
                .to_string(),
        }),
        "etx_faucet" => Ok(RpcRequest::Faucet {
            to: p
                .get("to")
                .and_then(|x| x.as_str())
                .ok_or("missing to")?
                .to_string(),
            amount_quarks: parse_optional_u128_field(&p, "amount_quarks")?,
        }),
        _ => Err("unknown method".to_string()),
    }
}

fn parse_u128_field(params: &Value, field: &str) -> Result<u128, String> {
    let value = params.get(field).ok_or_else(|| format!("missing {}", field))?;
    parse_u128_value(value, field)
}

fn parse_optional_u128_field(params: &Value, field: &str) -> Result<Option<u128>, String> {
    params
        .get(field)
        .map(|value| parse_u128_value(value, field))
        .transpose()
}

fn parse_u128_value(value: &Value, field: &str) -> Result<u128, String> {
    if let Some(n) = value.as_u64() {
        return Ok(n as u128);
    }
    if let Some(s) = value.as_str() {
        return s
            .parse::<u128>()
            .map_err(|_| format!("invalid {}, expected unsigned integer", field));
    }
    Err(format!("invalid {}, expected unsigned integer", field))
}
