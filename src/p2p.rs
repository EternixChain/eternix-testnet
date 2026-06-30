use std::collections::HashSet;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::models::{BlockKind, SlotResult, Tx};

#[derive(Clone, Debug)]
pub struct HelloMsg {
    pub addr: SocketAddr,
    pub slot: u64,
    pub slot_started_unix_ms: u128,
    pub mode: String,
    pub validator_id: Option<String>,
    pub validator_account: Option<String>,
}

pub struct P2p {
    socket: UdpSocket,
    peers: HashSet<SocketAddr>,
    seen_msgs: HashSet<String>,
    last_hello: Instant,
}

impl P2p {
    pub fn new(port: u16, bootstrap_peers: &[SocketAddr]) -> Result<Self> {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", port))?;
        socket.set_nonblocking(true)?;
        let mut this = Self {
            socket,
            peers: bootstrap_peers.iter().copied().collect(),
            seen_msgs: HashSet::new(),
            last_hello: Instant::now() - Duration::from_secs(2),
        };
        this.broadcast_hello("0|0|unknown|");
        Ok(this)
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn mark_seen(&mut self, id: String) -> bool {
        self.seen_msgs.insert(id)
    }

    pub fn tick_hello(&mut self, hello_payload: &str) {
        if self.last_hello.elapsed() >= Duration::from_millis(500) {
            self.broadcast_hello(hello_payload);
        }
    }

    pub fn recv_all(&mut self) -> Vec<(SocketAddr, String)> {
        let mut out = vec![];
        loop {
            let mut buf = [0_u8; 2048];
            match self.socket.recv_from(&mut buf) {
                Ok((n, from)) => {
                    if let Ok(s) = std::str::from_utf8(&buf[..n]) {
                        out.push((from, s.to_string()));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        out
    }

    pub fn add_peer(&mut self, peer: SocketAddr) {
        self.peers.insert(peer);
    }

    pub fn broadcast_tx(&self, tx: &Tx) {
        let id = tx_id(tx);
        let msg = format!(
            "TX|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            id,
            tx.chain_id,
            tx.from,
            tx.nonce,
            tx.to,
            tx.token_id,
            tx.value,
            tx.gas,
            tx.max_fee_per_gas,
            tx.fee_quarks,
            tx.fee_token_id,
            tx.kind,
            tx.valid_after_slot,
            tx.data,
            tx.signature_hex
        );
        self.broadcast_raw(&msg);
    }

    pub fn broadcast_message(&self, msg: &str) {
        self.broadcast_raw(msg);
    }

    pub fn send_to(&self, msg: &str, to: SocketAddr) {
        let _ = self.socket.send_to(msg.as_bytes(), to);
    }

    pub fn broadcast_raw_except(&self, msg: &str, except: SocketAddr) {
        for p in &self.peers {
            if *p != except {
                let _ = self.socket.send_to(msg.as_bytes(), p);
            }
        }
    }

    pub fn send_hello_now(&mut self, hello_payload: &str) {
        self.broadcast_hello(hello_payload);
    }

    fn broadcast_hello(&mut self, hello_payload: &str) {
        self.last_hello = Instant::now();
        if let Ok(addr) = self.socket.local_addr() {
            self.broadcast_raw(&format!("HELLO|{}|{}", addr, hello_payload));
        }
    }

    fn broadcast_raw(&self, msg: &str) {
        for p in &self.peers {
            let _ = self.socket.send_to(msg.as_bytes(), p);
        }
    }
}

pub fn parse_hello(msg: &str) -> Option<HelloMsg> {
    let p: Vec<&str> = msg.split('|').collect();
    if p.len() < 6 || p[0] != "HELLO" {
        return None;
    }
    let validator_id = if p.len() >= 6 && !p[5].is_empty() {
        Some(p[5].to_string())
    } else {
        None
    };
    let validator_account = if p.len() >= 7 && !p[6].is_empty() {
        Some(p[6].to_string())
    } else {
        None
    };
    Some(HelloMsg {
        addr: p[1].parse().ok()?,
        slot: p[2].parse().ok()?,
        slot_started_unix_ms: p[3].parse().ok()?,
        mode: p[4].to_string(),
        validator_id,
        validator_account,
    })
}

pub fn parse_tx_msg(msg: &str) -> Option<(String, Tx)> {
    let p: Vec<&str> = msg.split('|').collect();
    if p.len() != 16 || p[0] != "TX" {
        return None;
    }
    let kind = match p[12] {
        "transfer" => "transfer",
        "contract" => "contract",
        "system" => "system",
        "pbm_tx" => "pbm_tx",
        "burnTicket" => "burnTicket",
        "registerValidator" => "registerValidator",
        "buyTicket" => "buyTicket",
        "walletToVault" => "walletToVault",
        _ => "transfer",
    };
    Some((
        p[1].to_string(),
        Tx {
            chain_id: p[2].parse().ok()?,
            from: p[3].to_string(),
            nonce: p[4].parse().ok()?,
            to: p[5].to_string(),
            token_id: p[6].parse().ok()?,
            value: p[7].parse().ok()?,
            gas: p[8].parse().ok()?,
            max_fee_per_gas: p[9].parse().ok()?,
            fee_quarks: p[10].parse().ok()?,
            fee_token_id: p[11].parse().ok()?,
            kind,
            valid_after_slot: p[13].parse().ok()?,
            data: p[14].to_string(),
            signature_hex: p[15].to_string(),
        },
    ))
}

pub fn tx_id(tx: &Tx) -> String {
    let raw = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        tx.chain_id,
        tx.from,
        tx.nonce,
        tx.to,
        tx.token_id,
        tx.value,
        tx.gas,
        tx.max_fee_per_gas,
        tx.fee_quarks,
        tx.fee_token_id,
        tx.kind,
        tx.valid_after_slot
    );
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    hex::encode(h.finalize())
}

pub fn encode_slot_result(result: &SlotResult) -> String {
    let kind = match result.kind {
        BlockKind::Validator => "validator",
        BlockKind::ProtocolMiss => "protocol_miss",
        BlockKind::ProtocolCollision => "protocol_collision",
        BlockKind::ProtocolNoTickets => "protocol_notickets",
    };
    format!(
        "SLOTRES|{}|{}|{}|{}|{}|{}",
        result.slot, result.leader, kind, result.tx_count, result.gas_used, result.fees_burned
    )
}

pub fn parse_slot_result(msg: &str) -> Option<SlotResult> {
    let p: Vec<&str> = msg.split('|').collect();
    if p.len() != 7 || p[0] != "SLOTRES" {
        return None;
    }
    let kind = match p[3] {
        "validator" => BlockKind::Validator,
        "protocol_miss" => BlockKind::ProtocolMiss,
        "protocol_collision" => BlockKind::ProtocolCollision,
        "protocol_notickets" => BlockKind::ProtocolNoTickets,
        _ => return None,
    };
    Some(SlotResult {
        slot: p[1].parse().ok()?,
        leader: p[2].to_string(),
        kind,
        tx_count: p[4].parse().ok()?,
        gas_used: p[5].parse().ok()?,
        fees_burned: p[6].parse().ok()?,
    })
}
