use std::collections::HashSet;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::consensus_hash::{format_hash, parse_hash};
use crate::models::{Block, Hash, Tx};
use anyhow::Result;

#[derive(Clone, Debug)]
pub struct HelloMsg {
    pub addr: SocketAddr,
    pub slot: u64,
    pub slot_started_unix_ms: u128,
    pub mode: String,
    pub validator_id: Option<String>,
    pub validator_account: Option<String>,
    pub validator_bootstrap: bool,
}

pub struct P2p {
    socket: UdpSocket,
    peers: HashSet<SocketAddr>,
    seen_msgs: HashSet<Hash>,
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

    pub fn mark_seen(&mut self, id: Hash) -> bool {
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
            // State snapshots can be much larger than tx gossip, so receive up to the UDP payload limit.
            let mut buf = [0_u8; 65_507];
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
        if let (Some(bytes), Some(hash)) = (tx.canonical_bytes(), tx_id(tx)) {
            let msg = format!("TX|{}|{}", format_hash(&hash), hex::encode(bytes));
            self.broadcast_raw(&msg);
        }
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
    let validator_bootstrap = p.len() >= 8 && p[7] == "1";
    Some(HelloMsg {
        addr: p[1].parse().ok()?,
        slot: p[2].parse().ok()?,
        slot_started_unix_ms: p[3].parse().ok()?,
        mode: p[4].to_string(),
        validator_id,
        validator_account,
        validator_bootstrap,
    })
}

pub fn parse_tx_msg(msg: &str) -> Option<(Hash, Tx)> {
    let p: Vec<&str> = msg.split('|').collect();
    if p.len() != 3 || p[0] != "TX" {
        return None;
    }
    let claimed_hash = parse_hash(p[1])?;
    let tx = Tx::from_canonical_bytes(&hex::decode(p[2]).ok()?)?;
    (tx.hash()? == claimed_hash).then_some((claimed_hash, tx))
}

pub fn tx_id(tx: &Tx) -> Option<Hash> {
    tx.hash()
}

pub fn encode_block(block: &Block) -> String {
    format!(
        "BLOCK|{}",
        hex::encode(
            block
                .wire_bytes()
                .expect("locally constructed blocks have valid commitments")
        )
    )
}

pub fn parse_block(msg: &str) -> Option<Block> {
    let payload = msg.strip_prefix("BLOCK|")?;
    Block::from_wire_bytes(&hex::decode(payload).ok()?)
}
