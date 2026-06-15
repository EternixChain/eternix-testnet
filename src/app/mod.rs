use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sha2::{Digest, Sha256};
use serde_json::{json, Value};
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::rand_core::OsRng;
use k256::ecdsa::signature::Signer;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use rlp::{Rlp, RlpStream};
use sha3::Keccak256;

use crate::models::*;
use crate::p2p::{encode_slot_result, parse_hello, parse_slot_result, parse_tx_msg, tx_id, P2p};
use crate::leader_selection::select_leader_owner;
use crate::rpc::RpcRequest;
const GENESIS_EPOCH_SEED: [u8; 32] = [0x45; 32];
const TOKEN_ETX_ID: u64 = 0;
const TICKET_COST_QUARKS: u128 = 10_000_000_000_000;
const WEI_PER_QUARK: u64 = 100_000_000;

pub struct Protocol {
    rng: StdRng,
    pub state: ProtocolState,
    pub p2p: P2p,
}


mod accounts;
mod consensus;
mod core;
mod network;
mod rpc_eth;
mod utils;

use utils::*;
