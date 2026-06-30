use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Instant, SystemTime};

pub const SLOT_MS: u64 = 3000;
pub const LEADER_DEADLINE_MS: u64 = 2100;
pub const SUB_EPOCH_SLOTS: u64 = 1200;
pub const EPOCH_SUB_EPOCHS: u64 = 24;
pub const FINALITY_WINDOW_SLOTS: u64 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidatorState {
    Active,
    PausedLowVault,
    PunishedCooldown,
    Inactive,
    Jailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeMode {
    Standard,
    Validator,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub mode: NodeMode,
    pub p2p_port: u16,
    pub peers: Vec<SocketAddr>,
    pub rpc_port: u16,
    pub validator_account: Option<String>,
    pub genesis_path: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Normal,
    Pbm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecStatus {
    Idle,
    Executing,
    Posted,
    Missed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockKind {
    Validator,
    ProtocolMiss,
    ProtocolCollision,
    ProtocolNoTickets,
}

#[derive(Clone, Debug)]
pub struct Validator {
    pub id: String,
    pub owner_account: Option<String>,
    pub validator_pubkey: Option<String>,
    pub reward_address: Option<String>,
    pub state: ValidatorState,
    pub vault_quarks: u128,
    pub miss_counter: u32,
    pub double_sign_offenses: u32,
    pub blocks_this_sub_epoch: u32,
    pub cooldown_until_epoch: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct Ticket {
    pub id: u64,
    pub owner: String,
    pub bucket: u8,
    pub muted: bool,
    pub dead: bool,
    pub retiring: bool,
    pub retire_requested_epoch: Option<u64>,
    pub retire_effective_epoch: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct Tx {
    pub chain_id: u64,
    pub from: String,
    pub nonce: u64,
    pub to: String,
    pub token_id: u64,
    pub value: u128,
    pub gas: u64,
    pub fee_quarks: u64,
    pub max_fee_per_gas: u64,
    pub kind: &'static str,
    pub valid_after_slot: u64,
    pub fee_token_id: u64,
    pub data: String,
    pub signature_hex: String,
}

#[derive(Clone, Debug)]
pub struct Account {
    pub id: String,
    pub private_key_hex: String,
    pub public_key_hex: String,
    pub address: String,
    pub nonce: u64,
    pub balances: HashMap<u64, u128>,
}

#[derive(Clone, Debug)]
pub struct SlotResult {
    pub slot: u64,
    pub leader: String,
    pub kind: BlockKind,
    pub tx_count: u32,
    pub gas_used: u64,
    pub fees_burned: u64,
}

pub struct ProtocolState {
    pub slot: u64,
    pub slot_started: Instant,
    pub prev_hash: [u8; 32],
    pub validators: Vec<Validator>,
    pub tickets: Vec<Ticket>,
    pub mempool: VecDeque<Tx>,
    pub pbm_pool: VecDeque<Tx>,
    pub history: VecDeque<SlotResult>,
    pub events: VecDeque<String>,
    pub sync_pct: f64,
    pub burn_this_sub_epoch: u128,
    pub fees_burned_total: u128,
    pub base_issuance_total: u128,
    pub burn_offset_total: u128,
    pub annual_inflation_ppb: u64,
    pub base_reward_per_block_quarks: u128,
    pub burn_offset_k_permille: u64,
    pub epoch_validator_blocks: u64,
    pub epoch_total_slots: u64,
    pub mode: Mode,
    pub current_leader: String,
    pub exec_status: ExecStatus,
    pub current_result: Option<SlotResult>,
    pub nonce_tracker: HashMap<String, u64>,
    pub mode_local: NodeMode,
    pub local_validator_id: Option<String>,
    pub accounts: HashMap<String, Account>,
    pub wallet_addresses: Vec<String>,
    pub anchor_time: SystemTime,
    pub bootstrapped_from_peer: bool,
    pub validator_peers: HashMap<String, SocketAddr>,
    pub remote_slot_results: BTreeMap<u64, SlotResult>,
    pub history_synced: bool,
    pub liveness_epoch: u64,
    pub liveness_counted_slots: BTreeSet<u64>,
    pub liveness_total_slots: u64,
    pub liveness_validator_slots: u64,
    pub epoch_index: u64,
    pub sub_epoch_index: u64,
    pub epoch_seed: [u8; 32],
    pub blocks_this_sub_epoch: Vec<Option<String>>,
    pub retire_per_epoch_limit: u64,
    pub retire_schedule: BTreeMap<u64, Vec<u64>>,
    pub retire_finalize: BTreeMap<u64, Vec<u64>>,
    pub raw_txs: HashMap<String, RawTxRecord>,
    pub raw_tx_pending: VecDeque<String>,
    pub block_transactions: HashMap<u64, Vec<String>>,
    pub blocks: HashMap<u64, BlockRecord>,
    pub block_hash_to_number: HashMap<String, u64>,
}

#[derive(Clone, Debug)]
pub struct RawTxRecord {
    pub hash: String,
    pub raw: String,
    pub from: String,
    pub to: Option<String>,
    pub nonce: u64,
    pub gas: u64,
    pub input: String,
    pub value: u128,
    pub fee_quarks: u64,
    pub chain_id: u64,
    pub tx_type: String,
    pub v: String,
    pub r: String,
    pub s: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub tx_index: Option<u64>,
    pub success: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct BlockRecord {
    pub number: u64,
    pub hash: String,
    pub parent_hash: String,
    pub timestamp_ms: u64,
    pub gas_used: u64,
    pub tx_hashes: Vec<String>,
}
