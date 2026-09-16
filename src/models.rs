use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Instant, SystemTime};

pub const SLOT_MS: u64 = 3000;
pub const LEADER_DEADLINE_MS: u64 = 2100;
pub const SUB_EPOCH_SLOTS: u64 = 1200;
pub const EPOCH_SUB_EPOCHS: u64 = 24;
// Late validator blocks may correct provisional miss results while they are still visible in history.
pub const FINALITY_WINDOW_SLOTS: u64 = 20;
pub type Hash = [u8; 32];

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
    // When set, validator mode attaches to an already registered validator instead of creating a bootstrap validator.
    pub validator_id: Option<String>,
    pub validator_account: Option<String>,
    pub genesis_path: String,
    pub no_tui: bool,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxKind {
    Transfer,
    Contract,
    System,
    Pbm,
    RegisterValidator,
    BuyTicket,
    WalletToVault,
    VaultToWallet,
    BurnTicket,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Validator {
    pub id: String,
    // The account that pays validator system tx fees and owns vault/ticket operations.
    pub owner_account: Option<String>,
    pub validator_pubkey: Option<String>,
    pub reward_address: Option<String>,
    pub state: ValidatorState,
    pub vault_quarks: u128,
    // Rewards are part of vault balance immediately but cannot be withdrawn until their unlock epoch.
    pub locked_reward_quarks: u128,
    pub miss_counter: u32,
    pub double_sign_offenses: u32,
    pub blocks_this_sub_epoch: u32,
    pub cooldown_until_epoch: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
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
    pub kind: TxKind,
    // PBM transactions become executable only after this slot; normal mempool transactions use zero.
    pub valid_after_slot: u64,
    pub fee_token_id: u64,
    pub data: String,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockHeader {
    pub protocol_version: u32,
    pub chain_id: u64,
    pub slot: u64,
    pub block_kind: BlockKind,
    pub parent_hash: Hash,
    // Validator IDs are represented here by their fixed 32-byte canonical proposer commitment.
    pub proposer_id: Hash,
    // Ticket IDs are native u64 values and are serialized big-endian.
    pub ticket_id: u64,
    pub transaction_root: Hash,
    pub state_root: Hash,
    pub receipts_root: Hash,
    pub gas_used: u64,
    pub protocol_data_root: Hash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolData {
    pub missed_proposer: Option<String>,
    pub fees_burned: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    pub header: BlockHeader,
    // The readable ID is retained in the body so validators can verify its header commitment.
    pub proposer: Option<String>,
    pub transactions: Vec<Tx>,
    pub protocol_data: ProtocolData,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Account {
    pub id: String,
    pub private_key_hex: String,
    pub public_key_hex: String,
    pub address: String,
    pub nonce: u64,
    pub balances: HashMap<u64, u128>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProtocolState {
    pub slot: u64,
    pub slot_started: Instant,
    pub validators: Vec<Validator>,
    pub tickets: Vec<Ticket>,
    pub mempool: VecDeque<Tx>,
    pub pbm_pool: VecDeque<Tx>,
    pub history: VecDeque<Block>,
    pub events: VecDeque<String>,
    pub sync_pct: f64,
    // Fee burns accumulated in the current sub-epoch; ticket burns are deliberately excluded from burn-offset.
    pub burn_this_sub_epoch: u128,
    pub fees_burned_total: u128,
    pub ticket_burned_total: u128,
    pub base_issuance_total: u128,
    pub burn_offset_total: u128,
    // Period counters drive the TUI inflationary/deflationary indicators instead of all-time totals.
    pub sub_epoch_issued_quarks: u128,
    pub sub_epoch_burned_quarks: u128,
    pub epoch_issued_quarks: u128,
    pub epoch_burned_quarks: u128,
    pub annual_inflation_ppb: u64,
    pub base_reward_per_block_quarks: u128,
    pub burn_offset_k_permille: u64,
    pub epoch_validator_blocks: u64,
    pub epoch_total_slots: u64,
    pub mode: Mode,
    pub current_leader: String,
    pub current_ticket_id: u64,
    pub exec_status: ExecStatus,
    pub current_result: Option<Block>,
    pub nonce_tracker: HashMap<String, u64>,
    pub mode_local: NodeMode,
    pub local_validator_id: Option<String>,
    // Legacy bootstrap validators get synthetic startup vault/ticket state; registered validators do not.
    pub local_validator_bootstrap: bool,
    pub accounts: HashMap<String, Account>,
    pub wallet_addresses: Vec<String>,
    pub anchor_time: SystemTime,
    pub bootstrapped_from_peer: bool,
    pub validator_peers: HashMap<String, SocketAddr>,
    pub remote_slot_results: BTreeMap<u64, Block>,
    // History sync is only a bootstrap aid; later peer history is treated as correction data.
    pub history_synced: bool,
    pub liveness_epoch: u64,
    pub liveness_counted_slots: BTreeSet<u64>,
    pub liveness_total_slots: u64,
    pub liveness_validator_slots: u64,
    pub epoch_index: u64,
    pub sub_epoch_index: u64,
    pub epoch_seed: Hash,
    pub blocks_this_sub_epoch: Vec<Option<String>>,
    pub retire_per_epoch_limit: u64,
    pub retire_schedule: BTreeMap<u64, Vec<u64>>,
    pub retire_finalize: BTreeMap<u64, Vec<u64>>,
    pub reward_unlocks: BTreeMap<u64, Vec<(String, u128)>>,
    pub raw_txs: HashMap<Hash, RawTxRecord>,
    pub blocks: HashMap<u64, Block>,
    pub block_hash_to_number: HashMap<Hash, u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawTxRecord {
    pub hash: Hash,
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
    pub block_hash: Option<Hash>,
    pub tx_index: Option<u64>,
    pub success: Option<bool>,
}
