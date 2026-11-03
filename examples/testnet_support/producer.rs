//! S2 local pool and owned producer preparation. Selection reserves only starting funds; it never
//! previews execution, installs a state mirror or substitutes admission proofs for inclusion checks.
use super::profile::{MAX_BLOCKS, MAX_TRANSACTIONS, Profile, bounded_hex};
use super::tip;
use eternix_testnet::authenticated_fixture::{
    AuthenticatedFixtureStore, PreparedAuthenticatedBody, Snapshot,
};
use eternix_testnet::block_authentication::sign_block;
use eternix_testnet::canonical_fixture::Tip;
use eternix_testnet::native_transaction::{
    self as native, Address, Hash, SIGNED_LEN, TRANSFER_FEE_QUARKS, UnsignedTransaction,
};
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::zeroize::Zeroizing;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Local experiment pool bound; neither admission nor pending reservations change canonical state.
pub const MAX_POOL: usize = 128;
struct Entry {
    id: Hash,
    raw: [u8; SIGNED_LEN],
    unsigned: UnsignedTransaction,
}
#[derive(Default)]
struct Pool {
    entries: BTreeMap<(Address, u64), Entry>,
}
impl Pool {
    fn submit(
        &mut self,
        encoded: &str,
        profile: &Profile,
        snapshot: &Snapshot,
    ) -> Result<Value, String> {
        let bytes = bounded_hex(encoded, SIGNED_LEN)?;
        // Always cold-authenticate admission, including duplicates. Inclusion independently calls
        // the original executor; no authenticated-result flag crosses that boundary.
        let proof = native::authenticate(&bytes, &profile.manifest.fixture().context(), None)
            .map_err(|e| e.to_string())?;
        let id = proof.transaction_id();
        let tx = proof.transaction().unsigned();
        if let Some(old) = self.entries.values().find(|e| e.id == id) {
            if old.raw.as_slice() != bytes {
                return Err("ID/content mismatch".into());
            }
            return Ok(
                json!({"outcome":"duplicate_id","id":hex::encode(id),"count":self.entries.len()}),
            );
        }
        if snapshot.transactions.contains_key(&id) {
            return Ok(
                json!({"outcome":"already_included","id":hex::encode(id),"count":self.entries.len()}),
            );
        }
        if tx.nonce < snapshot.state.account(&tx.sender).nonce {
            return Err("stale canonical nonce".into());
        }
        tx.value
            .checked_add(TRANSFER_FEE_QUARKS as u128)
            .ok_or("unrepresentable value plus fee")?;
        let key = (tx.sender, tx.nonce);
        if self.entries.contains_key(&key) {
            return Err("sender/nonce already has a candidate; replacement disabled".into());
        }
        if self.entries.len() == MAX_POOL {
            return Err("native pool is full".into());
        }
        self.entries.insert(
            key,
            Entry {
                id,
                raw: bytes.try_into().map_err(|_| "native length")?,
                unsigned: tx.clone(),
            },
        );
        Ok(json!({"outcome":"admitted","id":hex::encode(id),"count":self.entries.len()}))
    }

    fn select(&self, snapshot: &Snapshot, slot: u64) -> (Vec<Vec<u8>>, Value) {
        let mut body = Vec::with_capacity(MAX_TRANSACTIONS);
        let mut reservations = BTreeMap::new();
        let (mut gap, mut immature, mut funds, mut stale, mut capacity) = (0, 0, 0, 0, 0);
        for ((sender, nonce), e) in &self.entries {
            if body.len() == MAX_TRANSACTIONS {
                capacity += 1;
                continue;
            }
            let state = reservations.entry(*sender).or_insert_with(|| {
                let a = snapshot.state.account(sender);
                (a.nonce, a.balance_quarks)
            });
            if *nonce < state.0 {
                stale += 1;
                continue;
            }
            if *nonce != state.0 {
                gap += 1;
                continue;
            }
            if e.unsigned.valid_after_slot > slot {
                immature += 1;
                continue;
            }
            let debit = e
                .unsigned
                .value
                .checked_add(TRANSFER_FEE_QUARKS as u128)
                .expect("admission exposure bound");
            if debit > state.1 {
                funds += 1;
                continue;
            }
            // Conservative reservations deliberately ignore ALL credits, including self credits.
            // This may defer a valid spend but cannot make an unfunded starting-state body valid.
            state.1 -= debit;
            state.0 = state
                .0
                .checked_add(1)
                .expect("authenticated incrementable nonce");
            body.push(e.raw.to_vec());
        }
        (
            body,
            json!({"nonce_gap":gap,"immature":immature,"funding":funds,"stale":stale,"body_limit":capacity}),
        )
    }

    fn reconcile(&mut self, snapshot: &Snapshot) -> usize {
        let before = self.entries.len();
        self.entries.retain(|(sender, nonce), entry| {
            !snapshot.transactions.contains_key(&entry.id)
                && *nonce >= snapshot.state.account(sender).nonce
        });
        before - self.entries.len()
    }
}

/// One non-cloneable prepared native body, plus an optional original private-channel proposal.
pub struct Pending {
    pub prepared: PreparedAuthenticatedBody,
    pub base: Tip,
    pub ids: Vec<Hash>,
    pub envelope: Option<Vec<u8>>,
    pub held: Value,
}

/// Key stays in this example-only role, never in a profile, canonical state, command or response.
/// Deliberately no Debug/Serialize implementation for the role or its signing material.
pub struct Producer {
    key: SigningKey,
    pool: Pool,
    pub pending: Option<Pending>,
}
impl Producer {
    /// Match full independent binding; the existing signer owns its secret/zeroization behavior.
    pub fn new(key: SigningKey, profile: &Profile) -> Result<Self, String> {
        if key.verifying_key().to_encoded_point(true).as_bytes()
            != profile
                .manifest
                .binding("P")
                .map_err(|_| "missing producer binding")?
                .public_key()
        {
            return Err("private signer does not match independent P binding".into());
        }
        Ok(Self {
            key,
            pool: Pool::default(),
            pending: None,
        })
    }
    /// Admission is local only, even for future nonces/maturity or currently unfunded candidates.
    pub fn submit(
        &mut self,
        encoded: &str,
        profile: &Profile,
        snapshot: &Snapshot,
    ) -> Result<Value, String> {
        self.pool.submit(encoded, profile, snapshot)
    }
    /// Pure, bounded pool view; canonical status remains the original S1 projection.
    pub fn view(&self, offset: u16, limit: u16) -> Result<Value, String> {
        if limit == 0 || limit > 16 {
            return Err("pool page limit must be 1..16".into());
        }
        let rows:Vec<_>=self.pool.entries.values().skip(offset as usize).take(limit as usize).map(|e|
            json!({"id":hex::encode(e.id),"sender":hex::encode(e.unsigned.sender),"nonce":e.unsigned.nonce,
                "valid_after_slot":e.unsigned.valid_after_slot,"value":e.unsigned.value.to_string()})).collect();
        Ok(
            json!({"count":self.pool.entries.len(),"maximum":MAX_POOL,"rows":rows,
            "prepared":self.pending.as_ref().map(|p|json!({"base":tip(p.base),"block_hash":hex::encode(p.prepared.block().hash()),"signed":p.envelope.is_some()}))}),
        )
    }
    /// Exactly one inclusion-time stage; repeated Prepare inspects the owned preparation instead.
    pub fn prepare(
        &mut self,
        store: &AuthenticatedFixtureStore,
        selected_head: Tip,
    ) -> Result<Value, String> {
        let snapshot = store.snapshot().map_err(|e| e.to_string())?;
        if let Some(p) = &self.pending {
            if p.base != snapshot.tip {
                return Err("stale preparation; explicit recovery required".into());
            }
            return Ok(Self::summary(p, "already_prepared"));
        }
        if snapshot.tip != selected_head {
            return Err("selected request unresolved; replay original E before preparing".into());
        }
        if snapshot.tip.revision >= MAX_BLOCKS as u64 {
            return Err("experiment block budget exhausted".into());
        }
        let slot = snapshot.tip.slot.checked_add(1).ok_or("slot overflow")?;
        let (body, held) = self.pool.select(snapshot, slot);
        let prepared = store
            .prepare_next("P", 1, &body)
            .map_err(|e| e.to_string())?;
        let ids = body
            .iter()
            .map(|b| eternix_testnet::block_commitment::hash_with_domain(native::ID_DOMAIN, b))
            .collect();
        self.pending = Some(Pending {
            base: prepared.base_tip(),
            prepared,
            ids,
            envelope: None,
            held,
        });
        Ok(Self::summary(
            self.pending.as_ref().expect("installed preparation"),
            "prepared",
        ))
    }
    fn summary(p: &Pending, outcome: &str) -> Value {
        json!({"outcome":outcome,"new_commit":false,"base":tip(p.base),"block_hash":hex::encode(p.prepared.block().hash()),
            "transaction_ids":p.ids.iter().map(hex::encode).collect::<Vec<_>>(),"held":p.held})
    }
    /// A proposal is private controller input, NEVER committed-block output. Repeats return exact
    /// cached E, not a new signature. Recover/canonical changes explicitly invalidate preparation.
    pub fn propose(
        &mut self,
        store: &AuthenticatedFixtureStore,
        profile: &Profile,
    ) -> Result<Value, String> {
        let p = self
            .pending
            .as_mut()
            .ok_or("prepare explicitly before proposing")?;
        if p.base != store.snapshot().map_err(|e| e.to_string())?.tip {
            return Err("stale preparation".into());
        }
        if p.envelope.is_none() {
            p.envelope = Some(
                sign_block(
                    p.prepared.block(),
                    &self.key,
                    &profile.manifest.context(),
                    profile.manifest.binding("P").map_err(|_| "binding")?,
                )
                .map_err(|e| e.to_string())?
                .wire_bytes(),
            );
        }
        let bytes = p.envelope.as_ref().expect("signed proposal");
        let envelope =
            eternix_testnet::block_authentication::SignedBlockEnvelope::from_wire_bytes(bytes)
                .map_err(|e| e.to_string())?;
        Ok(
            json!({"outcome":"proposal","new_commit":false,"committed":false,"base":tip(p.base),
            "block_hash":hex::encode(envelope.block().hash()),"envelope_id":hex::encode(envelope.envelope_id()),"envelope":hex::encode(bytes)}),
        )
    }
    /// Only a confirmed canonical transition/recovery permits inclusion cleanup/reconciliation.
    pub fn reconcile(&mut self, snapshot: &Snapshot) -> usize {
        self.pending = None;
        self.pool.reconcile(snapshot)
    }
}

/// Load exactly 32 raw bytes from a separate private regular file, never literal CLI key material.
/// The raw read buffer is zeroizing; no error includes file contents or key-derived secret text.
pub fn load_signer(path: &Path, directory: &Path, profile: &Profile) -> Result<Producer, String> {
    let canonical = path
        .canonicalize()
        .map_err(|_| "private key file unavailable")?;
    let data = directory
        .canonicalize()
        .map_err(|_| "data directory must exist")?;
    if canonical.starts_with(data) {
        return Err("private key file must be outside the data directory".into());
    }
    if !canonical.is_file() {
        return Err("private key must be a regular file".into());
    }
    let file = File::open(&canonical).map_err(|_| "private key file unavailable")?;
    let metadata = file.metadata().map_err(|_| "private key metadata")?;
    if !metadata.is_file() {
        return Err("private key must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("private key file must have no group/other permissions".into());
        }
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(33));
    file.take(33)
        .read_to_end(&mut bytes)
        .map_err(|_| "private key read failed")?;
    if bytes.len() != 32 {
        return Err("private signing material must be exactly 32 raw bytes".into());
    }
    let key = SigningKey::from_slice(&bytes).map_err(|_| "invalid private signing material")?;
    Producer::new(key, profile)
}
