//! Explicit trusted-history boundary. Linked headers and snapshot associations are checked here;
//! validating how each supplied state arose requires the later application/audit engine.
use super::*;
use crate::block_commitment::{BlockHeader, BlockKind, hash_with_domain};
use std::sync::Arc;

/// Exact historical header data, not a peer-advertised bare hash or an authenticated body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalHeader {
    header: BlockHeader,
    hash: Hash,
}
impl HistoricalHeader {
    /// Recompute H and compare its supplied claim; profile/chain/kind/range are checked before a
    /// header may participate in any prefix. The trusted genesis anchor is matched exactly later.
    pub fn new(header: BlockHeader, claimed_hash: Hash) -> Result<Self, Error> {
        if header.protocol_version != HEADER_PROFILE
            || header.chain_id != CHAIN_ID
            || header.block_kind != BlockKind::Validator
        {
            return Err(Error::Profile("historical header"));
        }
        if header.slot > MAX_SLOTS {
            return Err(Error::ExperimentLimit);
        }
        if header.hash() != claimed_hash {
            return Err(Error::Context("historical claimed H"));
        }
        Ok(Self {
            header,
            hash: claimed_hash,
        })
    }
    /// Immutable canonical header; cloning it gives no permission to mutate this entry.
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }
    /// Checked computed H, never a signed-envelope ID.
    pub fn hash(&self) -> Hash {
        self.hash
    }
}

/// Complete bounded linked prefix and exact independently supplied post-parent snapshot.
///
/// `from_trusted_history` is an authority boundary: caller must obtain these inputs independently
/// from trusted initialization/audited history, NOT a candidate/handshake. It validates linkage,
/// metadata and state invariants, not historical signatures/body execution/finality/reachability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrefixContext {
    pub(super) genesis: Genesis,
    pub(super) headers: Vec<HistoricalHeader>,
    pub(super) state: ClosedState,
    id: Hash,
}
impl PrefixContext {
    /// Require every header0..parent, exact genesis anchor and post-state association; no sparse
    /// window, source height or missing row can silently become genesis/zero/NoEligibleTickets.
    pub fn from_trusted_history(
        genesis: &Genesis,
        headers: Vec<HistoricalHeader>,
        state: ClosedState,
    ) -> Result<Self, Error> {
        if headers.len() > MAX_SLOTS as usize + 1 {
            return Err(Error::ExperimentLimit);
        }
        if state.policy != genesis.policy {
            return Err(Error::Context("snapshot genesis"));
        }
        let parent = state.position();
        let mut counts = [0u64; 2];
        let mut gas = 0u64;
        let mut fees = 0u128;
        for slot in 0..=parent.slot {
            let h = headers
                .get(slot as usize)
                .ok_or(Error::MissingHistory(slot))?;
            if h.header.slot != slot {
                return Err(Error::MissingHistory(slot));
            }
            if slot == 0 {
                if h.header != *genesis.anchor() {
                    return Err(Error::Context("independent anchor"));
                }
            } else {
                let prev = &headers[(slot - 1) as usize];
                if h.header.parent_hash != prev.hash {
                    return Err(Error::Context("historical parent link"));
                }
                let i = genesis
                    .policy
                    .configs
                    .iter()
                    .position(|v| {
                        crate::block_commitment::proposer_id(&v.id) == h.header.proposer_id
                    })
                    .ok_or(Error::UnknownProducer)?;
                let count = h.header.gas_used / 1000;
                if !genesis
                    .policy
                    .tickets
                    .iter()
                    .any(|t| t.id == h.header.ticket_id && t.owner == genesis.policy.configs[i].id)
                {
                    return Err(Error::Context("historical closed ticket association"));
                }
                // This checks a canonical C1 header claim, NOT the opaque historical body.
                HeaderClaim::new(
                    h.header.clone(),
                    genesis.policy.configs[i].id.clone(),
                    u16::try_from(count).map_err(|_| Error::Overflow)?,
                )?;
                counts[i] += 1;
                gas = gas.checked_add(h.header.gas_used).ok_or(Error::Overflow)?;
                fees = fees
                    .checked_add(count as u128 * 10000)
                    .ok_or(Error::Overflow)?;
                let credit = &state.data.credits[(slot - 1) as usize];
                if credit.slot != slot || credit.validator != genesis.policy.configs[i].id {
                    return Err(Error::Context("earning event/header"));
                }
            }
        }
        if headers.len() != parent.slot as usize + 1 {
            return Err(Error::Context("extra historical headers"));
        }
        if headers.last().map(|h| h.hash) != Some(parent.hash) {
            return Err(Error::Context("post-parent position"));
        }
        if parent.slot == 0 && state != *genesis.initial_state() {
            return Err(Error::Context("initial snapshot differs"));
        }
        if gas != state.data.gas_used
            || fees != state.data.fees_burned
            || counts
                .iter()
                .zip(&state.data.validators)
                .any(|(n, v)| *n != v.produced)
        {
            return Err(Error::Context("prefix/snapshot accounting"));
        }
        let mut bytes = Vec::from(genesis.network_id());
        bytes.extend_from_slice(&(headers.len() as u16).to_be_bytes());
        for h in &headers {
            bytes.extend_from_slice(&h.header.canonical_bytes());
        }
        let id = hash_with_domain(b"ETERNIX_POASH_C1_PREFIX\0", &bytes);
        Ok(Self {
            genesis: genesis.clone(),
            headers,
            state,
            id,
        })
    }
    /// Checked genesis-only context; no fabricated produced genesis block or reward.
    pub fn initial(genesis: &Genesis) -> Result<Self, Error> {
        Self::from_trusted_history(
            genesis,
            vec![HistoricalHeader::new(
                genesis.anchor().clone(),
                genesis.anchor().hash(),
            )?],
            genesis.initial_state().clone(),
        )
    }
    /// Exact linked-header identity; it is not an execution/finality certificate.
    pub fn id(&self) -> Hash {
        self.id
    }
    /// Immutable complete state after the parent, with its own exact comparison identity.
    pub fn state(&self) -> &ClosedState {
        &self.state
    }
    /// Explicit lookup failure instead of a default hash.
    pub fn historical_hash(&self, slot: u64) -> Result<Hash, Error> {
        self.headers
            .get(usize::try_from(slot).map_err(|_| Error::Overflow)?)
            .filter(|h| h.header.slot == slot)
            .map(|h| h.hash)
            .ok_or(Error::MissingHistory(slot))
    }
    /// Capture complete post-parent Start(s) and the DISTINCT randomness reference before selection.
    pub fn slot_start(&self) -> Result<SlotStartView, Error> {
        let slot = self
            .state
            .position()
            .slot
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        if slot > MAX_SLOTS {
            return Err(Error::ExperimentLimit);
        }
        let reference = if slot < LOOKBACK {
            self.genesis.network_id()
        } else {
            self.historical_hash(slot - LOOKBACK)?
        };
        let mut bytes = Vec::from(self.genesis.network_id());
        bytes.extend_from_slice(&self.id);
        bytes.extend_from_slice(&self.state.id());
        bytes.extend_from_slice(&slot.to_be_bytes());
        bytes.extend_from_slice(&self.state.position().hash);
        bytes.extend_from_slice(&reference);
        let id = hash_with_domain(b"ETERNIX_POASH_C1_SLOT_START\0", &bytes);
        Ok(SlotStartView {
            prefix: Arc::new(self.clone()),
            slot,
            reference,
            id,
        })
    }
}

/// Frozen view of the exact historical prefix/state/parent used for one next-slot plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlotStartView {
    pub(super) prefix: Arc<PrefixContext>,
    pub(super) slot: u64,
    pub(super) reference: Hash,
    id: Hash,
}
impl SlotStartView {
    /// Exact view identity includes complete state, linked prefix, N, slot, parent and reference.
    pub fn id(&self) -> Hash {
        self.id
    }
    /// Immutable complete supported Start(s), not state at s−32.
    pub fn state(&self) -> &ClosedState {
        &self.prefix.state
    }
    /// Exact post-parent position to which a proposal must bind.
    pub fn parent(&self) -> Position {
        self.prefix.state.position()
    }
    /// Independent new-genesis context, not a received network declaration.
    pub fn genesis(&self) -> &Genesis {
        &self.prefix.genesis
    }
    /// Planned next slot; no wall-clock scheduling or skipping is implied.
    pub fn slot(&self) -> u64 {
        self.slot
    }
    /// Startup N or already-required checked ancestor H.
    pub fn reference(&self) -> Hash {
        self.reference
    }
    /// Pure approved selector over this exact historical state; no mutation or body execution.
    pub fn select(&self) -> Result<Selection, Error> {
        selection::select_inputs(
            self.reference,
            self.slot,
            &self.state().data.validators,
            &self.state().data.tickets,
        )
    }
}
