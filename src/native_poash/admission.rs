//! C1 header attribution and eligibility planning only. No full block codec/body validity or writer.
use super::*;
use crate::block_commitment::{
    BlockHeader, BlockKind, EMPTY_RECEIPTS_ROOT, EMPTY_TX_ROOT, ProtocolData, keccak256,
    proposer_id,
};
use crate::native_transaction::{NativeSignature, SIGNATURE_LEN};

/// Immutable C1 header claim plus its bounded body-count metadata. Actual body bytes, native
/// signatures/outcomes and economic effects still require P2.2; this is not an executable block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderClaim {
    header: BlockHeader,
    producer: String,
    count: u16,
}
impl HeaderClaim {
    /// Check only the explicit C1 profile and header/count commitments. For populated claims the
    /// transaction root remains opaque until a later body-validity implementation.
    pub fn new(header: BlockHeader, producer: String, count: u16) -> Result<Self, Error> {
        if header.protocol_version != HEADER_PROFILE
            || header.chain_id != CHAIN_ID
            || header.block_kind != BlockKind::Validator
        {
            return Err(Error::Profile("C1 header interpretation"));
        }
        if !(1..=MAX_SLOTS).contains(&header.slot) || count as u64 > MAX_ENTRIES {
            return Err(Error::ExperimentLimit);
        }
        if !matches!(producer.as_str(), "trial-A" | "trial-B")
            || header.proposer_id != proposer_id(&producer)
        {
            return Err(Error::UnknownProducer);
        }
        if header.ticket_id == 0
            || header.state_root != [0; 32]
            || header.receipts_root != *EMPTY_RECEIPTS_ROOT
        {
            return Err(Error::Profile("C1 ticket/reserved roots"));
        }
        if header.gas_used != count as u64 * 1000
            || header.protocol_data_root
                != (ProtocolData {
                    missed_proposer: None,
                    fees_burned: count as u64 * 10000,
                })
                .root()
        {
            return Err(Error::Profile("C1 gas/fee claim"));
        }
        if count == 0 && header.transaction_root != *EMPTY_TX_ROOT {
            return Err(Error::Profile("empty transaction root"));
        }
        Ok(Self {
            header,
            producer,
            count,
        })
    }
    /// Exact canonical 229-byte content header, immutable after construction.
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }
    /// Header-derived H, independent of producer signature bytes.
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }
    /// Exact registry ID, never an incoming key declaration.
    pub fn producer(&self) -> &str {
        &self.producer
    }
    /// Claimed body count; not proof that a body was supplied or executed.
    pub fn transaction_count(&self) -> u16 {
        self.count
    }
    /// Read-only signing bytes under the distinct C1 outer4/auth1/rules2/profile3 mapping. This hash helper
    /// neither signs nor supplies a complete outer-wire4 block parser.
    pub fn signing_preimage(&self, network: Hash) -> [u8; 102] {
        let mut p = [0; 102];
        p[..20].copy_from_slice(crate::block_authentication::SIGNING_DOMAIN);
        p[20] = OUTER_WIRE;
        p[21] = AUTH_ENCODING;
        p[22..26].copy_from_slice(&AUTH_RULES.to_be_bytes());
        p[26..34].copy_from_slice(&self.header.chain_id.to_be_bytes());
        p[34..66].copy_from_slice(&network);
        p[66..70].copy_from_slice(&self.header.protocol_version.to_be_bytes());
        p[70..].copy_from_slice(&self.hash());
        p
    }
    /// Pure Keccak block prehash, not the native transaction domain or an envelope ID.
    pub fn signing_digest(&self, network: Hash) -> Hash {
        keccak256(&self.signing_preimage(network))
    }
    /// Independently authenticate a known producer, EVEN IF it will later be found non-selected.
    /// Network/full-key authority comes from genesis; recovery success alone is not authority.
    pub fn authenticate(
        &self,
        genesis: &Genesis,
        network_claim: Hash,
        bytes: &[u8],
    ) -> Result<AuthenticatedHeader, Error> {
        if network_claim != genesis.network_id() {
            return Err(Error::Context("candidate network"));
        }
        let binding = genesis
            .validators()
            .iter()
            .find(|v| v.id == self.producer)
            .ok_or(Error::UnknownProducer)?;
        let signature = NativeSignature::from_bytes(bytes).map_err(Error::Signature)?;
        let digest = self.signing_digest(genesis.network_id());
        let key = signature
            .recover_public_key(&digest)
            .map_err(Error::Signature)?;
        if key.to_encoded_point(true).as_bytes() != binding.public_key {
            return Err(Error::KeyMismatch);
        }
        Ok(AuthenticatedHeader {
            claim: self.clone(),
            network: genesis.network_id(),
            signature,
            digest,
            key: binding.public_key,
        })
    }
}

/// Private proof construction establishes ONLY full-key attribution under the new C1 header
/// mapping. Correctly authenticated non-selected producers must still fail the planning step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedHeader {
    claim: HeaderClaim,
    network: Hash,
    signature: NativeSignature,
    digest: Hash,
    key: [u8; 33],
}
impl AuthenticatedHeader {
    /// Exact immutable header/count claim; not an authenticated/executed body.
    pub fn claim(&self) -> &HeaderClaim {
        &self.claim
    }
    /// Independently matched compressed SEC1 key.
    pub fn public_key(&self) -> &[u8; 33] {
        &self.key
    }
    /// Exact checked prehash, useful for independent interoperability vectors.
    pub fn signing_digest(&self) -> Hash {
        self.digest
    }
    /// Original canonical r||s||parity bytes, not a new commitment receipt.
    pub fn signature_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        self.signature.as_bytes()
    }
}

/// Privately constructed read-only eligibility plan bound to a COMPLETE historical view and exact
/// attributed header. There is no owner generation, execution seal, SQL capability or fixture grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionPlan {
    view: SlotStartView,
    proof: AuthenticatedHeader,
    selection: Selection,
}
impl SlotStartView {
    /// Reject wrong context/parent/slot before returning the selection plan. Incoming fields only
    /// compare to the captured independent state and cannot manufacture eligible ticket inputs.
    pub fn plan(&self, proof: &AuthenticatedHeader) -> Result<AdmissionPlan, Error> {
        if proof.network != self.genesis().network_id() {
            return Err(Error::Context("proof genesis"));
        }
        let h = proof.claim.header();
        if h.slot != self.slot || h.parent_hash != self.parent().hash {
            return Err(Error::Context("planned slot/parent"));
        }
        let selection = self.select()?;
        if proof.claim.producer != selection.producer() || h.ticket_id != selection.ticket_id() {
            return Err(Error::NotSelected);
        }
        Ok(AdmissionPlan {
            view: self.clone(),
            proof: proof.clone(),
            selection,
        })
    }
}
impl AdmissionPlan {
    /// Exact historical state/prefix binding; no state mirror is installed.
    pub fn view(&self) -> &SlotStartView {
        &self.view
    }
    /// Attribution and exact submitted evidence captured by this plan.
    pub fn proof(&self) -> &AuthenticatedHeader {
        &self.proof
    }
    /// Selection derived from the independent historical state, not the candidate.
    pub fn selection(&self) -> &Selection {
        &self.selection
    }
    /// A plan cannot be reused for another state, parent, history, network or signed header. A
    /// separately authenticated alternative signature can obtain its own plan, not replace evidence.
    pub fn check(&self, view: &SlotStartView, proof: &AuthenticatedHeader) -> Result<(), Error> {
        if self.view.id() != view.id() || self.proof != *proof {
            return Err(Error::PlanMismatch);
        }
        Ok(())
    }
}
