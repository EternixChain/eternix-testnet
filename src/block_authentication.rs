//! Experimental offline producer attribution, not eligibility, live acceptance or durable evidence.
//!
//! One signed wire-3 envelope wraps unchanged wire-2/header-2 native content. All policy and producer
//! keys come from the caller. Signature evidence stays outside the historical header hash; an
//! immutable proof cannot authorize a state transition or establish an authenticated SQL archive.

use crate::block_commitment::{hash_with_domain, keccak256, proposer_id};
use crate::native_block::{
    BlockError, EXPERIMENTAL_HEADER_PROFILE, MAX_PROPOSER_BYTES, MAX_WIRE_BYTES, NativeBlock,
};
use crate::native_transaction::{
    self as native, AuthenticationContext, Hash, NativeSignature, SIGNATURE_LEN,
};
use k256::ecdsa::signature::hazmat::RandomizedPrehashSigner;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::rand_core::CryptoRngCore;
use k256::elliptic_curve::rand_core::OsRng;
use rand::{SeedableRng, rngs::StdRng};
use std::fmt;

/// Experimental signed outer framing; not a production numbering assignment.
pub const OUTER_WIRE_VERSION: u8 = 3;
/// The approved exact outer/authentication byte layout.
pub const AUTH_ENCODING_VERSION: u8 = 1;
/// The approved offline ECDSA/domain/profile interpretation, not native transaction rules.
pub const AUTH_RULES_VERSION: u32 = 1;
/// Exclusive block-signing domain, including precisely the displayed zero bytes.
pub const SIGNING_DOMAIN: &[u8; 20] = b"\x19ETERNIX\x00BLOCK_SIGN\x00";
/// Exact signed-envelope identification domain; never a signing digest or parent identity.
pub const ENVELOPE_ID_DOMAIN: &[u8; 27] = b"\x19ETERNIX\x00BLOCK_ENVELOPE_ID\x00";
/// Signed statement: outer/encoding/rules/chain/network/profile/computed header hash.
pub const PAYLOAD_LEN: usize = 82;
/// Fixed domain followed by the complete fixed-width signing statement.
pub const SIGNING_PREIMAGE_LEN: usize = 102;
/// Fixed outer prefix (42) and one signature (65), excluding the nested block.
pub const ENVELOPE_OVERHEAD: usize = 107;
/// Checked bound before any input-derived allocation.
pub const MAX_ENVELOPE_BYTES: usize = MAX_WIRE_BYTES + ENVELOPE_OVERHEAD;

/// Stateless, phase-distinguishable failures; none changes application state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Bounded framing, exact total length or reconstruction failure.
    Frame(&'static str),
    /// An unsigned/native/V1 envelope cannot be treated as a signed outer envelope.
    UnsupportedWire(u8),
    /// No alternative authentication layout is implicitly interpreted.
    UnsupportedEncoding(u8),
    /// No unimplemented authentication meaning is selected from incoming claims.
    UnsupportedRules(u32),
    /// Only the explicitly approved offline header-2 profile is supported.
    UnsupportedProfile(u32),
    /// Caller binding has invalid/reserved/unbounded producer text.
    InvalidProducerId,
    /// Caller binding is not one canonical compressed finite secp256k1 key.
    InvalidPublicKey,
    /// Exact proposer text/commitment does not name the supplied producer binding.
    ProducerMismatch,
    /// Recovered key or signing key differs from the trusted full public key.
    KeyMismatch,
    /// Outer network identity differs from caller policy, including for empty blocks.
    NetworkMismatch,
    /// The unchanged inner codec/preflight rejected this content.
    Block(BlockError),
    /// Existing primitive length/parity/scalar/low-s error, not a transaction sender failure.
    Signature(native::Error),
    /// Invalid/infinite recovery point/key or failed backend prehash verification.
    RecoveryFailed,
    /// External claim is not the exact complete signed-envelope identifier.
    ClaimedEnvelopeIdMismatch,
    /// Vetted signing backend could not produce canonical evidence.
    SigningFailed,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "offline block authentication: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<BlockError> for Error {
    fn from(e: BlockError) -> Self {
        Self::Block(e)
    }
}

/// Explicit trusted network/native/header/auth profile; deliberately has no default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockAuthenticationContext {
    native: AuthenticationContext,
    header_profile: u32,
    auth_rules: u32,
}
impl BlockAuthenticationContext {
    /// Supports precisely header 2/native encoding 2/rules 1/authentication rules 1.
    pub fn new(
        native: AuthenticationContext,
        header_profile: u32,
        auth_rules: u32,
    ) -> Result<Self, Error> {
        if header_profile != EXPERIMENTAL_HEADER_PROFILE {
            return Err(Error::UnsupportedProfile(header_profile));
        }
        if auth_rules != AUTH_RULES_VERSION {
            return Err(Error::UnsupportedRules(auth_rules));
        }
        // AuthenticationContext's private construction establishes implemented native rules 1.
        Ok(Self {
            native,
            header_profile,
            auth_rules,
        })
    }
    /// The caller's already-established chain/genesis/native-rules context.
    pub fn native_context(&self) -> AuthenticationContext {
        self.native
    }
    /// Explicit accepted header discriminator, not production activation.
    pub fn header_profile(&self) -> u32 {
        self.header_profile
    }
    /// Explicit accepted producer-authentication interpretation.
    pub fn auth_rules(&self) -> u32 {
        self.auth_rules
    }
}

/// One immutable caller-trusted exact identity/key association; not a validator registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProducerBinding {
    producer_id: String,
    public_key: [u8; 33],
}
impl ProducerBinding {
    /// Validates spelling bounds and canonical SEC1; never discovers authority from a packet.
    pub fn new(producer_id: &str, compressed_public_key: &[u8]) -> Result<Self, Error> {
        if producer_id.is_empty()
            || producer_id == "protocol"
            || producer_id.len() > MAX_PROPOSER_BYTES
        {
            return Err(Error::InvalidProducerId);
        }
        if compressed_public_key.len() != 33 || !matches!(compressed_public_key[0], 2 | 3) {
            return Err(Error::InvalidPublicKey);
        }
        let key = VerifyingKey::from_sec1_bytes(compressed_public_key)
            .map_err(|_| Error::InvalidPublicKey)?;
        if key.to_encoded_point(true).as_bytes() != compressed_public_key {
            return Err(Error::InvalidPublicKey);
        }
        Ok(Self {
            producer_id: producer_id.to_owned(),
            public_key: compressed_public_key
                .try_into()
                .map_err(|_| Error::InvalidPublicKey)?,
        })
    }
    /// Exact UTF-8 identity, with no normalization or owner/reward-address conversion.
    pub fn producer_id(&self) -> &str {
        &self.producer_id
    }
    /// Full canonical SEC1 key whose authority the caller supplied.
    pub fn public_key(&self) -> &[u8; 33] {
        &self.public_key
    }
    fn matches(&self, block: &NativeBlock) -> Result<(), Error> {
        if block.proposer() != self.producer_id
            || block.header().proposer_id != proposer_id(&self.producer_id)
        {
            return Err(Error::ProducerMismatch);
        }
        Ok(())
    }
}

/// Canonical evidence using the existing parity-only primitive, with a block-specific API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockSignature(NativeSignature);
impl BlockSignature {
    /// Exact length, parity first, scalar bounds then low-s; never normalizes received high-s.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        NativeSignature::from_bytes(bytes)
            .map(Self)
            .map_err(Error::Signature)
    }
    /// Exact r[32] || s[32] || y_parity[1] evidence.
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        self.0.as_bytes()
    }
    fn recover(&self, digest: &Hash) -> Result<VerifyingKey, Error> {
        #[cfg(test)]
        phase_evidence::recovery();
        self.0
            .recover_public_key(digest)
            .map_err(|_| Error::RecoveryFailed)
    }
}

/// Syntax-only signed object. Opaque evidence allows deterministic preflight-before-signature order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedBlockEnvelope {
    network: Hash,
    block: NativeBlock,
    signature: [u8; SIGNATURE_LEN],
}
impl SignedBlockEnvelope {
    /// Constructs an inspection object, not a proof. Signature and preflight checks remain separate.
    pub fn from_parts(
        block: NativeBlock,
        network: Hash,
        signature: [u8; SIGNATURE_LEN],
    ) -> Result<Self, Error> {
        let len = block.wire_bytes().len();
        if !(289..=MAX_WIRE_BYTES).contains(&len) {
            return Err(Error::Frame("inner length"));
        }
        Ok(Self {
            network,
            block,
            signature,
        })
    }
    /// Exact bounded decoding; no signature canonicality/recovery or unsigned fallback here.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(Error::Frame("envelope size"));
        }
        let wire = field::<1>(bytes, 0)?[0];
        if wire != OUTER_WIRE_VERSION {
            return Err(Error::UnsupportedWire(wire));
        }
        let encoding = field::<1>(bytes, 1)?[0];
        if encoding != AUTH_ENCODING_VERSION {
            return Err(Error::UnsupportedEncoding(encoding));
        }
        let rules = u32::from_be_bytes(field(bytes, 2)?);
        if rules != AUTH_RULES_VERSION {
            return Err(Error::UnsupportedRules(rules));
        }
        let network = field(bytes, 6)?;
        let len = usize::try_from(u32::from_be_bytes(field(bytes, 38)?))
            .map_err(|_| Error::Frame("inner width"))?;
        if !(289..=MAX_WIRE_BYTES).contains(&len) {
            return Err(Error::Frame("inner length"));
        }
        let total = len
            .checked_add(ENVELOPE_OVERHEAD)
            .ok_or(Error::Frame("total overflow"))?;
        if total != bytes.len() {
            return Err(Error::Frame("exact envelope length"));
        }
        // The entire declared allocation has been bounded to actual bytes before the inner decoder.
        let block = NativeBlock::from_wire_bytes(&bytes[42..42 + len])?;
        Ok(Self {
            network,
            block,
            signature: field(bytes, 42 + len)?,
        })
    }
    /// Reconstructs exactly one canonical outer frame; claimed inner hashes are not silently repaired.
    pub fn wire_bytes(&self) -> Vec<u8> {
        let inner = self.block.wire_bytes();
        let mut out = Vec::with_capacity(inner.len() + ENVELOPE_OVERHEAD);
        out.extend_from_slice(&[OUTER_WIRE_VERSION, AUTH_ENCODING_VERSION]);
        out.extend_from_slice(&AUTH_RULES_VERSION.to_be_bytes());
        out.extend_from_slice(&self.network);
        out.extend_from_slice(&(inner.len() as u32).to_be_bytes()); // constructor bounds below 2^32
        out.extend_from_slice(&inner);
        out.extend_from_slice(&self.signature);
        out
    }
    /// Read-only inner block, still without user/state/eligibility validation.
    pub fn block(&self) -> &NativeBlock {
        &self.block
    }
    /// Explicit outer network claim, not caller policy.
    pub fn network_id(&self) -> Hash {
        self.network
    }
    /// Opaque received evidence; use BlockSignature/authenticate_block to validate it.
    pub fn signature_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }
    /// Exactly 82 signing bytes. Inspection hashing alone establishes no authentication.
    pub fn signing_payload(&self) -> [u8; PAYLOAD_LEN] {
        let mut out = [0; PAYLOAD_LEN];
        out[0] = OUTER_WIRE_VERSION;
        out[1] = AUTH_ENCODING_VERSION;
        out[2..6].copy_from_slice(&AUTH_RULES_VERSION.to_be_bytes());
        out[6..14].copy_from_slice(&self.block.header().chain_id.to_be_bytes());
        out[14..46].copy_from_slice(&self.network);
        out[46..50].copy_from_slice(&self.block.header().protocol_version.to_be_bytes());
        out[50..82].copy_from_slice(&self.block.hash());
        out
    }
    /// Exact fixed domain plus statement; no text, additional message hash or Ethereum prefix.
    pub fn signing_preimage(&self) -> [u8; SIGNING_PREIMAGE_LEN] {
        let mut out = [0; SIGNING_PREIMAGE_LEN];
        out[..20].copy_from_slice(SIGNING_DOMAIN);
        out[20..].copy_from_slice(&self.signing_payload());
        out
    }
    /// Keccak prehash passed unchanged to ECDSA, distinct from block/envelope identities.
    pub fn signing_digest(&self) -> Hash {
        keccak256(&self.signing_preimage())
    }
    /// Exact signed-packet identifier, never a canonical parent/tip identity or validity assertion.
    pub fn envelope_id(&self) -> Hash {
        hash_with_domain(ENVELOPE_ID_DOMAIN, &self.wire_bytes())
    }
    fn preflight(&self, context: &BlockAuthenticationContext) -> Result<(), Error> {
        if self.network != context.native.network_id() {
            return Err(Error::NetworkMismatch);
        }
        self.block.preflight(&context.native)?;
        Ok(())
    }
}

/// Immutable attribution under caller policy, not eligibility, execution, persistence or a receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedProducerBlock {
    envelope: SignedBlockEnvelope,
    context: BlockAuthenticationContext,
    binding: ProducerBinding,
    signature: BlockSignature,
    digest: Hash,
    envelope_id: Hash,
}
impl AuthenticatedProducerBlock {
    /// Exact immutable content/evidence whose producer attribution was checked.
    pub fn envelope(&self) -> &SignedBlockEnvelope {
        &self.envelope
    }
    /// Original header-derived content identity; never includes the producer signature.
    pub fn block_hash(&self) -> Hash {
        self.envelope.block.hash()
    }
    /// Signature-bearing exact packet identity.
    pub fn envelope_id(&self) -> Hash {
        self.envelope_id
    }
    /// Checked exclusive block prehash.
    pub fn signing_digest(&self) -> Hash {
        self.digest
    }
    /// Canonical producer evidence, independently of native transaction signatures.
    pub fn signature(&self) -> &BlockSignature {
        &self.signature
    }
    /// Exact trusted identity/key that matched the recovered full key.
    pub fn producer_binding(&self) -> &ProducerBinding {
        &self.binding
    }
    /// Trusted context retained for downstream equality checks, not inferred from the packet.
    pub fn context(&self) -> BlockAuthenticationContext {
        self.context
    }
}

/// Cold exact envelope authentication in the approved phase order, with one producer recovery.
pub fn authenticate_block(
    bytes: &[u8],
    context: &BlockAuthenticationContext,
    binding: &ProducerBinding,
    claimed_id: Option<&Hash>,
) -> Result<AuthenticatedProducerBlock, Error> {
    let envelope = SignedBlockEnvelope::from_wire_bytes(bytes)?;
    envelope.preflight(context)?;
    if envelope.wire_bytes() != bytes {
        return Err(Error::Frame("noncanonical reconstruction"));
    }
    binding.matches(&envelope.block)?;
    let signature = BlockSignature::from_bytes(&envelope.signature)?;
    let digest = envelope.signing_digest();
    let envelope_id = hash_with_domain(ENVELOPE_ID_DOMAIN, bytes);
    if claimed_id.is_some_and(|id| *id != envelope_id) {
        return Err(Error::ClaimedEnvelopeIdMismatch);
    }
    let key = signature.recover(&digest)?;
    if key.to_encoded_point(true).as_bytes() != binding.public_key {
        return Err(Error::KeyMismatch);
    }
    Ok(AuthenticatedProducerBlock {
        envelope,
        context: *context,
        binding: binding.clone(),
        signature,
        digest,
        envelope_id,
    })
}

/// Signs only finalized immutable content under the block domain. No signing-intent journal exists.
pub fn sign_block(
    block: &NativeBlock,
    key: &SigningKey,
    context: &BlockAuthenticationContext,
    binding: &ProducerBinding,
) -> Result<SignedBlockEnvelope, Error> {
    let mut envelope = SignedBlockEnvelope::from_parts(
        block.clone(),
        context.native.network_id(),
        [0; SIGNATURE_LEN],
    )?;
    envelope.preflight(context)?;
    binding.matches(block)?;
    if key.verifying_key().to_encoded_point(true).as_bytes() != binding.public_key {
        return Err(Error::KeyMismatch);
    }
    let digest = envelope.signing_digest();
    let signature = sign_with_retry(|retry| {
        if !retry {
            key.sign_prehash_recoverable(&digest)
                .map_err(|_| Error::SigningFailed)
        } else {
            // Only vetted backend secret arithmetic; a fresh entropy-backed nonce replaces overflow.
            fresh_candidate(key, &digest, OsRng)
        }
    })?;
    envelope.signature = *signature.as_bytes();
    Ok(envelope)
}
fn fresh_candidate(
    key: &SigningKey,
    digest: &Hash,
    entropy: impl CryptoRngCore,
) -> Result<(Signature, RecoveryId), Error> {
    // Pinned ecdsa's randomized signer calls infallible rng.fill_bytes. Fallibly seed the existing
    // vetted CSPRNG first: an OS entropy error must be SigningFailed, not panic/deterministic reuse.
    // Secret scalar arithmetic and nonce derivation remain entirely in the vetted ECDSA backend.
    let mut rng = StdRng::from_rng(entropy).map_err(|_| Error::SigningFailed)?;
    let signature: Signature = key
        .sign_prehash_with_rng(&mut rng, digest)
        .map_err(|_| Error::SigningFailed)?;
    let id = RecoveryId::trial_recovery_from_prehash(key.verifying_key(), digest, &signature)
        .map_err(|_| Error::SigningFailed)?;
    Ok((signature, id))
}
fn sign_with_retry(
    mut candidate: impl FnMut(bool) -> Result<(Signature, RecoveryId), Error>,
) -> Result<BlockSignature, Error> {
    let mut retry = false;
    loop {
        let (signature, id) = candidate(retry)?;
        if id.is_x_reduced() {
            retry = true;
            continue;
        } // never mask ID 2/3 to parity
        let mut bytes = [0; SIGNATURE_LEN];
        bytes[..64].copy_from_slice(&signature.to_bytes());
        bytes[64] = id.to_byte();
        return BlockSignature::from_bytes(&bytes);
    }
}
fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], Error> {
    let end = offset
        .checked_add(N)
        .ok_or(Error::Frame("offset overflow"))?;
    bytes
        .get(offset..end)
        .ok_or(Error::Frame("truncation"))?
        .try_into()
        .map_err(|_| Error::Frame("field length"))
}

#[cfg(test)]
pub(crate) mod phase_evidence {
    use std::cell::Cell;
    thread_local! { static RECOVERIES: Cell<usize> = const { Cell::new(0) }; }
    pub(crate) fn recovery() {
        RECOVERIES.set(RECOVERIES.get() + 1);
    }
    pub(crate) fn reset() {
        RECOVERIES.set(0);
    }
    pub(crate) fn count() -> usize {
        RECOVERIES.get()
    }
}
#[cfg(test)]
mod tests;
