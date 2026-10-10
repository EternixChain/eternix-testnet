//! Native V2 canonical bytes and user authentication only.
//!
//! This module never imports the live node, V1 transaction types, or global protocol version. It
//! proves authorization under an explicitly supplied context; it does not check current balances,
//! exact account nonces, slot maturity, block producers, or perform any state transition. Production
//! genesis encoding, final chain ID, activation, and supported FCT semantics remain integration work.

use std::fmt;

use k256::ecdsa::signature::hazmat::RandomizedPrehashSigner;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::rand_core::OsRng;
use sha3::{Digest, Keccak256};

/// Raw Keccak commitment; hexadecimal is a presentation format, never a hash input.
pub type Hash = [u8; 32];
/// Ethereum-compatible account address, encoded as exactly twenty raw bytes.
pub type Address = [u8; 20];
/// Canonical native layout version, separate from both native rules and block-header versions.
pub const ENCODING_VERSION: u8 = 2;
/// The only implemented native authentication/rules revision; this is not live activation.
pub const NATIVE_RULES_VERSION: u32 = 1;
/// Primitive native transfer tag. No other transaction kind is implemented by this module.
pub const TRANSFER_KIND: u8 = 0;
/// The only supported value asset in the initial rules; all fee assets are also ETX.
pub const ETX_TOKEN_ID: u64 = 0;
/// Rules-1 intrinsic and actual gas for a primitive transfer, independent of its declared limit.
pub const INTRINSIC_GAS: u64 = 1000;
/// Rules-1 fixed price; it is not a user field or a fee bid.
pub const GAS_PRICE_QUARKS: u64 = 10;
/// Rules-1 transfer fee to be burned by a future executor, not charged by authentication.
pub const TRANSFER_FEE_QUARKS: u64 = 10_000;
/// Exact unsigned native transfer size. Extra fields or data cannot be silently ignored.
pub const UNSIGNED_LEN: usize = 134;
/// Compact r[32] || s[32] || y_parity[1], with low-s and parity zero or one only.
pub const SIGNATURE_LEN: usize = 65;
/// Exact signed transfer size, including authentication evidence.
pub const SIGNED_LEN: usize = UNSIGNED_LEN + SIGNATURE_LEN;
/// Exclusive native user-signing domain, including the explicitly specified zero bytes.
pub const SIGNING_DOMAIN: &[u8; 24] = b"\x19ETERNIX\x00NATIVE_TX_SIGN\x00";
/// Exclusive signed-object identifier domain, distinct from the authorization digest.
pub const ID_DOMAIN: &[u8; 22] = b"\x19ETERNIX\x00NATIVE_TX_ID\x00";
/// Fixed signing domain followed by the complete unsigned payload.
pub const SIGNING_PREIMAGE_LEN: usize = SIGNING_DOMAIN.len() + UNSIGNED_LEN;

/// Fail-closed codec, profile, and authentication failures. No error mutates node state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The byte layout admits neither truncation nor trailing fields.
    InvalidLength { expected: usize, actual: usize },
    /// A different encoding cannot be interpreted as the native V2 layout.
    UnsupportedEncoding(u8),
    /// Unknown kinds must not inherit transfer semantics.
    UnsupportedKind(u8),
    /// There are no implementations of future native rules to select as a default.
    UnsupportedRules(u32),
    /// Signed native rules disagree with the explicit authentication context.
    RulesMismatch,
    /// The signed transaction targets another chain.
    ChainMismatch,
    /// The signed transaction targets another canonical genesis identity.
    NetworkMismatch,
    /// Rules-1 intrinsic gas is required before any public-key recovery.
    GasBelowIntrinsic(u64),
    /// The declared nonce cannot be incremented in the canonical u64 representation.
    NonceExhausted,
    /// An asset has no implemented native transfer semantics under rules 1.
    UnsupportedToken(u64),
    /// Only a y-parity bit is permitted, never an Ethereum v or x-overflow recovery ID.
    InvalidParity(u8),
    /// Zero and out-of-range ECDSA scalars are invalid.
    InvalidScalar,
    /// Received high-s signatures are rejected, never rewritten into a different transaction ID.
    HighS,
    /// The recovery point or resulting key is invalid, infinite, or fails prehash verification.
    RecoveryFailed,
    /// Recovery or the provided signing key does not authorize the signed sender.
    SenderMismatch,
    /// An optional transport claim differs from the canonical signed transaction ID.
    ClaimedIdMismatch,
    /// The vetted signing backend could not produce a canonical signature.
    SigningFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid native length: expected {expected}, got {actual}"
                )
            }
            Self::UnsupportedEncoding(version) => {
                write!(f, "unsupported native encoding {version}")
            }
            Self::UnsupportedKind(kind) => write!(f, "unsupported native kind {kind}"),
            Self::UnsupportedRules(version) => write!(f, "unsupported native rules {version}"),
            Self::RulesMismatch => f.write_str("native rules context mismatch"),
            Self::ChainMismatch => f.write_str("native chain context mismatch"),
            Self::NetworkMismatch => f.write_str("native genesis identity mismatch"),
            Self::GasBelowIntrinsic(gas) => {
                write!(f, "native gas limit {gas} is below intrinsic gas")
            }
            Self::NonceExhausted => f.write_str("native nonce cannot be incremented"),
            Self::UnsupportedToken(token) => write!(f, "unsupported native transfer token {token}"),
            Self::InvalidParity(parity) => write!(f, "invalid native y parity {parity}"),
            Self::InvalidScalar => f.write_str("invalid native ECDSA scalar"),
            Self::HighS => f.write_str("noncanonical high-s native signature"),
            Self::RecoveryFailed => f.write_str("native public-key recovery failed"),
            Self::SenderMismatch => f.write_str("native signer does not match signed sender"),
            Self::ClaimedIdMismatch => f.write_str("claimed native transaction ID mismatch"),
            Self::SigningFailed => f.write_str("native signing backend failed"),
        }
    }
}

impl std::error::Error for Error {}

/// Explicit native validation context with no chain, genesis, or activation defaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticationContext {
    chain_id: u64,
    network_id: Hash,
    native_rules_version: u32,
}

impl AuthenticationContext {
    /// Explicit chain identity for fixture storage metadata; never a production default.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Caller-approved canonical-genesis identity, preserved unchanged by fixture storage.
    pub fn network_id(&self) -> Hash {
        self.network_id
    }

    /// Native rules identity, independent of local storage schema versions.
    pub fn native_rules_version(&self) -> u32 {
        self.native_rules_version
    }

    /// Uses a genesis identity already verified by the caller, without loading or defining genesis.
    pub fn new(chain_id: u64, network_id: Hash, native_rules_version: u32) -> Result<Self, Error> {
        if native_rules_version != NATIVE_RULES_VERSION {
            return Err(Error::UnsupportedRules(native_rules_version));
        }
        Ok(Self {
            chain_id,
            network_id,
            native_rules_version,
        })
    }
}

/// Hashes an already-canonical genesis preimage supplied by the caller.
///
/// This does not specify or validate a genesis schema. A future genesis codec must establish that
/// these bytes are canonical and exclude their own computed hash; no placeholder is substituted.
pub fn network_id_from_genesis_bytes(canonical_genesis_bytes: &[u8]) -> Hash {
    keccak(canonical_genesis_bytes)
}

/// Complete authenticated user-controlled transfer payload; no fee or execution wrapper exists.
///
/// Codec methods validate the layout, not stateful includability. For example, the approved
/// cryptographically valid gas-999 negative vector can still be encoded and hashed for inspection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedTransaction {
    /// Canonical byte-layout version, currently exactly two.
    pub encoding_version: u8,
    /// Native authentication, fee, and execution revision, not the global block protocol version.
    pub native_rules_version: u32,
    /// Explicit unsigned 64-bit chain identifier.
    pub chain_id: u64,
    /// Keccak of the final canonical genesis bytes, supplied explicitly.
    pub network_id: Hash,
    /// Explicit transaction tag, currently primitive transfer only.
    pub kind: u8,
    /// Intended authorizing account; recovered key must produce this exact address.
    pub sender: Address,
    /// Canonical account nonce to be checked against staged state by a future executor.
    pub nonce: u64,
    /// Transfer destination as raw address bytes.
    pub recipient: Address,
    /// Value asset identifier; initial authentication profile permits ETX only.
    pub token_id: u64,
    /// Value in the asset's base units, without floating-point or display conversion.
    pub value: u128,
    /// User-authorized gas bound; larger values do not raise the rules-1 transfer fee.
    pub gas_limit: u64,
    /// Earliest inclusion slot; authentication does not evaluate local time or current slot.
    pub valid_after_slot: u64,
}

impl UnsignedTransaction {
    fn validate_layout(&self) -> Result<(), Error> {
        if self.encoding_version != ENCODING_VERSION {
            return Err(Error::UnsupportedEncoding(self.encoding_version));
        }
        if self.kind != TRANSFER_KIND {
            return Err(Error::UnsupportedKind(self.kind));
        }
        Ok(())
    }

    fn validate_profile(&self, context: &AuthenticationContext) -> Result<(), Error> {
        self.validate_layout()?;
        if self.native_rules_version != context.native_rules_version {
            return Err(Error::RulesMismatch);
        }
        if self.chain_id != context.chain_id {
            return Err(Error::ChainMismatch);
        }
        if self.network_id != context.network_id {
            return Err(Error::NetworkMismatch);
        }
        if self.gas_limit < INTRINSIC_GAS {
            return Err(Error::GasBelowIntrinsic(self.gas_limit));
        }
        if self.nonce == u64::MAX {
            return Err(Error::NonceExhausted);
        }
        if self.token_id != ETX_TOKEN_ID {
            return Err(Error::UnsupportedToken(self.token_id));
        }
        Ok(())
    }

    /// Encodes the exact V2 field order, widths, and big-endian integer bytes.
    pub fn canonical_bytes(&self) -> Result<[u8; UNSIGNED_LEN], Error> {
        self.validate_layout()?;
        // Fixed slices are deliberate: no serializer defaults, variable lengths, or omitted zeros.
        let mut bytes = [0; UNSIGNED_LEN];
        bytes[0] = self.encoding_version;
        bytes[1..5].copy_from_slice(&self.native_rules_version.to_be_bytes());
        bytes[5..13].copy_from_slice(&self.chain_id.to_be_bytes());
        bytes[13..45].copy_from_slice(&self.network_id);
        bytes[45] = self.kind;
        bytes[46..66].copy_from_slice(&self.sender);
        bytes[66..74].copy_from_slice(&self.nonce.to_be_bytes());
        bytes[74..94].copy_from_slice(&self.recipient);
        bytes[94..102].copy_from_slice(&self.token_id.to_be_bytes());
        bytes[102..118].copy_from_slice(&self.value.to_be_bytes());
        bytes[118..126].copy_from_slice(&self.gas_limit.to_be_bytes());
        bytes[126..134].copy_from_slice(&self.valid_after_slot.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes exactly 134 bytes; it never accepts a prefix or silently ignores trailing fields.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, Error> {
        require_length(bytes, UNSIGNED_LEN)?;
        let transaction = Self {
            encoding_version: bytes[0],
            native_rules_version: u32::from_be_bytes(field(bytes, 1)),
            chain_id: u64::from_be_bytes(field(bytes, 5)),
            network_id: field(bytes, 13),
            kind: bytes[45],
            sender: field(bytes, 46),
            nonce: u64::from_be_bytes(field(bytes, 66)),
            recipient: field(bytes, 74),
            token_id: u64::from_be_bytes(field(bytes, 94)),
            value: u128::from_be_bytes(field(bytes, 102)),
            gas_limit: u64::from_be_bytes(field(bytes, 118)),
            valid_after_slot: u64::from_be_bytes(field(bytes, 126)),
        };
        transaction.validate_layout()?;
        Ok(transaction)
    }

    /// Fixed native domain followed by all unsigned bytes, never a textual representation.
    pub fn signing_preimage(&self) -> Result<[u8; SIGNING_PREIMAGE_LEN], Error> {
        let mut bytes = [0; SIGNING_PREIMAGE_LEN];
        bytes[..SIGNING_DOMAIN.len()].copy_from_slice(SIGNING_DOMAIN);
        bytes[SIGNING_DOMAIN.len()..].copy_from_slice(&self.canonical_bytes()?);
        Ok(bytes)
    }

    /// Keccak prehash passed directly to ECDSA, without a second hash or Ethereum prefix.
    pub fn signing_digest(&self) -> Result<Hash, Error> {
        Ok(keccak(&self.signing_preimage()?))
    }
}

/// Canonical compact signature. Private bytes prevent construction bypassing scalar/parity checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeSignature([u8; SIGNATURE_LEN]);

impl NativeSignature {
    /// Rejects noncompact encodings, zero/out-of-range scalars, high-s, and all non-parity IDs.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        require_length(bytes, SIGNATURE_LEN)?;
        if bytes[64] > 1 {
            return Err(Error::InvalidParity(bytes[64]));
        }
        let signature = Signature::from_slice(&bytes[..64]).map_err(|_| Error::InvalidScalar)?;
        if signature.normalize_s().is_some() {
            return Err(Error::HighS);
        }
        Ok(Self(field(bytes, 0)))
    }

    /// Exact canonical r || s || y_parity evidence, not hex text or DER.
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }

    /// Recovers and verifies a key using the vetted backend's exact prehash API.
    pub fn recover_public_key(&self, digest: &Hash) -> Result<VerifyingKey, Error> {
        let signature = Signature::from_slice(&self.0[..64]).map_err(|_| Error::InvalidScalar)?;
        let recovery_id =
            RecoveryId::from_byte(self.0[64]).ok_or(Error::InvalidParity(self.0[64]))?;
        // Constructor restricts the ID to 0/1, so k256 cannot select x=r+n. Its recovery routine
        // rejects invalid/infinite points and verifies ECDSA. Secp256k1 has cofactor one, hence
        // every valid finite curve point is in the required prime-order subgroup.
        VerifyingKey::recover_from_prehash(digest, &signature, recovery_id)
            .map_err(|_| Error::RecoveryFailed)
    }
}

/// Signed native object without any claim that it is authenticated or executable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedTransaction {
    unsigned: UnsignedTransaction,
    signature: NativeSignature,
}

impl SignedTransaction {
    /// Combines layout-valid payload and canonical evidence; context authentication is separate.
    pub fn from_parts(
        unsigned: UnsignedTransaction,
        signature: NativeSignature,
    ) -> Result<Self, Error> {
        unsigned.validate_layout()?;
        Ok(Self {
            unsigned,
            signature,
        })
    }

    /// Returns the payload immutably so evidence cannot be silently mutated in place.
    pub fn unsigned(&self) -> &UnsignedTransaction {
        &self.unsigned
    }

    /// Returns the already-canonical authentication evidence.
    pub fn signature(&self) -> &NativeSignature {
        &self.signature
    }

    /// Encodes exactly U[134] || r[32] || s[32] || y_parity[1].
    pub fn canonical_bytes(&self) -> Result<[u8; SIGNED_LEN], Error> {
        let mut bytes = [0; SIGNED_LEN];
        bytes[..UNSIGNED_LEN].copy_from_slice(&self.unsigned.canonical_bytes()?);
        bytes[UNSIGNED_LEN..].copy_from_slice(self.signature.as_bytes());
        Ok(bytes)
    }

    /// Exact decoding, including canonical signature checks; no V1/raw-Ethereum fallback exists.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, Error> {
        require_length(bytes, SIGNED_LEN)?;
        Self::from_parts(
            UnsignedTransaction::from_canonical_bytes(&bytes[..UNSIGNED_LEN])?,
            NativeSignature::from_bytes(&bytes[UNSIGNED_LEN..])?,
        )
    }

    /// Commits exact signed bytes under the ID domain, distinct from the signing digest.
    pub fn transaction_id(&self) -> Result<Hash, Error> {
        let mut hasher = Keccak256::new();
        hasher.update(ID_DOMAIN);
        hasher.update(self.canonical_bytes()?);
        Ok(hasher.finalize().into())
    }
}

/// Immutable authorization proof only, not a receipt or assertion of stateful includability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedTransaction {
    transaction: SignedTransaction,
    transaction_id: Hash,
    signing_digest: Hash,
    public_key: [u8; 65],
}

impl AuthenticatedTransaction {
    /// The exact object whose identity was checked.
    pub fn transaction(&self) -> &SignedTransaction {
        &self.transaction
    }

    /// Content-derived ID of the complete canonical signed object.
    pub fn transaction_id(&self) -> Hash {
        self.transaction_id
    }

    /// Authorization prehash, intentionally separate from the signed-object ID.
    pub fn signing_digest(&self) -> Hash {
        self.signing_digest
    }

    /// Recovered SEC1 uncompressed key for diagnostics or downstream identity checks.
    pub fn public_key(&self) -> &[u8; 65] {
        &self.public_key
    }
}

/// Derives the existing account identity from uncompressed x || y, excluding the SEC1 0x04 byte.
pub fn address_from_public_key(key: &VerifyingKey) -> Address {
    let point = key.to_encoded_point(false);
    let hash = keccak(&point.as_bytes()[1..]);
    field(&hash, 12)
}

/// Authenticates a cold canonical object under explicit chain/genesis/native-rules context.
///
/// All layout/profile/claimed-ID failures occur before recovery. This function has no cache, node
/// state, global chain defaults, wall-clock input, or admission/execution side effects.
pub fn authenticate(
    bytes: &[u8],
    context: &AuthenticationContext,
    claimed_id: Option<&Hash>,
) -> Result<AuthenticatedTransaction, Error> {
    let transaction = SignedTransaction::from_canonical_bytes(bytes)?;
    transaction.unsigned.validate_profile(context)?;
    let transaction_id = transaction.transaction_id()?;
    if claimed_id.is_some_and(|claimed| *claimed != transaction_id) {
        return Err(Error::ClaimedIdMismatch);
    }
    let signing_digest = transaction.unsigned.signing_digest()?;
    let key = transaction.signature.recover_public_key(&signing_digest)?;
    if address_from_public_key(&key) != transaction.unsigned.sender {
        return Err(Error::SenderMismatch);
    }
    let public_key = field(key.to_encoded_point(false).as_bytes(), 0);
    Ok(AuthenticatedTransaction {
        transaction,
        transaction_id,
        signing_digest,
        public_key,
    })
}

/// Signs only this native payload/domain using k256, after context and sender-key checks.
///
/// The ordinary path is deterministic RFC6979, matching the approved vectors. A rare x-overflow
/// candidate retries with fresh OS-generated additional entropy through k256's high-level
/// randomized prehash API; the overflow bit is never discarded or encoded as native parity.
pub fn sign(
    unsigned: UnsignedTransaction,
    key: &SigningKey,
    context: &AuthenticationContext,
) -> Result<SignedTransaction, Error> {
    unsigned.validate_profile(context)?;
    if address_from_public_key(key.verifying_key()) != unsigned.sender {
        return Err(Error::SenderMismatch);
    }
    let digest = unsigned.signing_digest()?;
    let signature = sign_with_retry(|retry| {
        if !retry {
            key.sign_prehash_recoverable(&digest)
                .map_err(|_| Error::SigningFailed)
        } else {
            let signature: Signature = key
                .sign_prehash_with_rng(&mut OsRng, &digest)
                .map_err(|_| Error::SigningFailed)?;
            let id =
                RecoveryId::trial_recovery_from_prehash(key.verifying_key(), &digest, &signature)
                    .map_err(|_| Error::SigningFailed)?;
            Ok((signature, id))
        }
    })?;
    SignedTransaction::from_parts(unsigned, signature)
}

fn sign_with_retry(
    mut candidate: impl FnMut(bool) -> Result<(Signature, RecoveryId), Error>,
) -> Result<NativeSignature, Error> {
    let mut retry = false;
    loop {
        let (signature, id) = candidate(retry)?;
        if id.is_x_reduced() {
            // The next backend call must generate a different nonce, not reproduce the same
            // deterministic rejected candidate or mask ID 2/3 down to its low bit.
            retry = true;
            continue;
        }
        let mut bytes = [0; SIGNATURE_LEN];
        bytes[..64].copy_from_slice(&signature.to_bytes());
        bytes[64] = id.to_byte();
        return NativeSignature::from_bytes(&bytes);
    }
}

fn keccak(bytes: &[u8]) -> Hash {
    Keccak256::digest(bytes).into()
}

fn require_length(bytes: &[u8], expected: usize) -> Result<(), Error> {
    if bytes.len() != expected {
        return Err(Error::InvalidLength {
            expected,
            actual: bytes.len(),
        });
    }
    Ok(())
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    // Only fixed protocol offsets after exact length validation, or backend fixed-size outputs,
    // reach this helper. Neither N nor offset is taken from an untrusted length prefix.
    bytes[offset..offset + N]
        .try_into()
        .expect("validated fixed field bounds")
}

#[cfg(test)]
mod tests;
