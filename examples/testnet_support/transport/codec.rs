//! Frozen S3 fixture framing, independent of existing signed E, hashes and canonical serialization.
use super::super::profile::{MAX_BLOCKS, MAX_PACKET_BYTES, Profile};
use eternix_testnet::canonical_fixture::Tip;
use eternix_testnet::native_transaction::Hash;

/// Fixed bytes are read before any length-derived buffer allocation. Integers are unsigned BE.
pub const HEADER_BYTES: usize = 144;
pub const MAX_BODY_BYTES: usize = 12 + MAX_PACKET_BYTES;
pub const MAX_FRAME_BYTES: usize = HEADER_BYTES + MAX_BODY_BYTES;
pub const MAGIC: &[u8; 4] = b"ETX3";
pub const VERSION: u8 = 1;

/// Transport context is independent operator policy, never incoming handshake/key authority.
#[derive(Clone)]
pub struct Context {
    pub node: u16,
    run_len: u8,
    run: [u8; 64],
    network: Hash,
    anchor: Hash,
}
impl Context {
    pub fn new(node: u16, profile: &Profile) -> Self {
        let mut run = [0; 64];
        run[..profile.run_id.len()].copy_from_slice(profile.run_id.as_bytes());
        Self {
            node,
            run_len: profile.run_id.len() as u8,
            run,
            network: profile.network,
            anchor: profile.anchor_tip().hash,
        }
    }
}
/// Four exact wire type values; no block/approval/retrieval fallback or optional fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Kind {
    Status = 1,
    Committed = 2,
    Reference = 3,
    Error = 4,
}
impl Kind {
    fn parse(n: u8) -> Result<Self, String> {
        match n {
            1 => Ok(Self::Status),
            2 => Ok(Self::Committed),
            3 => Ok(Self::Reference),
            4 => Ok(Self::Error),
            _ => Err("unknown peer frame type".into()),
        }
    }
    fn length(self, n: usize) -> bool {
        match self {
            Self::Status => n == 48,
            Self::Committed => (408..=MAX_BODY_BYTES).contains(&n),
            Self::Reference => n == 112,
            Self::Error => n == 48,
        }
    }
}
#[derive(Clone, Copy)]
pub struct Header {
    pub kind: Kind,
    pub sender: u16,
    pub length: usize,
}

/// Early magic/version/type/size rejection also bounds partial legacy text senders.
pub fn prefix(raw: &[u8]) -> Result<(), String> {
    if raw.len() >= 4 && &raw[..4] != MAGIC {
        return Err("wrong peer magic".into());
    }
    if raw.len() >= 5 && raw[4] != VERSION {
        return Err("wrong peer codec version".into());
    }
    if raw.len() >= 6 {
        Kind::parse(raw[5])?;
    }
    if raw.len() >= 8 && raw[6..8] != [0, 0] {
        return Err("peer reserved flags".into());
    }
    if raw.len() >= 12 {
        let n = u32::from_be_bytes(raw[8..12].try_into().expect("fixed field")) as usize;
        if !Kind::parse(raw[5])?.length(n) {
            return Err("peer type/length bound".into());
        }
    }
    Ok(())
}

/// Validate the ENTIRE fixed context before the network reserves a body Vec. Sender routing checks
/// are separate; neither those checks nor this unkeyed header authenticate producer statements.
pub fn header(raw: &[u8; HEADER_BYTES], context: &Context) -> Result<Header, String> {
    prefix(raw)?;
    if raw[14] != context.run_len
        || raw[15] != 0
        || raw[16..80] != context.run
        || raw[80..112] != context.network
        || raw[112..144] != context.anchor
    {
        return Err("peer run/network/anchor mismatch".into());
    }
    let sender = u16::from_be_bytes(raw[12..14].try_into().expect("fixed field"));
    if sender == 0 || sender == context.node {
        return Err("invalid peer sender ID".into());
    }
    Ok(Header {
        kind: Kind::parse(raw[5])?,
        sender,
        length: u32::from_be_bytes(raw[8..12].try_into().expect("fixed field")) as usize,
    })
}

/// Encode only after queue capacity/byte reservation has been checked by the transport.
pub fn encode(context: &Context, kind: Kind, body: &[u8]) -> Result<Vec<u8>, String> {
    if !kind.length(body.len()) {
        return Err("outbound peer type/length".into());
    }
    let mut bytes = vec![0; HEADER_BYTES + body.len()];
    bytes[..4].copy_from_slice(MAGIC);
    bytes[4] = VERSION;
    bytes[5] = kind as u8;
    bytes[8..12].copy_from_slice(&(body.len() as u32).to_be_bytes());
    bytes[12..14].copy_from_slice(&context.node.to_be_bytes());
    bytes[14] = context.run_len;
    bytes[16..80].copy_from_slice(&context.run);
    bytes[80..112].copy_from_slice(&context.network);
    bytes[112..144].copy_from_slice(&context.anchor);
    bytes[HEADER_BYTES..].copy_from_slice(body);
    Ok(bytes)
}

/// Delivery identity is flow control only, never a local canonical receipt or authority token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Delivery {
    pub revision: u64,
    pub hash: Hash,
    pub submitted: Hash,
}
/// Error codes contain no peer-supplied text, state mirror or repair instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Reject {
    Unavailable = 1,
    Unauthorized = 2,
    Invalid = 3,
    Order = 4,
    Busy = 5,
}
impl Reject {
    fn parse(n: u16) -> Result<Self, String> {
        match n {
            1 => Ok(Self::Unavailable),
            2 => Ok(Self::Unauthorized),
            3 => Ok(Self::Invalid),
            4 => Ok(Self::Order),
            5 => Ok(Self::Busy),
            _ => Err("unknown peer error code".into()),
        }
    }
}
pub enum Message<'a> {
    Status(Tip),
    Committed {
        revision: u64,
        envelope: &'a [u8],
    },
    Reference {
        new_commit: bool,
        delivery: Delivery,
        retained: Hash,
    },
    Error {
        code: Reject,
        revision: u64,
        submitted: Hash,
    },
}
fn u64_at(b: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(
        b[offset..offset + 8]
            .try_into()
            .expect("checked fixed body"),
    )
}
fn hash_at(b: &[u8], offset: usize) -> Hash {
    b[offset..offset + 32]
        .try_into()
        .expect("checked fixed body")
}

/// Bounded payload parsing does not allocate an envelope or authenticate it. The owner must still
/// use its independently loaded approval and the existing signed/native application path.
pub fn decode(kind: Kind, b: &[u8]) -> Result<Message<'_>, String> {
    if !kind.length(b.len()) {
        return Err("peer body length".into());
    }
    match kind {
        Kind::Status => {
            let tip = Tip {
                hash: hash_at(b, 0),
                slot: u64_at(b, 32),
                revision: u64_at(b, 40),
            };
            if tip.revision > MAX_BLOCKS as u64 || tip.slot != tip.revision {
                return Err("fixture status range".into());
            }
            Ok(Message::Status(tip))
        }
        Kind::Committed => {
            let revision = u64_at(b, 0);
            let n = u32::from_be_bytes(b[8..12].try_into().expect("fixed field")) as usize;
            if !(1..=MAX_BLOCKS as u64).contains(&revision)
                || n > MAX_PACKET_BYTES
                || n != b.len() - 12
            {
                return Err("committed payload range/length".into());
            }
            Ok(Message::Committed {
                revision,
                envelope: &b[12..],
            })
        }
        Kind::Reference => {
            if !matches!(b[0], 1 | 2) || b[1..8] != [0; 7] {
                return Err("reference tag/reserved bytes".into());
            }
            let delivery = Delivery {
                revision: u64_at(b, 8),
                hash: hash_at(b, 16),
                submitted: hash_at(b, 80),
            };
            let retained = hash_at(b, 48);
            if !(1..=MAX_BLOCKS as u64).contains(&delivery.revision)
                || (b[0] == 1 && retained != delivery.submitted)
            {
                return Err("reference identity".into());
            }
            Ok(Message::Reference {
                new_commit: b[0] == 1,
                delivery,
                retained,
            })
        }
        Kind::Error => {
            let code = Reject::parse(u16::from_be_bytes(b[..2].try_into().expect("fixed field")))?;
            let revision = u64_at(b, 8);
            let submitted = hash_at(b, 16);
            if b[2..8] != [0; 6]
                || revision > MAX_BLOCKS as u64
                || (revision == 0 && submitted != [0; 32])
            {
                return Err("error body/reserved bytes".into());
            }
            Ok(Message::Error {
                code,
                revision,
                submitted,
            })
        }
    }
}
pub fn status(t: Tip) -> Vec<u8> {
    let mut b = Vec::with_capacity(48);
    b.extend_from_slice(&t.hash);
    b.extend_from_slice(&t.slot.to_be_bytes());
    b.extend_from_slice(&t.revision.to_be_bytes());
    b
}
pub fn committed(revision: u64, e: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(12 + e.len());
    b.extend_from_slice(&revision.to_be_bytes());
    b.extend_from_slice(&(e.len() as u32).to_be_bytes());
    b.extend_from_slice(e);
    b
}
pub fn reference(new_commit: bool, d: Delivery, retained: Hash) -> Vec<u8> {
    let mut b = vec![0; 112];
    b[0] = if new_commit { 1 } else { 2 };
    b[8..16].copy_from_slice(&d.revision.to_be_bytes());
    b[16..48].copy_from_slice(&d.hash);
    b[48..80].copy_from_slice(&retained);
    b[80..112].copy_from_slice(&d.submitted);
    b
}
pub fn error(code: Reject, revision: u64, submitted: Hash) -> Vec<u8> {
    let mut b = vec![0; 48];
    b[..2].copy_from_slice(&(code as u16).to_be_bytes());
    b[8..16].copy_from_slice(&revision.to_be_bytes());
    b[16..48].copy_from_slice(&submitted);
    b
}

#[cfg(test)]
mod tests;
