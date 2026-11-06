//! Explicit bounded C1 peer3 dispatch. Routing/transport never supplies admission authority, signer
//! requests, snapshots or consensus timeouts. M1 peer1/peer2 codecs and executables are untouched.
use super::{application::MAX_ENVELOPE_BYTES, *};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// Distinct magic, including the trailing zero, rejects all M1/historical framing.
pub const MAGIC: &[u8; 8] = b"ETXC1P3\0";
/// Fixed header width; reserved bytes must be zero.
pub const HEADER_BYTES: usize = 128;
/// Entire frame is bounded before body allocation.
pub const MAX_FRAME_BYTES: usize = HEADER_BYTES + MAX_ENVELOPE_BYTES;
/// Operational whole-request I/O bound, not a PoAsh publication/absence decision.
pub const IO_TIMEOUT: Duration = Duration::from_secs(2);
/// Exact peer3 message kinds. No peer command can ask a node to sign or select another producer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Kind {
    /// Empty read-only tip request.
    Status = 1,
    /// slot8/H32/complete-local-snapshot comparison digest32; no checkpoint authority.
    Tip = 2,
    /// Complete already-committed original E, still independently admitted by the receiver.
    Push = 3,
    /// BE64 requested slot1..200.
    Get = 4,
    /// Exact retained original E, never historical re-signing.
    Envelope = 5,
    /// slot8/H32/retained-E-ID32/new-commit flag1.
    Ack = 6,
    /// One bounded diagnostic code byte; no invented protocol slot result.
    Reject = 7,
}
impl Kind {
    fn decode(n: u8) -> Result<Self, String> {
        Ok(match n {
            1 => Self::Status,
            2 => Self::Tip,
            3 => Self::Push,
            4 => Self::Get,
            5 => Self::Envelope,
            6 => Self::Ack,
            7 => Self::Reject,
            _ => return Err("unknown C1 peer kind".into()),
        })
    }
    fn check(self, n: usize) -> bool {
        match self {
            Self::Status => n == 0,
            Self::Tip => n == 72,
            Self::Push | Self::Envelope => (402..=MAX_ENVELOPE_BYTES).contains(&n),
            Self::Get => n == 8,
            Self::Ack => n == 73,
            Self::Reject => n == 1,
        }
    }
}
/// Syntax-checked C1 routing message, without attribution or canonical-write permission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    kind: Kind,
    request: u64,
    body: Vec<u8>,
}
impl Message {
    /// Check exact kind/body widths, bounded slot/flag fields and nonzero request correlation.
    pub fn new(kind: Kind, request: u64, body: Vec<u8>) -> Result<Self, String> {
        if request == 0 || !kind.check(body.len()) {
            return Err("C1 message width/request".into());
        }
        if matches!(kind, Kind::Get | Kind::Tip | Kind::Ack) {
            let slot = u64::from_be_bytes(body[..8].try_into().expect("checked width"));
            if slot > MAX_SLOTS || (kind != Kind::Tip && slot == 0) {
                return Err("C1 message slot bound".into());
            }
        }
        if kind == Kind::Ack && body[72] > 1 {
            return Err("C1 acknowledgement flag".into());
        }
        if kind == Kind::Reject && !(1..=4).contains(&body[0]) {
            return Err("C1 rejection code".into());
        }
        Ok(Self {
            kind,
            request,
            body,
        })
    }
    /// Exact read-only kind.
    pub fn kind(&self) -> Kind {
        self.kind
    }
    /// Correlation value only, not ordering, freshness or consensus authority.
    pub fn request(&self) -> u64 {
        self.request
    }
    /// Bounded exact payload; envelope authentication is the owner's responsibility.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    /// Canonical peer3 bytes: magic/version/kind/zero/profile/auth/PoAsh/chain/N/request/length/zero.
    pub fn bytes(&self, g: &Genesis) -> Vec<u8> {
        let mut out = vec![0; HEADER_BYTES];
        out[..8].copy_from_slice(MAGIC);
        out[8] = 3;
        out[9] = self.kind as u8;
        out[12..16].copy_from_slice(&HEADER_PROFILE.to_be_bytes());
        out[16..20].copy_from_slice(&AUTH_RULES.to_be_bytes());
        out[20..24].copy_from_slice(&POASH_RULES.to_be_bytes());
        out[24..32].copy_from_slice(&CHAIN_ID.to_be_bytes());
        out[32..64].copy_from_slice(&g.network_id());
        out[64..72].copy_from_slice(&self.request.to_be_bytes());
        out[72..76].copy_from_slice(&(self.body.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.body);
        out
    }
    /// Exact finite decode; a false header/length is rejected before any body copy.
    pub fn from_bytes(bytes: &[u8], g: &Genesis) -> Result<Self, String> {
        if bytes.len() < HEADER_BYTES || bytes.len() > MAX_FRAME_BYTES {
            return Err("C1 peer frame bound".into());
        }
        let (kind, request, len) = header(&bytes[..HEADER_BYTES], g)?;
        if bytes.len() != HEADER_BYTES + len {
            return Err("C1 exact peer frame length".into());
        }
        Self::new(kind, request, bytes[HEADER_BYTES..].to_vec())
    }
}
fn header(h: &[u8], g: &Genesis) -> Result<(Kind, u64, usize), String> {
    if h.len() != HEADER_BYTES
        || &h[..8] != MAGIC
        || h[8] != 3
        || h[10..12] != [0; 2]
        || h[76..] != [0; 52]
        || h[12..16] != HEADER_PROFILE.to_be_bytes()
        || h[16..20] != AUTH_RULES.to_be_bytes()
        || h[20..24] != POASH_RULES.to_be_bytes()
        || h[24..32] != CHAIN_ID.to_be_bytes()
        || h[32..64] != g.network_id()
    {
        return Err("C1 peer context/header".into());
    }
    let kind = Kind::decode(h[9])?;
    let request = u64::from_be_bytes(h[64..72].try_into().expect("width"));
    let len = u32::from_be_bytes(h[72..76].try_into().expect("width")) as usize;
    if request == 0 || !kind.check(len) {
        return Err("C1 peer declared body bound".into());
    }
    Ok((kind, request, len))
}
fn remaining(end: Instant) -> Result<Duration, String> {
    end.checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| "C1 whole-frame I/O deadline".into())
}
fn read_exact(s: &mut TcpStream, out: &mut [u8], end: Instant) -> Result<(), String> {
    let mut at = 0;
    while at < out.len() {
        s.set_read_timeout(Some(remaining(end)?))
            .map_err(|e| e.to_string())?;
        let n = s.read(&mut out[at..]).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("C1 truncated connection".into());
        }
        at += n;
    }
    Ok(())
}
/// Bounded whole-frame reader; a slow partial read does not restart the operational deadline.
pub fn read(s: &mut TcpStream, g: &Genesis, end: Instant) -> Result<Message, String> {
    let mut h = [0; HEADER_BYTES];
    read_exact(s, &mut h, end)?;
    let (kind, request, len) = header(&h, g)?;
    let mut body = vec![0; len];
    read_exact(s, &mut body, end)?;
    Message::new(kind, request, body)
}
/// Bounded whole-frame writer on a single connection; no unbounded queue or archive clone.
pub fn write(s: &mut TcpStream, g: &Genesis, m: &Message, end: Instant) -> Result<(), String> {
    let bytes = m.bytes(g);
    let mut at = 0;
    while at < bytes.len() {
        s.set_write_timeout(Some(remaining(end)?))
            .map_err(|e| e.to_string())?;
        let n = s.write(&bytes[at..]).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("C1 closed writer".into());
        }
        at += n;
    }
    Ok(())
}
/// One finite loopback request/reply, checking correlation and exact new-profile dispatch.
pub fn exchange(address: SocketAddr, g: &Genesis, m: &Message) -> Result<Message, String> {
    if !address.ip().is_loopback() {
        return Err("C1 experiment requires explicit loopback peer".into());
    }
    let end = Instant::now() + IO_TIMEOUT;
    let mut s = TcpStream::connect_timeout(&address, remaining(end)?).map_err(|e| e.to_string())?;
    s.set_nodelay(true).map_err(|e| e.to_string())?;
    write(&mut s, g, m, end)?;
    let reply = read(&mut s, g, end)?;
    if reply.request() != m.request() {
        return Err("C1 response correlation".into());
    }
    Ok(reply)
}
