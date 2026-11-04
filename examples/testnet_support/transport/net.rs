//! Two-connection nonblocking loopback I/O. No reconnect/retry loop or archive access lives here.
use super::super::profile::read_bounded;
use super::codec::{self, Context, Delivery, HEADER_BYTES, Header, Kind};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

pub const MAX_CONNECTIONS: usize = 2;
pub const MAX_QUEUED_FRAMES: usize = 8;
/// Retained RX bodies, TX frames and the single owner-dispatched body share this byte budget.
pub const MAX_BUFFER_BYTES: usize = 32 * 1024;
pub const IO_BYTES_PER_CONNECTION: usize = 2048;
pub const TIMEOUT: Duration = Duration::from_secs(2);
pub const MAX_SOCKET_BUFFER_BYTES: usize = 16 * 1024;

#[cfg(unix)]
fn socket_buffers(stream: &impl std::os::fd::AsRawFd) -> Result<(usize, usize), String> {
    let mut observed = [0; 2];
    for (i, option) in [libc::SO_SNDBUF, libc::SO_RCVBUF].into_iter().enumerate() {
        let requested: libc::c_int = 4096;
        let mut actual: libc::c_int = 0;
        let mut len = std::mem::size_of_val(&actual) as libc::socklen_t;
        // SAFETY: this borrowed live TcpStream owns the descriptor; each pointer names a correctly
        // sized initialized c_int for the synchronous setsockopt/getsockopt ABI. No pointer escapes.
        let ok = unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&requested as *const libc::c_int).cast(),
                std::mem::size_of_val(&requested) as libc::socklen_t,
            ) == 0
                && libc::getsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    (&mut actual as *mut libc::c_int).cast(),
                    &mut len,
                ) == 0
        };
        if !ok
            || len as usize != std::mem::size_of_val(&actual)
            || actual <= 0
            || actual as usize > MAX_SOCKET_BUFFER_BYTES
        {
            return Err("required bounded peer socket buffers unavailable".into());
        }
        observed[i] = actual as usize;
    }
    Ok((observed[0], observed[1]))
}
#[cfg(not(unix))]
fn socket_buffers(_stream: &TcpStream) -> Result<(usize, usize), String> {
    Err("fixture peer socket limits require Unix".into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    format: String,
    pub node_id: u16,
    pub listen: SocketAddr,
    pub peers: Vec<Peer>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub node_id: u16,
    pub endpoint: SocketAddr,
}
impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let c: Self = serde_json::from_slice(&read_bounded(path, 8192)?)
            .map_err(|_| "strict peer config JSON")?;
        let local = |a: SocketAddr| a.ip() == std::net::Ipv4Addr::LOCALHOST && a.port() != 0;
        if cfg!(not(unix))
            || c.format != "eternix-fixture-peers-v1"
            || !(1..=3).contains(&c.node_id)
            || !local(c.listen)
            || c.peers.len() > 2
        {
            return Err("invalid loopback/static peer configuration".into());
        }
        for (i, p) in c.peers.iter().enumerate() {
            if !(1..=3).contains(&p.node_id)
                || p.node_id == c.node_id
                || !local(p.endpoint)
                || p.endpoint == c.listen
                || c.peers[..i]
                    .iter()
                    .any(|old| old.node_id == p.node_id || old.endpoint == p.endpoint)
            {
                return Err("duplicate/nonloopback peer configuration".into());
            }
        }
        Ok(c)
    }
}

struct Outbound {
    bytes: Vec<u8>,
    position: usize,
    delivery: Option<Delivery>,
    since: Instant,
}
struct Flight {
    delivery: Delivery,
    since: Instant,
}
struct Connection {
    id: u64,
    stream: TcpStream,
    expected: Option<u16>,
    peer: Option<u16>,
    ready: bool,
    sent_status: bool,
    socket_buffers: (usize, usize),
    created: Instant,
    rx_since: Option<Instant>,
    header: [u8; HEADER_BYTES],
    header_pos: usize,
    parsed: Option<Header>,
    body: Option<Vec<u8>>,
    body_pos: usize,
    control: VecDeque<Outbound>,
    data: VecDeque<Outbound>,
    active: Option<Outbound>,
    flight: Option<Flight>,
}
impl Connection {
    fn new(id: u64, stream: TcpStream, expected: Option<u16>) -> Result<Self, String> {
        stream
            .set_nonblocking(true)
            .map_err(|_| "nonblocking peer socket unavailable")?;
        stream
            .set_nodelay(true)
            .map_err(|_| "TCP_NODELAY unavailable")?;
        let socket_buffers = socket_buffers(&stream)?;
        Ok(Self {
            id,
            stream,
            expected,
            peer: expected,
            ready: false,
            sent_status: false,
            socket_buffers,
            created: Instant::now(),
            rx_since: None,
            header: [0; HEADER_BYTES],
            header_pos: 0,
            parsed: None,
            body: None,
            body_pos: 0,
            control: VecDeque::new(),
            data: VecDeque::new(),
            active: None,
            flight: None,
        })
    }
    fn queued(&self) -> usize {
        self.control.len() + self.data.len() + usize::from(self.active.is_some())
    }
    fn used(&self) -> usize {
        self.body.as_ref().map_or(0, Vec::len)
            + self
                .control
                .iter()
                .chain(&self.data)
                .map(|o| o.bytes.len())
                .sum::<usize>()
            + self.active.as_ref().map_or(0, |o| o.bytes.len())
    }
    fn timed_out(&self) -> bool {
        (!self.ready && self.created.elapsed() >= TIMEOUT)
            || self.rx_since.is_some_and(|t| t.elapsed() >= TIMEOUT)
            || self
                .flight
                .as_ref()
                .is_some_and(|f| f.since.elapsed() >= TIMEOUT)
            || self
                .active
                .as_ref()
                .is_some_and(|o| o.since.elapsed() >= TIMEOUT)
            || self
                .control
                .front()
                .is_some_and(|o| o.since.elapsed() >= TIMEOUT)
            || self
                .data
                .front()
                .is_some_and(|o| o.since.elapsed() >= TIMEOUT)
    }
    fn read(
        &mut self,
        context: &Context,
        config: &Config,
        others: &[u16],
        space: usize,
    ) -> Result<usize, Issue> {
        if self.body.as_ref().is_some_and(|b| self.body_pos == b.len()) {
            return Ok(0);
        }
        let mut used = 0;
        if self.header_pos < HEADER_BYTES {
            let end = (self.header_pos + IO_BYTES_PER_CONNECTION).min(HEADER_BYTES);
            match self.stream.read(&mut self.header[self.header_pos..end]) {
                Ok(0) => {
                    return Err(if self.header_pos == 0 {
                        Issue::Io
                    } else {
                        Issue::Truncated
                    });
                }
                Ok(n) => {
                    self.rx_since.get_or_insert_with(Instant::now);
                    self.header_pos += n;
                    used += n;
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(used);
                }
                Err(_) => return Err(Issue::Io),
            }
            codec::prefix(&self.header[..self.header_pos]).map_err(|_| Issue::Protocol)?;
            if self.header_pos == HEADER_BYTES {
                let h = codec::header(&self.header, context).map_err(|_| Issue::Protocol)?;
                if !config.peers.iter().any(|p| p.node_id == h.sender)
                    || others.contains(&h.sender)
                    || self.expected.is_some_and(|n| n != h.sender)
                    || (self.expected.is_none() && h.sender >= context.node)
                    || (!self.ready && h.kind != Kind::Status)
                    || self.peer.is_some_and(|n| n != h.sender)
                {
                    return Err(Issue::Protocol);
                }
                if h.length > space {
                    return Err(Issue::Budget);
                }
                self.peer = Some(h.sender);
                self.parsed = Some(h);
                // No input-derived allocation before fixed header/type/context/routing validation.
                self.body = Some(vec![0; h.length]);
                self.body_pos = 0;
            }
        }
        if let Some(body) = &mut self.body {
            let count = (IO_BYTES_PER_CONNECTION - used).min(body.len() - self.body_pos);
            if count != 0 {
                match self
                    .stream
                    .read(&mut body[self.body_pos..self.body_pos + count])
                {
                    Ok(0) => return Err(Issue::Truncated),
                    Ok(n) => {
                        self.body_pos += n;
                        used += n;
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => return Err(Issue::Io),
                }
            }
        }
        Ok(used)
    }
    fn write(&mut self) -> Result<(usize, bool), Issue> {
        if self.active.is_none() {
            self.active = self.control.pop_front().or_else(|| {
                if self.flight.is_none() {
                    self.data.pop_front()
                } else {
                    None
                }
            });
            if let Some(active) = &self.active
                && let Some(delivery) = active.delivery
            {
                self.flight = Some(Flight {
                    delivery,
                    since: Instant::now(),
                });
            }
        }
        let Some(active) = &mut self.active else {
            return Ok((0, false));
        };
        let end = (active.position + IO_BYTES_PER_CONNECTION).min(active.bytes.len());
        match self.stream.write(&active.bytes[active.position..end]) {
            Ok(0) => Err(Issue::Io),
            Ok(n) => {
                active.position += n;
                if active.position == active.bytes.len() {
                    self.active = None;
                }
                Ok((n, false))
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                Ok((0, e.kind() == std::io::ErrorKind::WouldBlock))
            }
            Err(_) => Err(Issue::Io),
        }
    }
}
#[derive(Clone, Copy)]
enum Issue {
    Io,
    Truncated,
    Protocol,
    Budget,
    Timeout,
}
/// One complete body owned by the dispatcher; its bytes remain in the aggregate budget until done.
pub struct Event {
    pub connection: u64,
    pub sender: u16,
    pub header: Header,
    pub body: Vec<u8>,
    pub received: Instant,
}
#[derive(Default)]
pub struct Metrics {
    pub accepted: u64,
    pub refused: u64,
    pub closed: u64,
    pub protocol_rejected: u64,
    pub truncated: u64,
    pub timeouts: u64,
    pub queue_full: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub frames: u64,
    pub max_buffered: usize,
    pub max_rx: usize,
    pub max_queued: usize,
    pub max_connections: usize,
    pub failed_deliveries: u64,
    pub blocked_writes: u64,
}
/// All peer buffers live here, with at most two sockets, eight queued frames per socket, one
/// outstanding data delivery per socket, and no automatic retries or retained full flight packet.
pub struct Network {
    pub config: Config,
    pub context: Context,
    listener: TcpListener,
    connections: Vec<Connection>,
    next: u64,
    in_handler: usize,
    pub metrics: Metrics,
}
impl Network {
    pub fn bind(config: Config, context: Context) -> Result<Self, String> {
        let listener = TcpListener::bind(config.listen)
            .map_err(|_| "cannot bind fixture loopback listener")?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // Apply buffer caps to the listener as well so accepted/pending sockets inherit them.
            // SAFETY: a live borrowed listening descriptor and a small constant backlog; listen
            // retains no Rust pointer. Re-listening only narrows the new fixture listener's queue.
            socket_buffers(&listener)?;
            if unsafe { libc::listen(listener.as_raw_fd(), MAX_CONNECTIONS as libc::c_int) } != 0 {
                return Err("bounded fixture listen backlog unavailable".into());
            }
        }
        listener
            .set_nonblocking(true)
            .map_err(|_| "nonblocking listener unavailable")?;
        Ok(Self {
            config,
            context,
            listener,
            connections: Vec::new(),
            next: 1,
            in_handler: 0,
            metrics: Metrics::default(),
        })
    }
    fn used(&self) -> usize {
        self.in_handler + self.connections.iter().map(Connection::used).sum::<usize>()
    }
    fn observe(&mut self) {
        self.metrics.max_buffered = self.metrics.max_buffered.max(self.used());
        let rx = self.in_handler
            + self
                .connections
                .iter()
                .map(|c| c.body.as_ref().map_or(0, Vec::len))
                .sum::<usize>();
        self.metrics.max_rx = self.metrics.max_rx.max(rx);
        self.metrics.max_queued = self.metrics.max_queued.max(
            self.connections
                .iter()
                .map(Connection::queued)
                .max()
                .unwrap_or(0),
        );
        self.metrics.max_connections = self.metrics.max_connections.max(self.connections.len());
        debug_assert!(self.used() <= MAX_BUFFER_BYTES);
    }
    fn remove(&mut self, index: usize, issue: Issue) {
        let c = self.connections.remove(index);
        let _ = c.stream.shutdown(Shutdown::Both);
        self.metrics.closed += 1;
        self.metrics.failed_deliveries += c.data.len() as u64 + u64::from(c.flight.is_some());
        match issue {
            Issue::Protocol => self.metrics.protocol_rejected += 1,
            Issue::Budget => self.metrics.queue_full += 1,
            Issue::Truncated => self.metrics.truncated += 1,
            Issue::Timeout => self.metrics.timeouts += 1,
            Issue::Io => {}
        }
    }
    pub fn disconnect(&mut self, peer: u16) {
        if let Some(i) = self.connections.iter().position(|c| c.peer == Some(peer)) {
            self.remove(i, Issue::Io);
        }
    }
    pub fn reject(&mut self, id: u64) {
        if let Some(i) = self.connections.iter().position(|c| c.id == id) {
            self.remove(i, Issue::Protocol);
        }
    }
    pub fn close(&mut self, id: u64) {
        if let Some(i) = self.connections.iter().position(|c| c.id == id) {
            self.remove(i, Issue::Io);
        }
    }
    pub fn suspend(&mut self) {
        while !self.connections.is_empty() {
            self.remove(0, Issue::Io);
        }
    }
    pub fn connect(&mut self, peer: u16, status: &[u8]) -> Result<(), String> {
        if self.connections.len() == MAX_CONNECTIONS
            || self.connections.iter().any(|c| c.peer == Some(peer))
        {
            return Err("connection limit/already connected".into());
        }
        let endpoint = self
            .config
            .peers
            .iter()
            .find(|p| p.node_id == peer)
            .ok_or("unconfigured peer")?
            .endpoint;
        if peer <= self.config.node_id {
            return Err("only lower node ID initiates a connection".into());
        }
        // Only explicit operator Connect can block here, for at most 25 ms, to a fixed loopback IP.
        // No DNS, peer-triggered connect or automatic reconnect/retry work is performed.
        let stream = TcpStream::connect_timeout(&endpoint, Duration::from_millis(25))
            .map_err(|_| "loopback connect failed")?;
        let c = Connection::new(self.next, stream, Some(peer))?;
        let id = c.id;
        self.next += 1;
        self.connections.push(c);
        if let Err(error) = self.queue(id, Kind::Status, status, None) {
            self.close(id);
            return Err(error);
        }
        self.connections
            .last_mut()
            .expect("new connection")
            .sent_status = true;
        self.observe();
        Ok(())
    }
    pub fn queue(
        &mut self,
        id: u64,
        kind: Kind,
        body: &[u8],
        delivery: Option<Delivery>,
    ) -> Result<(), String> {
        let size = HEADER_BYTES + body.len();
        let i = self
            .connections
            .iter()
            .position(|c| c.id == id)
            .ok_or("peer connection closed")?;
        if self.connections[i].queued() >= MAX_QUEUED_FRAMES
            || size > MAX_BUFFER_BYTES.saturating_sub(self.used())
        {
            self.metrics.queue_full += 1;
            return Err("peer queue/aggregate byte budget full".into());
        }
        let bytes = if kind.extension() {
            codec::encode_extension(&self.context, kind, body)?
        } else {
            codec::encode(&self.context, kind, body)?
        };
        let frame = Outbound {
            bytes,
            position: 0,
            delivery,
            since: Instant::now(),
        };
        if delivery.is_some() {
            self.connections[i].data.push_back(frame);
        } else {
            self.connections[i].control.push_back(frame);
        }
        self.observe();
        Ok(())
    }
    pub fn targets(&self, except: Option<u16>) -> Vec<(u64, u16)> {
        self.connections
            .iter()
            .filter(|c| c.ready && c.peer != except)
            .map(|c| (c.id, c.peer.expect("ready peer")))
            .collect()
    }
    pub fn target(&self, peer: u16) -> Result<u64, String> {
        self.targets(None)
            .iter()
            .find(|(_, n)| *n == peer)
            .map(|(id, _)| *id)
            .ok_or("peer is not established".into())
    }
    pub fn establish(&mut self, id: u64, status: &[u8]) -> Result<(), String> {
        let c = self
            .connections
            .iter_mut()
            .find(|c| c.id == id)
            .ok_or("closed peer")?;
        c.ready = true;
        let reply = !c.sent_status;
        c.sent_status = true;
        if reply {
            self.queue(id, Kind::Status, status, None)?;
        }
        Ok(())
    }
    pub fn acknowledge(&mut self, id: u64, delivery: Delivery) -> bool {
        if let Some(c) = self.connections.iter_mut().find(|c| c.id == id)
            && c.flight.as_ref().is_some_and(|f| f.delivery == delivery)
            && !c
                .active
                .as_ref()
                .is_some_and(|o| o.delivery == Some(delivery))
        {
            c.flight = None;
            return true;
        }
        false
    }
    pub fn error_delivery(&mut self, id: u64, revision: u64, submitted: [u8; 32]) -> bool {
        let Some(c) = self.connections.iter_mut().find(|c| c.id == id) else {
            return false;
        };
        if c.flight
            .as_ref()
            .is_some_and(|f| f.delivery.revision == revision && f.delivery.submitted == submitted)
            && !c.active.as_ref().is_some_and(|o| o.delivery.is_some())
        {
            c.flight = None;
            self.metrics.failed_deliveries += 1;
            true
        } else {
            false
        }
    }
    /// At most one accept, two writes and four reads (<=4096 bytes each direction) per tick. Return
    /// at most one complete frame for owner work; rotate peers so a flood cannot monopolize dispatch.
    pub fn poll(&mut self, available: bool) -> Option<Event> {
        if let Ok((stream, from)) = self.listener.accept() {
            if !available || self.connections.len() == MAX_CONNECTIONS || !from.ip().is_loopback() {
                self.metrics.refused += 1;
                let _ = stream.shutdown(Shutdown::Both);
            } else if let Ok(c) = Connection::new(self.next, stream, None) {
                self.next += 1;
                self.connections.push(c);
                self.metrics.accepted += 1;
                self.observe();
            }
        }
        if !available {
            self.suspend();
            return None;
        }
        let mut i = 0;
        while i < self.connections.len() {
            if self.connections[i].timed_out() {
                self.remove(i, Issue::Timeout);
                continue;
            }
            match self.connections[i].write() {
                Ok((n, blocked)) => {
                    self.metrics.tx_bytes += n as u64;
                    self.metrics.blocked_writes += u64::from(blocked);
                }
                Err(e) => {
                    self.remove(i, e);
                    continue;
                }
            }
            let space = MAX_BUFFER_BYTES.saturating_sub(self.used());
            let others: Vec<_> = self
                .connections
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .filter_map(|(_, c)| c.peer)
                .collect();
            match self.connections[i].read(&self.context, &self.config, &others, space) {
                Ok(n) => self.metrics.rx_bytes += n as u64,
                Err(e) => {
                    self.remove(i, e);
                    continue;
                }
            }
            self.observe();
            i += 1;
        }
        let mut event = None;
        for c in &mut self.connections {
            if c.body.as_ref().is_some_and(|b| c.body_pos == b.len()) {
                let body = c.body.take().expect("complete body");
                let header = c.parsed.take().expect("validated header");
                c.header_pos = 0;
                c.body_pos = 0;
                c.rx_since = None;
                self.in_handler = body.len();
                self.metrics.frames += 1;
                event = Some(Event {
                    connection: c.id,
                    sender: header.sender,
                    header,
                    body,
                    received: Instant::now(),
                });
                break;
            }
        }
        if self.connections.len() > 1 {
            self.connections.rotate_left(1);
        }
        event
    }
    pub fn finish_event(&mut self) {
        self.in_handler = 0;
    }
    pub fn status(&self) -> Value {
        let connections: Vec<_> = self
            .connections
            .iter()
            .map(|c| {
                json!({"connection":c.id,"node_id":c.peer,"ready":c.ready,
            "queued_frames":c.queued(),"buffered_bytes":c.used(),"in_flight":c.flight.is_some(),
            "socket_send_bytes":c.socket_buffers.0,"socket_receive_bytes":c.socket_buffers.1})
            })
            .collect();
        let m = &self.metrics;
        json!({"node_id":self.config.node_id,"listen":self.config.listen.to_string(),"connections":connections,
            "buffered_bytes":self.used(),"max_buffered_bytes":m.max_buffered,"max_rx_body_bytes":m.max_rx,
            "max_queued_frames":m.max_queued,"max_connections":m.max_connections,"accepted":m.accepted,"refused":m.refused,
            "closed":m.closed,"protocol_rejected":m.protocol_rejected,"truncated":m.truncated,"timeouts":m.timeouts,
            "queue_full":m.queue_full,"failed_deliveries":m.failed_deliveries,"blocked_writes":m.blocked_writes,"rx_bytes":m.rx_bytes,"tx_bytes":m.tx_bytes,"frames":m.frames,
            "limits":{"connections":MAX_CONNECTIONS,"queued_frames_per_connection":MAX_QUEUED_FRAMES,"buffer_bytes":MAX_BUFFER_BYTES,
                "io_bytes_per_connection_per_tick":IO_BYTES_PER_CONNECTION,"frame_bytes":codec::MAX_FRAME_BYTES,"timeout_ms":TIMEOUT.as_millis(),
                "extension_frame_bytes":codec::MAX_EXTENSION_FRAME_BYTES,
                "socket_buffer_bytes_per_direction":MAX_SOCKET_BUFFER_BYTES,"requested_listen_backlog":MAX_CONNECTIONS,"automatic_retries":0}})
    }
}
