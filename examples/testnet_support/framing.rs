//! Synchronous bounded local framing: no read-ahead thread, queue or unbounded line reader.
use serde_json::Value;
use std::io::{self, Read, Write};

/// BE32 payload length is checked before allocation; these are local JSON limits, not protocol caps.
pub const MAX_COMMAND_BYTES: usize = 64 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Clean EOF is allowed only between frames. Bad/truncated framing terminates instead of resyncing.
pub fn read_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>, String> {
    let mut header = [0; 4];
    loop {
        match reader.read(&mut header[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("operator input failed".into()),
        }
    }
    reader
        .read_exact(&mut header[1..])
        .map_err(|_| "truncated frame header")?;
    let n = u32::from_be_bytes(header) as usize;
    if n == 0 || n > MAX_COMMAND_BYTES {
        return Err("command frame byte limit".into());
    }
    let mut bytes = vec![0; n];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| "truncated frame payload")?;
    Ok(Some(bytes))
}

struct Limited(Vec<u8>);
impl Write for Limited {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_RESPONSE_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::other("response byte limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Finish the one bounded response before reading another command. Output backpressure blocks this
/// owner rather than allocating a response queue; a failed write never reverses an earlier COMMIT.
pub fn write_frame(writer: &mut impl Write, value: &Value) -> Result<(), String> {
    let mut bytes = Limited(Vec::new());
    serde_json::to_writer(&mut bytes, value).map_err(|_| "response serialization/byte limit")?;
    writer
        .write_all(&(bytes.0.len() as u32).to_be_bytes())
        .and_then(|_| writer.write_all(&bytes.0))
        .and_then(|_| writer.flush())
        .map_err(|_| "operator output failed; commitment may already be durable".into())
}
