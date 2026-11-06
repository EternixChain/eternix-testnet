//! Signing schema1, independent of canonical schema4. Two EXTRA transactions intentionally leave
//! a durable reservation between them; no rollback/recovery path can delete or complete that row.
use super::*;
use rusqlite::{Row, types::ValueRef};
const TABLES: &[(&str, &str)] = &[
    (
        "metadata",
        "CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), version BLOB NOT NULL CHECK(typeof(version)='blob' AND version=x'00000001'), mode TEXT NOT NULL CHECK(mode='c1-signing-authority'), identity BLOB NOT NULL CHECK(typeof(identity)='blob' AND length(identity) BETWEEN 1 AND 256), barrier BLOB NOT NULL CHECK(typeof(barrier)='blob' AND length(barrier)=8))",
    ),
    (
        "reservations",
        "CREATE TABLE reservations (slot BLOB PRIMARY KEY CHECK(typeof(slot)='blob' AND length(slot)=8 AND slot>x'0000000000000000'), reservation BLOB NOT NULL CHECK(typeof(reservation)='blob' AND length(reservation) BETWEEN 295 AND 4055)) WITHOUT ROWID",
    ),
    (
        "originals",
        "CREATE TABLE originals (slot BLOB PRIMARY KEY REFERENCES reservations(slot) CHECK(typeof(slot)='blob' AND length(slot)=8), envelope BLOB NOT NULL CHECK(typeof(envelope)='blob' AND length(envelope) BETWEEN 402 AND 3650), signature BLOB NOT NULL CHECK(typeof(signature)='blob' AND length(signature)=65), envelope_id BLOB NOT NULL UNIQUE CHECK(typeof(envelope_id)='blob' AND length(envelope_id)=32)) WITHOUT ROWID",
    ),
];
fn triggers() -> Vec<(String, String)> {
    let mut out = vec![];
    for table in ["reservations", "originals"] {
        for op in ["UPDATE", "DELETE"] {
            let n = format!("immutable_{table}_{}", op.to_lowercase());
            out.push((n.clone(),format!("CREATE TRIGGER {n} BEFORE {op} ON {table} BEGIN SELECT RAISE(ABORT,'immutable signing protection'); END")));
        }
        let n = format!("no_replace_{table}");
        let predicate = if table == "originals" {
            "slot=NEW.slot OR envelope_id=NEW.envelope_id"
        } else {
            "slot=NEW.slot"
        };
        out.push((n.clone(),format!("CREATE TRIGGER {n} BEFORE INSERT ON {table} WHEN EXISTS(SELECT 1 FROM {table} WHERE {predicate}) BEGIN SELECT RAISE(ABORT,'no signing replacement'); END")));
    }
    out.push(("metadata_policy".into(),"CREATE TRIGGER metadata_policy BEFORE UPDATE ON metadata WHEN NEW.id IS NOT OLD.id OR NEW.version IS NOT OLD.version OR NEW.mode IS NOT OLD.mode OR NEW.identity IS NOT OLD.identity BEGIN SELECT RAISE(ABORT,'immutable authority'); END".into()));
    out.push(("metadata_delete".into(),"CREATE TRIGGER metadata_delete BEFORE DELETE ON metadata BEGIN SELECT RAISE(ABORT,'immutable authority'); END".into()));
    out.push(("metadata_replace".into(),"CREATE TRIGGER metadata_replace BEFORE INSERT ON metadata WHEN EXISTS(SELECT 1 FROM metadata) BEGIN SELECT RAISE(ABORT,'no authority replacement'); END".into()));
    out
}
fn identity(g: &Genesis, producer: &str, key: [u8; 33]) -> Vec<u8> {
    let mut b = Vec::from(b"ETERNIX_C1_SIGN_AUTHORITY\0".as_slice());
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&g.network_id());
    b.extend_from_slice(&POASH_RULES.to_be_bytes());
    b.extend_from_slice(&HEADER_PROFILE.to_be_bytes());
    b.extend_from_slice(&[INNER_WIRE, OUTER_WIRE, AUTH_ENCODING]);
    b.extend_from_slice(&AUTH_RULES.to_be_bytes());
    b.extend_from_slice(&key);
    super::super::text(&mut b, producer);
    b
}
pub(super) fn configure(c: &Connection) -> Result<(), Error> {
    disk::configure(c).map_err(invalid)?;
    let cache: i64 = c
        .query_row("PRAGMA cache_size", [], |r| r.get(0))
        .map_err(invalid)?;
    let spill: i64 = c
        .query_row("PRAGMA cache_spill", [], |r| r.get(0))
        .map_err(invalid)?;
    if cache != -2000 || spill <= 0 {
        return Err(invalid("signer default cache/spill"));
    }
    Ok(())
}
fn schema(c: &Connection) -> Result<(), Error> {
    let mut expected: BTreeMap<(String, String), String> = TABLES
        .iter()
        .map(|(n, d)| (("table".into(), (*n).into()), (*d).into()))
        .collect();
    for (n, d) in triggers() {
        expected.insert(("trigger".into(), n), d);
    }
    let mut q=c.prepare("SELECT type,name,sql FROM sqlite_schema WHERE substr(name,1,7)<>'sqlite_' ORDER BY type,name").map_err(invalid)?;
    let actual = q
        .query_map([], |r| Ok(((r.get(0)?, r.get(1)?), r.get(2)?)))
        .map_err(invalid)?
        .collect::<rusqlite::Result<BTreeMap<(String, String), String>>>()
        .map_err(invalid)?;
    if actual != expected {
        return Err(invalid("exact signing schema1"));
    }
    if c.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
        .map_err(invalid)?
        != "ok"
    {
        return Err(invalid("signer integrity"));
    }
    if c.prepare("PRAGMA foreign_key_check")
        .map_err(invalid)?
        .query([])
        .map_err(invalid)?
        .next()
        .map_err(invalid)?
        .is_some()
    {
        return Err(invalid("signer foreign keys"));
    }
    Ok(())
}
fn blob<'a>(r: &'a Row<'_>, col: usize, min: usize, max: usize) -> Result<&'a [u8], Error> {
    match r.get_ref(col).map_err(invalid)? {
        ValueRef::Blob(b) if (min..=max).contains(&b.len()) => Ok(b),
        _ => Err(invalid("bounded signing BLOB")),
    }
}
fn policy(c: &Connection, g: &Genesis, producer: &str, key: [u8; 33]) -> Result<(), Error> {
    let count: i64 = c
        .query_row("SELECT count(*) FROM metadata", [], |r| r.get(0))
        .map_err(invalid)?;
    if count != 1 {
        return Err(invalid("signing identity singleton"));
    }
    let mut q = c
        .prepare("SELECT version,mode,identity,barrier FROM metadata WHERE id=1")
        .map_err(invalid)?;
    let mut cursor = q.query([]).map_err(invalid)?;
    let r = cursor
        .next()
        .map_err(invalid)?
        .ok_or_else(|| invalid("signing metadata absent"))?;
    if blob(r, 0, 4, 4)? != 1u32.to_be_bytes()
        || r.get_ref(1).map_err(invalid)? != ValueRef::Text(b"c1-signing-authority")
        || blob(r, 2, 1, 256)? != identity(g, producer, key)
    {
        return Err(invalid("independent authority identity"));
    }
    blob(r, 3, 8, 8)?;
    Ok(())
}
pub(super) fn initialize(
    c: &Connection,
    g: &Genesis,
    producer: &str,
    key: [u8; 33],
) -> Result<(), Error> {
    c.execute_batch("BEGIN IMMEDIATE").map_err(invalid)?;
    for (_, ddl) in TABLES {
        c.execute_batch(ddl).map_err(invalid)?;
    }
    for (_, ddl) in triggers() {
        c.execute_batch(&ddl).map_err(invalid)?;
    }
    c.execute(
        "INSERT INTO metadata VALUES(1,x'00000001','c1-signing-authority',?1,?2)",
        params![identity(g, producer, key), 0u64.to_be_bytes().as_slice()],
    )
    .map_err(invalid)?;
    c.execute_batch("COMMIT").map_err(invalid)?;
    Ok(())
}
// Reconciliation checks the opaque comparison IDs against the owner's own historical view. This
// decoder checks exact context/layout/H/slot/parent/finalized body, never imports a claimed state.
pub(super) fn decode_reservation(
    bytes: &[u8],
    g: &Genesis,
    producer: &str,
    key: [u8; 33],
) -> Result<(app::Block, Hash), Error> {
    let parse = (|| -> Result<(app::Block, Hash), app::Error> {
        if bytes.len() > MAX_RESERVATION_BYTES {
            return Err(app::Error::Codec("reservation bound"));
        }
        let mut d = super::super::Decoder { bytes, at: 0 };
        if d.take(RESERVATION_DOMAIN.len())? != RESERVATION_DOMAIN
            || d.u32()? != 1
            || d.field::<32>()? != g.network_id()
            || d.u32()? != POASH_RULES
            || d.u32()? != HEADER_PROFILE
            || d.take(3)? != [INNER_WIRE, OUTER_WIRE, AUTH_ENCODING]
            || d.u32()? != AUTH_RULES
            || d.field::<33>()? != key
            || d.text(7)? != producer
        {
            return Err(app::Error::Codec("reservation context"));
        }
        let slot = d.u64()?;
        let hash = d.field::<32>()?;
        let parent = d.field::<32>()?;
        d.take(32 * 4)?;
        let candidate = d.field()?;
        let len = d.u32()? as usize;
        if !(295..=app::MAX_BLOCK_BYTES).contains(&len) {
            return Err(app::Error::Codec("reserved block length"));
        }
        let block = app::Block::from_wire_bytes(d.take(len)?)?;
        if d.at != bytes.len()
            || block.hash() != hash
            || block.claim().header().slot != slot
            || block.claim().header().parent_hash != parent
            || block.claim().producer() != producer
        {
            return Err(app::Error::Codec("exact reserved block"));
        }
        Ok((block, candidate))
    })();
    parse.map_err(Error::from)
}
fn read(
    c: &Connection,
    g: &Genesis,
    producer: &str,
    key: [u8; 33],
    authenticate: bool,
) -> Result<Intents, Error> {
    schema(c)?;
    policy(c, g, producer, key)?;
    let mut intents = Intents::new();
    let mut q = c
        .prepare("SELECT slot,reservation FROM reservations ORDER BY slot")
        .map_err(invalid)?;
    let mut rows = q.query([]).map_err(invalid)?;
    while let Some(r) = rows.next().map_err(invalid)? {
        if intents.len() >= MAX_SLOTS as usize {
            return Err(invalid("reservation row bound"));
        }
        let slot = u64::from_be_bytes(blob(r, 0, 8, 8)?.try_into().expect("width"));
        let bytes = blob(r, 1, 295, MAX_RESERVATION_BYTES)?.to_vec();
        let (block, _) = decode_reservation(&bytes, g, producer, key)?;
        if block.claim().header().slot != slot {
            return Err(invalid("reservation slot index"));
        }
        intents.insert(
            slot,
            Intent {
                reservation: bytes,
                original: None,
            },
        );
    }
    let mut q = c
        .prepare("SELECT slot,envelope,signature,envelope_id FROM originals ORDER BY slot")
        .map_err(invalid)?;
    let mut rows = q.query([]).map_err(invalid)?;
    let mut count = 0;
    while let Some(r) = rows.next().map_err(invalid)? {
        count += 1;
        if count > MAX_SLOTS {
            return Err(invalid("original row bound"));
        }
        let slot = u64::from_be_bytes(blob(r, 0, 8, 8)?.try_into().expect("width"));
        let bytes = blob(r, 1, 402, app::MAX_ENVELOPE_BYTES)?.to_vec();
        let envelope = app::Envelope::from_wire_bytes(&bytes)?;
        let i = intents
            .get_mut(&slot)
            .ok_or_else(|| invalid("original without reservation"))?;
        let (reserved, _) = decode_reservation(&i.reservation, g, producer, key)?;
        if envelope.block() != &reserved
            || envelope.network_id() != g.network_id()
            || envelope.signature_bytes() != blob(r, 2, 65, 65)?
            || envelope.id() != blob(r, 3, 32, 32)?
        {
            return Err(invalid("original exact reservation/S/E-ID"));
        }
        if authenticate {
            envelope.authenticate(g)?;
        }
        i.original = Some(bytes);
    }
    Ok(intents)
}
pub(super) fn verify(
    c: &Connection,
    g: &Genesis,
    producer: &str,
    key: [u8; 33],
    expected: &Intents,
) -> Result<(), Error> {
    if read(c, g, producer, key, false)? != *expected {
        return Err(invalid("exact known signing base"));
    }
    Ok(())
}
pub(super) fn load(
    c: &Connection,
    g: &Genesis,
    producer: &str,
    key: [u8; 33],
) -> Result<Intents, Error> {
    c.execute_batch("BEGIN").map_err(invalid)?;
    let result = read(c, g, producer, key, true);
    let end = c.execute_batch("ROLLBACK").map_err(invalid);
    result.and_then(|v| end.map(|_| v))
}
pub(super) fn barrier(
    c: &Connection,
    path: &Path,
    g: &Genesis,
    producer: &str,
    key: [u8; 33],
    expected: &Intents,
) -> Result<(), Error> {
    c.execute_batch("BEGIN IMMEDIATE").map_err(invalid)?;
    verify(c, g, producer, key, expected)?;
    let old = c
        .query_row("SELECT barrier FROM metadata WHERE id=1", [], |r| {
            disk::blob::<8>(r, 0)
        })
        .map_err(invalid)?;
    let next = u64::from_be_bytes(old)
        .checked_add(1)
        .ok_or_else(|| invalid("signer barrier exhausted"))?;
    if c.execute(
        "UPDATE metadata SET barrier=?1 WHERE id=1 AND barrier=?2",
        params![next.to_be_bytes().as_slice(), old.as_slice()],
    )
    .map_err(invalid)?
        != 1
    {
        return Err(invalid("signer barrier CAS"));
    }
    c.execute_batch("COMMIT").map_err(invalid)?;
    disk::sync_path(path).map_err(invalid)
}
