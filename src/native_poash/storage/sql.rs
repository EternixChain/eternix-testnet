//! Schema4 closure, byte-exact materialization and independently seeded full C1 replay.
//! All protocol quantities are explicit BE BLOBs; SQLite never performs consensus arithmetic.
use super::*;
use rusqlite::{Row, types::ValueRef};

// The complete supported snapshot is retained at every position, including immutable genesis0.
// Normalized native/accounting/reward indexes are redundant checked materializations, not authority.
const TABLES: &[(&str, &str)] = &[
    (
        "metadata",
        "CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), version BLOB NOT NULL CHECK(typeof(version)='blob' AND version=x'00000004'), mode TEXT NOT NULL CHECK(mode='native-poash-c1'), genesis BLOB NOT NULL CHECK(typeof(genesis)='blob' AND length(genesis) BETWEEN 1 AND 16384), revision BLOB NOT NULL CHECK(typeof(revision)='blob' AND length(revision)=8), barrier BLOB NOT NULL CHECK(typeof(barrier)='blob' AND length(barrier)=8), initialized INTEGER NOT NULL CHECK(initialized IN (0,1)))",
    ),
    (
        "accounts",
        "CREATE TABLE accounts (address BLOB PRIMARY KEY CHECK(typeof(address)='blob' AND length(address)=20), balance BLOB NOT NULL CHECK(typeof(balance)='blob' AND length(balance)=16), nonce BLOB NOT NULL CHECK(typeof(nonce)='blob' AND length(nonce)=8)) WITHOUT ROWID",
    ),
    (
        "accounting",
        "CREATE TABLE accounting (id INTEGER PRIMARY KEY CHECK(id=1), gas BLOB NOT NULL CHECK(typeof(gas)='blob' AND length(gas)=8), fees BLOB NOT NULL CHECK(typeof(fees)='blob' AND length(fees)=16), issuance BLOB NOT NULL CHECK(typeof(issuance)='blob' AND length(issuance)=16), supply BLOB NOT NULL CHECK(typeof(supply)='blob' AND length(supply)=16), participation BLOB NOT NULL CHECK(typeof(participation)='blob' AND length(participation)=8), eligible_fee_burn BLOB NOT NULL CHECK(typeof(eligible_fee_burn)='blob' AND length(eligible_fee_burn)=16))",
    ),
    (
        "year_zero",
        "CREATE TABLE year_zero (id INTEGER PRIMARY KEY CHECK(id=1), record BLOB NOT NULL CHECK(typeof(record)='blob' AND length(record)=120))",
    ),
    (
        "blocks",
        "CREATE TABLE blocks (slot BLOB PRIMARY KEY CHECK(typeof(slot)='blob' AND length(slot)=8 AND slot>x'0000000000000000'), hash BLOB NOT NULL UNIQUE CHECK(typeof(hash)='blob' AND length(hash)=32), parent BLOB NOT NULL CHECK(typeof(parent)='blob' AND length(parent)=32), header BLOB NOT NULL CHECK(typeof(header)='blob' AND length(header)=229), producer BLOB NOT NULL CHECK(typeof(producer)='blob' AND length(producer)=7), protocol BLOB NOT NULL CHECK(typeof(protocol)='blob' AND length(protocol)=10), signature BLOB NOT NULL CHECK(typeof(signature)='blob' AND length(signature)=65), envelope_id BLOB NOT NULL UNIQUE CHECK(typeof(envelope_id)='blob' AND length(envelope_id)=32), FOREIGN KEY(slot) REFERENCES bodies(slot) DEFERRABLE INITIALLY DEFERRED, FOREIGN KEY(slot,hash) REFERENCES states(slot,hash) DEFERRABLE INITIALLY DEFERRED) WITHOUT ROWID",
    ),
    (
        "bodies",
        "CREATE TABLE bodies (slot BLOB PRIMARY KEY REFERENCES blocks(slot) DEFERRABLE INITIALLY DEFERRED CHECK(typeof(slot)='blob' AND length(slot)=8), count BLOB NOT NULL CHECK(typeof(count)='blob' AND length(count)=8), gas BLOB NOT NULL CHECK(typeof(gas)='blob' AND length(gas)=8), fees BLOB NOT NULL CHECK(typeof(fees)='blob' AND length(fees)=8)) WITHOUT ROWID",
    ),
    (
        "transactions",
        "CREATE TABLE transactions (id BLOB PRIMARY KEY CHECK(typeof(id)='blob' AND length(id)=32), slot BLOB NOT NULL REFERENCES bodies(slot) CHECK(typeof(slot)='blob' AND length(slot)=8), position BLOB NOT NULL CHECK(typeof(position)='blob' AND length(position)=8), sender BLOB NOT NULL CHECK(typeof(sender)='blob' AND length(sender)=20), nonce BLOB NOT NULL CHECK(typeof(nonce)='blob' AND length(nonce)=8), signed BLOB NOT NULL CHECK(typeof(signed)='blob' AND length(signed)=199), UNIQUE(slot,position), UNIQUE(sender,nonce)) WITHOUT ROWID",
    ),
    (
        "rewards",
        "CREATE TABLE rewards (slot BLOB PRIMARY KEY REFERENCES blocks(slot) CHECK(typeof(slot)='blob' AND length(slot)=8), validator BLOB NOT NULL CHECK(typeof(validator)='blob' AND length(validator)=7), amount BLOB NOT NULL CHECK(typeof(amount)='blob' AND length(amount)=16), earning_epoch BLOB NOT NULL CHECK(typeof(earning_epoch)='blob' AND length(earning_epoch)=8), hold_epochs BLOB NOT NULL CHECK(typeof(hold_epochs)='blob' AND length(hold_epochs)=8)) WITHOUT ROWID",
    ),
    (
        "states",
        "CREATE TABLE states (slot BLOB PRIMARY KEY CHECK(typeof(slot)='blob' AND length(slot)=8), hash BLOB NOT NULL UNIQUE CHECK(typeof(hash)='blob' AND length(hash)=32), payload BLOB NOT NULL CHECK(typeof(payload)='blob' AND length(payload) BETWEEN 610 AND 200000), state_id BLOB NOT NULL CHECK(typeof(state_id)='blob' AND length(state_id)=32), UNIQUE(slot,hash)) WITHOUT ROWID",
    ),
    (
        "canonical_tip",
        "CREATE TABLE canonical_tip (id INTEGER PRIMARY KEY CHECK(id=1), slot BLOB NOT NULL CHECK(typeof(slot)='blob' AND length(slot)=8), hash BLOB NOT NULL CHECK(typeof(hash)='blob' AND length(hash)=32), FOREIGN KEY(slot,hash) REFERENCES states(slot,hash))",
    ),
];
pub(super) fn triggers() -> Vec<(String, String)> {
    let mut out = vec![];
    for t in [
        "blocks",
        "bodies",
        "transactions",
        "rewards",
        "states",
        "year_zero",
    ] {
        for op in ["UPDATE", "DELETE"] {
            let name = format!("immutable_{t}_{}", op.to_lowercase());
            out.push((name.clone(),format!("CREATE TRIGGER {name} BEFORE {op} ON {t} BEGIN SELECT RAISE(ABORT,'immutable C1 history'); END")));
        }
        let predicate = match t {
            "blocks" => "slot=NEW.slot OR hash=NEW.hash OR envelope_id=NEW.envelope_id",
            "states" => "slot=NEW.slot OR hash=NEW.hash",
            "transactions" => {
                "id=NEW.id OR (slot=NEW.slot AND position=NEW.position) OR (sender=NEW.sender AND nonce=NEW.nonce)"
            }
            "year_zero" => "id=NEW.id",
            _ => "slot=NEW.slot",
        };
        let name = format!("no_replace_{t}");
        out.push((name.clone(),format!("CREATE TRIGGER {name} BEFORE INSERT ON {t} WHEN EXISTS(SELECT 1 FROM {t} WHERE {predicate}) BEGIN SELECT RAISE(ABORT,'no C1 replacement'); END")));
    }
    out.push(("metadata_policy".into(),"CREATE TRIGGER metadata_policy BEFORE UPDATE ON metadata WHEN OLD.initialized=1 AND (NEW.id IS NOT OLD.id OR NEW.version IS NOT OLD.version OR NEW.mode IS NOT OLD.mode OR NEW.genesis IS NOT OLD.genesis OR NEW.initialized<>1) BEGIN SELECT RAISE(ABORT,'immutable C1 policy'); END".into()));
    out.push(("metadata_delete".into(),"CREATE TRIGGER metadata_delete BEFORE DELETE ON metadata BEGIN SELECT RAISE(ABORT,'immutable C1 policy'); END".into()));
    out.push(("metadata_replace".into(),"CREATE TRIGGER metadata_replace BEFORE INSERT ON metadata WHEN EXISTS(SELECT 1 FROM metadata) BEGIN SELECT RAISE(ABORT,'no policy replacement'); END".into()));
    out
}
pub(super) fn error(e: rusqlite::Error) -> Error {
    Error::Storage(disk::invalid(e))
}
pub(super) fn configure(c: &Connection) -> Result<(), Error> {
    disk::configure(c)?;
    let cache: i64 = c
        .query_row("PRAGMA cache_size", [], |r| r.get(0))
        .map_err(error)?;
    let spill: i64 = c
        .query_row("PRAGMA cache_spill", [], |r| r.get(0))
        .map_err(error)?;
    if cache != -2000 || spill <= 0 {
        return Err(invalid("required default cache/spill"));
    }
    Ok(())
}
pub(super) fn settings(c: &Connection) -> Result<StorageSettings, Error> {
    let q = |s| c.query_row(s, [], |r| r.get::<_, i64>(0)).map_err(error);
    Ok(StorageSettings {
        journal_mode: c
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .map_err(error)?,
        synchronous: q("PRAGMA synchronous")?,
        foreign_keys: q("PRAGMA foreign_keys")? == 1,
        page_size: q("PRAGMA page_size")?,
        cache_size: q("PRAGMA cache_size")?,
    })
}
fn schema(c: &Connection) -> Result<(), Error> {
    let present: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='metadata')",
            [],
            |r| r.get(0),
        )
        .map_err(error)?;
    if !present {
        return Err(StoreError::Uninitialized.into());
    }
    let mut expected: BTreeMap<(String, String), String> = TABLES
        .iter()
        .map(|(n, ddl)| (("table".into(), (*n).into()), (*ddl).into()))
        .collect();
    for (n, ddl) in triggers() {
        expected.insert(("trigger".into(), n), ddl);
    }
    let mut q=c.prepare("SELECT type,name,sql FROM sqlite_schema WHERE substr(name,1,7)<>'sqlite_' ORDER BY type,name").map_err(error)?;
    let actual = q
        .query_map([], |r| Ok(((r.get(0)?, r.get(1)?), r.get(2)?)))
        .map_err(error)?
        .collect::<rusqlite::Result<BTreeMap<(String, String), String>>>()
        .map_err(error)?;
    if actual != expected {
        return Err(invalid("exact schema4 tables/indexes/triggers"));
    }
    if c.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
        .map_err(error)?
        != "ok"
    {
        return Err(invalid("integrity"));
    }
    if c.prepare("PRAGMA foreign_key_check")
        .map_err(error)?
        .query([])
        .map_err(error)?
        .next()
        .map_err(error)?
        .is_some()
    {
        return Err(invalid("foreign keys"));
    }
    Ok(())
}
type Rows = Vec<Vec<Vec<u8>>>;
// Fixed table/column/order, byte-width bounds, row bound and the exact owned expected projection.
type MaterializationCheck<'a> = (&'a str, &'a str, &'a str, &'a [(usize, usize)], usize, Rows);
// Every allocation is bounded before copying a borrowed SQLite value. Rows/columns/order are
// fixed code-defined names, never peer/SQL strings. Comparison includes extra/missing rows.
fn rows(
    c: &Connection,
    table: &str,
    columns: &str,
    order: &str,
    widths: &[(usize, usize)],
    limit: usize,
) -> Result<Rows, Error> {
    let mut q = c
        .prepare(&format!("SELECT {columns} FROM {table} ORDER BY {order}"))
        .map_err(error)?;
    let mut cursor = q.query([]).map_err(error)?;
    let mut out = vec![];
    while let Some(r) = cursor.next().map_err(error)? {
        if out.len() >= limit {
            return Err(invalid(format!("{table} row bound")));
        }
        let mut row = vec![];
        for (i, (min, max)) in widths.iter().enumerate() {
            row.push(blob(r, i, *min, *max)?.to_vec());
        }
        out.push(row);
    }
    Ok(out)
}
fn blob<'a>(r: &'a Row<'_>, i: usize, min: usize, max: usize) -> Result<&'a [u8], Error> {
    match r.get_ref(i).map_err(error)? {
        ValueRef::Blob(b) if (min..=max).contains(&b.len()) => Ok(b),
        _ => Err(invalid("bounded unsigned BLOB")),
    }
}
fn policy(c: &Connection, g: &Genesis) -> Result<u64, Error> {
    let n: i64 = c
        .query_row("SELECT count(*) FROM metadata", [], |r| r.get(0))
        .map_err(error)?;
    if n != 1 {
        return Err(StoreError::Uninitialized.into());
    }
    let mut q = c
        .prepare(
            "SELECT version,mode,genesis,revision,barrier,initialized FROM metadata WHERE id=1",
        )
        .map_err(error)?;
    let mut cursor = q.query([]).map_err(error)?;
    let r = cursor
        .next()
        .map_err(error)?
        .ok_or_else(|| invalid("metadata singleton"))?;
    if blob(r, 0, 4, 4)? != 4u32.to_be_bytes()
        || r.get_ref(1).map_err(error)? != ValueRef::Text(b"native-poash-c1")
        || blob(r, 2, 1, MAX_GENESIS_BYTES)? != g.canonical_bytes()
        || r.get::<_, i64>(5).map_err(error)? != 1
    {
        return Err(invalid("independent exact genesis/schema policy"));
    }
    blob(r, 4, 8, 8)?;
    Ok(u64::from_be_bytes(
        blob(r, 3, 8, 8)?.try_into().expect("width"),
    ))
}
fn year_bytes(g: &Genesis) -> Vec<u8> {
    let mut b = vec![];
    g.year_zero().encode(&mut b);
    b
}
fn state_row(s: &ClosedState) -> Vec<Vec<u8>> {
    vec![
        s.position().slot.to_be_bytes().to_vec(),
        s.position().hash.to_vec(),
        s.canonical_bytes().to_vec(),
        s.id().to_vec(),
    ]
}
fn block_row(r: &Record) -> Vec<Vec<u8>> {
    let e = r.proof.envelope();
    let b = e.block();
    let h = b.claim().header();
    vec![
        h.slot.to_be_bytes().to_vec(),
        b.hash().to_vec(),
        h.parent_hash.to_vec(),
        h.canonical_bytes().to_vec(),
        b.claim().producer().as_bytes().to_vec(),
        b.protocol_data().canonical_bytes(),
        e.signature_bytes().to_vec(),
        e.id().to_vec(),
    ]
}
fn body_row(r: &Record) -> Vec<Vec<u8>> {
    vec![
        r.state.position().slot.to_be_bytes().to_vec(),
        (r.proof.envelope().block().transactions().len() as u64)
            .to_be_bytes()
            .to_vec(),
        r.outcome.gas_used.to_be_bytes().to_vec(),
        r.outcome.fees_burned.to_be_bytes().to_vec(),
    ]
}
fn reward_row(r: &Record) -> Vec<Vec<u8>> {
    let c = r
        .state
        .input()
        .credits
        .last()
        .expect("complete compound credit");
    vec![
        c.slot.to_be_bytes().to_vec(),
        c.validator.as_bytes().to_vec(),
        c.amount.to_be_bytes().to_vec(),
        0u64.to_be_bytes().to_vec(),
        REWARD_HOLD_EPOCHS.to_be_bytes().to_vec(),
    ]
}
fn transaction_rows(r: &Record) -> Rows {
    r.proof
        .envelope()
        .block()
        .transactions()
        .iter()
        .zip(&r.outcome.transaction_ids)
        .enumerate()
        .map(|(i, (bytes, id))| {
            let (sender, nonce) = sender_nonce(bytes);
            vec![
                id.to_vec(),
                r.state.position().slot.to_be_bytes().to_vec(),
                (i as u64).to_be_bytes().to_vec(),
                sender.to_vec(),
                nonce.to_be_bytes().to_vec(),
                bytes.to_vec(),
            ]
        })
        .collect()
}
fn accounting_row(s: &ClosedState) -> Result<Vec<Vec<u8>>, Error> {
    let d = s.input();
    let supply = INITIAL_SUPPLY
        .checked_add(d.base_issuance)
        .and_then(|n| n.checked_sub(d.fees_burned))
        .ok_or_else(overflow)?;
    Ok(vec![
        d.gas_used.to_be_bytes().to_vec(),
        d.fees_burned.to_be_bytes().to_vec(),
        d.base_issuance.to_be_bytes().to_vec(),
        supply.to_be_bytes().to_vec(),
        d.position.slot.to_be_bytes().to_vec(),
        d.fees_burned.to_be_bytes().to_vec(),
    ])
}
/// Exact complete stored base check, used under BEGIN IMMEDIATE. No authentication or native
/// application occurs here: compare immutable bytes and redundant state/index rows to owned values.
pub(super) fn verify(c: &Connection, g: &Genesis, s: &Snapshot) -> Result<(), Error> {
    schema(c)?;
    if policy(c, g)? != s.tip().slot {
        return Err(invalid("revision/base"));
    }
    let specs: [MaterializationCheck<'_>; 8] = [
        (
            "accounts",
            "address,balance,nonce",
            "address",
            &[(20, 20), (16, 16), (8, 8)],
            MAX_ACCOUNTS,
            s.state
                .input()
                .accounts
                .iter()
                .map(|a| {
                    vec![
                        a.address.to_vec(),
                        a.balance.to_be_bytes().to_vec(),
                        a.nonce.to_be_bytes().to_vec(),
                    ]
                })
                .collect(),
        ),
        (
            "accounting",
            "gas,fees,issuance,supply,participation,eligible_fee_burn",
            "id",
            &[(8, 8), (16, 16), (16, 16), (16, 16), (8, 8), (16, 16)],
            1,
            vec![accounting_row(&s.state)?],
        ),
        (
            "year_zero",
            "record",
            "id",
            &[(120, 120)],
            1,
            vec![vec![year_bytes(g)]],
        ),
        (
            "blocks",
            "slot,hash,parent,header,producer,protocol,signature,envelope_id",
            "slot",
            &[
                (8, 8),
                (32, 32),
                (32, 32),
                (229, 229),
                (7, 7),
                (10, 10),
                (65, 65),
                (32, 32),
            ],
            MAX_SLOTS as usize,
            s.records.iter().map(block_row).collect(),
        ),
        (
            "bodies",
            "slot,count,gas,fees",
            "slot",
            &[(8, 8); 4],
            MAX_SLOTS as usize,
            s.records.iter().map(body_row).collect(),
        ),
        (
            "states",
            "slot,hash,payload,state_id",
            "slot",
            &[(8, 8), (32, 32), (610, 200000), (32, 32)],
            MAX_SLOTS as usize + 1,
            std::iter::once(state_row(g.initial_state()))
                .chain(s.records.iter().map(|r| state_row(&r.state)))
                .collect(),
        ),
        (
            "rewards",
            "slot,validator,amount,earning_epoch,hold_epochs",
            "slot",
            &[(8, 8), (7, 7), (16, 16), (8, 8), (8, 8)],
            MAX_SLOTS as usize,
            s.records.iter().map(reward_row).collect(),
        ),
        (
            "canonical_tip",
            "slot,hash",
            "id",
            &[(8, 8), (32, 32)],
            1,
            vec![vec![
                s.tip().slot.to_be_bytes().to_vec(),
                s.tip().hash.to_vec(),
            ]],
        ),
    ];
    for (table, cols, order, widths, limit, expected) in specs {
        if rows(c, table, cols, order, widths, limit)? != expected {
            return Err(invalid(format!("exact {table} materialization")));
        }
    }
    let expected: Rows = s.records.iter().flat_map(transaction_rows).collect();
    if rows(
        c,
        "transactions",
        "id,slot,position,sender,nonce,signed",
        "slot,position",
        &[(32, 32), (8, 8), (8, 8), (20, 20), (8, 8), (199, 199)],
        (MAX_SLOTS * MAX_ENTRIES) as usize,
    )? != expected
    {
        return Err(invalid("exact native indexes/body"));
    }
    Ok(())
}
pub(super) fn write_accounts(c: &Connection, s: &ClosedState) -> Result<(), Error> {
    let mut q=c.prepare("INSERT INTO accounts VALUES(?1,?2,?3) ON CONFLICT(address) DO UPDATE SET balance=excluded.balance,nonce=excluded.nonce").map_err(error)?;
    for a in &s.input().accounts {
        q.execute(params![
            a.address.as_slice(),
            a.balance.to_be_bytes().as_slice(),
            a.nonce.to_be_bytes().as_slice()
        ])
        .map_err(error)?;
    }
    Ok(())
}
pub(super) fn write_accounting(c: &Connection, s: &ClosedState) -> Result<(), Error> {
    let row = accounting_row(s)?;
    c.execute("INSERT INTO accounting VALUES(1,?1,?2,?3,?4,?5,?6) ON CONFLICT(id) DO UPDATE SET gas=excluded.gas,fees=excluded.fees,issuance=excluded.issuance,supply=excluded.supply,participation=excluded.participation,eligible_fee_burn=excluded.eligible_fee_burn",rusqlite::params_from_iter(row)).map_err(error)?;
    Ok(())
}
fn insert(c: &Connection, table: &str, row: Vec<Vec<u8>>) -> Result<(), Error> {
    let placeholders = (1..=row.len())
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(",");
    c.execute(
        &format!("INSERT INTO {table} VALUES({placeholders})"),
        rusqlite::params_from_iter(row),
    )
    .map_err(error)?;
    Ok(())
}
pub(super) fn insert_block(c: &Connection, r: &Record) -> Result<(), Error> {
    insert(c, "blocks", block_row(r))
}
pub(super) fn insert_body(c: &Connection, r: &Record) -> Result<(), Error> {
    insert(c, "bodies", body_row(r))
}
pub(super) fn insert_transactions(c: &Connection, r: &Record) -> Result<(), Error> {
    for row in transaction_rows(r) {
        insert(c, "transactions", row)?;
    }
    Ok(())
}
pub(super) fn insert_reward(c: &Connection, r: &Record) -> Result<(), Error> {
    insert(c, "rewards", reward_row(r))
}
pub(super) fn insert_state(c: &Connection, s: &ClosedState) -> Result<(), Error> {
    insert(c, "states", state_row(s))
}
pub(super) fn initialize(
    c: &Connection,
    g: &Genesis,
    point: &mut impl FnMut(&str) -> Result<(), Error>,
) -> Result<(), Error> {
    for (_, ddl) in TABLES {
        c.execute_batch(ddl).map_err(error)?;
    }
    for (_, ddl) in triggers() {
        c.execute_batch(&ddl).map_err(error)?;
    }
    point("init_schema")?;
    c.execute(
        "INSERT INTO metadata VALUES(1,x'00000004','native-poash-c1',?1,?2,?2,0)",
        params![g.canonical_bytes(), 0u64.to_be_bytes().as_slice()],
    )
    .map_err(error)?;
    point("init_policy")?;
    c.execute("INSERT INTO year_zero VALUES(1,?1)", [year_bytes(g)])
        .map_err(error)?;
    point("init_year")?;
    write_accounts(c, g.initial_state())?;
    point("init_accounts")?;
    write_accounting(c, g.initial_state())?;
    point("init_accounting")?;
    insert_state(c, g.initial_state())?;
    point("init_state")?;
    c.execute(
        "INSERT INTO canonical_tip VALUES(1,?1,?2)",
        params![0u64.to_be_bytes().as_slice(), g.anchor().hash().as_slice()],
    )
    .map_err(error)?;
    point("init_tip")?;
    c.execute_batch("UPDATE metadata SET initialized=1 WHERE id=1")
        .map_err(error)?;
    point("init_marker")?;
    point("init_before_commit")?;
    Ok(())
}
pub(super) fn audit(c: &Connection, g: &Genesis) -> Result<Snapshot, Error> {
    c.execute_batch("BEGIN").map_err(error)?;
    let result = (|| -> Result<Snapshot, Error> {
        schema(c)?;
        let revision = policy(c, g)?;
        if revision > MAX_SLOTS {
            return Err(super::super::Error::ExperimentLimit.into());
        }
        let blocks = rows(
            c,
            "blocks",
            "slot,hash,parent,header,producer,protocol,signature,envelope_id",
            "slot",
            &[
                (8, 8),
                (32, 32),
                (32, 32),
                (229, 229),
                (7, 7),
                (10, 10),
                (65, 65),
                (32, 32),
            ],
            MAX_SLOTS as usize,
        )?;
        let txs = rows(
            c,
            "transactions",
            "id,slot,position,sender,nonce,signed",
            "slot,position",
            &[(32, 32), (8, 8), (8, 8), (20, 20), (8, 8), (199, 199)],
            (MAX_SLOTS * MAX_ENTRIES) as usize,
        )?;
        let mut s = Snapshot::initial(g);
        for row in blocks {
            let slot = u64::from_be_bytes(row[0].as_slice().try_into().expect("width"));
            if slot != s.tip().slot + 1 {
                return Err(super::super::Error::MissingHistory(s.tip().slot + 1).into());
            }
            let header = crate::block_commitment::BlockHeader::from_canonical_bytes(&row[3])
                .ok_or_else(|| invalid("header"))?;
            let protocol = crate::block_commitment::ProtocolData::from_canonical_bytes(&row[5])
                .ok_or_else(|| invalid("protocol"))?;
            let body: Vec<[u8; SIGNED_LEN]> = txs
                .iter()
                .filter(|tx| tx[1] == row[0])
                .map(|tx| tx[5].as_slice().try_into().expect("width"))
                .collect();
            let b = Block::from_parts(
                header,
                std::str::from_utf8(&row[4]).map_err(invalid)?.into(),
                protocol,
                body,
            )?;
            let e = Envelope::from_parts(
                b,
                g.network_id(),
                row[6].as_slice().try_into().expect("width"),
            );
            let proof = e.authenticate(g)?;
            let view = s.prefix(g)?.slot_start()?;
            view.plan(proof.header())?;
            let body: Vec<_> = proof
                .envelope()
                .block()
                .transactions()
                .iter()
                .map(|b| b.to_vec())
                .collect();
            let (native, applied) = app::stage_native(&view, &body)?;
            let state = app::compound(&view, proof.envelope().block(), native, &applied.outcome)?;
            s.insert(Record {
                proof,
                outcome: applied.outcome,
                state,
            })?;
        }
        if revision != s.tip().slot {
            return Err(super::super::Error::MissingHistory(s.tip().slot + 1).into());
        }
        // Includes EVERY per-slot state, original S/E-ID, year record, reward, index and current total.
        // Audit never trusts stored post-states as execution inputs or recalculates from current supply.
        verify(c, g, &s)?;
        Ok(s)
    })();
    let end = c.execute_batch("ROLLBACK").map_err(error);
    result.and_then(|s| end.map(|_| s))
}
pub(super) fn barrier(c: &Connection, path: &Path, g: &Genesis, s: &Snapshot) -> Result<(), Error> {
    c.execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| uncertain(error(e)))?;
    let work = (|| -> Result<(), Error> {
        // Recheck all audited bytes under the writer lock, closing load/barrier concurrent-writer races.
        verify(c, g, s)?;
        let old = c
            .query_row("SELECT barrier FROM metadata WHERE id=1", [], |r| {
                disk::blob::<8>(r, 0)
            })
            .map_err(error)?;
        let next = u64::from_be_bytes(old)
            .checked_add(1)
            .ok_or_else(overflow)?;
        if c.execute(
            "UPDATE metadata SET barrier=?1 WHERE id=1 AND barrier=?2",
            params![next.to_be_bytes().as_slice(), old.as_slice()],
        )
        .map_err(error)?
            != 1
        {
            return Err(invalid("barrier CAS"));
        }
        c.execute_batch("COMMIT").map_err(error)?;
        disk::sync_path(path)?;
        Ok(())
    })();
    work.map_err(uncertain)
}
