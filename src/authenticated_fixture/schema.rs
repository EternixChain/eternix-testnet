//! Independent schema 3: compact evidence on blocks; schema 1/2 definitions remain unchanged.
//! UInts are fixed BE BLOBs, keys/names are declarations compared to independent caller policy.
pub(super) const TABLES: &[(&str, &str)] = &[
    (
        "metadata",
        "CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), schema_version BLOB NOT NULL CHECK(typeof(schema_version)='blob' AND schema_version=x'00000003'), mode TEXT NOT NULL CHECK(mode='offline-authenticated-native-blocks'), chain BLOB NOT NULL CHECK(typeof(chain)='blob' AND length(chain)=8), network BLOB NOT NULL CHECK(typeof(network)='blob' AND length(network)=32), rules BLOB NOT NULL CHECK(typeof(rules)='blob' AND rules=x'00000001'), provenance TEXT NOT NULL CHECK(length(provenance)>0), seed_gas BLOB NOT NULL CHECK(typeof(seed_gas)='blob' AND length(seed_gas)=8), seed_burn BLOB NOT NULL CHECK(typeof(seed_burn)='blob' AND length(seed_burn)=16), seed_count BLOB NOT NULL CHECK(typeof(seed_count)='blob' AND length(seed_count)=8), revision BLOB NOT NULL CHECK(typeof(revision)='blob' AND length(revision)=8), barrier BLOB NOT NULL CHECK(typeof(barrier)='blob' AND length(barrier)=8), anchor_hash BLOB NOT NULL CHECK(typeof(anchor_hash)='blob' AND length(anchor_hash)=32), wire BLOB NOT NULL CHECK(typeof(wire)='blob' AND wire=x'02'), profile BLOB NOT NULL CHECK(typeof(profile)='blob' AND profile=x'00000002'), initialized INTEGER NOT NULL CHECK(initialized IN (0,1)), outer_wire BLOB NOT NULL CHECK(typeof(outer_wire)='blob' AND outer_wire=x'03'), auth_encoding BLOB NOT NULL CHECK(typeof(auth_encoding)='blob' AND auth_encoding=x'01'), auth_rules BLOB NOT NULL CHECK(typeof(auth_rules)='blob' AND auth_rules=x'00000001'), producer_count BLOB NOT NULL CHECK(typeof(producer_count)='blob' AND length(producer_count)=8))",
    ),
    (
        "producer_bindings",
        "CREATE TABLE producer_bindings (producer BLOB PRIMARY KEY CHECK(typeof(producer)='blob' AND length(producer) BETWEEN 1 AND 256), public_key BLOB NOT NULL UNIQUE CHECK(typeof(public_key)='blob' AND length(public_key)=33 AND substr(public_key,1,1) IN (x'02',x'03'))) WITHOUT ROWID",
    ),
    (
        "seed_accounts",
        "CREATE TABLE seed_accounts (address BLOB PRIMARY KEY CHECK(typeof(address)='blob' AND length(address)=20), balance BLOB NOT NULL CHECK(typeof(balance)='blob' AND length(balance)=16), nonce BLOB NOT NULL CHECK(typeof(nonce)='blob' AND length(nonce)=8)) WITHOUT ROWID",
    ),
    (
        "accounts",
        "CREATE TABLE accounts (address BLOB PRIMARY KEY CHECK(typeof(address)='blob' AND length(address)=20), balance BLOB NOT NULL CHECK(typeof(balance)='blob' AND length(balance)=16), nonce BLOB NOT NULL CHECK(typeof(nonce)='blob' AND length(nonce)=8)) WITHOUT ROWID",
    ),
    (
        "accounting",
        "CREATE TABLE accounting (id INTEGER PRIMARY KEY CHECK(id=1), gas BLOB NOT NULL CHECK(typeof(gas)='blob' AND length(gas)=8), burn BLOB NOT NULL CHECK(typeof(burn)='blob' AND length(burn)=16))",
    ),
    (
        "blocks",
        "CREATE TABLE blocks (hash BLOB PRIMARY KEY CHECK(typeof(hash)='blob' AND length(hash)=32), slot BLOB NOT NULL UNIQUE CHECK(typeof(slot)='blob' AND length(slot)=8), revision BLOB NOT NULL UNIQUE CHECK(typeof(revision)='blob' AND length(revision)=8), header BLOB NOT NULL CHECK(typeof(header)='blob' AND length(header)=229), proposer BLOB NOT NULL CHECK(typeof(proposer)='blob' AND length(proposer) BETWEEN 1 AND 256), protocol_data BLOB NOT NULL CHECK(typeof(protocol_data)='blob' AND length(protocol_data)=10), parent BLOB NOT NULL CHECK(typeof(parent)='blob' AND length(parent)=32), body_revision BLOB NOT NULL CHECK(typeof(body_revision)='blob' AND body_revision=revision), is_anchor INTEGER NOT NULL, producer_signature BLOB, signed_envelope_id BLOB UNIQUE, CHECK((revision=x'0000000000000000' AND is_anchor=1 AND producer_signature IS NULL AND signed_envelope_id IS NULL) OR (revision<>x'0000000000000000' AND is_anchor=0 AND producer_signature IS NOT NULL AND typeof(producer_signature)='blob' AND length(producer_signature)=65 AND signed_envelope_id IS NOT NULL AND typeof(signed_envelope_id)='blob' AND length(signed_envelope_id)=32)), UNIQUE(hash,revision,slot), FOREIGN KEY(body_revision) REFERENCES bodies(revision) DEFERRABLE INITIALLY DEFERRED) WITHOUT ROWID",
    ),
    (
        "bodies",
        "CREATE TABLE bodies (revision BLOB PRIMARY KEY CHECK(typeof(revision)='blob' AND length(revision)=8), block_hash BLOB NOT NULL UNIQUE CHECK(typeof(block_hash)='blob' AND length(block_hash)=32), slot BLOB NOT NULL CHECK(typeof(slot)='blob' AND length(slot)=8), encoding BLOB NOT NULL CHECK(typeof(encoding)='blob' AND encoding=x'02'), rules BLOB NOT NULL CHECK(typeof(rules)='blob' AND rules=x'00000001'), count BLOB NOT NULL CHECK(typeof(count)='blob' AND length(count)=8), gas BLOB NOT NULL CHECK(typeof(gas)='blob' AND length(gas)=8), burn BLOB NOT NULL CHECK(typeof(burn)='blob' AND length(burn)=8), FOREIGN KEY(block_hash,revision,slot) REFERENCES blocks(hash,revision,slot) DEFERRABLE INITIALLY DEFERRED) WITHOUT ROWID",
    ),
    (
        "transactions",
        "CREATE TABLE transactions (id BLOB PRIMARY KEY CHECK(typeof(id)='blob' AND length(id)=32), revision BLOB NOT NULL REFERENCES bodies(revision), position BLOB NOT NULL CHECK(typeof(position)='blob' AND length(position)=8), sender BLOB NOT NULL CHECK(typeof(sender)='blob' AND length(sender)=20), nonce BLOB NOT NULL CHECK(typeof(nonce)='blob' AND length(nonce)=8), signed BLOB NOT NULL CHECK(typeof(signed)='blob' AND length(signed)=199), UNIQUE(revision,position), UNIQUE(sender,nonce)) WITHOUT ROWID",
    ),
    (
        "canonical_tip",
        "CREATE TABLE canonical_tip (id INTEGER PRIMARY KEY CHECK(id=1), hash BLOB NOT NULL CHECK(typeof(hash)='blob' AND length(hash)=32), slot BLOB NOT NULL CHECK(typeof(slot)='blob' AND length(slot)=8), revision BLOB NOT NULL CHECK(typeof(revision)='blob' AND length(revision)=8), FOREIGN KEY(hash,revision,slot) REFERENCES blocks(hash,revision,slot))",
    ),
];

/// Fixed order/names/statements are part of the local schema contract, not runtime policy.
pub(super) fn triggers() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for table in [
        "blocks",
        "bodies",
        "transactions",
        "seed_accounts",
        "producer_bindings",
    ] {
        for op in ["UPDATE", "DELETE"] {
            let name = format!("immutable_{table}_{}", op.to_lowercase());
            out.push((name.clone(),format!("CREATE TRIGGER {name} BEFORE {op} ON {table} BEGIN SELECT RAISE(ABORT,'immutable authenticated archive'); END")));
        }
    }
    for table in ["seed_accounts", "producer_bindings"] {
        let name = format!("no_new_{table}");
        out.push((name.clone(),format!("CREATE TRIGGER {name} BEFORE INSERT ON {table} WHEN (SELECT initialized FROM metadata WHERE id=1)=1 BEGIN SELECT RAISE(ABORT,'immutable fixture policy'); END")));
    }
    out.push(("bound_producer".into(),"CREATE TRIGGER bound_producer BEFORE INSERT ON blocks WHEN NEW.is_anchor=0 AND NOT EXISTS(SELECT 1 FROM producer_bindings WHERE producer=NEW.proposer) BEGIN SELECT RAISE(ABORT,'unknown declared producer'); END".into()));
    out.push(("no_block_replace".into(),"CREATE TRIGGER no_block_replace BEFORE INSERT ON blocks WHEN EXISTS(SELECT 1 FROM blocks WHERE hash=NEW.hash OR slot=NEW.slot OR revision=NEW.revision) BEGIN SELECT RAISE(ABORT,'no archive replacement'); END".into()));
    out.push(("metadata_delete".into(),"CREATE TRIGGER metadata_delete BEFORE DELETE ON metadata BEGIN SELECT RAISE(ABORT,'immutable metadata'); END".into()));
    let fields = [
        "id",
        "schema_version",
        "mode",
        "chain",
        "network",
        "rules",
        "provenance",
        "seed_gas",
        "seed_burn",
        "seed_count",
        "anchor_hash",
        "wire",
        "profile",
        "outer_wire",
        "auth_encoding",
        "auth_rules",
        "producer_count",
    ];
    let predicate = fields
        .iter()
        .map(|f| format!("NEW.{f} IS NOT OLD.{f}"))
        .collect::<Vec<_>>()
        .join(" OR ");
    out.push(("metadata_policy".into(),format!("CREATE TRIGGER metadata_policy BEFORE UPDATE ON metadata WHEN OLD.initialized=1 AND (NEW.initialized<>1 OR {predicate}) BEGIN SELECT RAISE(ABORT,'immutable policy metadata'); END")));
    out
}
