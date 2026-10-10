//! Schema 2 exists only in new anchored offline files. Schema-1 NULL-tip files are never upgraded.
// Unsigned values are BE BLOBs. Deferred cyclic FKs make a block and its exact body inseparable.
pub(super) const TABLES: &[(&str, &str)] = &[
    (
        "metadata",
        "CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), schema_version BLOB NOT NULL CHECK(typeof(schema_version)='blob' AND length(schema_version)=4), mode TEXT NOT NULL CHECK(mode='offline-native-blocks'), chain BLOB NOT NULL CHECK(typeof(chain)='blob' AND length(chain)=8), network BLOB NOT NULL CHECK(typeof(network)='blob' AND length(network)=32), rules BLOB NOT NULL CHECK(typeof(rules)='blob' AND length(rules)=4), provenance TEXT NOT NULL CHECK(length(provenance)>0), seed_gas BLOB NOT NULL CHECK(typeof(seed_gas)='blob' AND length(seed_gas)=8), seed_burn BLOB NOT NULL CHECK(typeof(seed_burn)='blob' AND length(seed_burn)=16), seed_count BLOB NOT NULL CHECK(typeof(seed_count)='blob' AND length(seed_count)=8), revision BLOB NOT NULL CHECK(typeof(revision)='blob' AND length(revision)=8), barrier BLOB NOT NULL CHECK(typeof(barrier)='blob' AND length(barrier)=8), anchor_hash BLOB NOT NULL CHECK(typeof(anchor_hash)='blob' AND length(anchor_hash)=32), wire BLOB NOT NULL CHECK(wire=x'02'), profile BLOB NOT NULL CHECK(profile=x'00000002'), initialized INTEGER NOT NULL CHECK(initialized IN (0,1)))",
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
        "CREATE TABLE blocks (hash BLOB PRIMARY KEY CHECK(typeof(hash)='blob' AND length(hash)=32), slot BLOB NOT NULL UNIQUE CHECK(typeof(slot)='blob' AND length(slot)=8), revision BLOB NOT NULL UNIQUE CHECK(typeof(revision)='blob' AND length(revision)=8), header BLOB NOT NULL CHECK(typeof(header)='blob' AND length(header)=229), proposer BLOB NOT NULL CHECK(typeof(proposer)='blob' AND length(proposer) BETWEEN 1 AND 256), protocol_data BLOB NOT NULL CHECK(typeof(protocol_data)='blob' AND length(protocol_data)=10), parent BLOB NOT NULL CHECK(typeof(parent)='blob' AND length(parent)=32), body_revision BLOB NOT NULL CHECK(body_revision=revision), is_anchor INTEGER NOT NULL CHECK((revision=x'0000000000000000' AND is_anchor=1) OR (revision<>x'0000000000000000' AND is_anchor=0)), UNIQUE(hash,revision,slot), FOREIGN KEY(body_revision) REFERENCES bodies(revision) DEFERRABLE INITIALLY DEFERRED) WITHOUT ROWID",
    ),
    (
        "bodies",
        "CREATE TABLE bodies (revision BLOB PRIMARY KEY CHECK(typeof(revision)='blob' AND length(revision)=8), block_hash BLOB NOT NULL UNIQUE, slot BLOB NOT NULL CHECK(typeof(slot)='blob' AND length(slot)=8), encoding BLOB NOT NULL CHECK(encoding=x'02'), rules BLOB NOT NULL CHECK(rules=x'00000001'), count BLOB NOT NULL CHECK(typeof(count)='blob' AND length(count)=8), gas BLOB NOT NULL CHECK(typeof(gas)='blob' AND length(gas)=8), burn BLOB NOT NULL CHECK(typeof(burn)='blob' AND length(burn)=8), FOREIGN KEY(block_hash,revision,slot) REFERENCES blocks(hash,revision,slot) DEFERRABLE INITIALLY DEFERRED) WITHOUT ROWID",
    ),
    (
        "transactions",
        "CREATE TABLE transactions (id BLOB PRIMARY KEY CHECK(typeof(id)='blob' AND length(id)=32), revision BLOB NOT NULL REFERENCES bodies(revision), position BLOB NOT NULL CHECK(typeof(position)='blob' AND length(position)=8), sender BLOB NOT NULL CHECK(typeof(sender)='blob' AND length(sender)=20), nonce BLOB NOT NULL CHECK(typeof(nonce)='blob' AND length(nonce)=8), signed BLOB NOT NULL CHECK(typeof(signed)='blob' AND length(signed)=199), UNIQUE(revision,position), UNIQUE(sender,nonce)) WITHOUT ROWID",
    ),
    (
        "canonical_tip",
        "CREATE TABLE canonical_tip (id INTEGER PRIMARY KEY CHECK(id=1), hash BLOB NOT NULL, slot BLOB NOT NULL, revision BLOB NOT NULL, FOREIGN KEY(hash,revision,slot) REFERENCES blocks(hash,revision,slot))",
    ),
];
