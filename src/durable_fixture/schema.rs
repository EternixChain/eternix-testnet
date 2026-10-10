//! Local schema 1: unsigned values are fixed-width big-endian BLOBs, never SQL arithmetic.

// Exact schema definitions are verified on reopen, including constraints and unique indexes.
// The immutable seed is audit provenance, not a source from which reopen can repair live rows.
pub(super) const TABLES: &[(&str, &str)] = &[
    (
        "metadata",
        "CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), schema_version BLOB NOT NULL CHECK(typeof(schema_version)='blob' AND length(schema_version)=4), mode TEXT NOT NULL CHECK(mode='fixture-only'), chain BLOB NOT NULL CHECK(typeof(chain)='blob' AND length(chain)=8), network BLOB NOT NULL CHECK(typeof(network)='blob' AND length(network)=32), rules BLOB NOT NULL CHECK(typeof(rules)='blob' AND length(rules)=4), provenance TEXT NOT NULL CHECK(length(provenance)>0), seed_gas BLOB NOT NULL CHECK(typeof(seed_gas)='blob' AND length(seed_gas)=8), seed_burn BLOB NOT NULL CHECK(typeof(seed_burn)='blob' AND length(seed_burn)=16), seed_count BLOB NOT NULL CHECK(typeof(seed_count)='blob' AND length(seed_count)=8), revision BLOB NOT NULL CHECK(typeof(revision)='blob' AND length(revision)=8), barrier BLOB NOT NULL CHECK(typeof(barrier)='blob' AND length(barrier)=8), canonical_tip BLOB CHECK(canonical_tip IS NULL), initialized INTEGER NOT NULL CHECK(initialized IN (0,1)))",
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
        "bodies",
        "CREATE TABLE bodies (revision BLOB PRIMARY KEY CHECK(typeof(revision)='blob' AND length(revision)=8), slot BLOB NOT NULL CHECK(typeof(slot)='blob' AND length(slot)=8), encoding INTEGER NOT NULL CHECK(encoding=2), rules BLOB NOT NULL CHECK(typeof(rules)='blob' AND length(rules)=4), count BLOB NOT NULL CHECK(typeof(count)='blob' AND length(count)=8), gas BLOB NOT NULL CHECK(typeof(gas)='blob' AND length(gas)=8), burn BLOB NOT NULL CHECK(typeof(burn)='blob' AND length(burn)=8)) WITHOUT ROWID",
    ),
    (
        "transactions",
        "CREATE TABLE transactions (id BLOB PRIMARY KEY CHECK(typeof(id)='blob' AND length(id)=32), revision BLOB NOT NULL REFERENCES bodies(revision), position BLOB NOT NULL CHECK(typeof(position)='blob' AND length(position)=8), sender BLOB NOT NULL CHECK(typeof(sender)='blob' AND length(sender)=20), nonce BLOB NOT NULL CHECK(typeof(nonce)='blob' AND length(nonce)=8), signed BLOB NOT NULL CHECK(typeof(signed)='blob' AND length(signed)=199), UNIQUE(revision,position), UNIQUE(sender,nonce)) WITHOUT ROWID",
    ),
];
