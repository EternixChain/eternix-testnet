#!/usr/bin/env python3
"""Independently freeze/check S1 public test initialization using Python packing and OpenSSL Keccak.

No Rust codec is invoked. Published toy public-key points are derived with the existing independent
vector checker; this is test data, not a genesis/signing standard or a worker signing service.
--emit prints initial calculated data and never writes/replaces a golden.
"""
import json
import struct
import sys
from pathlib import Path
from reproduce_native_auth_vectors import G, OpenSSLKeccak, multiply

ROOT = Path(__file__).resolve().parents[1]


def public_key(number):
    """Public fixture points for already-published toy integers, never secret production material."""
    x, y = multiply(number, G)
    return bytes([2 + y % 2]) + x.to_bytes(32, "big")


def address(k, number):
    x, y = multiply(number, G)
    return k(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[12:]


def block(k, slot, parent, proposer, ticket, transactions):
    """Existing inner wire/header format, independently packed; no native execution implementation."""
    name = proposer.encode()
    ids = [k(b"\x19ETERNIX\x00NATIVE_TX_ID\x00" + tx) for tx in transactions]
    txroot = k(b"ETERNIX_TX_LIST_V1" + struct.pack(">Q", len(ids)) + b"".join(ids))
    pd = struct.pack(">BQB", 1, 10000 * len(ids), 0)
    header = struct.pack(">IQQB32s32sQ32s32s32sQ32s", 2, 1162, slot, 0, parent,
                         k(b"ETERNIX_PROPOSER_ID_V1" + struct.pack(">Q", len(name)) + name), ticket,
                         txroot, bytes(32), k(b"ETERNIX_RECEIPT_LIST_V1" + bytes(8)),
                         1000 * len(ids), k(b"ETERNIX_PROTOCOL_DATA_V1" + pd))
    identity = k(b"ETERNIX_BLOCK_HEADER_V1" + header)
    wire = (b"\x02" + identity + header + struct.pack(">I", len(name)) + name
            + struct.pack(">I", len(pd)) + pd + struct.pack(">Q", len(ids))
            + b"".join(struct.pack(">I", len(tx)) + tx for tx in transactions))
    return wire, identity, ids


def genesis(d):
    """Exact local test descriptor order; the network_id field deliberately is not encoded."""
    def text(s):
        b = s.encode("ascii")
        return struct.pack(">H", len(b)) + b
    anchor = bytes.fromhex(d["anchor_wire"])
    out = (b"ETERNIX_FIXTURE_GENESIS_S1\0" + struct.pack(">I", 1) + text(d["run_id"])
           + struct.pack(">QBIBIBBII", d["chain_id"], d["native_encoding"],
                         d["native_rules"], d["inner_wire"], d["header_profile"], d["outer_wire"],
                         d["auth_encoding"], d["auth_rules"], d["storage_schema"])
           + struct.pack(">I", len(anchor)) + anchor + text(d["provenance"]) + struct.pack(">H", 3))
    for i, seed in enumerate(d["accounts"]):
        out += (bytes([i]) + bytes.fromhex(seed["address"]) + int(seed["balance_quarks"]).to_bytes(16, "big")
                + struct.pack(">Q", seed["nonce"]))
    return (out + struct.pack(">Q", d["seed_gas"]) + int(d["seed_burn"]).to_bytes(16, "big")
            + struct.pack(">H", 1) + text(d["producer_id"]) + bytes.fromhex(d["producer_key"])
            + struct.pack(">QI", d["max_blocks"], d["max_transactions"]))


def calculate(k):
    anchor, anchor_hash, _ = block(k, 0, bytes(32), "fixture-anchor", 1, [])
    d = dict(format="eternix-fixture-profile-v1", run_id="s1-golden-2026", chain_id=1162,
             native_encoding=2, native_rules=1, inner_wire=2, header_profile=2, outer_wire=3,
             auth_encoding=1, auth_rules=1, storage_schema=3, network_id="", anchor_wire=anchor.hex(),
             provenance="controller-fixture-S1:s1-golden-2026",
             accounts=[dict(role=role, address=address(k, number).hex(),
                            balance_quarks=str(1000000000 if i == 0 else 0), nonce=0)
                       for i, (role, number) in enumerate((("alice", 1), ("bob", 3), ("carol", 4)))],
             seed_gas=0, seed_burn="0", producer_id="P", producer_key=public_key(2).hex(),
             max_blocks=200, max_transactions=16)
    raw = genesis(d)
    d["network_id"] = k(raw).hex()
    return dict(profile=d, genesis_hex=raw.hex(), anchor_hash=anchor_hash.hex())


def main():
    k = OpenSSLKeccak()
    try:
        calculated = calculate(k)
        if sys.argv[1:] == ["--emit"]:
            print(json.dumps(calculated, indent=2))
        else:
            assert not sys.argv[1:]
            d = json.loads((ROOT / "tests/fixtures/testnet_fixture_profile.json").read_text())
            raw = bytes.fromhex((ROOT / "tests/fixtures/testnet_fixture_genesis.hex").read_text().strip())
            assert d == calculated["profile"] and raw.hex() == calculated["genesis_hex"]
            assert k(raw).hex() == d["network_id"]
            print(f"independent_s1_genesis_bytes={len(raw)} network_id={d['network_id']} exact_anchor_and_seeds=true")
    finally:
        k.close()


if __name__ == "__main__":
    main()
