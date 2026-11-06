#!/usr/bin/env python3
"""Independent P2.2 codec/signature/compound-state goldens; no Rust or SQLite calls.

Only published small-integer test points are used. Explicit integer packing and OpenSSL Keccak,
independent public-test ECDSA/recovery, and a separate body-ordered monetary calculation reproduce
the fixed bundle. --emit prints candidate vectors; this program never replaces a fixture.
"""
import json
from pathlib import Path
import struct
import sys
import reproduce_native_poash_eligibility as p
from reproduce_native_auth_vectors import OpenSSLKeccak, recover, sign_test_vector, SIGN_DOMAIN, ID_DOMAIN

ROOT = Path(__file__).resolve().parents[1]


def snapshot(slot, parent, accounts, counts, credits, gas, fees):
    """Complete C1 state bytes, retaining the original boundary record despite current supply."""
    out = struct.pack(">IQ32sI", 1, slot, parent, len(accounts))
    for address, (balance, nonce) in sorted(accounts.items()):
        out += address + p.u128(balance) + struct.pack(">Q", nonce)
    out += struct.pack(">H", 2)
    for name in p.IDS:
        locked = counts[name] * p.R0
        out += (p.text(name) + b"\0" + p.u128(p.V0 + locked) + p.u128(locked)
                + struct.pack(">IIQ", 0, 0, counts[name]) + b"\0")
    out += struct.pack(">H", 2)
    for t in p.TICKETS:
        out += struct.pack(">Q", t["id"]) + p.text(t["owner"]) + bytes([3, 0, 0, 0])
    out += struct.pack(">H", len(credits))
    for earning, name in credits:
        out += struct.pack(">Q", earning) + p.text(name) + p.u128(p.R0) + struct.pack(">QQ", 0, 4)
    out += struct.pack(">Q", gas)
    out += b"".join(p.u128(n) for n in (fees, 2*p.T, slot*p.R0, 0, 0, 0, 0))
    out += bytes(24) + struct.pack(">QQQ", 0, 0, 1)
    out += b"".join(p.u128(n) for n in (p.S0, 3, 50, p.R0, 0, 50*p.YEAR))
    return out


def calculate():
    k = OpenSSLKeccak()
    try:
        empty = k(b"ETERNIX_TX_LIST_V1" + bytes(8))
        receipts = k(b"ETERNIX_RECEIPT_LIST_V1" + bytes(8))

        def header(slot, parent, name, ticket, txs):
            ids = [k(ID_DOMAIN + tx) for tx in txs]
            root = k(b"ETERNIX_TX_LIST_V1" + struct.pack(">Q", len(ids)) + b"".join(ids))
            pd = b"\x01" + struct.pack(">Q", len(txs)*10000) + b"\0"
            proposer = k(b"ETERNIX_PROPOSER_ID_V1" + struct.pack(">Q", len(name)) + name.encode())
            h = struct.pack(">IQQB32s32sQ32s32s32sQ32s", 3, 1162, slot, 0, parent,
                            proposer, ticket, root, bytes(32), receipts, len(txs)*1000,
                            k(b"ETERNIX_PROTOCOL_DATA_V1" + pd))
            return h, pd, ids

        anchor, _, _ = header(0, bytes(32), "c1-anchor", 1, [])
        anchor_h = k(b"ETERNIX_BLOCK_HEADER_V1" + anchor)
        accounts = {a: [b, 0] for a, b in p.SEEDS}
        counts = {n: 0 for n in p.IDS}
        initial = snapshot(0, anchor_h, accounts, counts, [], 0, 0)
        roster = struct.pack(">H", 2) + b"".join(p.text(n)+p.POINTS[n]+p.OWNERS[n]*2+p.u128(p.V0) for n in p.IDS)
        genesis = (b"ETERNIX_POASH_C1_GENESIS\0" + struct.pack(">I", 1) + p.text(p.RUN)
                   + p.parameters() + anchor + roster + struct.pack(">I", len(initial)) + initial)
        old = json.loads((ROOT/"tests/fixtures/native_poash_eligibility.json").read_text())
        assert genesis.hex() == "".join(old["genesis"]["hex_parts"])
        network = k(genesis)
        alice, bob = p.OWNERS["trial-A"], p.OWNERS["trial-B"]
        carol = bytes.fromhex("1eff47bc3a10a45d4b230b5d10e37751fe6aa718")
        # (public test scalar, recipient, value, exact nonce). Zero credit does not create an account.
        workload = {2: [(1, bob, 1000000, 0), (3, carol, 20000, 0),
                        (1, alice, 123, 1), (1, b"\x77"*20, 0, 2)],
                    3: [(3, carol, 0, 1)], 4: [(4, carol, 5000, 0)]}
        senders = {1: alice, 3: bob, 4: carol}
        hashes = [anchor_h]; credits = []; gas = fees = 0; vectors = []
        for slot in range(1, 66):
            reference = network if slot < 32 else hashes[slot-32]
            selection = p.select(k, reference, slot, p.TICKETS)
            txs = []
            for scalar, recipient, value, nonce in workload.get(slot, []):
                sender = senders[scalar]
                unsigned = struct.pack(">BIQ32sB20sQ20sQ16sQQ", 2, 1, 1162, network, 0,
                                       sender, nonce, recipient, 0, p.u128(value), 1001, 0)
                digest = k(SIGN_DOMAIN + unsigned)
                sig = sign_test_vector(scalar, digest)
                recover(digest, sig)  # independent OpenSSL ECDSA verification too
                txs.append(unsigned + sig)
                assert accounts[sender][1] == nonce and accounts[sender][0] >= value+10000
                accounts[sender][0] -= value+10000; accounts[sender][1] += 1
                if value:
                    accounts.setdefault(recipient, [0, 0])[0] += value
                gas += 1000; fees += 10000
            h, pd, ids = header(slot, hashes[-1], selection["producer"], selection["ticket"], txs)
            block_h = k(b"ETERNIX_BLOCK_HEADER_V1" + h)
            inner = (b"\x04"+block_h+h+struct.pack(">I", 7)+selection["producer"].encode()
                     +struct.pack(">I", 10)+pd+struct.pack(">Q", len(txs))
                     +b"".join(struct.pack(">I", 199)+tx for tx in txs))
            pre = b"\x19ETERNIX\0BLOCK_SIGN\0"+struct.pack(">BBIQ32sI32s", 4, 1, 2, 1162, network, 3, block_h)
            counts[selection["producer"]] += 1; credits.append((slot, selection["producer"]))
            hashes.append(block_h)
            state = snapshot(slot, block_h, accounts, counts, credits, gas, fees)
            supply = sum(a[0] for a in accounts.values()) + 2*p.V0 + slot*p.R0
            assert supply == p.S0 + slot*p.R0 - fees
            if slot <= 5 or slot in (31, 32, 33, 64, 65):
                digest = k(pre); scalar = 2 if selection["producer"] == "trial-A" else 5
                signature = sign_test_vector(scalar, digest)
                point = recover(digest, signature)
                assert bytes([2+point[1]%2])+point[0].to_bytes(32,"big") == p.POINTS[selection["producer"]]
                prefix = b"\x04\x01"+struct.pack(">I", 2)+network+struct.pack(">I", len(inner))
                vectors.append(dict(slot=slot, producer=selection["producer"], ticket=selection["ticket"],
                    reference=reference.hex(), hash=block_h.hex(), inner_bytes=len(inner),
                    inner_keccak=k(inner).hex(), signing_digest=digest.hex(), signature=signature.hex(),
                    envelope_id=k(b"\x19ETERNIX\0BLOCK_ENVELOPE_ID\0"+prefix+inner+signature).hex(),
                    state_bytes=len(state), state_id=k(b"ETERNIX_POASH_C1_SNAPSHOT\0"+network+state).hex(),
                    gas=gas, fees=fees, issuance=slot*p.R0, supply=supply,
                    counts=dict(counts), accounts=[dict(address=a.hex(), balance=b, nonce=n) for a,(b,n) in sorted(accounts.items())],
                    transaction_ids=[i.hex() for i in ids],
                    empty_inner=inner.hex() if slot == 1 else None))
        assert empty == k(b"ETERNIX_TX_LIST_V1"+bytes(8))
        return dict(test_only=True, format="eternix-native-poash-application-v1", network_id=network.hex(),
                    retained_year_zero_reward=p.R0, vectors=vectors)
    finally:
        k.close()


if __name__ == "__main__":
    value = calculate()
    if sys.argv[1:] == ["--emit"]:
        print(json.dumps(value, indent=2))
    elif sys.argv[1:] == ["--emit-compact"]:
        print(json.dumps(value, separators=(",", ":")))
    else:
        assert not sys.argv[1:]
        p.check(value, json.loads((ROOT/"tests/fixtures/native_poash_application.json").read_text()))
        print("independent_C1_application vectors=10 prefix_slots=65 native_entries=6 full_state_codec=true no_Rust_calls=true")
