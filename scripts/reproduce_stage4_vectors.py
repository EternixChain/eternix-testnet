#!/usr/bin/env python3
"""Reproduce experimental offline block/manifests using independent Python packing and OpenSSL.

No Rust codecs are invoked. The existing independent native checker supplies public toy-key
RFC6979/curve arithmetic and OpenSSL Keccak; --emit prints the calculated vector for initial freezing,
never writes it. Normal operation compares the committed golden file byte-for-byte as data.
"""
import json
import struct
import sys
from pathlib import Path
from reproduce_native_auth_vectors import OpenSSLKeccak, SIGN_DOMAIN, ID_DOMAIN, G, sign_test_vector, recover


def calculate(k):
    genesis = b"ETERNIX_NATIVE_AUTH_VECTOR_GENESIS_V1"
    network = k(genesis)
    sender = k(G[0].to_bytes(32, "big") + G[1].to_bytes(32, "big"))[12:]
    recipient = b"\x22" * 20
    proposer = b"offline-validator"
    receipt = k(b"ETERNIX_RECEIPT_LIST_V1" + bytes(8))
    prop = k(b"ETERNIX_PROPOSER_ID_V1" + struct.pack(">Q", len(proposer)) + proposer)

    def transaction(nonce, value, target, gas, maturity):
        unsigned = struct.pack(">BIQ32sB20sQ20sQ16sQQ", 2, 1, 1162, network, 0, sender,
                               nonce, target, 0, value.to_bytes(16, "big"), gas, maturity)
        digest = k(SIGN_DOMAIN + unsigned)
        sig = sign_test_vector(1, digest)
        assert recover(digest, sig) == G
        return unsigned + sig

    def block(slot, parent, txs):
        ids = [k(ID_DOMAIN + tx) for tx in txs]
        root = k(b"ETERNIX_TX_LIST_V1" + struct.pack(">Q", len(txs)) + b"".join(ids))
        pd = struct.pack(">BQB", 1, 10_000 * len(txs), 0)
        pr = k(b"ETERNIX_PROTOCOL_DATA_V1" + pd)
        header = struct.pack(">IQQB32s32sQ32s32s32sQ32s", 2, 1162, slot, 0,
                             parent, prop, 7, root, bytes(32), receipt, 1000 * len(txs), pr)
        assert len(header) == 229
        identity = k(b"ETERNIX_BLOCK_HEADER_V1" + header)
        wire = (b"\x02" + identity + header + struct.pack(">I", len(proposer)) + proposer
                + struct.pack(">I", len(pd)) + pd + struct.pack(">Q", len(txs))
                + b"".join(struct.pack(">I", 199) + tx for tx in txs))
        return {"slot": slot, "parent": parent.hex(), "header": header.hex(), "hash": identity.hex(),
                "transaction_root": root.hex(), "protocol_data": pd.hex(), "wire": wire.hex(),
                "transactions": [tx.hex() for tx in txs], "ids": [i.hex() for i in ids]}

    prefix = []
    parent = bytes(32)
    for slot in range(43):
        anchor = block(slot, parent, [])
        parent = bytes.fromhex(anchor["hash"])
        prefix.append(anchor["hash"])
    base = transaction(0, 10_000_000_000, recipient, 1000, 0)
    single = block(43, parent, [base])
    empty = block(44, bytes.fromhex(single["hash"]), [])
    sequential = block(43, parent, [base, transaction(1, 0, recipient, (1 << 64) - 1, 43),
                                    transaction(2, 100_000, sender, 1001, 0)])

    def project(txs):
        # Separate public-fixture execution using Python integers, not copied Rust outcomes.
        accounts = {sender: [20_000_000_000, 0]}
        gas_total, burn_total = 7, 13
        for signed in txs:
            encoding, rules, chain, net, kind, source, nonce, target, token, value, gas_limit, maturity = struct.unpack(
                ">BIQ32sB20sQ20sQ16sQQ", signed[:134])
            assert (encoding, rules, chain, net, kind, token) == (2, 1, 1162, network, 0, 0)
            assert gas_limit >= 1000 and maturity <= 43
            value = int.from_bytes(value, "big")
            balance, current = accounts.get(source, [0, 0])
            assert current == nonce and nonce < (1 << 64) - 1
            debit = value + 10_000
            assert debit < 1 << 128 and balance >= debit
            accounts[source] = [balance - debit, nonce + 1]
            if value:
                credit, target_nonce = accounts.get(target, [0, 0])
                assert credit + value < 1 << 128
                accounts[target] = [credit + value, target_nonce]
            gas_total += 1000
            burn_total += 10_000
            assert gas_total < 1 << 64 and burn_total < 1 << 128
        return {"sender_balance": str(accounts[sender][0]), "sender_nonce": str(accounts[sender][1]),
                "recipient_balance": str(accounts[recipient][0]), "gas": str(gas_total), "burn": str(burn_total)}
    return {"test_only": True, "experimental_wire": 2, "experimental_header_profile": 2,
            "native_encoding": 2, "native_rules": 1, "chain_id": 1162,
            "canonical_genesis_hex": genesis.hex(), "network_id": network.hex(), "proposer": proposer.decode(),
            "ticket": 7, "provenance": "stage4-public-toy-anchor-42-v1",
            "post_anchor_state": {"accounts": [{"address": sender.hex(), "balance": "20000000000", "nonce": "0"}],
                                  "gas": "7", "burn": "13"},
            "prefix_hashes": prefix, "vectors": {"anchor": anchor, "single": single, "empty": empty, "sequential": sequential},
            "after_single": project([base]),
            "after_sequential": project([bytes.fromhex(b) for b in sequential["transactions"]])}


def main():
    k = OpenSSLKeccak()
    try:
        calculated = calculate(k)
        if sys.argv[1:] == ["--emit"]:
            print(json.dumps(calculated, indent=2))
        else:
            assert not sys.argv[1:], "only --emit is supported"
            path = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "stage4_native_blocks.json"
            expected = json.loads(path.read_text())
            assert expected == calculated, "experimental block/manifest golden mismatch"
            print("independent_stage4_vectors=4 prefix_headers=43 native_signatures=3 exact_codec_and_hashes=true")
            print("backend=Python struct/RFC6979/curve arithmetic; OpenSSL KECCAK-256 and ECDSA; no Rust calls")
    finally:
        k.close()


if __name__ == "__main__":
    main()
