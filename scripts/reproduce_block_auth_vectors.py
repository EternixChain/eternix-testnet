#!/usr/bin/env python3
"""Independent public-test block vectors: Python packing/curve math and OpenSSL, no Rust calls.

--emit outputs newly calculated golden data for explicit freezing. Ordinary operation compares the
entire fixture and exercises canonicality/context/key/domain rejection. Toy scalars/nonce below are
published test integers, never a secret signer or production genesis/key-registration specification.
"""
import json
import struct
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from reproduce_native_auth_vectors import (OpenSSLKeccak, N, G, multiply, nonce_candidates,
                                           recover, SIGN_DOMAIN)
from reproduce_stage4_vectors import calculate as stage4

BLOCK_SIGN = b"\x19ETERNIX\x00BLOCK_SIGN\x00"
ENVELOPE_ID = b"\x19ETERNIX\x00BLOCK_ENVELOPE_ID\x00"


def sign_public(digest, alternate=False):
    """Expose raw s/parity to independently freeze signer low-s normalization and parity correction."""
    nonce = 7 if alternate else next(nonce_candidates(2, digest))
    point = multiply(nonce, G)
    ref = ec.derive_private_key(nonce, ec.SECP256K1()).public_key().public_numbers()
    assert point == (ref.x, ref.y) and 0 < point[0] < N
    r, parity = point[0], point[1] & 1
    raw_s = pow(nonce, -1, N) * (int.from_bytes(digest, "big") + r * 2) % N
    assert raw_s != 0
    s = N - raw_s if raw_s > N // 2 else raw_s
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([parity ^ (raw_s > N // 2)])
    return sig, raw_s, parity


def calculate(k):
    old = stage4(k)  # independently rebuild existing native/header/body commitments too
    public = multiply(2, G)
    ref = ec.derive_private_key(2, ec.SECP256K1()).public_key().public_numbers()
    assert public == (ref.x, ref.y)
    compressed = bytes([2 | (public[1] & 1)]) + public[0].to_bytes(32, "big")
    uncompressed = b"\x04" + public[0].to_bytes(32, "big") + public[1].to_bytes(32, "big")
    genesis = bytes.fromhex(old["canonical_genesis_hex"])
    network = k(genesis)
    rows = []
    for name in ("empty", "single", "sequential", "empty_other_network", "extreme", "empty_alternate"):
        base = old["vectors"][name if name in old["vectors"] else "empty"]
        inner = bytes.fromhex(base["wire"])
        header = bytes.fromhex(base["header"])
        producer = b"offline-validator"
        chain, profile = 1162, 2
        net = k(b"ETERNIX_BLOCK_AUTH_OTHER_TEST_GENESIS_V1") if name == "empty_other_network" else network
        if name == "extreme":
            producer = ("é" * 128).encode()
            chain = (1 << 64) - 1
            pd = struct.pack(">BQB", 1, 0, 0)
            prop = k(b"ETERNIX_PROPOSER_ID_V1" + struct.pack(">Q", len(producer)) + producer)
            root = k(b"ETERNIX_TX_LIST_V1" + bytes(8))
            receipts = k(b"ETERNIX_RECEIPT_LIST_V1" + bytes(8))
            header = struct.pack(">IQQB32s32sQ32s32s32sQ32s", 2, chain, chain, 0, b"\x77" * 32,
                                 prop, chain, root, bytes(32), receipts, 0,
                                 k(b"ETERNIX_PROTOCOL_DATA_V1" + pd))
            identity = k(b"ETERNIX_BLOCK_HEADER_V1" + header)
            inner = (b"\x02" + identity + header + struct.pack(">I", len(producer)) + producer
                     + struct.pack(">I", 10) + pd + bytes(8))
        identity = k(b"ETERNIX_BLOCK_HEADER_V1" + header)
        payload = struct.pack(">BBIQ32sI32s", 3, 1, 1, chain, net, profile, identity)
        preimage = BLOCK_SIGN + payload
        digest = k(preimage)
        signature, raw_s, raw_parity = sign_public(digest, name == "empty_alternate")
        assert recover(digest, signature) == public
        envelope = struct.pack(">BBI32sI", 3, 1, 1, net, len(inner)) + inner + signature
        assert (len(header), len(payload), len(preimage), len(signature)) == (229, 82, 102, 65)
        assert len(envelope) == len(inner) + 107
        rows.append({"name": name, "chain_id": str(chain), "network_id": net.hex(),
                     "producer": producer.decode(), "block_hash": identity.hex(),
                     "payload": payload.hex(), "preimage": preimage.hex(), "digest": digest.hex(),
                     "signature": signature.hex(), "raw_s": f"{raw_s:064x}", "raw_parity": raw_parity,
                     "normalized_low_s": raw_s > N // 2, "deterministic": name != "empty_alternate",
                     "envelope": envelope.hex(), "envelope_id": k(ENVELOPE_ID + envelope).hex()})
    assert any(r["normalized_low_s"] for r in rows)
    assert {bytes.fromhex(r["signature"])[64] for r in rows} == {0, 1}
    assert rows[0]["block_hash"] == rows[3]["block_hash"] == rows[5]["block_hash"]
    assert len({rows[i]["envelope_id"] for i in (0, 3, 5)}) == 3
    return {"test_only": True, "published_toy_producer_scalar": 2,
            "canonical_genesis_hex": genesis.hex(), "sign_domain": BLOCK_SIGN.hex(),
            "envelope_id_domain": ENVELOPE_ID.hex(), "compressed_key": compressed.hex(),
            "uncompressed_key": uncompressed.hex(), "vectors": rows}


def rejection_checks(k, fixture):
    base = fixture["vectors"][0]
    digest, sig = bytes.fromhex(base["digest"]), bytes.fromhex(base["signature"])
    invalid = [bytes(32) + sig[32:], N.to_bytes(32, "big") + sig[32:],
               sig[:32] + bytes(32) + sig[64:], sig[:32] + N.to_bytes(32, "big") + sig[64:],
               sig[:32] + (N-int.from_bytes(sig[32:64], "big")).to_bytes(32, "big") + bytes([sig[64] ^ 1]),
               (5).to_bytes(32, "big") + (1).to_bytes(32, "big") + b"\0", sig[:64], sig+b"\0"]
    invalid += [sig[:64] + bytes([p]) for p in range(2, 256)]
    for bad in invalid:
        try:
            recover(digest, bad)
        except ValueError:
            continue
        raise AssertionError("noncanonical signature recovered")
    public = multiply(2, G)
    payload = bytes.fromhex(base["payload"])
    # These messages may recover a *different* valid key. Trusted full-key comparison is essential.
    for domain in (SIGN_DOMAIN, b"\x19Ethereum Signed Message:\n102", b"BLOCK_SIGN"):
        assert recover(k(domain+payload), sig) != public
    for i in range(len(payload)):
        changed = bytearray(payload)
        changed[i] ^= 1
        assert recover(k(BLOCK_SIGN + changed), sig) != public
    return len(invalid), len(payload)


def main():
    k = OpenSSLKeccak()
    try:
        data = calculate(k)
        invalid, mutations = rejection_checks(k, data)
        if sys.argv[1:] == ["--emit"]:
            print(json.dumps(data, ensure_ascii=False, indent=2))
        else:
            assert not sys.argv[1:], "only --emit supported"
            path = Path(__file__).resolve().parents[1] / "tests/fixtures/block_authentication.json"
            expected = json.loads(path.read_text())
            # Literal prefix + existing frozen inner bytes + literal S freeze the complete E without
            # duplicating old native goldens. The extreme inner is frozen as literal hex chunks.
            native_fixture = json.loads((path.parent / "stage4_native_blocks.json").read_text())
            for row in expected["vectors"]:
                inner = row.pop("inner")
                inner_hex = native_fixture["vectors"][inner]["wire"] if isinstance(inner, str) else "".join(inner)
                row["envelope"] = row.pop("outer_prefix") + inner_hex + row["signature"]
            if expected != data:
                for stored, rebuilt in zip(expected["vectors"], data["vectors"]):
                    for field in rebuilt:
                        if stored[field] != rebuilt[field]:
                            a, b = str(stored[field]), str(rebuilt[field])
                            first = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
                            print(f"golden mismatch name={rebuilt['name']} field={field} lengths={len(a)}/{len(b)} first_difference={first} stored={a[first:first+80]} computed={b[first:first+80]}", file=sys.stderr)
                raise AssertionError("independent block authentication golden mismatch")
            print(f"independent_block_auth_vectors={len(data['vectors'])} malformed_signatures={invalid} payload_mutations={mutations} both_parities=true low_s_normalization=true alternate_signature=true")
            print("backend=Python struct/RFC6979/curve arithmetic; OpenSSL Keccak/ECDSA; no Rust calls")
    finally:
        k.close()


if __name__ == "__main__":
    main()
