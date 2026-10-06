#!/usr/bin/env python3
"""Independently reproduce test-only native V2 vectors, without importing any Rust implementation.

Uses OpenSSL KECCAK-256, Python struct packing and RFC6979 arithmetic, and OpenSSL-backed
secp256k1 key derivation/ECDSA verification via cryptography. The variable-time curve arithmetic
below is a vector checker for public test inputs, not a production wallet/signing implementation.
This script never writes fixtures, defines production genesis, or admits transactions to the node.
"""

import ctypes
import ctypes.util
import hashlib
import hmac
import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
SIGN_DOMAIN = b"\x19ETERNIX\x00NATIVE_TX_SIGN\x00"
ID_DOMAIN = b"\x19ETERNIX\x00NATIVE_TX_ID\x00"


class OpenSSLKeccak:
    """Direct independent digest provider, not Python SHA3 or the Rust sha3 crate."""

    def __init__(self):
        library = ctypes.util.find_library("crypto")
        if library is None:
            raise RuntimeError("OpenSSL libcrypto with KECCAK-256 is required")
        self.library = ctypes.CDLL(library)
        self.library.EVP_MD_fetch.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        self.library.EVP_MD_fetch.restype = ctypes.c_void_p
        self.library.EVP_MD_free.argtypes = [ctypes.c_void_p]
        self.library.EVP_Digest.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint),
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self.library.EVP_Digest.restype = ctypes.c_int
        self.digest = self.library.EVP_MD_fetch(None, b"KECCAK-256", None)
        if not self.digest:
            raise RuntimeError("OpenSSL KECCAK-256 provider is unavailable; SHA3 is not a substitute")

    def __call__(self, data):
        output = ctypes.create_string_buffer(64)
        length = ctypes.c_uint()
        result = self.library.EVP_Digest(
            data, len(data), output, ctypes.byref(length), self.digest, None
        )
        if result != 1 or length.value != 32:
            raise RuntimeError("OpenSSL Keccak calculation failed")
        return output.raw[:32]

    def close(self):
        self.library.EVP_MD_free(self.digest)


def add(a, b):
    """Public-vector affine arithmetic, intentionally separate from k256."""
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y + v) % P == 0:
        return None
    if a == b:
        slope = 3 * x * x * pow(2 * y, -1, P) % P
    else:
        slope = (v - y) * pow(u - x, -1, P) % P
    next_x = (slope * slope - x - u) % P
    return next_x, (slope * (x - next_x) - y) % P


def multiply(k, point):
    result = None
    while k:
        if k & 1:
            result = add(result, point)
        point = add(point, point)
        k >>= 1
    return result


def nonce_candidates(private_scalar, digest):
    """RFC6979 HMAC-SHA256, only internal nonce generation; message digest remains Keccak."""
    seed = private_scalar.to_bytes(32, "big") + (int.from_bytes(digest, "big") % N).to_bytes(32, "big")
    key, value = bytes(32), b"\x01" * 32

    def hm(k, data):
        return hmac.new(k, data, hashlib.sha256).digest()

    key = hm(key, value + b"\x00" + seed)
    value = hm(key, value)
    key = hm(key, value + b"\x01" + seed)
    value = hm(key, value)
    while True:
        value = hm(key, value)
        k = int.from_bytes(value, "big")
        if 1 <= k < N:
            yield k
        # Advance the generator on a rejected nonce rather than restarting with the same candidate.
        key = hm(key, value + b"\x00")
        value = hm(key, value)


def sign_test_vector(private_scalar, digest):
    for k in nonce_candidates(private_scalar, digest):
        point = multiply(k, G)
        reference = ec.derive_private_key(k, ec.SECP256K1()).public_key().public_numbers()
        assert point == (reference.x, reference.y)
        if point[0] >= N or point[0] == 0:
            continue
        r = point[0]
        s = pow(k, -1, N) * (int.from_bytes(digest, "big") + r * private_scalar) % N
        if s == 0:
            continue
        parity = point[1] & 1
        if s > N // 2:
            s = N - s
            parity ^= 1
        return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([parity])
    raise AssertionError("nonce stream exhausted")


def recover(digest, signature):
    if len(signature) != 65:
        raise ValueError("length")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:64], "big")
    parity = signature[64]
    if not (1 <= r < N and 1 <= s <= N // 2 and parity in (0, 1)):
        raise ValueError("canonicality")
    alpha = (r * r * r + 7) % P
    y = pow(alpha, (P + 1) // 4, P)
    if y * y % P != alpha:
        raise ValueError("recovery point")
    if y & 1 != parity:
        y = P - y
    point = (r, y)
    assert multiply(N, point) is None
    z = int.from_bytes(digest, "big") % N
    public = multiply(pow(r, -1, N), add(multiply(s, point), multiply((-z) % N, G)))
    if public is None:
        raise ValueError("infinite key")
    # Prehashed only supplies a 32-byte length marker; ECDSA receives the existing Keccak digest
    # unchanged. This does not SHA256-hash the message or replace its signing domain.
    verifier = ec.EllipticCurvePublicNumbers(*public, ec.SECP256K1()).public_key()
    verifier.verify(utils.encode_dss_signature(r, s), digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    return public


def encode_unsigned(fixture, vector, network_id):
    # Independent struct format, not the offsets or encoder from the Rust module.
    return struct.pack(
        ">BIQ32sB20sQ20sQ16sQQ",
        fixture["encoding_version"],
        fixture["native_rules_version"],
        fixture["chain_id"],
        network_id,
        fixture["kind"],
        bytes.fromhex(fixture["sender"]),
        int(vector["nonce"]),
        bytes.fromhex(fixture["recipient"]),
        int(vector["token_id"]),
        int(fixture["value"]).to_bytes(16, "big"),
        int(vector["gas_limit"]),
        int(fixture["valid_after_slot"]),
    )


def main():
    path = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "native_auth_v2.json"
    fixture = json.loads(path.read_text())
    if fixture.get("test_only") is not True:
        raise RuntimeError("only explicitly test-only fixtures may be reproduced")
    private_scalar = int(fixture["test_private_key_hex"], 16)
    assert private_scalar == 1, "this checker uses only the published scalar-one test key"
    keccak = OpenSSLKeccak()
    try:
        assert keccak(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        network_id = keccak(bytes.fromhex(fixture["canonical_genesis_hex"]))
        assert network_id.hex() == fixture["network_id"]
        reference = ec.derive_private_key(private_scalar, ec.SECP256K1()).public_key().public_numbers()
        assert (reference.x, reference.y) == G
        rows = []
        invalid_verified = 0
        for vector in fixture["vectors"]:
            unsigned = encode_unsigned(fixture, vector, network_id)
            preimage = SIGN_DOMAIN + unsigned
            digest = keccak(preimage)
            signature = sign_test_vector(private_scalar, digest)
            public = recover(digest, signature)
            public_bytes = b"\x04" + public[0].to_bytes(32, "big") + public[1].to_bytes(32, "big")
            address = keccak(public_bytes[1:])[12:]
            signed = unsigned + signature
            transaction_id = keccak(ID_DOMAIN + signed)
            assert (len(unsigned), len(preimage), len(signature), len(signed)) == (134, 158, 65, 199)
            assert public_bytes.hex() == fixture["public_key"]
            assert address.hex() == fixture["sender"]
            assert digest.hex() == vector["digest"]
            assert signature.hex() == vector["signature"]
            assert transaction_id.hex() == vector["transaction_id"]
            if vector["name"] == "base":
                assert unsigned.hex() == fixture["unsigned_bytes"]
                assert preimage.hex() == fixture["signing_preimage"]
                assert signed.hex() == fixture["signed_bytes"]
                for invalid in [
                    bytes.fromhex(fixture["high_s_signature"]),
                    bytes(32) + signature[32:],
                    signature[:32] + bytes(32) + signature[64:],
                    N.to_bytes(32, "big") + signature[32:],
                    signature[:32] + N.to_bytes(32, "big") + signature[64:],
                    (5).to_bytes(32, "big") + (1).to_bytes(32, "big") + b"\x00",
                    signature[:64],
                    signature + b"\x00",
                ] + [signature[:64] + bytes([p]) for p in range(2, 256)]:
                    try:
                        recover(digest, invalid)
                    except ValueError:
                        invalid_verified += 1
                        continue
                    raise AssertionError("invalid signature unexpectedly recovered")
            # Independently classify the stateless rules-1 negative controls, rather than using
            # their expected labels to drive either the encoding or signing calculation.
            profile_error = None
            if int(vector["gas_limit"]) < 1000:
                profile_error = "gas"
            elif int(vector["nonce"]) == (1 << 64) - 1:
                profile_error = "nonce"
            elif int(vector["token_id"]) != 0:
                profile_error = "token"
            assert profile_error == vector["expected_error"]
            rows.append({
                "name": vector["name"],
                "unsigned_bytes": unsigned.hex(),
                "signing_preimage": preimage.hex(),
                "digest": digest.hex(),
                "signature": signature.hex(),
                "public_key": public_bytes.hex(),
                "address": address.hex(),
                "signed_bytes": signed.hex(),
                "transaction_id": transaction_id.hex(),
                "expected_profile_error": profile_error,
            })
        print(json.dumps({
            "backend": "OpenSSL KECCAK-256; independent Python RFC6979/curve arithmetic; cryptography/OpenSSL ECDSA verification",
            "network_id": network_id.hex(),
            "verified_vectors": len(rows),
            "verified_invalid_signatures": invalid_verified,
            "vectors": rows,
        }, indent=2))
    finally:
        keccak.close()


if __name__ == "__main__":
    main()
