#!/usr/bin/env python3
"""Independent C1 signing-reservation/authority/peer3 bytes; no Rust/SQLite encoder calls.

Uses the independently reproduced P2.1/P2.2 public goldens, explicit Python packing and OpenSSL
Keccak. Mock peer tip comparison bytes carry no checkpoint authority. --emit only prints.
"""
import json
from pathlib import Path
import struct
import sys
import reproduce_native_poash_eligibility as p
import reproduce_native_poash_application as application
from reproduce_native_auth_vectors import OpenSSLKeccak

ROOT = Path(__file__).resolve().parents[1]


def calculate():
    pure = p.calculate()
    applied = application.calculate()
    k = OpenSSLKeccak()
    try:
        n = bytes.fromhex(pure["genesis"]["network_id"])
        anchor = bytes.fromhex(pure["genesis"]["anchor_header"])
        h0 = bytes.fromhex(pure["genesis"]["anchor_hash"])
        state0 = bytes.fromhex(pure["genesis"]["initial_state_id"])
        prefix = k(b"ETERNIX_POASH_C1_PREFIX\0" + n + struct.pack(">H", 1) + anchor)
        view = k(b"ETERNIX_POASH_C1_SLOT_START\0" + n + prefix + state0 + struct.pack(">Q", 1) + h0 + n)
        evidence = k(b"ETERNIX_C1_SIGN_BASE_EVIDENCE\0" + n + struct.pack(">H", 0))
        first = applied["vectors"][0]
        inner = bytes.fromhex(first["empty_inner"])
        h1 = bytes.fromhex(first["hash"])
        candidate = bytes.fromhex(first["state_id"])
        context = (struct.pack(">I", 1) + n + struct.pack(">II", 1, 3)
                   + bytes([4, 4, 1]) + struct.pack(">I", 2) + p.POINTS["trial-A"] + p.text("trial-A"))
        identity = b"ETERNIX_C1_SIGN_AUTHORITY\0" + context
        reservation = (b"ETERNIX_C1_SIGN_RESERVATION\0" + context + struct.pack(">Q", 1) + h1 + h0
                       + state0 + prefix + view + evidence + candidate + struct.pack(">I", len(inner)) + inner)
        envelope = b"\x04\x01" + struct.pack(">I", 2) + n + struct.pack(">I", len(inner)) + inner + bytes.fromhex(first["signature"])
        eid = k(b"\x19ETERNIX\0BLOCK_ENVELOPE_ID\0" + envelope)
        assert eid.hex() == first["envelope_id"]
        frames = []
        for name, kind, request, body in [
            ("status", 1, 7, b""),
            ("tip", 2, 7, struct.pack(">Q", 1)+h1+b"\x55"*32),
            ("push", 3, 9, envelope),
            ("get", 4, 8, struct.pack(">Q", 1)),
            ("original", 5, 8, envelope),
            ("ack", 6, 9, struct.pack(">Q", 1)+h1+eid+b"\x01"),
            ("reject", 7, 10, b"\x03"),
        ]:
            header = (b"ETXC1P3\0" + bytes([3, kind]) + bytes(2) + struct.pack(">IIIQ", 3, 2, 1, 1162)
                      + n + struct.pack(">QI", request, len(body)) + bytes(52))
            assert len(header) == 128
            frame = header+body
            frames.append(dict(name=name, kind=kind, request=request, body=body.hex(),
                               wire_parts=[frame[i:i+64].hex() for i in range(0, len(frame), 64)], bytes=len(frame), keccak=k(frame).hex()))
        return dict(test_only=True, format="eternix-c1-signing-peer-v1", network_id=n.hex(),
                    authority_identity=identity.hex(), authority_bytes=len(identity),
                    reservation_parts=[reservation[i:i+64].hex() for i in range(0, len(reservation), 64)],
                    reservation_bytes=len(reservation), reservation_keccak=k(reservation).hex(),
                    state_id=state0.hex(), prefix_id=prefix.hex(), view_id=view.hex(), evidence_id=evidence.hex(),
                    candidate_id=candidate.hex(), frames=frames)
    finally:
        k.close()


if __name__ == "__main__":
    value = calculate()
    if sys.argv[1:] == ["--emit"]:
        print(json.dumps(value, indent=2))
    else:
        assert not sys.argv[1:]
        p.check(value, json.loads((ROOT/"tests/fixtures/native_poash_signing.json").read_text()))
        print(f"independent_C1_authority_bytes={value['authority_bytes']} reservation_bytes={value['reservation_bytes']} peer3_frames=7 no_Rust_calls=true")
