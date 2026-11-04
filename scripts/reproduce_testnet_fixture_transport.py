#!/usr/bin/env python3
"""Independent S3 fixed-header/payload golden reproduction, with existing public signed E as data.

Python explicit packing/OpenSSL Keccak/public toy signing is test setup only. --emit prints and
never writes goldens. No Rust transport codec, credential fixture or new signing domain is used.
"""
import json
from pathlib import Path
import struct
import sys
from reproduce_native_auth_vectors import OpenSSLKeccak
from test_testnet_fixture_worker import packet

ROOT=Path(__file__).resolve().parents[1]
HEADER_BYTES=144
MAX_FRAME_BYTES=3800


def frame(profile,kind,sender,body):
    run=profile["run_id"].encode("ascii")
    assert 0<len(run)<=64 and kind in (1,2,3,4)
    header=(struct.pack(">4sBBHIHBB64s32s32s",b"ETX3",1,kind,0,len(body),sender,len(run),0,run,
                        bytes.fromhex(profile["network_id"]),bytes.fromhex(profile["anchor_wire"])[1:33]))
    assert len(header)==HEADER_BYTES and len(header)+len(body)<=MAX_FRAME_BYTES
    return header+body


def status(tip):
    return bytes.fromhex(tip["hash"])+struct.pack(">QQ",tip["slot"],tip["revision"])


def committed(revision,envelope):
    return struct.pack(">QI",revision,len(envelope))+envelope


def reference(new_commit,revision,h,retained,submitted):
    return struct.pack(">B7xQ32s32s32s",1 if new_commit else 2,revision,h,retained,submitted)


def error(code,revision=0,submitted=bytes(32)):
    return struct.pack(">H6xQ32s",code,revision,submitted)


def calculate():
    profile=json.loads((ROOT/"tests/fixtures/testnet_fixture_profile.json").read_text())
    k=OpenSSLKeccak()
    try:
        anchor=bytes.fromhex(profile["anchor_wire"])[1:33]
        p=packet(k,bytes.fromhex(profile["network_id"]),1,anchor,[])
        tip=dict(hash=anchor.hex(),slot=0,revision=0)
        values=[("status",1,1,status(tip)),("committed",2,1,committed(1,p["envelope"])),
                ("reference_new",3,2,reference(True,1,p["hash"],p["eid"],p["eid"])),
                ("reference_duplicate",3,2,reference(False,1,p["hash"],p["eid"],p["eid"])),
                ("error_unavailable",4,2,error(1)),("error_rejected",4,2,error(3,1,p["eid"]))]
        return dict(test_only=True,format="eternix-fixture-peer-v1",header_bytes=HEADER_BYTES,max_frame_bytes=MAX_FRAME_BYTES,
                    run_id=profile["run_id"],network_id=profile["network_id"],anchor_hash=anchor.hex(),
                    block_hash=p["hash"].hex(),envelope_id=p["eid"].hex(),envelope=p["envelope"].hex(),
                    frames=[dict(name=name,kind=kind,sender=sender,hex=frame(profile,kind,sender,body).hex())
                            for name,kind,sender,body in values])
    finally:k.close()


if __name__=="__main__":
    value=calculate()
    if sys.argv[1:]==["--emit"]:print(json.dumps(value,indent=2))
    else:
        assert not sys.argv[1:]
        expected=json.loads((ROOT/"tests/fixtures/testnet_fixture_transport.json").read_text())
        assert value==expected,"S3 exact frame golden mismatch"
        print("independent_s3_frames=6 header_bytes=144 max_frame_bytes=3800 existing_signed_envelope_unchanged=true")
