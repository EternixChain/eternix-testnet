#!/usr/bin/env python3
"""Independent S4 extension bytes. The frozen S3 signed envelope is opaque, unchanged input.

Explicit Python packing checks the new transport version only, not a new signature/hash/ledger
format. --emit prints initial vectors; it never overwrites the checked-in golden.
"""
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
REQUEST_ID=0x0102030405060708


def frame(profile,kind,sender,body):
    run=profile["run_id"].encode("ascii")
    assert kind in (5,6,7) and len(body)+144<=3808
    return (struct.pack(">4sBBHIHBB64s32s32s",b"ETX3",2,kind,0,len(body),sender,len(run),0,run,
                        bytes.fromhex(profile["network_id"]),bytes.fromhex(profile["anchor_wire"])[1:33])+body)


def request(request_id,base,base_eid,target,target_eid):
    return (struct.pack(">Q32sQQ32s32sQQ32s",request_id,bytes.fromhex(base["hash"]),base["slot"],base["revision"],
                        base_eid,bytes.fromhex(target["hash"]),target["slot"],target["revision"],target_eid))


def successor(request_id,revision,envelope):
    return struct.pack(">QQI",request_id,revision,len(envelope))+envelope


def error(request_id,code,revision):
    return struct.pack(">QH6xQ",request_id,code,revision)


def calculate():
    profile=json.loads((ROOT/"tests/fixtures/testnet_fixture_profile.json").read_text())
    old=json.loads((ROOT/"tests/fixtures/testnet_fixture_transport.json").read_text())
    anchor=dict(hash=old["anchor_hash"],slot=0,revision=0)
    one=dict(hash=old["block_hash"],slot=1,revision=1)
    two=dict(hash="33"*32,slot=2,revision=2)
    eid=bytes.fromhex(old["envelope_id"]);envelope=bytes.fromhex(old["envelope"])
    values=[("anchor_request",5,3,request(REQUEST_ID,anchor,bytes(32),one,eid)),
            ("nonanchor_request",5,3,request(REQUEST_ID,one,eid,two,b"\x44"*32)),
            ("successor",6,2,successor(REQUEST_ID,1,envelope)),
            ("error",7,2,error(REQUEST_ID,2,2))]
    frames=[]
    for name,kind,sender,body in values:
        raw=frame(profile,kind,sender,body)
        # Reuse, rather than duplicate or regenerate, the already frozen original signed E.
        prefix=body[:-len(envelope)] if name=="successor" else body
        frames.append(dict(name=name,kind=kind,sender=sender,header_hex=raw[:144].hex(),
                           payload_prefix_hex=prefix.hex(),append_s3_envelope=name=="successor"))
    return dict(test_only=True,format="eternix-fixture-retrieval-v2",header_bytes=144,
                max_frame_bytes=3808,request_id=REQUEST_ID,frames=frames)


if __name__=="__main__":
    result=calculate()
    if sys.argv[1:]==["--emit"]:print(json.dumps(result,indent=2))
    else:
        assert not sys.argv[1:]
        assert result==json.loads((ROOT/"tests/fixtures/testnet_fixture_catchup.json").read_text())
        print("independent_s4_frames=4 header_bytes=144 max_frame_bytes=3808 s3_bytes_unchanged=true")
