#!/usr/bin/env python3
"""Independent P2.1 C1 bytes/selection/header-attribution vectors; invokes no Rust code.

Public toy points/signatures are test inputs, never deployment credentials. Explicit Python packing,
OpenSSL Keccak, independent public-test RFC6979/curve arithmetic and OpenSSL ECDSA verification
reproduce the fixture. Empty historical headers/earning metadata are synthetic caller-trusted setup,
not an economic application engine or proof of historical execution. --emit prints, never writes.
"""
import json
from pathlib import Path
import struct
import sys
from reproduce_native_auth_vectors import OpenSSLKeccak, recover, sign_test_vector
from reproduce_testnet_fixture_profile import public_key

ROOT=Path(__file__).resolve().parents[1]
RUN="c1-eligibility-golden-2026"
T=10_000_000_000_000
S0=1_752_000_000_000_000
V0=60_000_000_000_000
R0=10_000_000
YEAR=10_512_000
IDS=("trial-A","trial-B")
POINTS={name:public_key(n) for name,n in zip(IDS,(2,5))}
OWNERS={"trial-A":bytes.fromhex("7e5f4552091a69125d5dfcb7b8c2659029395bdf"),
        "trial-B":bytes.fromhex("6813eb9362372eef6200f3b1dbc3f819671cba69")}
SEEDS=sorted([(OWNERS["trial-A"],1_600_000_000_000_000),
              (OWNERS["trial-B"],32_000_000_000_000),
              (bytes.fromhex("1eff47bc3a10a45d4b230b5d10e37751fe6aa718"),0)])
TICKETS=[dict(id=1,owner="trial-A",bucket=3),dict(id=255,owner="trial-B",bucket=3)]


def u128(n):return n.to_bytes(16,"big")
def text(s):
    b=s.encode("ascii")
    return struct.pack(">H",len(b))+b


def parameters():
    return (struct.pack(">QBIIIBBBI",1162,2,1,1,3,4,4,1,2)
            +struct.pack(">III",3000,2000,2100)
            +struct.pack(">7Q",1200,24,32,20,20,4,YEAR)
            +b"".join(u128(n) for n in (T,5,2,3,50,9,10,1,200))
            +struct.pack(">QQIQB",200,16,3000,16_000_000,1))


def snapshot(slot,parent,produced,credits):
    """Exact supported snapshot bytes, with every metadata field explicitly ordered/width-limited."""
    out=struct.pack(">IQ32sI",1,slot,parent,3)
    for a,b in SEEDS:out+=a+u128(b)+struct.pack(">Q",0)
    out+=struct.pack(">H",2)
    for name in IDS:
        locked=produced[name]*R0
        out+=(text(name)+b"\x00"+u128(V0+locked)+u128(locked)
              +struct.pack(">IIQ",0,0,produced[name])+b"\x00")
    out+=struct.pack(">H",2)
    for t in TICKETS:
        out+=struct.pack(">Q",t["id"])+text(t["owner"])+bytes([t["bucket"],0,0,0])
    out+=struct.pack(">H",len(credits))
    for s,name in credits:out+=struct.pack(">Q",s)+text(name)+u128(R0)+struct.pack(">QQ",0,4)
    out+=struct.pack(">Q",0)
    out+=b"".join(u128(n) for n in (0,2*T,slot*R0,0,0,0,0))
    out+=bytes(24)  # year/epoch/sub-epoch indices, all0 for the supported finite prefix
    out+=struct.pack(">QQQ",0,0,1)+b"".join(u128(n) for n in (S0,3,50,R0,0,50*YEAR))
    return out


def select(k,reference,slot,tickets):
    seed=k(b"eternix:leader-selection:v1"+reference+struct.pack(">Q",slot))
    counts={b:sum(t["bucket"]==b for t in tickets) for b in range(2,256)}
    total=sum(counts.values());assert total>0
    threshold=(1<<64)%total;retry=0
    while True:
        h=k(b"eternix:bucket-selection:v1"+seed+struct.pack(">Q",retry))
        raw=int.from_bytes(h[:8],"big")
        if raw>=threshold:break
        retry+=1
    offset=raw%total;remaining=offset
    for bucket in range(2,256):
        if remaining<counts[bucket]:break
        remaining-=counts[bucket]
    scores={str(t["id"]):k(b"eternix:ticket-selection:v1"+seed+struct.pack(">Q",t["id"])).hex()
            for t in tickets if t["bucket"]==bucket}
    winner=min((bytes.fromhex(scores[str(t["id"])]),t["id"],t["owner"])
               for t in tickets if t["bucket"]==bucket)
    return dict(reference=reference.hex(),slot=slot,seed=seed.hex(),total=total,bucket=bucket,
                retry=retry,raw=raw,offset=offset,producer=winner[2],ticket=winner[1],score=winner[0].hex(),scores=scores)


def calculate():
    k=OpenSSLKeccak()
    try:
        empty_tx=k(b"ETERNIX_TX_LIST_V1"+bytes(8))
        receipts=k(b"ETERNIX_RECEIPT_LIST_V1"+bytes(8))
        protocol=k(b"ETERNIX_PROTOCOL_DATA_V1"+b"\x01"+bytes(9))
        def header(slot,parent,name,ticket):
            proposer=k(b"ETERNIX_PROPOSER_ID_V1"+struct.pack(">Q",len(name.encode()))+name.encode())
            return struct.pack(">IQQB32s32sQ32s32s32sQ32s",3,1162,slot,0,parent,proposer,ticket,
                               empty_tx,bytes(32),receipts,0,protocol)
        def identity(h):return k(b"ETERNIX_BLOCK_HEADER_V1"+h)
        anchor=header(0,bytes(32),"c1-anchor",1);anchor_h=identity(anchor)
        initial=snapshot(0,anchor_h,{n:0 for n in IDS},[])
        roster=struct.pack(">H",2)+b"".join(text(n)+POINTS[n]+OWNERS[n]+OWNERS[n]+u128(V0) for n in IDS)
        raw=(b"ETERNIX_POASH_C1_GENESIS\0"+struct.pack(">I",1)+text(RUN)+parameters()+anchor+roster
             +struct.pack(">I",len(initial))+initial)
        network=k(raw)
        headers=[anchor];hashes=[anchor_h];produced={n:0 for n in IDS};credits=[];cases=[]
        for slot in range(1,65):
            reference=network if slot<32 else hashes[slot-32]
            s=select(k,reference,slot,TICKETS)
            if slot in (31,32,33,64):
                body=snapshot(slot-1,hashes[-1],produced,credits)
                sid=k(b"ETERNIX_POASH_C1_SNAPSHOT\0"+network+body)
                pid=k(b"ETERNIX_POASH_C1_PREFIX\0"+network+struct.pack(">H",len(headers))+b"".join(headers))
                vid=k(b"ETERNIX_POASH_C1_SLOT_START\0"+network+pid+sid+struct.pack(">Q",slot)+hashes[-1]+reference)
                proofs=[]
                for name,ticket,number in (("trial-A",1,2),("trial-B",255,5)):
                    claim=header(slot,hashes[-1],name,ticket);h=identity(claim)
                    pre=(b"\x19ETERNIX\0BLOCK_SIGN\0"+struct.pack(">BBIQ32sI32s",4,1,2,1162,network,3,h))
                    digest=k(pre);sig=sign_test_vector(number,digest)
                    point=recover(digest,sig)
                    assert bytes([2+point[1]%2])+point[0].to_bytes(32,"big")==POINTS[name]
                    proofs.append(dict(producer=name,ticket=ticket,public_key=POINTS[name].hex(),header=claim.hex(),
                                       hash=h.hex(),preimage=pre.hex(),digest=digest.hex(),signature=sig.hex(),
                                       selected=name==s["producer"]))
                cases.append(dict(slot=slot,parent=hashes[-1].hex(),state_bytes=len(body),state_id=sid.hex(),
                                  prefix_id=pid.hex(),view_id=vid.hex(),selection=s,proofs=proofs))
            h=header(slot,hashes[-1],s["producer"],s["ticket"])
            headers.append(h);hashes.append(identity(h));produced[s["producer"]]+=1;credits.append((slot,s["producer"]))
        multi=[dict(id=254,owner="trial-A",bucket=2),dict(id=1,owner="trial-A",bucket=3),
               dict(id=255,owner="trial-B",bucket=3),dict(id=253,owner="trial-B",bucket=255)]
        kernels=[dict(tickets=TICKETS,selection=select(k,b"\x44"*32,42,TICKETS)),
                 dict(tickets=TICKETS,selection=select(k,b"\x22"*32,32,TICKETS)),
                 dict(tickets=multi,selection=select(k,b"\x44"*32,42,multi)),
                 dict(tickets=multi,selection=select(k,b"\x45"*32,42,multi))]
        return dict(test_only=True,format="eternix-native-poash-eligibility-v1",run_id=RUN,
                    genesis=dict(hex_parts=[raw[i:i+64].hex() for i in range(0,len(raw),64)],bytes=len(raw),network_id=network.hex(),anchor_header=anchor.hex(),anchor_hash=anchor_h.hex(),
                                 initial_state_bytes=len(initial),initial_state_id=k(b"ETERNIX_POASH_C1_SNAPSHOT\0"+network+initial).hex()),
                    history_hashes=[h.hex() for h in hashes],cases=cases,kernels=kernels,
                    assurance="pure planning; linked caller-trusted header/state context, no historical execution certificate")
    finally:k.close()


def check(actual,expected,path="vector"):
    """Useful bounded diagnostics for public golden mismatches, including long byte strings."""
    if isinstance(actual,dict):
        assert set(actual)==set(expected),path+" keys"
        for name in actual:check(actual[name],expected[name],path+"."+name)
    elif isinstance(actual,list):
        assert len(actual)==len(expected),path+" length"
        for i,(a,b) in enumerate(zip(actual,expected)):check(a,b,path+f"[{i}]")
    elif actual!=expected:
        if isinstance(actual,str):
            i=next((i for i,(a,b) in enumerate(zip(actual,expected)) if a!=b),min(len(actual),len(expected)))
            raise AssertionError(f"{path} at character {i}: calculated={actual[max(0,i-16):i+32]} golden={expected[max(0,i-16):i+32]}")
        raise AssertionError(f"{path}: calculated={actual} golden={expected}")


if __name__=="__main__":
    value=calculate()
    if sys.argv[1:]==["--emit"]:print(json.dumps(value,indent=2))
    elif sys.argv[1:]==["--emit-genesis"]:print(json.dumps(value["genesis"]["hex_parts"],indent=2))
    else:
        assert not sys.argv[1:]
        expected=json.loads((ROOT/"tests/fixtures/native_poash_eligibility.json").read_text())
        check(value,expected)
        print("independent_c1_genesis_bytes="+str(value["genesis"]["bytes"])+
              " prefix_hashes=65 slots=31,32,33,64 authenticated_headers=8 kernels=4 no_Rust_calls=true")
