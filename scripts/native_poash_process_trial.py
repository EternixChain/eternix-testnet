#!/usr/bin/env python3
"""One finite C1 three-process signing/application/publication/restart/catch-up experiment.

All keys here are explicitly public small-integer TEST inputs, provisioned to external private files.
The oracle observes originals AFTER commitment, never issues H/E-ID grants. It independently checks
selection, exact headers/body commitments and the complete supported economic snapshot. Raw timings
and outliers are retained; this is not a capacity matrix or a PoAsh deadline/finality result.
"""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import select
import socket
import statistics
import struct
import subprocess
import time
import reproduce_native_poash_eligibility as p
from reproduce_native_poash_application import snapshot
from reproduce_native_auth_vectors import OpenSSLKeccak, SIGN_DOMAIN, ID_DOMAIN, sign_test_vector, recover


def read_exact(stream, length, timeout=60):
    end = time.monotonic()+timeout
    result = bytearray()
    while len(result) < length:
        left = end-time.monotonic()
        if left <= 0 or not select.select([stream], [], [], left)[0]:
            raise TimeoutError("finite C1 process did not answer")
        part = os.read(stream.fileno(), length-len(result))
        if not part:
            raise EOFError("C1 process closed before complete reply")
        result.extend(part)
    return bytes(result)


class Process:
    def __init__(self, exe, folder, name, config, generation):
        self.name = name
        self.log_path = folder/f"{name}-{generation}.stderr.log"
        self.log = self.log_path.open("wb")
        path = folder/f"{name}-{generation}.config.json"
        path.write_text(json.dumps(config, indent=2))
        self.p = subprocess.Popen([str(exe), str(path)], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=self.log)
        ready = self.read()
        assert ready["ok"] and ready["result"]["outcome"] == "ready", ready
        self.address = ready["result"]["address"]

    def write(self, value):
        encoded = json.dumps(value, separators=(",", ":")).encode()
        assert 0 < len(encoded) <= 65536
        self.p.stdin.write(struct.pack(">I", len(encoded))+encoded)
        self.p.stdin.flush()

    def read(self):
        length, = struct.unpack(">I", read_exact(self.p.stdout, 4))
        assert 0 < length <= 65536
        return json.loads(read_exact(self.p.stdout, length))

    def call(self, command, **fields):
        self.write(dict(command=command, **fields))
        value = self.read()
        assert value["ok"], (self.name, command, value)
        return value["result"]

    def stop(self):
        if self.p.poll() is None:
            self.call("stop")
            assert self.p.wait(timeout=5) == 0
        self.log.close()

    def kill(self):
        if self.p.poll() is None:
            self.p.kill()
            assert self.p.wait(timeout=5) != 0
        self.log.close()


def pages(proc, section, limit=16):
    result = []
    while True:
        value = proc.call("inspect", section=section, offset=len(result), limit=limit)
        result.extend(value["rows"])
        if len(result) == value["total"]:
            return result


def complete(proc):
    state = bytearray()
    while True:
        part = proc.call("state", offset=len(state), length=1024)
        state.extend(bytes.fromhex(part["hex"]))
        if len(state) == part["total"]:
            break
    status = proc.call("status")
    return dict(state=state.hex(), records=pages(proc, "records", 1),
                transactions=pages(proc, "transactions"), sender_nonces=pages(proc, "sender_nonces"),
                slot=status["slot"], hash=status["hash"], state_id=status["state_id"],
                snapshot_digest=status["snapshot_digest"])


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return f"127.0.0.1:{s.getsockname()[1]}"


def peer_frame(network, kind, request, body):
    return (b"ETXC1P3\0"+bytes([3, kind])+bytes(2)+struct.pack(">IIIQ", 3, 2, 1, 1162)
            + network+struct.pack(">QI", request, len(body))+bytes(52)+body)


def exchange(address, frame, network):
    host, port = address.split(":")
    with socket.create_connection((host, int(port)), timeout=3) as s:
        s.settimeout(3)
        s.sendall(frame)
        def exact(n):
            out = bytearray()
            while len(out) < n:
                part = s.recv(n-len(out))
                if not part:
                    raise EOFError("peer closed")
                out.extend(part)
            return bytes(out)
        header = exact(128)
        assert header[:9] == b"ETXC1P3\0\x03" and header[32:64] == network
        assert header[64:72] == frame[64:72]
        n, = struct.unpack(">I", header[72:76])
        assert n <= 3650
        return header[9], exact(n)


def empty_claim(k, network, parent, name, number):
    ticket = 1 if name == "trial-A" else 255
    proposer = k(b"ETERNIX_PROPOSER_ID_V1"+struct.pack(">Q", 7)+name.encode())
    header = struct.pack(">IQQB32s32sQ32s32s32sQ32s", 3, 1162, 1, 0, parent, proposer, ticket,
                         k(b"ETERNIX_TX_LIST_V1"+bytes(8)), bytes(32),
                         k(b"ETERNIX_RECEIPT_LIST_V1"+bytes(8)), 0,
                         k(b"ETERNIX_PROTOCOL_DATA_V1\x01"+bytes(9)))
    h = k(b"ETERNIX_BLOCK_HEADER_V1"+header)
    inner = b"\x04"+h+header+struct.pack(">I", 7)+name.encode()+struct.pack(">I", 10)+b"\x01"+bytes(17)
    digest = k(b"\x19ETERNIX\0BLOCK_SIGN\0"+struct.pack(">BBIQ32sI32s", 4, 1, 2, 1162, network, 3, h))
    signature = sign_test_vector(number, digest)
    recover(digest, signature)
    return b"\x04\x01"+struct.pack(">I", 2)+network+struct.pack(">I", len(inner))+inner+signature


class Oracle:
    """Independent verification AFTER observed commitment; never a source of admission permission."""
    def __init__(self, k, network, anchor):
        self.k, self.network = k, network
        self.hashes = [anchor]
        self.accounts = {a: [b, 0] for a, b in p.SEEDS}
        self.counts = {n: 0 for n in p.IDS}
        self.credits = []
        self.gas = self.fees = 0
        self.ids = {}
        self.nonces = {}
        self.originals = []

    def observed(self, encoded, expected_body):
        k, network = self.k, self.network
        envelope = bytes.fromhex(encoded)
        assert envelope[:6] == b"\x04\x01\0\0\0\x02" and envelope[6:38] == network
        length, = struct.unpack(">I", envelope[38:42])
        assert len(envelope) == length+107
        inner = envelope[42:42+length]
        assert inner[0] == 4
        h = inner[1:33]
        fields = struct.unpack(">IQQB32s32sQ32s32s32sQ32s", inner[33:262])
        profile, chain, slot, kind, parent, proposer, ticket, tx_root, state_root, receipts, gas, protocol = fields
        assert (profile, chain, slot, kind, parent) == (3, 1162, len(self.hashes), 0, self.hashes[-1])
        assert k(b"ETERNIX_BLOCK_HEADER_V1"+inner[33:262]) == h
        reference = network if slot < 32 else self.hashes[slot-32]
        selection = p.select(k, reference, slot, p.TICKETS)
        name = selection["producer"]
        assert ticket == selection["ticket"] and inner[266:273].decode() == name
        assert proposer == k(b"ETERNIX_PROPOSER_ID_V1"+struct.pack(">Q", 7)+name.encode())
        digest = k(b"\x19ETERNIX\0BLOCK_SIGN\0"+struct.pack(">BBIQ32sI32s", 4, 1, 2, 1162, network, 3, h))
        point = recover(digest, envelope[-65:])
        assert bytes([2+point[1]%2])+point[0].to_bytes(32,"big") == p.POINTS[name]
        count, = struct.unpack(">Q", inner[287:295])
        assert count == len(expected_body) <= 16 and len(inner) == 295+203*count
        ids = []
        for i in range(count):
            start = 295+i*203
            assert inner[start:start+4] == struct.pack(">I", 199)
            tx = inner[start+4:start+203]
            assert tx.hex() == expected_body[i]
            version, rules, tx_chain, tx_n, tx_kind, sender, nonce, recipient, token, value_bytes, limit, mature = struct.unpack(">BIQ32sB20sQ20sQ16sQQ", tx[:134])
            value = int.from_bytes(value_bytes,"big")
            assert (version,rules,tx_chain,tx_n,tx_kind,token)==(2,1,1162,network,0,0)
            assert limit >= 1000 and mature <= slot and self.accounts[sender][1] == nonce
            assert self.accounts[sender][0] >= value+10000
            self.accounts[sender][0] -= value+10000; self.accounts[sender][1] += 1
            if value:
                self.accounts.setdefault(recipient,[0,0])[0] += value
            tx_id = k(ID_DOMAIN+tx)
            member = dict(slot=slot, hash=h.hex(), index=i)
            self.ids[tx_id.hex()] = dict(id=tx_id.hex(), **member)
            self.nonces[(sender.hex(),nonce)] = dict(sender=sender.hex(),nonce=nonce,**member)
            ids.append(tx_id)
        assert gas == count*1000 and state_root == bytes(32)
        assert receipts == k(b"ETERNIX_RECEIPT_LIST_V1"+bytes(8))
        pd = b"\x01"+struct.pack(">Q",count*10000)+b"\0"
        assert inner[277:287] == pd and protocol == k(b"ETERNIX_PROTOCOL_DATA_V1"+pd)
        assert tx_root == k(b"ETERNIX_TX_LIST_V1"+struct.pack(">Q",count)+b"".join(ids))
        self.gas += count*1000; self.fees += count*10000
        self.counts[name] += 1; self.credits.append((slot,name)); self.hashes.append(h)
        state = snapshot(slot,h,self.accounts,self.counts,self.credits,self.gas,self.fees)
        state_id = k(b"ETERNIX_POASH_C1_SNAPSHOT\0"+network+state)
        eid = k(b"\x19ETERNIX\0BLOCK_ENVELOPE_ID\0"+envelope)
        self.originals.append(dict(slot=slot,hash=h.hex(),state_id=state_id.hex(),envelope=encoded,envelope_id=eid.hex(),gas=count*1000,fees=count*10000,transaction_ids=[i.hex() for i in ids]))
        return name,state_id.hex()

    def compare(self, actual):
        slot=len(self.hashes)-1
        state=snapshot(slot,self.hashes[-1],self.accounts,self.counts,self.credits,self.gas,self.fees)
        assert actual["state"] == state.hex()
        assert actual["records"] == self.originals
        assert actual["transactions"] == [self.ids[i] for i in sorted(self.ids)]
        assert actual["sender_nonces"] == [self.nonces[i] for i in sorted(self.nonces)]
        assert sum(a[0] for a in self.accounts.values())+2*p.V0+slot*p.R0 == p.S0+slot*p.R0-self.fees


def main():
    args=argparse.ArgumentParser()
    args.add_argument("--executable",type=Path,required=True)
    args.add_argument("--output",type=Path,required=True)
    args.add_argument("--run-id",required=True)
    args=args.parse_args()
    exe=args.executable.resolve()
    output=args.output.resolve()
    output.mkdir()  # Exclusive finite run: never erase/reseed an old archive or signing root.
    p.RUN=args.run_id
    inputs=p.calculate()
    raw=bytes.fromhex("".join(inputs["genesis"]["hex_parts"]))
    network=bytes.fromhex(inputs["genesis"]["network_id"])
    anchor=bytes.fromhex(inputs["genesis"]["anchor_hash"])
    genesis_file=output/"genesis.bin";genesis_file.write_bytes(raw)
    protection=output/"shared-signing-protection";protection.mkdir()
    for name,n in [("A",2),("B",5)]:
        fd=os.open(output/f"{name}.key",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"wb") as f:f.write(n.to_bytes(32,"big"))
    k=OpenSSLKeccak();processes=[]
    try:
        plan=[];nonce=0
        for slot in range(1,201):
            body=[]
            if slot not in (1,32,64,128,200):
                for i in range(16):
                    recipient=p.OWNERS["trial-A"] if i%4==0 else p.OWNERS["trial-B"] if i%4==1 else bytes.fromhex("1eff47bc3a10a45d4b230b5d10e37751fe6aa718")
                    value=0 if i%4==3 else 1
                    unsigned=struct.pack(">BIQ32sB20sQ20sQ16sQQ",2,1,1162,network,0,p.OWNERS["trial-A"],nonce,recipient,0,p.u128(value),1001,0)
                    body.append((unsigned+sign_test_vector(1,k(SIGN_DOMAIN+unsigned))).hex());nonce+=1
            plan.append(body)
        plan_file=output/"opaque-native-body-plan.json";plan_file.write_text(json.dumps(plan))
        addresses={name:port() for name in ("A","B","O")}
        assert len(set(addresses.values()))==3
        configs={}
        for name in addresses:
            archive=output/f"archive-{name}";archive.mkdir()
            configs[name]=dict(id=name,archive=str(archive),genesis=str(genesis_file),mode="create",listen=addresses[name],
                peers=[dict(id=p,address=a) for p,a in addresses.items() if p!=name],
                producer=None if name=="O" else dict(id="trial-"+name,key_file=str(output/f"{name}.key"),authority_root=str(protection),mode="create"),
                body_plan=None if name=="O" else str(plan_file))
        nodes={name:Process(exe,output,name,c,0) for name,c in configs.items()};processes.extend(nodes.values())
        # Same key/network, a different archive directory, same configured authority root.
        competing=dict(configs["A"]);competing["archive"]=str(output/"competing-archive");Path(competing["archive"]).mkdir();competing["listen"]="127.0.0.1:0"
        path=output/"competing.config.json";path.write_text(json.dumps(competing))
        rejected=subprocess.run([str(exe),str(path)],capture_output=True,timeout=30)
        assert rejected.returncode!=0 and b"Owned" in rejected.stderr
        generation=Counter()
        unavailable=nodes["O"].call("status")["selected"][-1]
        survivor="B" if unavailable=="A" else "A"
        nodes[unavailable].stop()
        assert nodes[survivor].call("advance",slot=1)["outcome"]=="not_selected"
        assert nodes[survivor].call("status")["slot"]==nodes["O"].call("status")["slot"]==0
        host,number=addresses[unavailable].split(":")
        try:
            with socket.create_connection((host,int(number)),timeout=2):
                raise AssertionError("stopped selected producer still served")
        except OSError:
            pass
        configs[unavailable]["mode"]="reopen";configs[unavailable]["producer"]["mode"]="reopen";generation[unavailable]+=1
        nodes[unavailable]=Process(exe,output,unavailable,configs[unavailable],generation[unavailable]);processes.append(nodes[unavailable])
        selected=nodes["O"].call("status")["selected"];wrong="trial-B" if selected=="trial-A" else "trial-A"
        invalid=empty_claim(k,network,anchor,wrong,5 if wrong=="trial-B" else 2)
        before={name:complete(node) for name,node in nodes.items()}
        for name,node in nodes.items():
            kind,_=exchange(node.address,peer_frame(network,3,555,invalid),network)
            assert kind==7 and complete(node)==before[name]
        oracle=Oracle(k,network,anchor);counts=Counter();dispatch=[];checkpoints=[]
        for slot in range(1,201):
            status={name:node.call("status") for name,node in nodes.items()}
            assert len({(v["slot"],v["hash"],v["state_id"],v["snapshot_digest"]) for v in status.values()})==1
            selected=status["O"]["selected"];name=selected[-1];other="B" if name=="A" else "A"
            unchanged=nodes[other].call("status")["snapshot_digest"]
            assert nodes[other].call("advance",slot=slot)["outcome"]=="not_selected"
            assert nodes[other].call("status")["snapshot_digest"]==unchanged
            start=time.perf_counter_ns()
            if slot==65:
                # The caller actually leaves the committed reply unread, kills that process, then
                # retries against reopened protection. Supervisor stderr preserves its timing row.
                actor=nodes[name];actor.write(dict(command="advance",slot=slot))
                end=time.monotonic()+30
                while nodes["O"].call("status")["slot"]!=slot:
                    assert time.monotonic()<end;time.sleep(.01)
                while not any(t.get("slot")==slot and t.get("action")=="advance" for t in timing_log(actor.log_path)):
                    assert time.monotonic()<end;time.sleep(.01)
                actor.kill();configs[name]["mode"]="reopen";configs[name]["producer"]["mode"]="reopen";generation[name]+=1
                actor=Process(exe,output,name,configs[name],generation[name]);nodes[name]=actor;processes.append(actor)
                assert actor.call("status")["signing_calls"]==0
                response=actor.call("advance",slot=slot)
                assert response["outcome"]=="retained_committed" and actor.call("status")["signing_calls"]==0
            else:
                response=nodes[name].call("advance",slot=slot)
                assert response["outcome"]=="committed" and response["producer"]==selected
            dispatch.append(dict(slot=slot,producer=selected,operator_roundtrip_ns=time.perf_counter_ns()-start,lost_reply_restart=slot==65))
            encoded=nodes[name].call("export",slot=slot)["envelope"]
            actual,state_id=oracle.observed(encoded,plan[slot-1]);assert actual==selected;counts[actual]+=1
            for node in nodes.values():assert node.call("status")["state_id"]==state_id
            if slot%32==0:
                old=nodes["O"].call("status")["snapshot_digest"]
                kind,ack=exchange(nodes["O"].address,peer_frame(network,3,1000+slot,bytes.fromhex(encoded)),network)
                assert kind==6 and ack[-1]==0 and nodes["O"].call("status")["snapshot_digest"]==old
            if slot==64:
                saved={n:complete(node) for n,node in nodes.items()}
                assert saved["A"]==saved["B"]==saved["O"];oracle.compare(saved["O"])
                for node in nodes.values():node.stop()
                for n in nodes:
                    configs[n]["mode"]="reopen"
                    if configs[n]["producer"]:configs[n]["producer"]["mode"]="reopen"
                    generation[n]+=1;nodes[n]=Process(exe,output,n,configs[n],generation[n]);processes.append(nodes[n]);assert complete(nodes[n])==saved[n]
                    recovered=nodes[n].call("recover")
                    assert recovered["outcome"]=="reconciled_no_automatic_application_or_publication" and not recovered["halted"]
                    assert complete(nodes[n])==saved[n]
                    if n!="O":assert nodes[n].call("status")["signing_calls"]==0
                checkpoints.append(dict(slot=64,complete_restart_equality=True))
        final={n:complete(node) for n,node in nodes.items()};assert final["A"]==final["B"]==final["O"];oracle.compare(final["O"])
        assert set(counts)==set(p.IDS)
        for n in ("A","B"):
            unchanged=nodes[n].call("status")
            nodes[n].write(dict(command="advance",slot=201));assert nodes[n].read()["ok"] is False
            after=nodes[n].call("status");assert after["snapshot_digest"]==unchanged["snapshot_digest"] and after["signing_calls"]==unchanged["signing_calls"]
        # All three close/reopen at the final prefix; signing services are then STOPPED. The retained
        # observer and a keyless offline validator archive can serve originals without any signer.
        for node in nodes.values():node.stop()
        for n in nodes:
            generation[n]+=1;nodes[n]=Process(exe,output,n,configs[n],generation[n]);processes.append(nodes[n]);assert complete(nodes[n])==final[n]
        for n in ("A","B"):nodes[n].stop()
        source=nodes["O"]
        offline=dict(configs["B"]);offline["id"]="offline";offline["producer"]=None;offline["body_plan"]=None;offline["listen"]="127.0.0.1:0";offline["peers"]=[dict(id="O",address=source.address)]
        offline_node=Process(exe,output,"offline",offline,0);processes.append(offline_node);assert complete(offline_node)==final["O"]
        fresh_config=dict(offline);fresh_config["id"]="fresh";fresh_config["archive"]=str(output/"archive-fresh");Path(fresh_config["archive"]).mkdir();fresh_config["mode"]="create"
        fresh=Process(exe,output,"fresh",fresh_config,0);processes.append(fresh)
        start=time.perf_counter_ns();fresh.call("catchup",source="O",target_slot=200,target_hash=final["O"]["hash"]);catchup_ns=time.perf_counter_ns()-start
        assert complete(fresh)==final["O"];fresh.stop();fresh_config["mode"]="reopen";fresh=Process(exe,output,"fresh",fresh_config,1);processes.append(fresh);assert complete(fresh)==final["O"]
        assert nodes["A"].p.poll()==0 and nodes["B"].p.poll()==0
        fresh.stop();offline_node.stop();source.stop()
        timings=[dict(process=path.name,**t) for path in sorted(output.glob("*.stderr.log")) for t in timing_log(path)]
        assert len([t for t in timings if t["action"]=="advance" and t["signing_ns"]>0])==200
        assert sum(t["owner_recovery_ns"]>0 for t in timings)==17
        assert sum(t["signer_recovery_ns"]>0 for t in timings)==10
        summary={}
        for field in [name for name in timings[0] if name.endswith("_ns")]:
            values=[t for t in timings if t[field]>0]
            if values:
                maximum=max(values,key=lambda t:t[field]);numbers=[v[field] for v in values]
                summary[field]=dict(count=len(numbers),minimum=min(numbers),median=statistics.median(numbers),maximum=maximum[field],maximum_process=maximum["process"],maximum_slot=maximum["slot"],maximum_action=maximum["action"])
        report=dict(format="eternix-c1-finite-process-trial-v1",run_id=args.run_id,network_id=network.hex(),slots=200,native_entries=nonce,
            selected=dict(counts),empty_slots=[1,32,64,128,200],gas=oracle.gas,fee_burn=oracle.fees,base_issuance=200*p.R0,
            supply=p.S0+200*p.R0-oracle.fees,retained_year_zero_reward=p.R0,tip=final["O"]["hash"],state_id=final["O"]["state_id"],
            complete_projection=final["O"],checkpoints=checkpoints,authenticated_nonselected_rejected_all_processes=True,
            competing_archive_signer_excluded=True,unread_reply_sigkill_restart_slot=65,repeated_reply_new_signing_calls=0,
            unavailable_selected_halt_prefix=0,unsupported_slot201_rejected_without_effects=True,
            offline_keyless_archive_equality=True,fresh_catchup_and_reopen_equality=True,producer_signing_services_stopped=True,
            catchup_roundtrip_ns=catchup_ns,dispatch=dispatch,timings=timings,timing_summary=summary,
            limitations="one finite experiment; operational I/O bounds are not PoAsh timing; SIGKILL is not power loss; D5-D9 deferred; no cloned-key/signing-store rollback protection")
        (output/"report.json").write_text(json.dumps(report,indent=2))
        print(json.dumps({k:v for k,v in report.items() if k not in ("complete_projection","dispatch","timings")},indent=2))
    finally:
        for proc in processes:
            if proc.p.poll() is None:proc.kill()
        k.close()


def timing_log(path):
    return [json.loads(line.removeprefix("C1_TIMING ")) for line in path.read_text().splitlines() if line.startswith("C1_TIMING ")]


if __name__=="__main__":
    main()
