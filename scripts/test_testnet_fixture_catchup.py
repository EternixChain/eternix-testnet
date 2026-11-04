#!/usr/bin/env python3
"""Finite S4/M1 process acceptance; independent approvals, real sockets/files, no PoAsh activation.

All measured samples (including outliers) are emitted and saved under target/. This runner's
SIGKILL/timeout evidence is distinct from the real-VFS owner tests and existing power-loss model.
"""
import copy
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
import unittest
import test_testnet_fixture_transport as s3
from test_testnet_fixture_worker import Worker as Inspector, packet, approvals
from testnet_fixture_controller import Controller
from reproduce_testnet_fixture_catchup import frame, request, successor, error
from reproduce_testnet_fixture_transport import frame as old_frame, status, committed

SAMPLES=[]


def observe(**value):
    SAMPLES.append(value)
    print(json.dumps(value,sort_keys=True),flush=True)


def recv_frame(sock):
    h=s3.recv_exact(sock,144)
    assert h[:5]==b"ETX3\x02"
    n=int.from_bytes(h[8:12],"big");assert 0<n<=3664
    return h[5],s3.recv_exact(sock,n)


class CatchupAcceptance(unittest.TestCase):
    # Reuse actual process/control and the independent full-state/index/evidence oracle, without
    # inheriting/rerunning S3's test methods as purportedly new S4 cases.
    setUp=s3.TransportAcceptance.setUp
    config=s3.TransportAcceptance.config
    start=s3.TransportAcceptance.start
    triple=s3.TransportAcceptance.triple
    wait=s3.TransportAcceptance.wait
    connect_triple=s3.TransportAcceptance.connect_triple
    tx=s3.TransportAcceptance.tx
    prepare_commit=s3.TransportAcceptance.prepare_commit
    grant_receivers=s3.TransportAcceptance.grant_receivers
    check_limits=s3.TransportAcceptance.check_limits
    assert_equivalent=s3.TransportAcceptance.assert_equivalent
    target=s3.TransportAcceptance.target
    raw_peer=s3.TransportAcceptance.raw_peer

    def pin(self,packets,name="pin"):
        p=packets[-1]
        path=self.root/f"{name}.json"
        d=dict(format="eternix-fixture-catchup-target-v1",run_id=self.profile["run_id"],
               network_id=self.profile["network_id"],anchor_hash=self.profile["anchor_wire"][2:66],
               target=dict(hash=p["hash"].hex(),slot=len(packets),revision=len(packets)),envelope_id=p["eid"].hex())
        path.write_text(json.dumps(d))
        return path,d

    def chain(self):
        a=packet(self.k,self.network,1,bytes.fromhex(self.profile["anchor_wire"])[1:33],[])
        b=packet(self.k,self.network,2,a["hash"],[])
        return [a,b]

    def connect_source(self,r1,r2):
        self.wait(lambda:not r1.ok("peer_status")["connections"])
        r1.ok("peer_connect",node_id=3)
        self.wait(lambda:any(c["ready"] for c in r2.ok("peer_status")["connections"]))

    def caught_up(self,node):
        # A finite multi-step transfer has a per-request deadline, not one slot for the whole
        # history. Fail immediately on a halted session; retain the complete wall time separately.
        def progress():
            state=node.ok("catchup_status")
            self.assertNotEqual(state["phase"],"halted",state)
            return state["phase"]=="complete"
        self.wait(progress,seconds=420)

    def test_finite_m1_maximum_offline_suffix_p_stopped_interruption_and_fresh_join(self):
        p,r1,r2=self.triple()
        # Mixed native cases first, then maximum-sized blocks up to the declared H=200/N=16
        # experiment bounds. Alice's pool nonce remains ordered; Bob spends only after funding.
        batches=[[],[self.tx(0,value=30000)],
                 [self.tx(2,target=b"\x55"*20),self.tx(0,source=3,target=4,value=10000),self.tx(1,target=1,value=1000),
                  s3.transaction(self.k,self.network,1,3,s3.address(self.k,3),0,maturity=5).hex()],
                 [],[self.tx(i) for i in range(4,19)]]
        nonce=19
        for _ in range(195):
            batches.append([self.tx(i) for i in range(nonce,nonce+16)]);nonce+=16
        all_observations=[]
        for index,batch in enumerate(batches,1):
            if index==4:
                r2.stop()  # Deliberately offline, with only its already durable prefix of three.
                self.wait(lambda:len(r1.ok("peer_status")["connections"])==1)
            n,prepared,_=self.prepare_commit(p,batch)
            self.c.release_follower(p,r1)
            if index<=3:r2.ok("extend_approvals",path=str(self.c.path("follower-approvals",n)))
            began=time.perf_counter_ns();p.ok("publish",revision=n)
            self.wait(lambda:r1.ok("status")["tip"]["revision"]==n,seconds=30)
            if index<=3:self.wait(lambda:r2.ok("status")["tip"]["revision"]==n,seconds=30)
            all_observations.append(dict(revision=n,transactions=len(prepared["transaction_ids"]),
                                         publish_to_observed_r1_ms=(time.perf_counter_ns()-began)/1e6))
        expected=Inspector.dump(p)
        producer_limits=self.check_limits(p)
        self.assertEqual(expected["status"]["transactions"],3140)
        self.assertEqual(expected["status"]["gas_used_total"],3140000)
        self.assertEqual(expected["status"]["fees_burned_total"],"31400000")
        accounts={a["address"]:(a["balance_quarks"],a["nonce"]) for a in expected["accounts"]}
        self.assertEqual(accounts[s3.address(self.k,1).hex()],("968580000",3139))
        self.assertEqual(accounts[s3.address(self.k,3).hex()],("10000",1))
        self.assertEqual(accounts[s3.address(self.k,4).hex()],("10000",0))
        self.assertEqual(expected,Inspector.dump(r1))
        p.stop();self.c.close();self.key.unlink()
        # Actual CLI restart of the authority plane: no --producer/--worker/--key-file, and P's
        # signing file no longer exists. Only the already released history can be exported.
        exported=json.loads(subprocess.check_output([sys.executable,"-B",str(s3.ROOT/"scripts/testnet_fixture_controller.py"),
                                                    "history","--directory",str(self.c.root)]))
        target=exported["target"];selected=Path(exported["approvals"])
        before=time.perf_counter_ns()
        r2=self.start("follower","open",self.root/"r2",selected,self.config(3,[2]))
        startup_ms=(time.perf_counter_ns()-before)/1e6
        self.assertEqual(r2.ok("status")["tip"]["revision"],3)
        self.connect_source(r1,r2)
        r2.ok("catchup_start",node_id=2,target_path=target)
        self.wait(lambda:r2.ok("status")["tip"]["revision"]>=5,seconds=30)
        interrupted=r2.ok("status")["tip"]["revision"]
        self.assertLess(interrupted,200)
        r2.close()  # SIGKILL while this explicit suffix session is still active.
        self.wait(lambda:not r1.ok("peer_status")["connections"])
        before=time.perf_counter_ns()
        r2=self.start("follower","open",self.root/"r2",selected,self.config(3,[2]))
        resumed_startup_ms=(time.perf_counter_ns()-before)/1e6
        retained=r2.ok("status")["tip"]["revision"]
        self.assertGreaterEqual(retained,interrupted);self.assertLess(retained,200)
        self.assertEqual(r2.ok("catchup_status")["phase"],"idle")
        self.connect_source(r1,r2)
        before=time.perf_counter_ns();r2.ok("catchup_start",node_id=2,target_path=target)
        self.caught_up(r2)
        resumed_ms=(time.perf_counter_ns()-before)/1e6
        resumed=r2.ok("catchup_status")
        self.assertEqual(resumed["applied"],200-retained);self.assertEqual(resumed["requests"],200-retained)
        self.assertEqual(expected,Inspector.dump(r2))
        resumed_limits=self.check_limits(r2)
        self.assertFalse(r2.request("publish",revision=200)["ok"])
        r2.stop()
        directory=self.root/"fresh";directory.mkdir()
        before=time.perf_counter_ns()
        fresh=self.start("follower","init",directory,selected,self.config(3,[2]))
        fresh_startup_ms=(time.perf_counter_ns()-before)/1e6
        self.connect_source(r1,fresh)
        before=time.perf_counter_ns();fresh.ok("catchup_start",node_id=2,target_path=target)
        self.caught_up(fresh)
        fresh_ms=(time.perf_counter_ns()-before)/1e6
        self.assertEqual(fresh.ok("catchup_status")["applied"],200)
        # Reopen R2 on another static ID/port after fresh completes, solely for a three-way oracle.
        config=self.config(1,[2],name="r2-inspection.json")
        before=time.perf_counter_ns()
        r2=self.start("follower","open",self.root/"r2",selected,config)
        full_reopen_ms=(time.perf_counter_ns()-before)/1e6
        self.assertEqual(expected,self.assert_equivalent(r1,r2,fresh))
        limits=[self.check_limits(n) for n in (r1,r2,fresh)]
        self.assertTrue(all(n["relay_attempts"]==0 for n in limits[1:]))
        observe(kind="s4_m1",blocks=200,max_body=16,producer_stopped=True,key_absent=True,
                startup_ms=startup_ms,resumed_startup_ms=resumed_startup_ms,resumed_from=retained,
                interrupted_observed_revision=interrupted,resumed_catchup_ms=resumed_ms,resumed=resumed,
                fresh_startup_ms=fresh_startup_ms,fresh_catchup_ms=fresh_ms,fresh=fresh.ok("catchup_status"),
                full_200_block_reopen_ms=full_reopen_ms,
                production_samples=all_observations,
                queue_high_water=[n["max_buffered_bytes"] for n in (producer_limits,limits[0],resumed_limits,limits[2])],
                nodes=[dict(name=name,ready=True,tip=node.ok("status")["tip"],
                            records=201,transactions=3140,exact_original_evidence=True)
                       for name,node in (("source-r1",r1),("resumed-r2",r2),("fresh",fresh))],
                exact_state_indexes_bodies_evidence_and_originals=True)

    def test_target_is_strict_local_authority_status_never_starts_retrieval(self):
        packets=self.chain();node,port,_=self.target(packets)
        sock=self.raw_peer(port,2);pin,document=self.pin(packets)
        sock.sendall(old_frame(self.profile,1,2,status(dict(hash="ff"*32,slot=200,revision=200))))
        time.sleep(.02)
        self.assertEqual(node.ok("catchup_status")["phase"],"idle")
        before=Inspector.dump(node)
        for field,value in (("format","old"),("run_id","other"),("network_id","00"*32),
                            ("anchor_hash","00"*32),("envelope_id","11"*32),("extra",True)):
            bad=copy.deepcopy(document);bad[field]=value;pin.write_text(json.dumps(bad))
            self.assertFalse(node.request("catchup_start",node_id=2,target_path=str(pin))["ok"])
        pin.write_text(json.dumps(document))
        other,_,_=self.target(name="no-authority")
        self.assertFalse(other.request("catchup_start",node_id=2,target_path=str(pin))["ok"])
        self.assertEqual(before,Inspector.dump(node))
        node.ok("catchup_start",node_id=2,target_path=str(pin))
        kind,_=recv_frame(sock);self.assertEqual(kind,5)
        # Even independently authorized unsolicited S3 data cannot race the active request's base.
        sock.sendall(old_frame(self.profile,2,2,committed(1,packets[0]["envelope"])))
        kind,body=s3.recv_frame(sock);self.assertEqual(kind,4);self.assertEqual(int.from_bytes(body[:2],"big"),5)
        self.assertEqual(before,Inspector.dump(node))
        for command,fields in (("apply",dict(selection=1,envelope=packets[0]["envelope"].hex())),
                               ("extend_approvals",dict(path=str(self.c.path("follower-approvals",0)))),("prepare",{})):
            self.assertFalse(node.request(command,**fields)["ok"])
        node.ok("recover")
        self.assertEqual(node.ok("catchup_status")["phase"],"halted")
        self.assertEqual(node.ok("peer_status")["connections"],[])
        node.ok("catchup_cancel")
        self.assertEqual(node.ok("catchup_status")["phase"],"halted")
        self.assertEqual(before,Inspector.dump(node))

    def test_bad_responses_omission_and_wrong_context_halt_without_gap_or_retry(self):
        packets=self.chain();pin,_=self.pin(packets)
        fork=packet(self.k,self.network,1,bytes.fromhex(self.profile["anchor_wire"])[1:33],
                    [bytes.fromhex(self.tx(0))])
        for case in ("reordered","tampered","conflict","wrong-context","wrong-request","omitted","source-error"):
            node,port,_=self.target(packets,name=case);sock=self.raw_peer(port,2)
            before=Inspector.dump(node);node.ok("catchup_start",node_id=2,target_path=str(pin))
            kind,body=recv_frame(sock);self.assertEqual(kind,5)
            request_id=int.from_bytes(body[:8],"big")
            self.assertEqual(int.from_bytes(body[48:56],"big"),0)
            envelope=packets[0]["envelope"];revision=1
            if case=="reordered":envelope=packets[1]["envelope"];revision=2
            if case=="tampered":envelope=envelope[:-1]+bytes([envelope[-1]^1])
            if case=="conflict":envelope=fork["envelope"]
            raw=frame(self.profile,6,2,successor(request_id+(case=="wrong-request"),revision,envelope))
            if case=="wrong-context":raw=raw[:80]+bytes([raw[80]^1])+raw[81:]
            if case=="source-error":raw=frame(self.profile,7,2,error(request_id,4,1))
            began=time.perf_counter_ns()
            if case!="omitted":sock.sendall(raw)
            self.wait(lambda:node.ok("catchup_status")["phase"]=="halted",seconds=4)
            elapsed=(time.perf_counter_ns()-began)/1e6
            self.assertEqual(before,Inspector.dump(node))
            self.assertEqual(node.ok("catchup_status")["requests"],1)
            time.sleep(.02);self.assertEqual(node.ok("catchup_status")["requests"],1)
            observe(kind="s4_rejected_response",case=case,halt_ms=elapsed,session=node.ok("catchup_status"))
            sock.close();node.stop()

    def test_duplicate_successor_and_lost_response_resume_only_from_retained_prefix(self):
        packets=self.chain();pin,_=self.pin(packets)
        node,port,_=self.target(packets);sock=self.raw_peer(port,2)
        node.ok("catchup_start",node_id=2,target_path=str(pin));_,body=recv_frame(sock)
        first_id=int.from_bytes(body[:8],"big")
        response=frame(self.profile,6,2,successor(first_id,1,packets[0]["envelope"]))
        sock.sendall(response+response)
        self.wait(lambda:node.ok("peer_status")["duplicate_deliveries"]==1)
        kind,body=recv_frame(sock);self.assertEqual(kind,5)
        self.assertEqual(int.from_bytes(body[48:56],"big"),1)
        self.assertEqual(body[56:88],packets[0]["eid"])
        sock.close()  # Lose the next response. Retention of step 1 is not a receipt for step 2.
        self.wait(lambda:node.ok("catchup_status")["phase"]=="halted")
        self.assertEqual(node.ok("status")["tip"]["revision"],1)
        sock=self.raw_peer(port,2)
        node.ok("catchup_start",node_id=2,target_path=str(pin));_,body=recv_frame(sock)
        next_id=int.from_bytes(body[:8],"big");self.assertGreater(next_id,first_id)
        self.assertEqual(int.from_bytes(body[48:56],"big"),1)
        sock.sendall(frame(self.profile,6,2,successor(next_id,2,packets[1]["envelope"])))
        self.wait(lambda:node.ok("catchup_status")["phase"]=="complete")
        self.assertEqual(node.ok("status")["records"],3)
        self.assertEqual(node.ok("peer_status")["relay_attempts"],0)
        self.assertEqual(node.ok("catchup_status")["applied"],1)
        for n,p in enumerate(packets,1):self.assertEqual(node.ok("export",revision=n)["envelope"],p["envelope"].hex())

    def test_service_duplicate_requests_and_wrong_prefix_never_change_original_history(self):
        packets=self.chain();source,port,_=self.target(packets)
        for n,p in enumerate(packets,1):source.ok("apply",selection=n,envelope=p["envelope"].hex())
        before=Inspector.dump(source);sock=self.raw_peer(port,2)
        base=dict(hash=self.profile["anchor_wire"][2:66],slot=0,revision=0)
        target=dict(hash=packets[1]["hash"].hex(),slot=2,revision=2)
        body=request(41,base,bytes(32),target,packets[1]["eid"])
        raw=frame(self.profile,5,2,body);sock.sendall(raw+raw)
        a,b=recv_frame(sock),recv_frame(sock)
        self.assertEqual(a,b);self.assertEqual(a,(6,successor(41,1,packets[0]["envelope"])))
        variants=[]
        bad=bytearray(body);bad[8]^=1;variants.append(bytes(bad))
        bad=bytearray(body);bad[136]^=1;variants.append(bytes(bad))
        badbase=dict(hash=packets[0]["hash"].hex(),slot=1,revision=1)
        variants.append(request(42,badbase,b"\x55"*32,target,packets[1]["eid"]))
        for v in variants:
            sock.sendall(frame(self.profile,5,2,v));kind,reply=recv_frame(sock)
            self.assertEqual(kind,7);self.assertIn(int.from_bytes(reply[8:10],"big"),(2,4))
        self.assertEqual(before,Inspector.dump(source))
        self.assertEqual(source.ok("peer_status")["fresh_publications"],2)

    def test_historical_export_cannot_release_unobserved_selection_or_repair_corrupt_inputs(self):
        with self.c.node("producer") as p:
            p.ok("prepare");proposal=p.ok("propose");self.c.select(proposal)
        self.c.close();self.key.unlink()
        with Controller(self.c.root,historical=True) as historical:
            with self.assertRaises(ValueError):historical.historical_target()
            with self.assertRaises(ValueError):historical.select(proposal)
            with self.assertRaises(ValueError):historical.write_approvals("producer",1)
        selected=self.c.path("selected",1);original=selected.read_bytes()
        d=json.loads(original);d["envelope_id"]="00"*32;selected.write_text(json.dumps(d))
        with self.assertRaises(ValueError):Controller(self.c.root,historical=True)
        self.assertEqual(json.loads(selected.read_text()),d)
        selected.write_bytes(original)
        p=self.c.profile_path;d=json.loads(p.read_text());d["accounts"][0]["nonce"]=1;p.write_text(json.dumps(d))
        with self.assertRaises(ValueError):Controller(self.c.root,historical=True)


if __name__=="__main__":
    if len(sys.argv)<4:raise SystemExit("usage: python3 -B scripts/test_testnet_fixture_catchup.py PEER WORKER PRODUCER [TEST ...]")
    s3.PEER,s3.WORKER,s3.PRODUCER=(Path(p).resolve(strict=True) for p in sys.argv[1:4]);del sys.argv[1:4]
    program=unittest.main(verbosity=2,exit=False)
    report=dict(kind="s4_process_complete",tests=program.result.testsRun,failures=len(program.result.failures),
                errors=len(program.result.errors),samples=SAMPLES,outliers="all retained")
    mode=s3.PEER.parent.parent.name
    (s3.ROOT/f"target/s4-process-{mode}-{time.time_ns()}.json").write_text(json.dumps(report,sort_keys=True,indent=2))
    print(json.dumps({k:v for k,v in report.items() if k!="samples"}),flush=True)
    raise SystemExit(not program.result.wasSuccessful())
