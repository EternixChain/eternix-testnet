#!/usr/bin/env python3
"""Finite S3 actual-socket/process tests. JSON observations retain all measured samples/outliers.

The controller/operator remains the sole source of selections; injected peer claims never grant
authority. Test key files are private runtime files using already-public toy inputs. SIGKILL, SQL
interference and transport timeouts are not physical power-loss or production-deadline evidence.
"""
import copy
from contextlib import closing
import json
import os
from pathlib import Path
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from reproduce_native_auth_vectors import OpenSSLKeccak
from reproduce_testnet_fixture_profile import ROOT, address
from reproduce_testnet_fixture_transport import frame, status, committed, reference
from test_testnet_fixture_worker import Worker as Inspector, transaction, packet, approvals
from testnet_fixture_controller import Controller, Node

PEER=WORKER=PRODUCER=None
SAMPLES=[]


def free_ports():
    sockets=[]
    try:
        for _ in range(3):
            s=socket.socket();s.bind(("127.0.0.1",0));sockets.append(s)
        return [s.getsockname()[1] for s in sockets]
    finally:
        for s in sockets:s.close()


class PeerNode(Node):
    def __init__(self,role,mode,profile,selected,directory,config,key=None):
        args=[str(PEER),role,mode,str(profile),str(selected),str(directory),str(config)]
        if key is not None:args.append(str(key))
        self.process=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        try:
            self.initial=self.read()
            if not self.initial["ok"]:raise ValueError(self.initial)
        except BaseException:
            self.close();raise

    def close(self):
        super().close()
        self.process.stderr.close()

    def stop(self):
        before=time.monotonic();result=self.ok("stop")
        assert result["outcome"]=="stopped"
        assert self.process.wait(timeout=2)==0
        return (time.monotonic()-before)*1000


def recv_exact(s,n):
    assert n<=3800
    out=bytearray()
    while len(out)<n:
        part=s.recv(n-len(out))
        if not part:raise EOFError("peer closed")
        out.extend(part)
    return bytes(out)


def recv_frame(s):
    h=recv_exact(s,144)
    assert h[:4]==b"ETX3" and h[4]==1
    n=int.from_bytes(h[8:12],"big");assert 0<n<=3656
    return h[5],recv_exact(s,n)


class TransportAcceptance(unittest.TestCase):
    def setUp(self):
        # Real file-backed durability on the same existing disk parent as previous archive work.
        self.temp=tempfile.TemporaryDirectory(prefix="eternix-s3-",dir=ROOT/"target")
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.k=OpenSSLKeccak();self.addCleanup(self.k.close)
        self.profile=json.loads((ROOT/"tests/fixtures/testnet_fixture_profile.json").read_text())
        self.network=bytes.fromhex(self.profile["network_id"])
        self.key=self.root/"private.key";fd=os.open(self.key,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        os.write(fd,(2).to_bytes(32,"big"));os.close(fd)
        self.c=Controller(self.root/"controller",WORKER,PRODUCER,self.key,ROOT/"tests/fixtures/testnet_fixture_profile.json")
        self.addCleanup(self.c.close);self.c.initialize_nodes()
        self.ports=free_ports();self.children=[]

    def config(self,node,peers,ports=None,name=None):
        ports=ports or self.ports
        p=self.root/(name or f"peers-{node}.json")
        p.write_text(json.dumps(dict(format="eternix-fixture-peers-v1",node_id=node,listen=f"127.0.0.1:{ports[node-1]}",
                               peers=[dict(node_id=n,endpoint=f"127.0.0.1:{ports[n-1]}") for n in peers])))
        return p

    def start(self,role,mode,directory,selected,config,key=None):
        child=PeerNode(role,mode,self.c.profile_path,selected,directory,config,key)
        self.addCleanup(child.close);self.children.append(child)
        return child

    def triple(self):
        p=self.start("producer","open",self.c.root/"producer",self.c.path("producer-approvals",0),self.config(1,[2]),self.key)
        r1=self.start("follower","open",self.c.root/"follower",self.c.path("follower-approvals",0),self.config(2,[1,3]))
        directory=self.root/"r2";directory.mkdir()
        r2=self.start("follower","init",directory,self.c.path("follower-approvals",0),self.config(3,[2]))
        self.connect_triple(p,r1,r2)
        return p,r1,r2

    def wait(self,predicate,seconds=5):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            value=predicate()
            if value:return value
            time.sleep(.002)
        self.fail("bounded test wait timed out")

    def connect_triple(self,p,r1,r2):
        p.ok("peer_connect",node_id=2);r1.ok("peer_connect",node_id=3)
        for n,count in ((p,1),(r1,2),(r2,1)):
            self.wait(lambda n=n,count=count:sum(c["ready"] for c in n.ok("peer_status")["connections"])==count)

    def tx(self,nonce=0,source=1,target=3,value=0):
        a=address(self.k,target) if isinstance(target,int) else target
        return transaction(self.k,self.network,source,nonce,a,value).hex()

    def prepare_commit(self,p,txs):
        for tx in txs:p.ok("submit_native",transaction=tx)
        prepared=p.ok("prepare");proposal=p.ok("propose")
        n=self.c.select(proposal);path=self.c.write_approvals("producer",n)
        p.ok("extend_approvals",path=str(path));self.c.producer_count=n
        response=p.ok("commit_prepared",selection=n)
        self.assertTrue(response["new_commit"])
        self.assertEqual(response["envelope"],proposal["envelope"])
        return n,prepared,proposal

    def grant_receivers(self,p,r1,r2):
        n=self.c.release_follower(p,r1)
        r2.ok("extend_approvals",path=str(self.c.path("follower-approvals",n)))

    def check_limits(self,node):
        stats=node.ok("peer_status")
        self.assertLessEqual(len(stats["connections"]),2)
        self.assertLessEqual(stats["max_connections"],2)
        self.assertLessEqual(stats["buffered_bytes"],32768)
        self.assertLessEqual(stats["max_buffered_bytes"],32768)
        self.assertLessEqual(stats["max_queued_frames"],8)
        self.assertEqual(stats["limits"]["automatic_retries"],0)
        for connection in stats["connections"]:
            self.assertLessEqual(connection["socket_send_bytes"],16384)
            self.assertLessEqual(connection["socket_receive_bytes"],16384)
        return stats

    def assert_equivalent(self,p,r1,r2):
        a,b,c=(Inspector.dump(n) for n in (p,r1,r2))
        self.assertEqual(a,b);self.assertEqual(b,c)
        ids,nonces,slots,hashes=[],[],[],[]
        for i,r in enumerate(a["records"]):
            t=r["tip"];self.assertEqual(t["revision"],i)
            slots.append(dict(slot=i,hash=t["hash"]));hashes.append(dict(hash=t["hash"],tip=t))
            if i==0:
                self.assertEqual(r["kind"],"trusted_anchor");self.assertIsNone(r["signature"])
                self.assertEqual(r["inner"],self.profile["anchor_wire"]);continue
            selected=self.c.records[i-1];raw=bytes.fromhex(selected["envelope"])
            length=int.from_bytes(raw[38:42],"big");inner=raw[42:42+length]
            self.assertEqual(r["inner"],inner.hex());self.assertEqual(r["signature"],raw[-65:].hex())
            self.assertEqual(r["envelope_id"],selected["envelope_id"])
            for node in (p,r1,r2):self.assertEqual(node.ok("export",revision=i)["envelope"],raw.hex())
            count=int.from_bytes(inner[281:289],"big");ordered=[]
            for pos in range(count):
                start=289+203*pos;self.assertEqual(inner[start:start+4],(199).to_bytes(4,"big"))
                tx=inner[start+4:start+203]
                identity=self.k(b"\x19ETERNIX\x00NATIVE_TX_ID\x00"+tx).hex();ordered.append(identity)
                ids.append(dict(id=identity,tip=t,position=pos))
                nonces.append(dict(sender=tx[46:66].hex(),nonce=int.from_bytes(tx[66:74],"big"),tip=t,position=pos))
            self.assertEqual(r["outcome"],dict(transaction_ids=ordered,gas_used=1000*count,fees_burned=10000*count))
        self.assertEqual(a["transactions"],sorted(ids,key=lambda x:x["id"]))
        self.assertEqual(a["sender_nonces"],sorted(nonces,key=lambda x:(x["sender"],x["nonce"])))
        self.assertEqual(a["slots"],slots);self.assertEqual(a["hashes"],sorted(hashes,key=lambda x:x["hash"]))
        return a

    def target(self,packets=None,name="target"):
        directory=self.root/name;directory.mkdir()
        selected=self.root/f"{name}-approvals.json";selected.write_text(json.dumps(approvals(self.profile,packets or [])))
        ports=free_ports();config=self.config(3,[1,2],ports,name=f"{name}-peers.json")
        node=self.start("follower","init",directory,selected,config)
        return node,ports[2],directory

    def raw_peer(self,port,node_id=1,fragment=False,small_buffer=False):
        s=socket.socket();s.settimeout(2)
        if small_buffer:s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,1024)
        s.connect(("127.0.0.1",port));self.addCleanup(s.close)
        hello=frame(self.profile,1,node_id,status(dict(hash=self.profile["anchor_wire"][2:66],slot=0,revision=0)))
        if fragment:
            for start,end in ((0,1),(1,4),(4,13),(13,40),(40,144),(144,len(hello))):
                s.sendall(hello[start:end]);time.sleep(.003)
        else:s.sendall(hello)
        kind,_=recv_frame(s);self.assertEqual(kind,1)
        return s

    def test_three_process_exchange_exact_equivalence_duplicates_and_measurements(self):
        p,r1,r2=self.triple()
        bodies=[[],[self.tx(0,value=30000)],
                [self.tx(2,target=b"\x55"*20),self.tx(0,source=3,target=4,value=10000),self.tx(1,target=1,value=1000)],
                [self.tx(i) for i in range(3,19)],[],[self.tx(19,value=1)],
                [self.tx(i) for i in range(20,36)],[]]
        for batch in bodies:
            n,prepared,proposal=self.prepare_commit(p,batch)
            self.assertEqual(r1.ok("status")["tip"]["revision"],n-1)
            self.assertEqual(r2.ok("status")["tip"]["revision"],n-1)
            self.grant_receivers(p,r1,r2)
            started=time.perf_counter_ns();published=p.ok("publish",revision=n)
            self.assertFalse(published["new_commit"])
            observed={}
            def complete():
                for name,node in (("r1",r1),("r2",r2)):
                    if name not in observed and node.ok("status")["tip"]["revision"]==n:
                        observed[name]=(time.perf_counter_ns()-started)/1e6
                return len(observed)==2
            self.wait(complete)
            sample=dict(kind="s3_sample",revision=n,body_size=len(prepared["transaction_ids"]),
                        r1_observed_commit_ms=observed["r1"],r2_observed_commit_ms=observed["r2"],
                        r1_dispatch_commit_us=r1.ok("peer_observations",offset=n-1,limit=1)["rows"][0]["received_to_commit_us"],
                        r2_dispatch_commit_us=r2.ok("peer_observations",offset=n-1,limit=1)["rows"][0]["received_to_commit_us"],
                        queue_high_water=[self.check_limits(node)["max_buffered_bytes"] for node in (p,r1,r2)])
            SAMPLES.append(sample);print(json.dumps(sample,sort_keys=True),flush=True)
            before=self.assert_equivalent(p,r1,r2)
            relay=r1.ok("peer_status")["relay_attempts"]
            dup=r1.ok("peer_status")["duplicate_deliveries"]
            self.assertFalse(p.ok("retransmit",node_id=2,revision=n)["new_commit"])
            self.wait(lambda:r1.ok("peer_status")["duplicate_deliveries"]==dup+1)
            self.assertEqual(r1.ok("peer_status")["relay_attempts"],relay)
            self.assertEqual(before,self.assert_equivalent(p,r1,r2))
            self.assertFalse(p.request("publish",revision=n)["ok"])
        full=self.assert_equivalent(p,r1,r2)
        self.assertEqual(full["status"]["transactions"],37)
        self.assertEqual(full["status"]["gas_used_total"],37000)
        self.assertEqual(full["status"]["fees_burned_total"],"370000")
        accounts={a["address"]:(a["balance_quarks"],a["nonce"]) for a in full["accounts"]}
        self.assertEqual(accounts[address(self.k,1).hex()],("999609999",36))
        self.assertEqual(accounts[address(self.k,3).hex()],("10001",1))
        self.assertEqual(accounts[address(self.k,4).hex()],("10000",0))
        for node in (r1,r2):self.assertEqual(node.ok("peer_observations",offset=0,limit=16)["total"],8)
        for node in (p,r1,r2):self.assertLess(node.stop(),1500)

    def test_fragmented_handshake_coalesced_frames_and_duplicate_reference(self):
        p=packet(self.k,self.network,1,bytes.fromhex(self.profile["anchor_wire"])[1:33],
                 [transaction(self.k,self.network,1,0,address(self.k,3),0)])
        node,port,_=self.target([p]);s=self.raw_peer(port,fragment=True)
        hello=frame(self.profile,1,1,status(dict(hash="44"*32,slot=200,revision=200)))
        data=frame(self.profile,2,1,committed(1,p["envelope"]))
        s.sendall(hello+data+data)
        one=recv_frame(s);two=recv_frame(s)
        self.assertEqual((one[0],one[1][0],two[0],two[1][0]),(3,1,3,2))
        self.assertEqual(one[1][48:80],p["eid"]);self.assertEqual(two[1][80:112],p["eid"])
        self.assertEqual(node.ok("status")["transactions"],1)
        self.assertEqual(node.ok("peer_status")["new_peer_commits"],1)
        self.assertEqual(node.ok("peer_status")["duplicate_deliveries"],1)
        self.check_limits(node)

    def test_bad_headers_legacy_tags_and_context_reject_before_body_allocation(self):
        node,port,_=self.target()
        good=frame(self.profile,1,1,status(dict(hash=self.profile["anchor_wire"][2:66],slot=0,revision=0)))[:144]
        bad=[]
        for offset in (0,4,5,6,8,14,15,16,79,80,112):
            h=bytearray(good);h[offset]^=255;bad.append(bytes(h))
        for sender in (0,3,99):
            h=bytearray(good);h[12:14]=sender.to_bytes(2,"big");bad.append(bytes(h))
        bad.extend((b"HELLO|unsafe",b"STATE|unsafe",b"HIST|unsafe",b"BLOCK|unsafe"))
        before=Inspector.dump(node)
        for h in bad:
            count=node.ok("peer_status")["protocol_rejected"]
            with socket.create_connection(("127.0.0.1",port),timeout=2) as s:
                s.sendall(h)
                self.wait(lambda:node.ok("peer_status")["protocol_rejected"]>count)
            self.assertEqual(before,Inspector.dump(node))
        stats=self.check_limits(node);self.assertEqual(stats["max_rx_body_bytes"],0)
        print(json.dumps(dict(kind="s3_rejection_headers",cases=len(bad),rx_alloc_high_water=0)),flush=True)

    def test_strict_static_loopback_config_fails_before_archive_creation(self):
        base=dict(format="eternix-fixture-peers-v1",node_id=3,listen=f"127.0.0.1:{free_ports()[2]}",
                  peers=[dict(node_id=1,endpoint=f"127.0.0.1:{free_ports()[0]}")])
        variants=[]
        for field,value in (("format","legacy"),("node_id",0),("listen","0.0.0.0:30333"),
                            ("listen","127.0.0.1:0"),("extra",True)):
            bad=copy.deepcopy(base);bad[field]=value;variants.append(bad)
        bad=copy.deepcopy(base);bad["peers"]*=3;variants.append(bad)
        bad=copy.deepcopy(base);bad["peers"]*=2;variants.append(bad)
        bad=copy.deepcopy(base);bad["peers"][0]["endpoint"]="192.0.2.1:30333";variants.append(bad)
        bad=copy.deepcopy(base);bad["peers"][0]["node_id"]=3;variants.append(bad)
        for i,value in enumerate(variants):
            directory=self.root/f"config-{i}";directory.mkdir()
            config=self.root/f"bad-config-{i}.json";config.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                PeerNode("follower","init",self.c.profile_path,self.c.path("follower-approvals",0),directory,config)
            self.assertEqual(list(directory.iterdir()),[])
        config=self.root/"huge-config.json";config.write_bytes(b" "*8193)
        directory=self.root/"huge-config";directory.mkdir()
        with self.assertRaises(ValueError):
            PeerNode("follower","init",self.c.profile_path,self.c.path("follower-approvals",0),directory,config)
        self.assertEqual(list(directory.iterdir()),[])

    def test_payload_rejection_unauthorized_wrong_signer_tampered_unsigned_and_order(self):
        base=bytes.fromhex(self.profile["anchor_wire"])[1:33]
        tx=transaction(self.k,self.network,1,0,address(self.k,3),0)
        original=packet(self.k,self.network,1,base,[tx])
        wrong=packet(self.k,self.network,1,base,[tx],signer=3)
        signature=copy.deepcopy(original);signature["envelope"]=signature["envelope"][:-1]+b"\x1b"
        signature["eid"]=self.k(b"\x19ETERNIX\x00BLOCK_ENVELOPE_ID\x00"+signature["envelope"])
        tampered=copy.deepcopy(original);raw=bytearray(tampered["envelope"]);raw[42+289+4+117]^=1
        tampered["envelope"]=bytes(raw);tampered["eid"]=self.k(b"\x19ETERNIX\x00BLOCK_ENVELOPE_ID\x00"+raw)
        wrong_context=copy.deepcopy(original);raw=bytearray(wrong_context["envelope"]);raw[6]^=1
        wrong_context["envelope"]=bytes(raw);wrong_context["eid"]=self.k(b"\x19ETERNIX\x00BLOCK_ENVELOPE_ID\x00"+raw)
        cases=[("unauthorized",[],original["envelope"],1), ("wrong-signer",[wrong],wrong["envelope"],1),
               ("signature",[signature],signature["envelope"],1),("tampered",[tampered],tampered["envelope"],1),
               ("unsigned",[original],original["inner"],1),("embedded-context",[wrong_context],wrong_context["envelope"],1)]
        future=packet(self.k,self.network,2,original["hash"],[])
        cases.append(("out-of-order",[original,future],future["envelope"],2))
        for name,selected,envelope,revision in cases:
            node,port,_=self.target(selected,name=name);before=Inspector.dump(node)
            s=self.raw_peer(port)
            s.sendall(frame(self.profile,2,1,committed(revision,envelope)))
            kind,body=recv_frame(s);self.assertEqual(kind,4);self.assertIn(int.from_bytes(body[:2],"big"),(2,3,4))
            self.assertEqual(before,Inspector.dump(node));self.assertEqual(node.ok("peer_status")["new_peer_commits"],0)
            self.check_limits(node);s.close();node.stop()

    def test_truncation_invalid_payloads_and_peer_reports_do_not_change_state(self):
        node,port,_=self.target();before=Inspector.dump(node)
        for raw in (b"E",frame(self.profile,1,1,status(dict(hash=self.profile["anchor_wire"][2:66],slot=0,revision=0)))[:-1]):
            old=node.ok("peer_status")["truncated"]
            with socket.create_connection(("127.0.0.1",port),timeout=2) as s:
                s.sendall(raw);s.shutdown(socket.SHUT_WR)
                self.wait(lambda:node.ok("peer_status")["truncated"]>old)
        for kind,body in [(1,status(dict(hash="44"*32,slot=201,revision=201))),
                          (3,reference(True,1,bytes(32),bytes(32),bytes(32))),
                          (3,b"\x03"+bytes(111)),(4,struct.pack(">H6xQ32s",99,0,bytes(32)))]:
            s=self.raw_peer(port);old=node.ok("peer_status")["protocol_rejected"]
            s.sendall(frame(self.profile,kind,1,body));self.wait(lambda:node.ok("peer_status")["protocol_rejected"]>old)
            self.assertEqual(before,Inspector.dump(node));s.close()

    def test_queue_connection_bounds_and_slow_partial_peers_leave_control_responsive(self):
        base=bytes.fromhex(self.profile["anchor_wire"])[1:33]
        p=packet(self.k,self.network,1,base,[transaction(self.k,self.network,1,i,address(self.k,3),0) for i in range(16)])
        node,port,_=self.target([p]);node.ok("apply",selection=1,envelope=p["envelope"].hex())
        a=self.raw_peer(port,1);b=self.raw_peer(port,2)
        extra=socket.create_connection(("127.0.0.1",port),timeout=2);self.addCleanup(extra.close)
        self.wait(lambda:node.ok("peer_status")["refused"]>=1)
        replies=[]
        # Saturate one queue first: alternating equally reaches the aggregate byte budget at four
        # maximum frames per peer and cannot independently exercise the eight-frame per-peer cap.
        for peer in (1,2):
            for _ in range(24):replies.append(node.request("retransmit",node_id=peer,revision=1)["ok"])
        stats=self.check_limits(node)
        self.assertTrue(any(replies));self.assertTrue(any(not r for r in replies))
        self.assertGreater(stats["queue_full"],0);self.assertEqual(stats["max_queued_frames"],8)
        start=time.monotonic();node.ok("recover");recovery_ms=(time.monotonic()-start)*1000
        after=node.ok("peer_status")
        self.assertLess(after["recovery_dispatch_us"],1500000)
        self.assertEqual(after["connections"],[])
        self.assertFalse(node.request("publish",revision=1)["ok"],"refresh cannot mint another first publication")
        partial=socket.create_connection(("127.0.0.1",port),timeout=2);self.addCleanup(partial.close)
        partial.sendall(b"E")
        started=time.monotonic();self.assertEqual(node.ok("status")["tip"]["revision"],1)
        status_ms=(time.monotonic()-started)*1000;stop_ms=node.stop()
        self.assertLess(status_ms,1500);self.assertLess(stop_ms,1500)
        print(json.dumps(dict(kind="s3_resource",high_water=stats,queued_results=replies,recovery_ms=recovery_ms,
                              recovery_dispatch_us=after["recovery_dispatch_us"],recovery_action_us=after["recovery_action_us"],
                              partial_sender_status_ms=status_ms,stop_ms=stop_ms),sort_keys=True),flush=True)
        a.close();b.close()

    def test_timeout_disconnection_and_explicit_retransmit_are_not_new_commitments(self):
        p,r1,r2=self.triple();n,_,proposal=self.prepare_commit(p,[]);self.grant_receivers(p,r1,r2)
        r1.ok("peer_disconnect",node_id=3)
        self.wait(lambda:len(r2.ok("peer_status")["connections"])==0)
        p.ok("publish",revision=n)
        self.wait(lambda:r1.ok("status")["tip"]["revision"]==1)
        self.assertEqual(r2.ok("status")["tip"]["revision"],0)
        r1.ok("peer_connect",node_id=3)
        self.wait(lambda:any(c["ready"] and c["node_id"]==3 for c in r1.ok("peer_status")["connections"]))
        # Duplicate delivery at R1 cannot reauthorize relay of a missing downstream block.
        p.ok("retransmit",node_id=2,revision=1)
        self.wait(lambda:r1.ok("peer_status")["duplicate_deliveries"]>=1)
        self.assertEqual(r2.ok("status")["tip"]["revision"],0)
        result=r1.ok("retransmit",node_id=3,revision=1);self.assertFalse(result["new_commit"])
        self.wait(lambda:r2.ok("status")["tip"]["revision"]==1)
        self.assert_equivalent(p,r1,r2)
        # A separate partial sender is closed on a hard frame deadline, not an unbounded trickle.
        node,port,_=self.target(name="timeout")
        raw=socket.create_connection(("127.0.0.1",port),timeout=2);self.addCleanup(raw.close);raw.sendall(b"E")
        self.wait(lambda:node.ok("peer_status")["timeouts"]>=1,seconds=4)
        self.assertEqual(node.ok("peer_status")["connections"],[])

    def test_real_blocked_socket_writes_do_not_starve_operator_control(self):
        p=packet(self.k,self.network,1,bytes.fromhex(self.profile["anchor_wire"])[1:33],[])
        node,port,_=self.target([p]);node.ok("apply",selection=1,envelope=p["envelope"].hex())
        peer=self.raw_peer(port,small_buffer=True)
        raw=frame(self.profile,2,1,committed(1,p["envelope"]))
        sent=[0]
        def flood():
            try:
                for _ in range(1000):peer.sendall(raw);sent[0]+=1
            except OSError:pass
        writer=threading.Thread(target=flood);writer.start()
        try:
            self.wait(lambda:node.ok("peer_status")["blocked_writes"]>0)
            stats=self.check_limits(node)
            start=time.monotonic();self.assertEqual(node.ok("status")["tip"]["revision"],1)
            status_ms=(time.monotonic()-start)*1000
            start=time.monotonic();node.ok("recover");recover_ms=(time.monotonic()-start)*1000
            after=node.ok("peer_status")
            stop_ms=node.stop()
            print(json.dumps(dict(kind="s3_blocked_socket",observed=stats,after_recovery=after,status_ms=status_ms,recovery_ms=recover_ms,
                                  stop_ms=stop_ms,offered_frames=1000,sent_frames=sent[0]),sort_keys=True),flush=True)
            for elapsed in (status_ms,stop_ms):self.assertLess(elapsed,1500)
            # Responsiveness tests dispatch latency, not a new hard bound on the unchanged full
            # SQLite audit/barrier. Retain the ENTIRE recovery wall/action time, including outliers.
            self.assertLess(after["recovery_dispatch_us"],1500000)
        finally:
            peer.close();writer.join(timeout=5);self.assertFalse(writer.is_alive())

    def test_unavailable_owner_suppresses_relay_export_and_publication_until_explicit_recovery(self):
        p,r1,r2=self.triple();n,_,proposal=self.prepare_commit(p,[self.tx(0)]);self.grant_receivers(p,r1,r2)
        db=self.c.root/"follower/archive.sqlite"
        with closing(sqlite3.connect(db)) as sql:
            sql.execute("CREATE TRIGGER s3_test_abort BEFORE INSERT ON bodies BEGIN SELECT RAISE(ABORT,'controlled S3 abort'); END");sql.commit()
        p.ok("publish",revision=n)
        self.wait(lambda:not r1.ok("peer_status")["owner_available"])
        self.assertEqual(r2.ok("status")["tip"]["revision"],0)
        for command,fields in (("status",{}),("export",dict(revision=1)),("publish",dict(revision=1)),
                               ("retransmit",dict(node_id=3,revision=1))):self.assertFalse(r1.request(command,**fields)["ok"])
        stats=self.check_limits(r1);self.assertEqual(stats["connections"],[]);self.assertEqual(stats["buffered_bytes"],0)
        self.assertFalse(r1.request("recover")["ok"])
        with closing(sqlite3.connect(db)) as sql:sql.execute("DROP TRIGGER s3_test_abort");sql.commit()
        self.assertIs(r1.ok("recover")["attempted_present"],False)
        self.wait(lambda:len(p.ok("peer_status")["connections"])==0 and len(r2.ok("peer_status")["connections"])==0)
        self.connect_triple(p,r1,r2)
        p.ok("retransmit",node_id=2,revision=1)
        self.wait(lambda:r2.ok("status")["tip"]["revision"]==1)
        self.assert_equivalent(p,r1,r2)


if __name__=="__main__":
    if len(sys.argv)!=4:raise SystemExit("usage: python3 -B scripts/test_testnet_fixture_transport.py PEER_EXEC WORKER_EXEC PRODUCER_EXEC")
    PEER,WORKER,PRODUCER=(Path(p).resolve(strict=True) for p in sys.argv[1:]);del sys.argv[1:]
    program=unittest.main(verbosity=2,exit=False)
    print(json.dumps(dict(kind="s3_complete",tests=program.result.testsRun,failures=len(program.result.failures),
                         errors=len(program.result.errors),samples=len(SAMPLES),outliers="all retained")),flush=True)
    raise SystemExit(not program.result.wasSuccessful())
