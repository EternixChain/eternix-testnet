#!/usr/bin/env python3
"""S2 actual producer/follower process, pool, controller persistence and restart acceptance.

Published toy credentials are generated only in private temporary files at runtime. No credential
fixture is written to source. SQL interference, syscall-error injection and SIGKILL have distinct
claims and do not constitute physical power-loss testing.
"""
import copy
from contextlib import closing
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from reproduce_native_auth_vectors import OpenSSLKeccak, SIGN_DOMAIN, sign_test_vector
from reproduce_testnet_fixture_profile import ROOT, address, genesis
from test_testnet_fixture_worker import Worker as Inspector, transaction
from testnet_fixture_controller import Controller, Node, durable_file, read_json

WORKER = PRODUCER = None


def dump(node):
    return Inspector.dump(node)


def write_json(path, value):
    path.write_text(json.dumps(value))
    return path


class ProducerAcceptance(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="eternix-s2-process-")
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.k=OpenSSLKeccak();self.addCleanup(self.k.close)
        self.profile=json.loads((ROOT/"tests/fixtures/testnet_fixture_profile.json").read_text())
        self.network=bytes.fromhex(self.profile["network_id"])
        self.profile_path=write_json(self.root/"profile.json",self.profile)
        # Already-published toy integer 2, materialized only as a runtime private file, not a source
        # credential or CLI value. Real confidentiality is separately tested with an ephemeral key.
        self.key=self.root/"private.key"
        fd=os.open(self.key,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        os.write(fd,(2).to_bytes(32,"big"));os.close(fd)
        self.c=Controller(self.root/"run",WORKER,PRODUCER,self.key,self.profile_path)
        self.addCleanup(self.c.close)
        self.c.initialize_nodes()

    def tx(self,nonce=0,source=1,target=3,value=0,maturity=0):
        recipient=address(self.k,target) if isinstance(target,int) else target
        return transaction(self.k,self.network,source,nonce,recipient,value,maturity).hex()

    def approve(self,p,proposal):
        n=self.c.select(proposal)
        path=self.c.write_approvals("producer",n)
        p.ok("extend_approvals",path=str(path));self.c.producer_count=n
        return n

    def assert_full_equivalence(self, controller=None):
        c=controller or self.c
        with c.node("producer") as p,c.node("follower") as f:
            left,right=dump(p),dump(f)
            self.assertEqual(left,right)
            txs,nonces,slots,hashes=[],[],[],[]
            for i,record in enumerate(left["records"]):
                tip=record["tip"]
                self.assertEqual(tip["revision"],i)
                slots.append(dict(slot=i,hash=tip["hash"]));hashes.append(dict(hash=tip["hash"],tip=tip))
                if i==0:
                    self.assertEqual(record["inner"],self.profile["anchor_wire"])
                    self.assertEqual(record["kind"],"trusted_anchor");self.assertIsNone(record["signature"])
                    continue
                selected=c.records[i-1]
                raw=bytes.fromhex(selected["envelope"]);length=int.from_bytes(raw[38:42],"big")
                inner=raw[42:42+length]
                self.assertEqual(record["inner"],inner.hex());self.assertEqual(record["signature"],raw[-65:].hex())
                self.assertEqual(record["envelope_id"],selected["envelope_id"])
                self.assertEqual(p.ok("export",revision=i)["envelope"],selected["envelope"])
                self.assertEqual(f.ok("export",revision=i)["envelope"],selected["envelope"])
                count=int.from_bytes(inner[281:289],"big")
                ids=[]
                for pos in range(count):
                    offset=289+203*pos
                    self.assertEqual(inner[offset:offset+4],(199).to_bytes(4,"big"))
                    tx=inner[offset+4:offset+203]
                    identity=self.k(b"\x19ETERNIX\x00NATIVE_TX_ID\x00"+tx).hex();ids.append(identity)
                    txs.append(dict(id=identity,tip=tip,position=pos))
                    nonces.append(dict(sender=tx[46:66].hex(),nonce=int.from_bytes(tx[66:74],"big"),tip=tip,position=pos))
                self.assertEqual(record["outcome"],dict(transaction_ids=ids,gas_used=1000*count,fees_burned=10000*count))
            self.assertEqual(left["transactions"],sorted(txs,key=lambda v:v["id"]))
            self.assertEqual(left["sender_nonces"],sorted(nonces,key=lambda v:(v["sender"],v["nonce"])))
            self.assertEqual(left["slots"],slots);self.assertEqual(left["hashes"],sorted(hashes,key=lambda v:v["hash"]))
            return left

    def test_controller_empty_single_ordered_multi_and_funding_deferral(self):
        self.assertEqual(self.c.step([])["selection"],1)
        result=self.c.step([self.tx(0,source=3,target=4,value=10000),self.tx(0,value=30000)])
        self.assertEqual(result["held"]["funding"],1)
        self.c.step([self.tx(2,target=b"\x55"*20),self.tx(1,target=1,value=1000),self.tx(0,source=3,target=4,value=10000)])
        full=self.assert_full_equivalence()
        self.assertEqual(full["status"]["gas_used_total"],4000)
        self.assertEqual(full["status"]["fees_burned_total"],"40000")
        accounts={a["address"]:a for a in full["accounts"]}
        for source,balance,nonce in ((1,"999940000",3),(3,"10000",1),(4,"10000",0)):
            self.assertEqual((accounts[address(self.k,source).hex()]["balance_quarks"],accounts[address(self.k,source).hex()]["nonce"]),(balance,nonce))
        self.assertEqual(len(accounts),3)

    def test_documented_controller_cli_init_step_reconcile_and_replay(self):
        directory=self.root/"cli-run"
        common=["--worker",str(WORKER),"--producer",str(PRODUCER),"--key-file",str(self.key),"--directory",str(directory)]
        def invoke(operation,extra=()):
            result=subprocess.run([sys.executable,"-B",str(ROOT/"scripts/testnet_fixture_controller.py"),operation,*common,*extra],
                                  capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            self.assertLessEqual(len(result.stdout),65536)
            return json.loads(result.stdout)
        self.assertEqual(invoke("init",["--profile",str(self.profile_path)])["outcome"],"initialized")
        batch=write_json(self.root/"batch.json",dict(transactions=[self.tx(0)]))
        self.assertEqual(invoke("step",["--transactions",str(batch)])["selection"],1)
        report=invoke("reconcile");self.assertEqual(report["producer_retained"],1);self.assertFalse(report["new_commit"])
        replay=invoke("replay");self.assertFalse(replay["producer_new_commit"]);self.assertFalse(replay["follower_new_commit"])

    def test_admission_capacity_dedup_no_replacement_and_commit_only_cleanup(self):
        with self.c.node("producer") as p:
            before=dump(p)
            inputs=[self.tx(i) for i in range(129)]
            for tx in inputs[:128]: self.assertEqual(p.ok("submit_native",transaction=tx)["outcome"],"admitted")
            self.assertEqual(before,dump(p),"admission never reserves canonical nonce/balance")
            self.assertEqual(p.ok("submit_native",transaction=inputs[0])["outcome"],"duplicate_id")
            self.assertFalse(p.request("submit_native",transaction=self.tx(0,value=1))["ok"])
            self.assertFalse(p.request("submit_native",transaction=inputs[128])["ok"])
            self.assertEqual(p.ok("pool",offset=0,limit=16)["count"],128)
            prepared=p.ok("prepare");self.assertEqual(len(prepared["transaction_ids"]),16)
            proposal=p.ok("propose");self.assertEqual(proposal,p.ok("propose"))
            self.assertEqual(p.ok("prepare")["outcome"],"already_prepared")
            self.assertFalse(p.request("commit_prepared",selection=1)["ok"])
            self.assertEqual(p.ok("pool",offset=0,limit=16)["count"],128)
            self.assertEqual(before,dump(p))
            n=self.approve(p,proposal)
            self.assertFalse(self.c.path("follower-approvals",n).exists())
            with self.assertRaises(ValueError):self.c.write_approvals("follower",n)
            committed=p.ok("commit_prepared",selection=n)
            self.assertEqual(committed["pool_removed"],16)
            self.assertEqual(p.ok("pool",offset=0,limit=16)["count"],112)
            self.c.release_follower(p)
            with self.c.node("follower") as f: f.ok("apply",selection=n,envelope=proposal["envelope"])
        self.assertEqual(self.assert_full_equivalence()["status"]["transactions"],16)

    def test_nonce_gaps_maturity_self_credit_and_selection_are_local_policy(self):
        with self.c.node("producer") as p:
            p.ok("submit_native",transaction=self.tx(1))
            p.ok("submit_native",transaction=self.tx(0,maturity=2))
            p.ok("submit_native",transaction=self.tx(0,source=3,target=4,value=10000))
            before=dump(p)
            prepared=p.ok("prepare")
            self.assertEqual(prepared["transaction_ids"],[])
            self.assertEqual(prepared["held"]["immature"],1)
            self.assertEqual(prepared["held"]["nonce_gap"],1)
            self.assertEqual(prepared["held"]["funding"],1)
            self.assertEqual(before,dump(p))
            proposal=p.ok("propose");n=self.approve(p,proposal)
            p.ok("commit_prepared",selection=n)
            self.assertEqual(p.ok("pool",offset=0,limit=16)["count"],3)
            next_body=p.ok("prepare")
            self.assertEqual(len(next_body["transaction_ids"]),2)
            self.assertEqual(next_body["held"]["funding"],1)
        # A different fresh producer proves self-credit is also intentionally not previewed.
        directory=self.root/"self-credit";directory.mkdir()
        empty=ROOT/"tests/fixtures/testnet_fixture_approvals_empty.json"
        q=Node(PRODUCER,"init",self.profile_path,empty,directory,self.key)
        try:
            q.ok("submit_native",transaction=self.tx(0,target=1,value=999980000))
            q.ok("submit_native",transaction=self.tx(1,value=1))
            selected=q.ok("prepare")
            self.assertEqual(len(selected["transaction_ids"]),1)
            self.assertEqual(selected["held"]["funding"],1)
            self.assertEqual(q.ok("status")["tip"]["revision"],0)
        finally: q.close()

    def test_selection_order_independent_of_arrival_and_invalid_admission(self):
        inputs=[self.tx(2),self.tx(0),self.tx(1)]
        empty=ROOT/"tests/fixtures/testnet_fixture_approvals_empty.json"
        proposals=[]
        for i,batch in enumerate((inputs,list(reversed(inputs)))):
            directory=self.root/f"order-{i}";directory.mkdir()
            p=Node(PRODUCER,"init",self.profile_path,empty,directory,self.key)
            try:
                for tx in batch: p.ok("submit_native",transaction=tx)
                p.ok("prepare");proposals.append(p.ok("propose"))
            finally: p.close()
        self.assertEqual(proposals[0],proposals[1])
        with self.c.node("producer") as p:
            before=dump(p)
            bad=["", "00", self.tx(0)[:-2]+"1b"]
            for field,value in (("network",b"\x00"*32),("nonce",(2**64-1).to_bytes(8,"big")),("gas",(999).to_bytes(8,"big"))):
                raw=bytearray(bytes.fromhex(self.tx(0))[:134]);start={"network":13,"nonce":66,"gas":118}[field]
                raw[start:start+len(value)]=value
                bad.append((raw+sign_test_vector(1,self.k(SIGN_DOMAIN+raw))).hex())
            for tx in bad: self.assertFalse(p.request("submit_native",transaction=tx)["ok"])
            self.assertEqual(p.ok("pool",offset=0,limit=16)["count"],0)
            self.assertEqual(before,dump(p))

    def test_wrong_approval_and_stale_preparation_do_not_install_or_replace_authority(self):
        empty=ROOT/"tests/fixtures/testnet_fixture_approvals_empty.json"
        directory=self.root/"other";directory.mkdir()
        q=Node(PRODUCER,"init",self.profile_path,empty,directory,self.key)
        try:
            with self.c.node("producer") as p:
                p.ok("submit_native",transaction=self.tx(0))
                p.ok("prepare");original=p.ok("propose")
                q.ok("prepare");other=q.ok("propose")
                self.assertNotEqual(original["block_hash"],other["block_hash"])
                n=self.approve(p,other)  # explicit controller choice, wrong for p's pending effects
                self.assertFalse(p.request("commit_prepared",selection=n)["ok"])
                self.assertEqual(p.ok("pool",offset=0,limit=16)["count"],1)
                self.assertEqual(p.ok("status")["tip"]["revision"],0)
                replacement=self.c.approval_document(1)
                replacement["steps"][0]["block_hash"]=original["block_hash"]
                replacement["steps"][0]["envelope_id"]=original["envelope_id"]
                path=write_json(self.root/"replacement.json",replacement)
                self.assertFalse(p.request("extend_approvals",path=str(path))["ok"])
                self.assertFalse(p.request("apply",selection=1,envelope=other["envelope"])["ok"])
                p.ok("recover")
                for cmd in ("prepare","propose"):
                    self.assertFalse(p.request(cmd)["ok"])
                self.assertFalse(p.request("commit_prepared",selection=1)["ok"])
                p.ok("apply",selection=1,envelope=other["envelope"])
                self.assertEqual(p.ok("pool",offset=0,limit=16)["count"],1)
        finally:q.close()

    def test_storage_uncertainty_blocks_signing_cleanup_and_follower_authority_until_recovery(self):
        with self.c.node("producer") as p:
            p.ok("submit_native",transaction=self.tx(0))
            p.ok("prepare");proposal=p.ok("propose");n=self.approve(p,proposal)
            db=self.c.root/"producer/archive.sqlite"
            with closing(sqlite3.connect(db)) as sql:
                sql.execute("CREATE TRIGGER s2_test_abort BEFORE INSERT ON bodies BEGIN SELECT RAISE(ABORT,'controlled S2 abort'); END");sql.commit()
            result=p.request("commit_prepared",selection=n)
            self.assertEqual(result["error"]["kind"],"recovery_required");self.assertNotIn("result",result)
            for cmd,fields in (("prepare",{}),("propose",{}),("submit_native",dict(transaction=self.tx(0))),
                               ("commit_prepared",dict(selection=n)),("pool",dict(offset=0,limit=16)),("export",dict(revision=1))):
                self.assertEqual(p.request(cmd,**fields)["error"]["kind"],"unavailable")
            self.assertFalse(p.request("recover")["ok"])
            with self.assertRaises(ValueError):self.c.release_follower(p)
            self.assertFalse(self.c.path("follower-approvals",1).exists())
            with closing(sqlite3.connect(db)) as sql:sql.execute("DROP TRIGGER s2_test_abort");sql.commit()
            self.assertIs(p.ok("recover")["attempted_present"],False)
            self.assertEqual(p.ok("pool",offset=0,limit=16)["count"],1)
            self.assertFalse(p.request("prepare")["ok"])
            self.assertFalse(p.request("propose")["ok"])
            result=p.ok("apply",selection=n,envelope=proposal["envelope"])
            self.assertTrue(result["new_commit"])
            self.assertEqual(p.ok("pool",offset=0,limit=16)["count"],0)
            self.c.release_follower(p)
            with self.c.node("follower") as f:f.ok("apply",selection=n,envelope=proposal["envelope"])
        self.assertEqual(self.assert_full_equivalence()["status"]["transactions"],1)

    def restart_controller(self):
        root=self.c.root;self.c.close()
        c=Controller(root,WORKER,PRODUCER,self.key);self.addCleanup(c.close)
        return c

    def test_selected_original_survives_before_authorization_and_blocks_new_signing_on_restart(self):
        with self.c.node("producer") as p:
            p.ok("submit_native",transaction=self.tx(0));p.ok("prepare")
            proposal=p.ok("propose");self.c.select(proposal)
            self.assertFalse(self.c.path("producer-approvals",1).exists())
            self.assertFalse(self.c.path("follower-approvals",1).exists())
        c=self.restart_controller()
        report=c.reconcile()
        self.assertEqual((report["selected"],report["producer_retained"],report["follower_retained"]),(1,0,0))
        with c.node("producer") as p:
            self.assertFalse(p.request("prepare")["ok"])
            self.assertFalse(p.request("propose")["ok"])
        with self.assertRaises(ValueError):c.step([])
        self.assertEqual(c.replay()["producer"],"committed")
        self.assertFalse(c.replay()["producer_new_commit"])
        self.assertEqual(read_json(c.path("selected",1),16384)["envelope"],proposal["envelope"])
        self.assert_full_equivalence(c)

    def test_lost_commit_reply_reconciles_without_resigning_or_duplicate_execution(self):
        with self.c.node("producer") as p:
            p.ok("submit_native",transaction=self.tx(0));p.ok("prepare")
            proposal=p.ok("propose");self.approve(p,proposal)
            raw=json.dumps(dict(command="commit_prepared",selection=1)).encode()
            p.process.stdin.write(struct.pack(">I",len(raw))+raw);p.process.stdin.flush()
            length,=struct.unpack(">I",p.exact(4));self.assertTrue(0<length<=65536)
            p.close()  # producer handled command; controller did not consume its result payload
        original=self.c.path("selected",1).read_bytes()
        c=self.restart_controller()
        calls=[];method=Node.ok
        def observed(node,command,**fields):
            calls.append(command);return method(node,command,**fields)
        with patch.object(Node,"ok",observed):
            report=c.reconcile();self.assertEqual(report["producer_retained"],1);self.assertFalse(report["new_commit"])
            replay=c.replay();self.assertFalse(replay["producer_new_commit"])
        self.assertFalse(set(calls)&{"prepare","propose","commit_prepared","submit_native"})
        self.assertEqual(c.path("selected",1).read_bytes(),original)
        full=self.assert_full_equivalence(c)
        self.assertEqual(full["status"]["transactions"],1)

    def test_selection_file_sync_failure_delivers_no_authorization_and_resyncs_original_only(self):
        for which in ("file","directory"):
            if which=="directory":
                self.c.close()
                self.c=Controller(self.root/"run-directory",WORKER,PRODUCER,self.key,self.profile_path)
                self.addCleanup(self.c.close);self.c.initialize_nodes()
            with self.c.node("producer") as p:
                p.ok("prepare");proposal=p.ok("propose")
                real=os.fsync
                def fail(fd):
                    if which=="file" or stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError("injected selected-artifact sync failure")
                    real(fd)
                with patch("testnet_fixture_controller.os.fsync",side_effect=fail):
                    with self.assertRaises(OSError):self.c.select(proposal)
                self.assertFalse(self.c.path("producer-approvals",1).exists())
                self.assertFalse(self.c.path("follower-approvals",1).exists())
                self.assertFalse(p.request("commit_prepared",selection=1)["ok"])
                self.assertEqual(p.ok("status")["tip"]["revision"],0)
            c=self.restart_controller()
            self.assertEqual(c.reconcile()["producer_retained"],0)
            self.assertTrue(c.replay()["producer_new_commit"])
            self.assertEqual(c.records[0]["envelope"],proposal["envelope"])
            c.close()

    def test_corrupt_selected_artifact_and_controller_lock_fail_closed(self):
        with self.assertRaises(BlockingIOError): Controller(self.c.root,WORKER,PRODUCER,self.key)
        with self.c.node("producer") as p:
            p.ok("prepare");proposal=p.ok("propose");self.c.select(proposal)
        path=self.c.path("selected",1);path.write_bytes(b"{")
        root=self.c.root;self.c.close()
        with self.assertRaises(ValueError):Controller(root,WORKER,PRODUCER,self.key)
        self.assertEqual(path.read_bytes(),b"{")
        self.assertFalse((root/"producer-approvals-0001.json").exists())

    def test_signer_permissions_binding_and_ephemeral_secret_exclusion(self):
        # A high-entropy temporary key makes accidental literal-key leakage checks meaningful;
        # the normal public toy key's many zero bytes also occur legitimately in block headers.
        secret=secrets.token_bytes(32)
        key=ec.derive_private_key(int.from_bytes(secret,"big"),ec.SECP256K1())
        public=key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint).hex()
        profile=copy.deepcopy(self.profile);profile["producer_key"]=public
        profile["network_id"]=self.k(genesis(profile)).hex()
        path=write_json(self.root/"ephemeral-profile.json",profile)
        key_path=self.root/"ephemeral.key";fd=os.open(key_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        os.write(fd,secret);os.close(fd)
        with Controller(self.root/"ephemeral",WORKER,PRODUCER,key_path,path) as c:
            c.initialize_nodes();c.step([])
            for p in c.root.iterdir():
                if p.is_file():
                    raw=p.read_bytes();self.assertNotIn(secret,raw);self.assertNotIn(secret.hex().encode(),raw)
            with c.node("producer") as p:
                self.assertNotIn(secret.hex(),json.dumps(p.ok("status")))
                args=Path(f"/proc/{p.process.pid}/cmdline").read_bytes()
                self.assertNotIn(secret,args);self.assertNotIn(secret.hex().encode(),args)
        os.chmod(self.key,0o644)
        with self.assertRaises(ValueError):
            with self.c.node("producer"):pass
        os.chmod(self.key,0o600)
        wrong=self.root/"wrong.key";fd=os.open(wrong,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        os.write(fd,(3).to_bytes(32,"big"));os.close(fd)
        with self.assertRaises(ValueError):
            Node(PRODUCER,"open",self.c.profile_path,self.c.path("producer-approvals",0),self.c.root/"producer",wrong)


if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: python3 -B scripts/test_testnet_fixture_producer.py WORKER_EXECUTABLE PRODUCER_EXECUTABLE")
    WORKER,PRODUCER=(Path(p).resolve(strict=True) for p in sys.argv[1:])
    del sys.argv[1:]
    unittest.main(verbosity=2)
