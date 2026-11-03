#!/usr/bin/env python3
"""S2 trusted local controller: immutable original selections precede authorization.

No key bytes are read here, no peer sockets or automatic scheduling/re-signing exist. Each CLI
invocation performs one explicit init/step/reconcile/replay operation under a lifetime controller
directory lock. Local durability assumes honest file/directory fsync and the archive's SQLite model.
"""
import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import selectors
import struct
import subprocess
import time
from reproduce_native_auth_vectors import OpenSSLKeccak

MAX_FRAME = 65536
MAX_PACKET = 3644
MAX_STEPS = 200


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def read_json(path, bound):
    """No unbounded ledger/batch reads, including malformed or partially written artifacts."""
    if not path.is_file():
        raise ValueError("required regular controller input is missing")
    with path.open("rb") as f:
        raw = f.read(bound+1)
    if len(raw) > bound:
        raise ValueError("controller input byte limit")
    return json.loads(raw, object_pairs_hook=strict_object)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def hex_bytes(text, size=None, maximum=MAX_PACKET):
    if (not isinstance(text, str) or len(text) > 2*maximum or len(text) % 2
            or re.fullmatch("[0-9a-f]*", text) is None):
        raise ValueError("invalid bounded controller hex")
    data = bytes.fromhex(text)
    if size is not None and len(data) != size:
        raise ValueError("wrong controller hex width")
    return data


def sync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def durable_file(path, value, bound=512*1024):
    """Exclusive immutable publication. Exact existing artifacts are re-synchronized, never replaced.

    Any short/failed write/sync leaves an unusable/uncertain artifact and raises before permission is
    delivered. Reconciliation can resync a fully validated complete file, never fill in corrupt data.
    """
    raw = encoded(value)
    if len(raw) > bound:
        raise ValueError("controller artifact byte limit")
    if path.exists():
        if encoded(read_json(path, bound)) != raw:
            raise ValueError("immutable controller artifact differs")
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            data = memoryview(raw)
            while data:
                count = os.write(fd, data)
                if not count:
                    raise OSError("controller short write")
                data = data[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
    sync_directory(path.parent)


class Node:
    """One bounded local pipe exchange at a time. Failure is uncertainty, never an instruction to retry."""
    def __init__(self, executable, mode, profile, approvals, directory, key_file=None):
        args = [str(executable), mode, str(profile), str(approvals), str(directory)]
        if key_file is not None:
            args.append(str(key_file))  # Path only, NEVER the private signing bytes.
        self.process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, bufsize=0, close_fds=True)
        try:
            initial = self.read()
            if not initial.get("ok"):
                raise ValueError("worker startup failed; inspect profile/selection/storage separately")
        except BaseException:
            self.close()
            raise

    def exact(self, count):
        if not 0 < count <= MAX_FRAME:
            raise ValueError("worker frame byte limit")
        out = bytearray()
        deadline = time.monotonic()+30
        with selectors.DefaultSelector() as poll:
            poll.register(self.process.stdout, selectors.EVENT_READ)
            while len(out) < count:
                if not poll.select(max(0, deadline-time.monotonic())):
                    raise TimeoutError("worker response unresolved; explicitly reconcile original selection")
                raw = os.read(self.process.stdout.fileno(), count-len(out))
                if not raw:
                    raise EOFError("worker response lost; explicitly reconcile original selection")
                out.extend(raw)
        return bytes(out)

    def read(self):
        n, = struct.unpack(">I", self.exact(4))
        return json.loads(self.exact(n), object_pairs_hook=strict_object)

    def request(self, command, **fields):
        raw = encoded(dict(command=command, **fields))
        if not 0 < len(raw) <= MAX_FRAME:
            raise ValueError("operator frame byte limit")
        data = memoryview(struct.pack(">I", len(raw))+raw)
        while data:
            n = self.process.stdin.write(data)
            if not n:
                raise EOFError("worker command pipe closed")
            data = data[n:]
        self.process.stdin.flush()
        return self.read()

    def ok(self, command, **fields):
        result = self.request(command, **fields)
        if result.get("ok") is not True:
            raise ValueError("worker rejected operation; no automatic retry or re-signing")
        return result["result"]

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=10)
        self.process.stdin.close()
        self.process.stdout.close()


class Controller:
    def __init__(self, directory, worker, producer, key_file, profile=None):
        self.root = Path(directory).resolve()
        self.worker, self.producer = Path(worker).resolve(), Path(producer).resolve()
        self.key = Path(key_file).resolve(strict=True)
        self.k = None
        self.lock = None
        try:
            if profile is not None:
                self.root.mkdir(mode=0o700)  # explicit fresh creation, existing root fails
            if self.key.is_relative_to(self.root):
                raise ValueError("private key file must be outside controller artifacts")
            self.lock = os.open(self.root/"controller.lock", os.O_RDWR | (os.O_CREAT if profile is not None else 0), 0o600)
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.k = OpenSSLKeccak()
            if profile is not None:
                d = read_json(Path(profile), 16*1024)
                durable_file(self.root/"profile.json", d, 16*1024)
                (self.root/"producer").mkdir()
                (self.root/"follower").mkdir()
                sync_directory(self.root)
            self.profile_path = self.root/"profile.json"
            self.profile = read_json(self.profile_path, 16*1024)
            self.network = hex_bytes(self.profile["network_id"], 32)
            self.anchor = dict(hash=self.profile["anchor_wire"][2:66], slot=0, revision=0)
            self.records = self.load_records()
            self.producer_count = self.artifact_head("producer-approvals")
            self.follower_count = self.artifact_head("follower-approvals")
            if profile is not None:
                self.write_approvals("producer", 0)
                self.write_approvals("follower", 0)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.k is not None:
            self.k.close(); self.k = None
        if self.lock is not None:
            os.close(self.lock); self.lock = None

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()

    def path(self, kind, n):
        return self.root/f"{kind}-{n:04}.json"

    def head(self, n=None):
        n = len(self.records) if n is None else n
        if n == 0:
            return self.anchor
        r = self.records[n-1]
        return dict(hash=r["block_hash"], slot=r["slot"], revision=n)

    def packet_identity(self, text, base):
        """Recompute existing H/E-ID and structural association, not producer/native authentication.
        The worker's existing seal/receiver routes retain those independent cryptographic checks.
        """
        raw = hex_bytes(text)
        if len(raw) < 396 or raw[:6] != b"\x03\x01\x00\x00\x00\x01" or raw[6:38] != self.network:
            raise ValueError("wrong selected envelope context/framing")
        length, = struct.unpack(">I", raw[38:42])
        if length+107 != len(raw):
            raise ValueError("selected envelope length")
        inner = raw[42:42+length]
        header = inner[33:262]
        if len(header) != 229 or inner[0] != 2:
            raise ValueError("selected inner framing")
        h = self.k(b"ETERNIX_BLOCK_HEADER_V1"+header)
        if (inner[1:33] != h or struct.unpack(">IQQB", header[:21]) != (2,1162,base["slot"]+1,0)
                or header[21:53] != hex_bytes(base["hash"],32) or int.from_bytes(header[85:93],"big") != 1
                or inner[262:267] != b"\x00\x00\x00\x01P"):
            raise ValueError("selected base/header/producer/ticket mismatch")
        return h.hex(), self.k(b"\x19ETERNIX\x00BLOCK_ENVELOPE_ID\x00"+raw).hex()

    def load_records(self):
        indices = []
        for count, p in enumerate(self.root.iterdir(),1):
            if count > 1210:
                raise ValueError("controller directory entry limit")
            if p.name.startswith("selected-"):
                match = re.fullmatch(r"selected-(\d{4})\.json", p.name)
                if match is None:
                    raise ValueError("unexpected selected artifact name")
                indices.append(int(match[1]))
        if sorted(indices) != list(range(1,len(indices)+1)) or len(indices)>MAX_STEPS:
            raise ValueError("selected corpus has gaps or exceeds experiment bound")
        records, previous = [], self.anchor
        for n in sorted(indices):
            r = read_json(self.path("selected",n),16*1024)
            expected = {"format","network_id","anchor_hash","producer_id","ticket_id","selection","base","slot","block_hash","envelope_id","envelope"}
            if (set(r)!=expected or r["format"]!="eternix-controller-selection-v1" or r["network_id"]!=self.profile["network_id"]
                    or r["anchor_hash"]!=self.anchor["hash"] or r["producer_id"]!="P" or type(r["ticket_id"]) is not int or r["ticket_id"]!=1
                    or type(r["selection"]) is not int or r["selection"]!=n or r["base"]!=previous
                    or not isinstance(r["base"],dict) or set(r["base"])!={"hash","slot","revision"}
                    or type(r["base"]["slot"]) is not int or type(r["base"]["revision"]) is not int
                    or type(r["slot"]) is not int or r["slot"]!=n):
                raise ValueError("selected corpus metadata differs")
            h,eid = self.packet_identity(r["envelope"],previous)
            if (r["block_hash"],r["envelope_id"])!=(h,eid):
                raise ValueError("selected corpus original bytes/identity differ")
            records.append(r)
            previous=dict(hash=h,slot=n,revision=n)
            # Complete validated uncertain files get a real synchronization barrier, never repair.
            durable_file(self.path("selected",n),r,16*1024)
        return records

    def approval_document(self,n):
        return dict(format="eternix-fixture-approvals-v1",network_id=self.profile["network_id"],anchor_hash=self.anchor["hash"],
                    producer_id="P",ticket_id=1,steps=[{key:r[key] for key in ("base","slot","block_hash","envelope_id")}
                                                     for r in self.records[:n]])

    def artifact_head(self,kind):
        indices=[]
        for p in self.root.iterdir():
            if p.name.startswith(kind+"-"):
                m=re.fullmatch(re.escape(kind)+r"-(\d{4})\.json",p.name)
                if m is None or int(m[1])>len(self.records):
                    raise ValueError("unexpected approvals artifact")
                n=int(m[1]);indices.append(n)
                if read_json(p,512*1024)!=self.approval_document(n):
                    raise ValueError("approval artifact changed historical authority")
                if kind=="follower-approvals":
                    for i in range(1,n+1):
                        expected=self.observation(i)
                        if read_json(self.path("producer-retained",i),16*1024)!=expected:
                            raise ValueError("follower authority lacks a matching producer observation")
                        durable_file(self.path("producer-retained",i),expected,16*1024)
                durable_file(p,self.approval_document(n))
        return max(indices,default=0)

    def write_approvals(self,role,n):
        if role not in ("producer","follower") or type(n) is not int or not 0<=n<=len(self.records):
            raise ValueError("invalid derived approval range/role")
        if role=="follower":
            for i in range(1,n+1):
                if read_json(self.path("producer-retained",i),16*1024)!=self.observation(i):
                    raise ValueError("cannot release follower authority without producer retention observation")
        path=self.path(role+"-approvals",n)
        durable_file(path,self.approval_document(n))
        return path

    @contextmanager
    def node(self,role,mode="open"):
        if role=="producer":
            # Rebuild only the exact derived authority from the synchronized selected corpus before
            # opening a signer. An unresolved selection must block new preparation after restart.
            self.write_approvals("producer",len(self.records))
            self.producer_count=len(self.records)
        n=self.producer_count if role=="producer" else self.follower_count
        child=Node(self.producer if role=="producer" else self.worker,mode,self.profile_path,
                   self.path(role+"-approvals",n),self.root/role,self.key if role=="producer" else None)
        try:
            yield child
        finally:
            child.close()

    def initialize_nodes(self):
        with self.node("producer","init") as p, self.node("follower","init") as f:
            if p.ok("status")["tip"]!=self.anchor or f.ok("status")["tip"]!=self.anchor:
                raise ValueError("new worker anchor mismatch")
        return dict(outcome="initialized",new_commit=False)

    def select(self,proposal):
        if len(self.records)==MAX_STEPS:
            raise ValueError("experiment selection budget exhausted")
        base=self.head()
        if proposal.get("outcome")!="proposal" or proposal.get("new_commit") is not False or proposal.get("committed") is not False or proposal.get("base")!=base:
            raise ValueError("private proposal is not a matching new uncommitted request")
        h,eid=self.packet_identity(proposal["envelope"],base)
        if (proposal.get("block_hash"),proposal.get("envelope_id"))!=(h,eid):
            raise ValueError("proposal identity mismatch")
        n=len(self.records)+1
        r=dict(format="eternix-controller-selection-v1",network_id=self.profile["network_id"],anchor_hash=self.anchor["hash"],
               producer_id="P",ticket_id=1,selection=n,base=base,slot=n,block_hash=h,envelope_id=eid,envelope=proposal["envelope"])
        # CRITICAL ORDER: original E and base/H/E-ID are file+directory synchronized before an
        # approval artifact is written or any worker is told to extend authority/commit.
        durable_file(self.path("selected",n),r,16*1024)
        self.records.append(r)
        return n

    def inspect_retention(self,node):
        status=node.ok("status")
        n=status["tip"]["revision"]
        if type(n) is not int or not 0<=n<=len(self.records) or status["tip"]!=self.head(n):
            raise ValueError("worker has an unexplained prefix")
        for i in range(1,n+1):
            if node.ok("export",revision=i)["envelope"]!=self.records[i-1]["envelope"]:
                raise ValueError("retained original envelope differs")
        return n

    def observe_producer(self,p):
        n=self.inspect_retention(p)
        if n<self.follower_count:
            raise ValueError("producer regressed behind already released follower authority")
        for i in range(1,n+1):
            durable_file(self.path("producer-retained",i),self.observation(i))
        return n

    def observation(self,i):
        return dict(format="eternix-controller-observation-v1",selection=i,outcome="observed_retained",
                    new_commit=False,tip=self.head(i),envelope_id=self.records[i-1]["envelope_id"])

    def release_follower(self,p,f=None):
        n=self.observe_producer(p)  # Never trust a previous observation instead of current Ready data.
        path=self.write_approvals("follower",n)
        if f is not None:
            f.ok("extend_approvals",path=str(path))
        self.follower_count=n
        return n

    def step(self,transactions):
        if not isinstance(transactions,list) or len(transactions)>128:
            raise ValueError("explicit transaction batch must contain at most 128 entries")
        for tx in transactions: hex_bytes(tx,199,199)
        with self.node("producer") as p:
            if self.observe_producer(p)!=len(self.records):
                raise ValueError("selected request unresolved; explicitly reconcile/replay original E")
            with self.node("follower") as f:
                if self.inspect_retention(f)!=len(self.records):
                    raise ValueError("follower selected request unresolved; explicitly reconcile/replay original E")
                for tx in transactions: p.ok("submit_native",transaction=tx)
                prepared=p.ok("prepare")
                proposal=p.ok("propose")
                n=self.select(proposal)
                path=self.write_approvals("producer",n)
                p.ok("extend_approvals",path=str(path));self.producer_count=n
                committed=p.ok("commit_prepared",selection=n)
                if committed.get("new_commit") is not True or committed.get("outcome")!="committed" or committed.get("envelope")!=self.records[n-1]["envelope"]:
                    raise ValueError("producer commitment response unresolved")
                self.release_follower(p,f)
                result=f.ok("apply",selection=n,envelope=self.records[n-1]["envelope"])
                if self.inspect_retention(f)!=n:
                    raise ValueError("follower did not retain selected request")
                return dict(outcome="step_complete",selection=n,producer=committed["outcome"],follower=result["outcome"],
                            tip=self.head(),held=prepared["held"],new_commit=True)

    def reconcile(self):
        # No Prepare/Propose/Apply/Commit calls. This can re-establish controller artifact durability
        # and release authority only after CURRENT producer retention, never fabricate old receipts.
        with self.node("producer") as p:
            n=self.release_follower(p)
            with self.node("follower") as f:
                follower=self.inspect_retention(f)
        return dict(outcome="reconciled",selected=len(self.records),producer_retained=n,follower_retained=follower,new_commit=False)

    def replay(self):
        if not self.records:
            raise ValueError("there is no original selected request to replay")
        n=len(self.records)
        self.write_approvals("producer",n);self.producer_count=n
        with self.node("producer") as p:
            retained=self.observe_producer(p)
            if retained<n-1:
                raise ValueError("replay supports only the one unresolved selected tail")
            result=p.ok("apply",selection=n,envelope=self.records[n-1]["envelope"])
            self.release_follower(p)
            with self.node("follower") as f:
                if self.inspect_retention(f)<n-1:
                    raise ValueError("follower has more than one missing selected tail")
                follower=f.ok("apply",selection=n,envelope=self.records[n-1]["envelope"])
                if self.inspect_retention(f)!=n: raise ValueError("follower retention mismatch")
        return dict(outcome="original_request_replayed",selection=n,producer=result["outcome"],follower=follower["outcome"],
                    producer_new_commit=result["new_commit"],follower_new_commit=follower["new_commit"])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation",choices=("init","step","reconcile","replay"))
    parser.add_argument("--worker",required=True)
    parser.add_argument("--producer",required=True)
    parser.add_argument("--key-file",required=True)
    parser.add_argument("--directory",required=True)
    parser.add_argument("--profile")
    parser.add_argument("--transactions")
    args=parser.parse_args()
    if (args.operation=="init") != (args.profile is not None) or (args.operation=="step") != (args.transactions is not None):
        parser.error("init requires --profile only; step requires --transactions only")
    try:
        with Controller(args.directory,args.worker,args.producer,args.key_file,args.profile) as c:
            if args.operation=="init": result=c.initialize_nodes()
            elif args.operation=="step":
                document=read_json(Path(args.transactions),65536)
                if not isinstance(document,dict) or set(document)!={"transactions"}: raise ValueError("strict transaction batch schema")
                result=c.step(document["transactions"])
            elif args.operation=="reconcile": result=c.reconcile()
            else: result=c.replay()
        print(json.dumps(result,sort_keys=True))
    except (OSError,ValueError,KeyError,TypeError,EOFError,TimeoutError) as error:
        # No raw command, secret file content, key bytes or child argv is logged.
        raise SystemExit("fixture controller stopped: "+str(error)) from error


if __name__=="__main__":
    main()
