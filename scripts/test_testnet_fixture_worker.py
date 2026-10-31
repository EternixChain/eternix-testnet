#!/usr/bin/env python3
"""Finite S1 acceptance against a prebuilt actual worker executable and separate OS processes.

All signing is test-controller setup using published toy integers and independent Python packing;
the worker contains no signing service. SIGKILL and deliberate SQLite test interference are not
power-loss tests. Every child is reaped, and test reads have deadlines and bounded frame sizes.
"""
import copy
from contextlib import closing
import json
import os
import selectors
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from reproduce_native_auth_vectors import OpenSSLKeccak, SIGN_DOMAIN, sign_test_vector, G, N, multiply, recover
from reproduce_testnet_fixture_profile import ROOT, address, block, genesis, public_key

PROGRAM = None
LIMIT = 65536


def frame(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    return struct.pack(">I", len(raw)) + raw


def exact(pipe, length, seconds=10):
    """Never trust an output length or wait forever for a broken child/test."""
    assert length <= LIMIT
    deadline, result = time.monotonic() + seconds, bytearray()
    with selectors.DefaultSelector() as poll:
        poll.register(pipe, selectors.EVENT_READ)
        while len(result) < length:
            assert poll.select(max(0, deadline-time.monotonic())), "worker response timeout"
            part = os.read(pipe.fileno(), length-len(result))
            assert part, "unexpected worker EOF"
            result.extend(part)
    return bytes(result)


class Worker:
    def __init__(self, profile, approvals, directory, mode="init"):
        self.process = subprocess.Popen([str(PROGRAM), mode, str(profile), str(approvals), str(directory)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        bufsize=0)
        try:
            self.initial = self.read()
        except BaseException:
            self.close()
            raise

    def read(self):
        n, = struct.unpack(">I", exact(self.process.stdout, 4))
        assert 0 < n <= LIMIT, "response length limit"
        return json.loads(exact(self.process.stdout, n))

    def send(self, value):
        remaining = memoryview(frame(value))
        while remaining:
            written = self.process.stdin.write(remaining)
            assert written, "operator pipe closed"
            remaining = remaining[written:]
        self.process.stdin.flush()

    def request(self, value):
        self.send(value)
        return self.read()

    def ok(self, command, **fields):
        value = self.request(dict(command=command, **fields))
        assert value["ok"], value
        return value["result"]

    def dump(self):
        """Complete canonical projection assembled by the controller from bounded read-only pages."""
        result = dict(status=self.ok("status"))
        for section in ("accounts", "records", "transactions", "sender_nonces", "slots", "hashes"):
            rows, total = [], None
            while total is None or len(rows) < total:
                page = self.ok("inspect", section=section, offset=len(rows), limit=1 if section == "records" else 16)
                total = page["total"]
                assert page["rows"] or len(rows) == total
                rows.extend(page["rows"])
            result[section] = rows
        return result

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=10)
        for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
            pipe.close()

    def stop(self):
        assert self.ok("stop")["outcome"] == "stopped"
        assert self.process.wait(timeout=10) == 0


def transaction(k, network, source, nonce, recipient, value, maturity=0):
    unsigned = struct.pack(">BIQ32sB20sQ20sQ16sQQ", 2, 1, 1162, network, 0, address(k, source),
                           nonce, recipient, 0, value.to_bytes(16, "big"), 1000, maturity)
    return unsigned + sign_test_vector(source, k(SIGN_DOMAIN + unsigned))


def packet(k, network, slot, parent, txs, signer=2, ticket=1):
    """Independent existing block-signing payload; no new signing domain or eligibility rule."""
    inner, identity, ids = block(k, slot, parent, "P", ticket, txs)
    payload = struct.pack(">BBIQ32sI32s", 3, 1, 1, 1162, network, 2, identity)
    signature = sign_test_vector(signer, k(b"\x19ETERNIX\x00BLOCK_SIGN\x00" + payload))
    envelope = struct.pack(">BBI32sI", 3, 1, 1, network, len(inner)) + inner + signature
    return dict(inner=inner, hash=identity, ids=ids, signature=signature, envelope=envelope,
                eid=k(b"\x19ETERNIX\x00BLOCK_ENVELOPE_ID\x00" + envelope), txs=txs)


def approvals(profile, packets):
    previous = dict(hash=profile["anchor_wire"][2:66], slot=0, revision=0)
    steps = []
    for i, p in enumerate(packets, 1):
        steps.append(dict(base=previous, slot=i, block_hash=p["hash"].hex(), envelope_id=p["eid"].hex()))
        previous = dict(hash=p["hash"].hex(), slot=i, revision=i)
    return dict(format="eternix-fixture-approvals-v1", network_id=profile["network_id"],
                anchor_hash=profile["anchor_wire"][2:66], producer_id="P", ticket_id=1, steps=steps)


class Acceptance(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eternix-s1-process-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.k = OpenSSLKeccak()
        self.addCleanup(self.k.close)
        self.profile = json.loads((ROOT / "tests/fixtures/testnet_fixture_profile.json").read_text())
        self.network = bytes.fromhex(self.profile["network_id"])
        self.profile_path = self.write("profile.json", self.profile)
        a, b, c = (bytes.fromhex(s["address"]) for s in self.profile["accounts"])
        first = packet(self.k, self.network, 1, bytes.fromhex(self.profile["anchor_wire"])[1:33],
                       [transaction(self.k, self.network, 1, 0, b, 30000),
                        transaction(self.k, self.network, 3, 0, c, 10000)])
        empty = packet(self.k, self.network, 2, first["hash"], [])
        last = packet(self.k, self.network, 3, empty["hash"],
                      [transaction(self.k, self.network, 1, 1, a, 1000),
                       transaction(self.k, self.network, 1, 2, b"\x55"*20, 0)])
        self.packets = [first, empty, last]
        self.selected = approvals(self.profile, self.packets)
        self.approval_path = self.write("approvals.json", self.selected)

    def write(self, name, value):
        p = self.root / name
        p.write_text(json.dumps(value))
        return p

    def start(self, name, mode="init", profile=None, selected=None):
        directory = self.root / name
        if mode == "init":
            directory.mkdir(exist_ok=True)
        w = Worker(profile or self.profile_path, selected or self.approval_path, directory, mode)
        self.addCleanup(w.close)
        return w

    def apply(self, w, index, p=None):
        p = self.packets[index-1] if p is None else p
        return w.request(dict(command="apply", selection=index, envelope=p["envelope"].hex()))

    def assert_projection(self, dump, count):
        """Independent exact body/evidence/index oracle, not just equality of two implementations."""
        self.assertEqual(len(dump["records"]), count+1)
        self.assertEqual(dump["records"][0]["kind"], "trusted_anchor")
        self.assertIsNone(dump["records"][0]["signature"])
        self.assertEqual(dump["records"][0]["inner"], self.profile["anchor_wire"])
        transactions, sender_nonces, slots, hashes = [], [], [], []
        anchor = dict(hash=self.profile["anchor_wire"][2:66], slot=0, revision=0)
        slots.append(dict(slot=0, hash=anchor["hash"]))
        hashes.append(dict(hash=anchor["hash"], tip=anchor))
        for i, p in enumerate(self.packets[:count], 1):
            t = dict(hash=p["hash"].hex(), slot=i, revision=i)
            self.assertEqual(dump["records"][i], dict(tip=t, kind="authenticated_append", inner=p["inner"].hex(),
                             signature=p["signature"].hex(), envelope_id=p["eid"].hex(),
                             outcome=dict(transaction_ids=[v.hex() for v in p["ids"]],
                                          gas_used=1000*len(p["ids"]), fees_burned=10000*len(p["ids"]))))
            for pos, (identity, tx) in enumerate(zip(p["ids"], p["txs"])):
                transactions.append(dict(id=identity.hex(), tip=t, position=pos))
                sender_nonces.append(dict(sender=tx[46:66].hex(), nonce=int.from_bytes(tx[66:74], "big"), tip=t, position=pos))
            slots.append(dict(slot=i, hash=t["hash"]))
            hashes.append(dict(hash=t["hash"], tip=t))
        self.assertEqual(dump["transactions"], sorted(transactions, key=lambda v: v["id"]))
        self.assertEqual(dump["sender_nonces"], sorted(sender_nonces, key=lambda v: (v["sender"], v["nonce"])))
        self.assertEqual(dump["slots"], slots)
        self.assertEqual(dump["hashes"], sorted(hashes, key=lambda v: v["hash"]))
        n = 2 if count in (1, 2) else 4 if count == 3 else 0
        self.assertEqual(dump["status"]["gas_used_total"], 1000*n)
        self.assertEqual(dump["status"]["fees_burned_total"], str(10000*n))
        expected = [(1000000000, 0), (0, 0), (0, 0)] if count == 0 else [
            (999940000 if count == 3 else 999960000, 3 if count == 3 else 1), (10000, 1), (10000, 0)]
        self.assertEqual(dump["accounts"], sorted([dict(address=s["address"], balance_quarks=str(balance), nonce=nonce)
                         for s, (balance, nonce) in zip(self.profile["accounts"], expected)], key=lambda v: v["address"]))

    def test_two_workers_complete_equivalence_export_duplicates_and_kill_reopen(self):
        a, b = self.start("a"), self.start("b")
        self.assertTrue(a.initial["ok"] and b.initial["ok"])
        for i in range(1, 4):
            for w in (a, b):
                self.assertEqual(self.apply(w, i)["result"]["outcome"], "committed")
                self.assertEqual(w.ok("export", revision=i)["envelope"], self.packets[i-1]["envelope"].hex())
            x, y = a.dump(), b.dump()
            self.assertEqual(x, y)
            self.assert_projection(x, i)
            for w in (a, b):
                before = w.dump()
                duplicate = self.apply(w, i)["result"]
                self.assertEqual(duplicate["outcome"], "already_committed")
                self.assertFalse(duplicate["new_commit"])
                self.assertEqual(duplicate["retained_envelope_id"], self.packets[i-1]["eid"].hex())
                self.assertEqual(before, w.dump())
        # Confirmed complete responses precede SIGKILL. This tests process/lock recovery, not power loss.
        b.close()
        reopened = self.start("b", "open")
        self.assertEqual(a.dump(), reopened.dump())
        self.assert_projection(reopened.dump(), 3)
        a.stop()
        reopened.stop()

    def test_pure_reads_and_invalid_operator_or_packet_inputs(self):
        w = self.start("a")
        before = w.dump()
        missing = w.ok("account", address="55"*20)
        self.assertEqual((missing["exists"], missing["balance_quarks"], missing["nonce"]), (False, "0", 0))
        self.assertEqual(before, w.dump())
        for request in [dict(command="apply", selection=0, envelope=self.packets[0]["envelope"].hex()),
                        dict(command="apply", selection=2, envelope=self.packets[1]["envelope"].hex()),
                        dict(command="apply", selection=1, envelope="00"),
                        dict(command="apply", selection=1, envelope=self.packets[0]["inner"].hex()),
                        dict(command="apply", selection=1, envelope="gg"),
                        dict(command="apply", selection=1, envelope=self.packets[0]["envelope"].hex(), approval=self.selected["steps"][0]),
                        dict(command="status", extra=True),dict(command="recover",extra=True),
                        dict(command="stop",extra=True),dict(command="HELLO"),dict(command="STATE"),
                        dict(command="BLOCK"),dict(command="HIST"),dict(command="sign"),dict(command="submit_tx"),
                        dict(command="inspect", section="records", offset=0, limit=16),
                        dict(command="inspect", section="accounts", offset=0, limit=0),
                        dict(command="inspect", section="transactions", offset=0, limit=17),
                        dict(command="export", revision=0)]:
            self.assertFalse(w.request(request)["ok"], request.get("command"))
            self.assertEqual(before, w.dump())
        self.assertEqual(w.ok("inspect", section="accounts", offset=2**32-1, limit=1)["rows"], [])
        bad = copy.deepcopy(self.packets[0]); bad["envelope"] = bad["envelope"][:-1] + b"\x1b"
        self.assertFalse(self.apply(w, 1, bad)["ok"])
        self.assertEqual(before, w.dump())

    def test_known_hash_authentication_and_alternate_signature_are_noop_references(self):
        w = self.start("a")
        self.assertTrue(self.apply(w,1)["ok"])
        before = w.dump()
        bad = copy.deepcopy(self.packets[0])
        bad["envelope"] = bad["envelope"][:-1]+b"\x1b"
        self.assertEqual(self.apply(w,1,bad)["error"]["kind"],"rejected")
        wrong = packet(self.k,self.network,1,bytes.fromhex(self.selected["anchor_hash"]),self.packets[0]["txs"],signer=3)
        self.assertEqual(self.apply(w,1,wrong)["error"]["kind"],"rejected")
        # A second canonical signature for the public toy scalar 2, using public fixed nonce 7.
        # This variable-time arithmetic belongs only to adversarial test setup, never the worker.
        payload = struct.pack(">BBIQ32sI32s",3,1,1,1162,self.network,2,self.packets[0]["hash"])
        digest = self.k(b"\x19ETERNIX\x00BLOCK_SIGN\x00"+payload)
        r,y = multiply(7,G)
        self.assertTrue(0<r<N)
        s = (int.from_bytes(digest,"big")+r*2)*pow(7,-1,N)%N
        parity = y&1
        if s>N//2: s=N-s;parity^=1
        signature=r.to_bytes(32,"big")+s.to_bytes(32,"big")+bytes([parity])
        self.assertEqual(recover(digest,signature),multiply(2,G))
        alternate = copy.deepcopy(self.packets[0])
        alternate["envelope"] = alternate["envelope"][:-65]+signature
        eid=self.k(b"\x19ETERNIX\x00BLOCK_ENVELOPE_ID\x00"+alternate["envelope"]).hex()
        self.assertNotEqual(eid,self.packets[0]["eid"].hex())
        reference = self.apply(w,1,alternate)["result"]
        self.assertEqual(reference["outcome"],"already_committed")
        self.assertFalse(reference["new_commit"])
        self.assertEqual(reference["submitted_envelope_id"],eid)
        self.assertEqual(reference["retained_envelope_id"],self.packets[0]["eid"].hex())
        self.assertEqual(before,w.dump())
        self.assertEqual(w.ok("export",revision=1)["envelope"],self.packets[0]["envelope"].hex())

    def test_selected_pins_do_not_override_signature_or_native_validation(self):
        base = bytes.fromhex(self.selected["anchor_hash"])
        b = address(self.k, 3)
        variants = [packet(self.k, self.network, 1, base, [], signer=3),
                    packet(self.k, self.network, 1, base, [transaction(self.k,self.network,1,1,b,1)]),
                    packet(self.k, self.network, 1, base, [transaction(self.k,self.network,1,0,b,1,maturity=2)]),
                    packet(self.k, self.network, 1, base, [transaction(self.k,self.network,1,0,b,2000000000)]),
                    packet(self.k, self.network, 1, base,
                           [transaction(self.k,self.network,1,0,b,30000),
                            transaction(self.k,self.network,3,0,address(self.k,4),10000,maturity=2)])]
        for i, p in enumerate(variants):
            selected = self.write(f"bad-selected-{i}.json", approvals(self.profile, [p]))
            w = self.start(f"bad-{i}", selected=selected)
            before = w.dump()
            self.assertFalse(self.apply(w, 1, p)["ok"])
            self.assertEqual(before, w.dump())

    def test_explicit_init_open_and_lifetime_lock(self):
        directory = self.root / "missing"; directory.mkdir()
        missing = self.start("missing", "open")
        self.assertFalse(missing.initial["ok"])
        self.assertNotEqual(missing.process.wait(timeout=5), 0)
        self.assertEqual(list(directory.iterdir()), [])
        absent = self.start("does-not-exist", "open")
        self.assertFalse(absent.initial["ok"])
        self.assertFalse((self.root / "does-not-exist").exists())
        w = self.start("a")
        before = w.dump()
        for mode in ("init", "open"):
            other = self.start("a", mode)
            self.assertFalse(other.initial["ok"])
            self.assertIn("another worker", other.initial["error"]["detail"])
            self.assertNotEqual(other.process.wait(timeout=5), 0)
        self.assertEqual(before, w.dump())
        w.stop()
        repeated = self.start("a")
        self.assertFalse(repeated.initial["ok"])
        self.assertNotEqual(repeated.process.wait(timeout=5), 0)
        opened = self.start("a", "open")
        self.assertEqual(before, opened.dump())

    def test_wrong_profile_approval_and_retained_prefix_fail_closed(self):
        w = self.start("a")
        self.assertTrue(self.apply(w, 1)["ok"])
        expected = w.dump()
        w.stop()
        for key, value in [("network_id", "00"*32), ("chain_id", 1163), ("seed_burn", "1"),
                           ("max_blocks", 201), ("extra", 0), ("anchor_wire", "00")]:
            bad = copy.deepcopy(self.profile);bad[key] = value
            child = self.start("a", "open", profile=self.write(f"profile-{key}.json", bad))
            self.assertFalse(child.initial["ok"])
        for key in ("run_id", "producer_key", "accounts"):
            bad = copy.deepcopy(self.profile)
            if key == "run_id":
                bad[key] += "-other";bad["provenance"] = "controller-fixture-S1:"+bad[key]
            elif key == "producer_key":
                bad[key] = public_key(4).hex()
            else:
                bad[key][0]["balance_quarks"] = "999999999"
            bad["network_id"] = self.k(genesis(bad)).hex()
            selected = copy.deepcopy(self.selected);selected["network_id"] = bad["network_id"]
            child = self.start("a", "open", profile=self.write(f"changed-{key}.json", bad),
                               selected=self.write(f"changed-selected-{key}.json", selected))
            self.assertFalse(child.initial["ok"])
        bad = copy.deepcopy(self.selected);bad["steps"][0]["envelope_id"] = "00"*32
        child = self.start("a", "open", selected=self.write("changed-pin.json", bad))
        self.assertFalse(child.initial["ok"])
        empty = self.start("a", "open", selected=self.write("missing-prefix.json",approvals(self.profile,[])))
        self.assertFalse(empty.initial["ok"])
        for change in ("base", "context", "count", "unknown"):
            bad = copy.deepcopy(self.selected)
            if change == "base": bad["steps"][0]["base"]["hash"] = "00"*32
            elif change == "context": bad["network_id"] = "00"*32
            elif change == "count": bad["steps"] *= 67
            else: bad["unexpected"] = 0
            child = self.start("a", "open", selected=self.write(f"bad-approvals-{change}.json", bad))
            self.assertFalse(child.initial["ok"])
        opened = self.start("a", "open")
        self.assertEqual(expected, opened.dump())

    def test_actual_uncertain_abort_and_failed_recovery_hide_owner_until_explicit_success(self):
        w = self.start("a")
        before = w.dump()
        db = self.root / "a/archive.sqlite"
        # Test-only external SQLite interference deliberately violates the worker ownership model.
        # An actual trigger error rolls writes back, but unexpected DDL prevents confirmation/audit.
        with closing(sqlite3.connect(db)) as c:
            c.execute("CREATE TRIGGER s1_test_abort BEFORE INSERT ON bodies BEGIN SELECT RAISE(ABORT,'selected test failure'); END")
            c.commit()
        response = self.apply(w, 1)
        self.assertEqual(response["error"]["kind"], "recovery_required")
        for request in [dict(command="status"),dict(command="account",address="55"*20),
                        dict(command="inspect",section="records",offset=0,limit=1),dict(command="export",revision=0),
                        dict(command="apply",selection=1,envelope="00")]:
            self.assertEqual(w.request(request)["error"]["kind"], "unavailable")
        self.assertEqual(w.request(dict(command="recover"))["error"]["kind"], "unavailable")
        with closing(sqlite3.connect(db)) as c:
            c.execute("DROP TRIGGER s1_test_abort")
            c.commit()
        recovered = w.ok("recover")
        self.assertIs(recovered["attempted_present"], False)
        self.assertFalse(recovered["new_commit"])
        self.assertEqual(before, w.dump())
        self.assertEqual(self.apply(w, 1)["result"]["outcome"], "committed")

    def test_lost_response_kill_reopen_is_observed_retention_not_a_new_commit(self):
        w = self.start("a")
        w.send(dict(command="apply",selection=1,envelope=self.packets[0]["envelope"].hex()))
        length, = struct.unpack(">I", exact(w.process.stdout, 4))
        self.assertTrue(0 < length <= LIMIT)
        # The response header starts only after the owner handled COMMIT, but the result was not read.
        w.close()
        reopened = self.start("a", "open")
        self.assert_projection(reopened.dump(), 1)
        self.assertFalse(self.apply(reopened, 1)["result"]["new_commit"])

    def test_maximum_experiment_body_and_finite_history_limits(self):
        base = bytes.fromhex(self.selected["anchor_hash"])
        txs = [transaction(self.k,self.network,1,i,address(self.k,3),0) for i in range(17)]
        for n in (16, 17):
            p = packet(self.k,self.network,1,base,txs[:n])
            w = self.start(f"body-{n}", selected=self.write(f"body-selected-{n}.json", approvals(self.profile,[p])))
            self.assertEqual(self.apply(w, 1, p)["ok"], n == 16)
            self.assertEqual(w.ok("status")["transactions"], n if n == 16 else 0)
        packets = []
        for i in range(1,201):
            p = packet(self.k,self.network,i,base,[]);packets.append(p);base=p["hash"]
        w = self.start("history", selected=self.write("history.json", approvals(self.profile,packets)))
        for i,p in enumerate(packets,1): self.assertTrue(self.apply(w,i,p)["ok"])
        self.assertEqual(w.ok("status")["tip"]["revision"],200)
        self.assertFalse(w.request(dict(command="apply",selection=201,envelope=packets[-1]["envelope"].hex()))["ok"])
        self.assertEqual(w.ok("status")["records"],201)

    def test_framing_partial_input_and_blocked_output_have_bounded_memory(self):
        for name, raw in (("oversize",struct.pack(">I",LIMIT+1)),("short",b"\x00\x00"),
                          ("payload",struct.pack(">I",4)+b"{")):
            w = self.start(name)
            w.process.stdin.write(raw);w.process.stdin.close()
            self.assertFalse(w.read()["ok"])
            self.assertNotEqual(w.process.wait(timeout=5),0)
        w = self.start("json")
        w.process.stdin.write(struct.pack(">I",1)+b"{")
        self.assertFalse(w.read()["ok"])
        self.assertTrue(w.ok("status"))
        huge = self.root / "huge-profile.json";huge.write_bytes(b" "*(16*1024+1))
        child = self.start("huge",profile=huge)
        self.assertFalse(child.initial["ok"])
        self.assertFalse((self.root / "huge/archive.sqlite").exists())
        if not Path("/proc/self/status").exists(): self.skipTest("RSS observations require Linux /proc")
        def rss(worker):
            text = Path(f"/proc/{worker.process.pid}/status").read_text()
            return int(next(s.split()[1] for s in text.splitlines() if s.startswith("VmRSS:")))
        partial = self.start("partial")
        partial.process.stdin.write(struct.pack(">I",LIMIT)+b"{")
        time.sleep(.1); partial_first=rss(partial);time.sleep(.1)
        self.assertIsNone(partial.process.poll())
        partial_second=rss(partial)
        self.assertLessEqual(partial_second-partial_first,8192)
        blocked = self.start("blocked")
        def fill():
            try:
                for _ in range(10000): blocked.send(dict(command="status"))
            except (BrokenPipeError,OSError,ValueError): pass
        writer=threading.Thread(target=fill);writer.start()
        time.sleep(.1); first=rss(blocked);time.sleep(.1)
        self.assertTrue(writer.is_alive(),"finite pipes should backpressure the command writer")
        self.assertIsNone(blocked.process.poll())
        second=rss(blocked)
        self.assertLessEqual(second-first,8192)
        blocked.close();writer.join(timeout=5);self.assertFalse(writer.is_alive())
        print(f"s1_io_memory partial_rss_kib={partial_first},{partial_second} blocked_output_rss_kib={first},{second} offered_commands=10000 bounded_pipe_backpressure=true not_a_heap_cap=true")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python3 -B scripts/test_testnet_fixture_worker.py PREBUILT_WORKER_EXECUTABLE")
    PROGRAM = Path(sys.argv.pop()).resolve(strict=True)
    unittest.main(verbosity=2)
