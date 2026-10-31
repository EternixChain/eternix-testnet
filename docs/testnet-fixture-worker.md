# S1 — Local Authenticated Fixture Worker

`examples/testnet_fixture_node.rs` implements the approved S1 portion of the bounded M1 experiment.
It is a long-lived process with **one serialized `AuthenticatedFixtureStore` owner**, strict public
initialization/selection inputs and local operator commands. It contains no producer signing,
mempool, peer sockets, scheduler, PoAsh eligibility or prototype-node integration.

Supporting code is confined to `examples/testnet_support/{profile,framing,mod,tests}.rs`. Existing
archive schemas, cryptographic domains/bytes, native rules, durability/audits/recovery and legacy
HIST/BLOCK rejection are reused unchanged. There was no archive API gap requiring a contract change.

## Build and Invocation

```bash
cargo build --example testnet_fixture_node
cargo build --release --example testnet_fixture_node
```

Actual executable syntax, exactly four arguments:

```text
testnet_fixture_node init|open PROFILE_JSON APPROVALS_JSON EXISTING_DATA_DIR
```

The operator creates the data directory first. `init` exclusively creates `archive.sqlite`; it does
not open an existing database. `open` requires both `archive.sqlite` and the existing `worker.lock`,
uses no CREATE, and never initializes, repairs or fills missing state. Failed initialization can
leave an unusable artifact; it is not silently replaced. Opening/recovery performs the archive's
complete authenticated/native audit and synchronized barrier before usable status.

The process canonicalizes the directory and holds `std::fs::File::try_lock()` on its persistent
`worker.lock` until **after** the store/SQLite connection is dropped. Competing init/open workers
fail before opening the archive. Normal exit or SIGKILL releases the OS advisory lock; never unlink
or replace its inode while workers run. This excludes cooperating workers per directory, not arbitrary
programs ignoring the lock or operator-created hard-link aliases. Local filesystem locking/sync
assumptions still apply. Verified on Linux/Rust 1.98; the standard locking API requires Rust 1.89+.

Startup emits one framed Ready status on success. A startup/framing error emits one bounded terminal
error when output is usable, then exits nonzero; diagnostics on stderr are separate from framed stdout.
Clean EOF between commands closes the worker normally. No canonical state is reconstructed from a
legacy wallet, pending nonce tracker, HELLO/STATE snapshot or peer declaration.

## Independent Public Profile and Exact Test-Genesis Bytes

Public golden input: [`../tests/fixtures/testnet_fixture_profile.json`](../tests/fixtures/testnet_fixture_profile.json).
Every field is required; unknown/duplicate fields, wrong types, extra data, unsupported parameters,
noncanonical hex, repeated seed addresses and inconsistent derived context fail closed. Profiles are
regular files limited to **16 KiB**, read with one overflow-detection byte. Hex is lowercase without
`0x`, whitespace or normalization. This file carries public keys/addresses, never private keys.

Frozen S1 profile:

- Format `eternix-fixture-profile-v1`; run ID `s1-golden-2026`.
- Chain 1162 as a test choice; native encoding/rules 2/1, inner wire/header 2/2, outer wire/auth
  encoding/auth rules 3/1/1, local storage schema 3. These are independent version fields.
- Exact literal 302-byte unsigned empty anchor, slot 0, zero parent, proposer `fixture-anchor`,
  synthetic ticket 1, existing reserved roots and zero body gas/burn. Its hash is
  `80f28277239841d073164e851ca2d1a60d7f844e9cf47c05bd90475c5b4039ff`.
- Provenance `controller-fixture-S1:s1-golden-2026`; post-anchor gas/burn zero.
- Exactly these ordered seeds, canonical nonces all zero; balances are decimal strings:

| Role | Raw 20-byte address (hex) | Quarks |
|---|---|---:|
| Alice | `7e5f4552091a69125d5dfcb7b8c2659029395bdf` | 1000000000 |
| Bob | `6813eb9362372eef6200f3b1dbc3f819671cba69` | 0 |
| Carol | `1eff47bc3a10a45d4b230b5d10e37751fe6aa718` | 0 |

- One static binding `P` to full canonical compressed key
  `02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5`.
  Appended blocks must name P and ticket 1. This is experiment authority, not ticket eligibility.
- Exactly the experiment limits 200 appended blocks and 16 transactions per block. These do not
  alter the library's 3,000-entry/gas limits or any prototype slot constants.

The **630 golden genesis bytes**, not display text, are frozen in
[`../tests/fixtures/testnet_fixture_genesis.hex`](../tests/fixtures/testnet_fixture_genesis.hex).
Their existing `network_id_from_genesis_bytes` Keccak-256 is:

```text
d94c203efc1b5a9e032b7435ad57df7fa599ff8a5ed124f1d2b085b70c300fda
```

Encoding, in this exact order (all integers unsigned BE, no alignment/default serialization):

```text
b"ETERNIX_FIXTURE_GENESIS_S1\0"                       # literal 27-byte test descriptor
BE32(1) || T(run_id) || BE64(chain_id)
native_encoding:u8 || BE32(native_rules)
inner_wire:u8 || BE32(header_profile)
outer_wire:u8 || auth_encoding:u8 || BE32(auth_rules) || BE32(storage_schema)
BE32(anchor_wire_byte_length) || exact existing anchor wire bytes
T(provenance) || BE16(3)
for Alice, Bob, Carol in that fixed role order:
    role:u8 (0,1,2) || raw_address[20] || BE128(balance) || BE64(nonce)
BE64(seed_gas) || BE128(seed_burn) || BE16(1)
T(producer_id) || raw_compressed_public_key[33]
BE64(max_blocks) || BE32(max_transactions)

T(s) = BE16(UTF-8 byte length) || exact UTF-8 bytes
```

S1 strings are bounded ASCII: run ID 1..64 alphanumeric/`-`/`_`, exact derived provenance, fixed
producer ID P. The supplied `network_id` is checked against this calculation but **excluded from its
own preimage**; no computed genesis self-hash is encoded. The embedded anchor hash is its separate
existing header hash and has no network-ID dependency for this empty anchor. No new signing domain,
header field or production genesis convention is introduced. JSON key order/whitespace do not enter
the genesis encoding; seed role order does, and is enforced. An incompatible reset needs a new
run descriptor/genesis/network identity and fresh directories. Literal keys/addresses can be selected
in a different trusted run profile; incoming data cannot select them.

Independent reproduction uses separate Python `struct` packing/public-vector arithmetic and OpenSSL
Keccak, no Rust codec:

```bash
python3 -B scripts/reproduce_testnet_fixture_profile.py
```

`--emit` prints calculated golden data for inspection and never writes/replaces fixtures. The
published toy points in this vector are test inputs, not deployment credentials or worker-held keys.

## Independent Selected Requests

The trusted local operator supplies a separate regular **approvals JSON file, at most 512 KiB**.
It is loaded once before the owner becomes usable. The profile and approvals are trusted experiment
authority; neither a peer nor an Apply packet can supply/rewrite them. The controller retains its
original exact packets outside the worker and prepares these pins before requests are submitted.

Actual schema (all fields required, unknown/duplicate fields rejected):

```json
{
  "format": "eternix-fixture-approvals-v1",
  "network_id": "<independently pinned profile network ID>",
  "anchor_hash": "<independently pinned anchor H>",
  "producer_id": "P",
  "ticket_id": 1,
  "steps": [
    {
      "base": {"hash": "<prior selected H>", "slot": 0, "revision": 0},
      "slot": 1,
      "block_hash": "<selected H>",
      "envelope_id": "<selected exact E-ID>"
    }
  ]
}
```

Steps are contiguous from the trusted anchor, at most 200, without repeated block or envelope IDs;
their base Tips, slots and revisions must form exactly one chain. Hashes/IDs are exactly 32 bytes.
An empty approval list is valid for initialization/inspection; a usable matching empty example is
[`../tests/fixtures/testnet_fixture_approvals_empty.json`](../tests/fixtures/testnet_fixture_approvals_empty.json).
Opening a nonempty archive with omitted/different historical pins fails rather than downgrading to
fresh unpinned attribution. Valid shorter local prefixes are reported as `catching_up`; no catch-up
service is implemented in S1. Changing/expanding approvals requires explicit stop/open with a matching
retained prefix; there is no hot-reload command.

For a new append, the worker compares the independent selection's profile/anchor/base/H/slot with
the submitted envelope, checks P/ticket/body budget and exact E-ID, constructs the fixture grant
**from selection fields**, then calls the archive's signed staging once. The sealed proof's E-ID
must still match before commitment. Controller approval cannot bypass producer signatures or native
nonce/funding/maturity/outcome rules. Packet-derived H/context is used only for comparison, never
to manufacture an approval or grant. No preauthenticated flag or arbitrary native effects can enter.

For a known selected H, the archive authenticates the submitted envelope before returning a no-op
reference, including a valid alternative S. Retained/submitted E-IDs distinguish the alternative;
it is never installed, exported as retained or given a new commitment acknowledgement. Invalid
signatures on known H fail. Unknown selection indexes, wrong bases, unsigned content, or injected
`approval`/context fields in commands cannot authorize work.

The expected profile/pins remain independent authority. A checksum in the same hostile input/file
would not authenticate that authority. Protect the operator channel and files; this is not a public
RPC, signed-manifest protocol, consensus/finality rule or anti-equivocation journal. The archive's
attribution-versus-selection/freshness limits remain as documented in
[`authenticated-block-storage.md`](authenticated-block-storage.md).

## Bounded Operator Framing and Actual Commands

Both stdin commands and stdout responses use **BE32 JSON-payload-byte-length followed by exact UTF-8
JSON**, without a newline. Length must be 1..65,536. Prefix validation precedes allocation. Bad length
or truncated header/payload terminates; malformed/unknown JSON in a correctly framed payload returns
a command error and allows the next frame. JSON field schemas are strict, including empty commands.

There is one synchronous command loop and one bounded response in flight. No per-request thread,
read-ahead message queue or asynchronous output queue exists; only bounded standard I/O buffering.
Partial input can wait while holding at most one capped frame. A blocked consumer backpressures the
owner instead of accumulating responses. Such waits have **no worker timeout**: restore/drain the
operator pipe or externally terminate/reopen the worker. Stop/recovery commands cannot overtake a
partial frame or blocked write. A broken output after commitment exits without undoing that commitment;
the caller must inspect/reconcile the original selected request on reopen.

Response JSON is capped at 65,536 bytes **before writing its header**; diagnostics are truncated to
1,024 UTF-8 bytes. Inspection is paginated (never a whole mutable snapshot mirror). S1's P ID/body
budget bounds a signed envelope to **3,644 bytes**, hence at most 7,288 lowercase hex characters.
Amounts above u64 use decimal strings in responses. These are payload/run bounds, not a hard heap
cap or a substitute for the existing archive audit's input validation.

| Exact command JSON | Result |
|---|---|
| `{"command":"status"}` | Audited local Tip, anchor/network/run, counts/accounting/limits and `catching_up`; no claim of latest network state |
| `{"command":"account","address":"<40 lowercase hex chars>"}` | Pure `exists`, balance and canonical nonce; missing reads return zero without insertion |
| `{"command":"inspect","section":"accounts","offset":0,"limit":16}` | `{total,offset,rows}` in deterministic order; also sections `records`, `transactions`, `sender_nonces`, `slots`, `hashes` |
| `{"command":"inspect","section":"records","offset":0,"limit":1}` | Exact inner wire, distinct anchor/append kind, Tip, S/E-ID and native outcome. Records require limit 1; other sections allow 1..16 |
| `{"command":"export","revision":1}` | Exact retained signed envelope in lowercase hex. Revision 0 has no signed export |
| `{"command":"apply","selection":1,"envelope":"<original E hex>"}` | 1-based independently selected step; only `outcome=committed,new_commit=true` represents a new durable append |
| `{"command":"recover"}` | Explicit full synchronized recovery, independent-prefix recheck, `attempted_present` diagnostic and `new_commit=false` |
| `{"command":"stop"}` | Framed stop acknowledgement, then orderly connection close and lock release |

`ok=true` alone is not a commitment receipt: startup, reads, recovery, stop and
`already_committed,new_commit=false` references also succeed. Reference responses contain both
`retained_envelope_id` and `submitted_envelope_id`. Error kinds include `command`, `selection`,
`rejected`, `aborted`, `recovery_required`, `unavailable`, and terminal startup/framing failures.

### Minimal runnable inspection client

Run from the repository root after the release build above. The public empty approvals file
authorizes no appends; populated/empty signed-append workflows are exercised by the process checker.

```python
import json, struct, subprocess, tempfile

with tempfile.TemporaryDirectory(prefix="s1-demo-", dir="target") as directory:
    args = ["target/release/examples/testnet_fixture_node", "init",
            "tests/fixtures/testnet_fixture_profile.json",
            "tests/fixtures/testnet_fixture_approvals_empty.json", directory]
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    def receive():
        header = p.stdout.read(4)
        if len(header) != 4:
            raise RuntimeError("worker closed")
        n, = struct.unpack(">I", header)
        assert 0 < n <= 65536
        payload = p.stdout.read(n)
        assert len(payload) == n
        return json.loads(payload)
    def command(value):
        raw = json.dumps(value, separators=(",", ":")).encode()
        p.stdin.write(struct.pack(">I", len(raw)) + raw)
        p.stdin.flush()
        return receive()
    print(receive())  # initial Ready, not an append acknowledgement
    print(command({"command": "status"}))
    print(command({"command": "account", "address": "55" * 20}))
    print(command({"command": "inspect", "section": "records", "offset": 0, "limit": 1}))
    print(command({"command": "stop"}))
    assert p.wait() == 0
    # To reopen this same directory, invoke the executable with "open", not "init".
```

## Ownership, Unavailability and Recovery

Only the archive contains mutable canonical accounts, accounting, body/index maps, Tip and evidence.
The wrapper retains immutable initialization/selection data and a readiness gate, not a second
mutable state mirror. Apply constructs one sealed archive candidate and consumes it in one commit;
there is no signing, separate `apply_body`, nonce reservation, pool cleanup or network publication.
Status/account/inspect/export borrow the Ready snapshot and never modify canonical state. Reopen/
recovery additionally write the required local synchronization-barrier metadata, not a new revision
or account effect.

`Aborted` permits no new commitment success; the archive may remain unavailable after stale-base
rejection. `RecoveryRequired` blocks application and every authoritative read/export. Recover and
stop remain available. Recovery invalidates prior generations, audits from trusted seeds and
reconciles an in-memory exact attempt; even after successful archive recovery, a mismatched independent
selected prefix keeps this wrapper unavailable. Failed recovery never makes cached state usable.

A new process has lost any old in-memory attempt; reopen proves an audited selected prefix, not
that a particular old caller received success. `attempted_present=null` without such an attempt is
not guessed into true/false. Retry the **same original selected request** only through an explicit
operator action after reconciliation; a retained request returns a reference without reapplication.
No automatic retry, reset, re-signing or transaction/evidence repair occurs.

## Executed Verification and Evidence Limits

Focused checks completed on the actual debug and release worker executables:

```bash
cargo test --example testnet_fixture_node
cargo build --example testnet_fixture_node
python3 -B scripts/test_testnet_fixture_worker.py target/debug/examples/testnet_fixture_node
cargo test --release --example testnet_fixture_node
cargo build --release --example testnet_fixture_node
python3 -B scripts/test_testnet_fixture_worker.py target/release/examples/testnet_fixture_node
```

**Three Rust unit tests passed in each mode**, covering independent golden genesis bytes, strict
profile failures and duplicate fields, framing/response bounds, and strict empty commands. A
development process test found that Serde unit variants accepted surplus command fields; empty
struct variants plus a regression fixed it. Final results below include that correction.

**Ten separate-process acceptance tests passed in each mode** (debug ~2.619 s, release ~1.888 s):

- Two simultaneous OS worker processes, independent files, populated two-user funding/spending,
  empty append and self/zero-transfer suffix. Independent Python wire/signature generation and
  explicit arithmetic/index oracles check complete accounts/nonces/gas/burns, every ordered inner
  body/outcome/Tip/S/E-ID, all transaction/sender-nonce/slot/hash indexes and byte-for-byte E exports.
  Final Alice/Bob/Carol balances are 999,940,000 / 10,000 / 10,000 quarks, nonces 3/1/0, gas 4,000,
  burns 40,000. Zero credit and missing-account reads create no extra record.
- Exact duplicates and independently valid alternate low-s S remain authenticated no-op references;
  invalid signatures/wrong keys on known H fail. Retained signatures/exports/state do not change.
- Correctly selected but wrong-signer, bad-nonce, immature and unfunded requests still fail native/
  producer validation, including a later immature entry after an earlier staged transfer.
  Malformed/unsigned/wrong-selection/base input, packet-carried approval fields,
  injected legacy commands, invalid pages and anchor signed export cause no canonical mutation.
- Missing DB/directory, repeated initialization, competing process ownership, wrong profile/key/
  network/anchor/seeds, malformed selection chains, omitted/different historical pins and byte/run
  bounds fail closed. A 16-entry body succeeds; an otherwise native-valid 17-entry body exceeds the S1 budget.
  A finite 200-empty-block trial completes; selection 201 is refused.
- SIGKILL after acknowledged progress and after only the next response header was consumed, followed
  by no-create reopen, retains the exact selected archive; retries produce references, not a second
  effect. OS process death releases the lifetime lock. This is **process termination with OS/device
  caches surviving, not power loss** or a sweep of every internal SQL boundary.
- Deliberate **test-only external SQLite interference**, bypassing the advisory ownership contract,
  adds an aborting body trigger: actual SQL rollback occurs, while unexpected DDL prevents full
  abort confirmation and yields RecoveryRequired. Status/account/inspect/export/apply stay blocked;
  recovery fails while DDL remains. Removing the test trigger and explicitly recovering returns
  `attempted_present=false` and the exact old prefix; the original selected request can then commit.
  This is selected real SQL/control/audit uncertainty evidence, **not a new VFS I/O/power-loss suite**.
- Partial input and a blocked output consumer remain alive without expanding a message queue.
  Actual short-window RSS observations: debug partial 7,008→7,008 KiB and blocked 6,984→6,984;
  release partial 6,000→6,000 and blocked 5,924→5,924. The parent offered 10,000 status commands and
  its writer was backpressured by finite pipes. These observations and framing bounds are not an
  allocator cap, isolated peak study or throughput/deadline measurement.

Existing compatibility checks also completed:

```bash
cargo test
cargo test --release --lib
python3 -B scripts/reproduce_native_auth_vectors.py
python3 -B scripts/reproduce_stage4_vectors.py
python3 -B scripts/reproduce_block_auth_vectors.py
python3 -B scripts/reproduce_testnet_fixture_profile.py
cargo fmt --check
cargo clippy --all-targets --all-features
```

The existing full debug suite passed **173 tests** (129 library + 44 binary, including live UDP
HIST/BLOCK rejection), release library **129 passed**, 12 benchmark/controlled-child entries ignored.
The three new example unit tests and ten process tests are the explicit additional commands above.
Independent checks reproduced 5 native-auth vectors/262 malformed signatures, 4 block vectors/43
prefix headers, 6 producer-auth vectors/262 malformed signatures/82 payload mutations, and all
630 S1 genesis bytes. Clippy completed with existing prototype warnings and no new S1 warnings.
Tracked/new-file whitespace checks were clean. Logs remain local under `target/s1-worker-*`,
`target/s1-compatibility-*`, `target/s1-final-clippy.log` and `target/s1-native-vector-check.log`.

## S1 Stopping Boundary

This implements independently approved signed application and inspection across local worker
processes. It does not implement S2 producer orchestration/pool admission, S3 peer transport, S4
missing-block retrieval, autonomous slots or PoAsh consensus/finality. The `catching_up` flag is a
comparison to the trusted selected corpus, not a synchronization service. No 3,000-transaction or
2,000 ms timing claim follows from these low-load tests. Existing schema-3 full-history copying,
audit/reopen cost and durability assumptions remain. Local plans/handoffs stay excluded. The initial
S1 delivery was for review without staging, commit or push.
