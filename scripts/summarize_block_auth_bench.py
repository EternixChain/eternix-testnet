#!/usr/bin/env python3
"""Read-only complete-run paired analysis. Refuse incomplete/overlapping logs; retain all outliers."""
import json
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def stats(values):
    """Observed median/range, never inferred percentiles or a deadline guarantee."""
    if not values or not all(math.isfinite(v) for v in values):
        raise ValueError("missing/nonfinite observations")
    return f"{statistics.median(values):.3f} [{min(values):.3f}, {max(values):.3f}]"


def load(name):
    records = [json.loads(line) for line in Path(name).read_text().splitlines() if line.startswith("{")]
    methods = [r for r in records if r.get("kind") == "block_auth_method"]
    done = [r for r in records if r.get("kind") == "block_auth_complete"]
    if len(methods) != 1 or len(done) != 1 or done[0]["failures"] != 0:
        raise ValueError(f"{name}: not one complete successful benchmark")
    m = methods[0]
    cases = range(len(m["cases"])) if m["selected_case"] is None else [m["selected_case"]]
    bodies = [0, 1, 3000] if m["selected_body"] is None else [m["selected_body"]]
    expected = {(case, body, role, mode): 2 * m[field]
                for case in cases for body in bodies for role in m["roles"]
                for mode, field in (("phases", "phase_pairs"), ("ordinary", "ordinary_pairs"))}
    groups = defaultdict(list)
    for r in records:
        if r.get("kind") == "block_auth_sample":
            groups[(r["case"], r["body_size"], r["role"], r["mode"])].append(r)
    if ({key: len(rows) for key, rows in groups.items()} != expected
            or sum(map(len, groups.values())) != done[0]["samples"]):
        raise ValueError("declared matrix/sample count mismatch")
    return groups, records


def main(names):
    groups, records = {}, []
    for name in names:
        new, extra = load(name)
        if groups.keys() & new.keys():
            raise ValueError("overlapping experiments; analyze pilots separately")
        groups.update(new)
        records.extend(extra)
    print(f"complete_runs={len(names)} samples={sum(map(len, groups.values()))}")
    print("Milliseconds: median [minimum, maximum]; every sample and paired difference retained.")
    fields = ("pipeline_ms", "durable_ms", "native_preparation_ms", "signing_and_encoding_ms",
              "receiver_attribution_ms", "native_stage_ms", "cache_preparation_ms",
              "cache_destruction_ms", "stored_comparison_ms", "pre_reopen_ms", "post_reopen_ms")
    for (case, body, role, mode), rows in sorted(groups.items()):
        print(f"case={case} A={rows[0]['accounts']} H={rows[0]['history_blocks']} T={rows[0]['history_txs']} N={body} role={role} mode={mode}")
        pairs = defaultdict(dict)
        for r in rows:
            signed = r["signed"]
            if signed in pairs[r["pair"]]:
                raise ValueError("duplicated pair member")
            order = [False, True] if r["pair"] % 2 == 0 else [True, False]
            if order[r["order_position"]] != signed:
                raise ValueError("incorrect US/SU order")
            pairs[r["pair"]][signed] = r
        if sorted(pairs) != list(range(len(pairs))) or any(set(p) != {False, True} for p in pairs.values()):
            raise ValueError("incomplete paired identities")
        for field in ("pipeline_ms", "durable_ms"):
            delta = [p[True][field] - p[False][field] for _, p in sorted(pairs.items())]
            percent = [100 * (p[True][field] / p[False][field] - 1) for _, p in sorted(pairs.items())]
            print(f"  paired signed_minus_unsigned_{field}: {stats(delta)} all_pairs={[round(v,3) for v in delta]}")
            print(f"  paired {field}_overhead_percent: {stats(percent)} signed_slower={sum(v>0 for v in delta)}/{len(delta)}")
        for signed in (False, True):
            data = sorted((r for r in rows if r["signed"] == signed), key=lambda r: r["pair"])
            print(f" signed={signed} n={len(data)} wire_bytes={sorted({r['wire_bytes'] for r in data})}")
            for field in fields:
                values = [r[field] for r in data]
                print(f"  {field}: {stats(values)}")
                if field in ("pipeline_ms", "durable_ms"):
                    print(f"  all_{field}_in_pair_order: {[round(v,3) for v in values]}")
            if mode == "phases":
                for field in data[0]["sql"]:
                    print(f"  sql/{field}: {stats([r['sql'][field] for r in data])}")
            for phase in ("pre_reopen", "post_reopen"):
                for field in ("audit_ms", "validation_materialization_ms", "barrier_ms"):
                    print(f"  {phase}/{field}: {stats([r[phase][field] for r in data])}")
            recovered = [r for r in data if r["recovery"] is not None]
            if recovered:
                print(f"  recovery kind=fixture_ready_refresh n={len(recovered)} total_ms: {stats([r['recovery']['total_ms'] for r in recovered])}")
                print(f"  recovery/audit_ms: {stats([r['recovery']['load']['audit_ms'] for r in recovered])}")
    for case in sorted({key[0] for key in groups}):
        artifacts = [r for r in records if r.get("kind") == "block_auth_artifact_audit" and r["case"] == case]
        print(f"case={case} separate_test_artifact_reauthentication envelopes={artifacts[0]['envelopes']} n={len(artifacts)} elapsed_ms={stats([r['elapsed_ms'] for r in artifacts])} source=in-memory-test-artifacts-not-SQL")
    samples = [r for rows in groups.values() for r in rows]
    print(f"observed_shared_process_max_rss_kib={max(r['memory']['rss_kib'] for r in samples)} cumulative_hwm_kib={max(r['memory']['cumulative_hwm_kib'] for r in samples)} not_a_per_admission_peak_comparison=true")
    # Compact tables use the same validated observations; modes and roles are never pooled.
    for mode in ("phases", "ordinary"):
        print(f"table_pipeline mode={mode}")
        print("| A/H/T | N | Unsigned producer | Signed producer | Unsigned receiver | Signed receiver |")
        print("|---|---:|---:|---:|---:|---:|")
        for case, body in sorted({(key[0], key[1]) for key in groups}):
            base = groups[(case, body, "producer", mode)][0]
            cells = [stats([r["pipeline_ms"] for r in groups[(case, body, role, mode)]
                            if r["signed"] == signed])
                     for role in ("producer", "receiver") for signed in (False, True)]
            print(f"| {base['accounts']}/{base['history_blocks']}/{base['history_txs']} | {body} | " + " | ".join(cells) + " |")
    print("table_coarse_costs mode=phases signed=true")
    print("| case | N | Producer signing+encoding | Receiver attribution | Producer paired pipeline delta | Receiver paired pipeline delta |")
    print("|---:|---:|---:|---:|---:|---:|")
    for case, body in sorted({(key[0], key[1]) for key in groups}):
        producer, receiver = (groups[(case, body, role, "phases")] for role in ("producer", "receiver"))
        deltas = []
        for rows in (producer, receiver):
            lookup = {(r["pair"], r["signed"]): r for r in rows}
            deltas.append(stats([lookup[(pair, True)]["pipeline_ms"] - lookup[(pair, False)]["pipeline_ms"]
                                 for pair in range(len(rows)//2)]))
        print(f"| {case} | {body} | {stats([r['signing_and_encoding_ms'] for r in producer if r['signed']])} | {stats([r['receiver_attribution_ms'] for r in receiver if r['signed']])} | " + " | ".join(deltas) + " |")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("provide actual completed block-auth benchmark logs")
    try:
        main(sys.argv[1:])
    except (ValueError, KeyError) as error:
        raise SystemExit(str(error)) from error
