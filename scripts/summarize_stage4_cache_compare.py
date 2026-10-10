#!/usr/bin/env python3
"""Analyze completed, actual cache-comparison logs without mixing pilots or dropping outliers.

Each input must be a complete declared experiment (possibly selected by history/body). Counts,
budget pairs and AB/BA positions are checked before reporting. Duplicate workload groups across
inputs are rejected so a pilot cannot silently inflate the main sample count.
"""
import json
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path


POLICIES = ("ExistingDefault", "Trial32MiB")


def stats(values):
    """Median and observed range, not a tail estimate or a confidence interval."""
    if not values or not all(math.isfinite(v) for v in values):
        raise ValueError("missing/nonfinite observations")
    return f"{statistics.median(values):.3f} [{min(values):.3f}, {max(values):.3f}]"


def paired(rows, fields):
    """Check exact paired identities/order, then retain every paired percentage difference."""
    pairs = defaultdict(dict)
    for row in rows:
        policy, pair = row["policy"], row["pair"]
        if policy not in POLICIES or policy in pairs[pair]:
            raise ValueError("unknown policy or duplicate pair member")
        expected = POLICIES if pair % 2 == 0 else POLICIES[::-1]
        if expected[row["order_position"]] != policy:
            raise ValueError("unexpected budget order")
        pairs[pair][policy] = row
    if sorted(pairs) != list(range(len(pairs))):
        raise ValueError("missing pair index")
    for pair in pairs.values():
        if set(pair) != set(POLICIES):
            raise ValueError("incomplete budget pair")
    for field in fields:
        changes = [100 * (1 - p[POLICIES[1]][field] / p[POLICIES[0]][field])
                   for _, p in sorted(pairs.items())]
        print(f"  paired {field} reduction_percent: {stats(changes)} "
              f"trial_faster={sum(v > 0 for v in changes)}/{len(changes)} "
              f"all_pairs={[round(v, 3) for v in changes]}")


def load(name):
    """Fail closed on partial output; benchmark completion is required, not inferred from rows."""
    text = Path(name).read_text()
    records = [json.loads(line) for line in text.splitlines() if line.startswith("{")]
    methods = [r for r in records if r.get("kind") == "cache_compare_method"]
    done = [r for r in records if r.get("kind") == "cache_compare_complete"]
    if (len(methods) != 1 or len(done) != 1 or done[0]["failures"] != 0
            or "test result: ok." not in text or "test result: FAILED" in text):
        raise ValueError(f"{name}: not one successfully completed comparison")
    method = methods[0]
    histories = ([method["selected_history"]] if method["selected_history"] is not None
                 else method["retained_transactions"])
    bodies = ([method["selected_body"]] if method["selected_body"] is not None
              else method["body_sizes"])
    expected = {(h, n, mode): 2 * method[f"{mode}_samples_per_budget"]
                for h in histories for n in bodies for mode in ("stock", "phase", "passive")}
    # The emitted mode is plural "phases", while its declared count uses singular "phase".
    expected = {(h, n, "phases" if mode == "phase" else mode): count
                for (h, n, mode), count in expected.items()}
    groups = defaultdict(list)
    for r in records:
        if r.get("kind") == "cache_compare_sample":
            if r["budget_kib"] != dict(zip(POLICIES, (2000, 32768)))[r["policy"]]:
                raise ValueError("unexpected queried budget")
            groups[(r["history"], r["body_size"], r["mode"])].append(r)
    if {key: len(rows) for key, rows in groups.items()} != expected:
        raise ValueError(f"{name}: declared workload/sample count mismatch")
    representative = [r for r in records if r.get("kind") == "cache_compare_representative"]
    memory = [r for r in records if r.get("kind") == "cache_compare_isolated_memory"]
    has_large = 100000 in histories and 3000 in bodies
    if len(representative) != (2 * method["representative_samples_per_budget"] if has_large else 0):
        raise ValueError("representative sample count mismatch")
    if sorted(r["policy"] for r in memory) != (sorted(POLICIES) if has_large else []):
        raise ValueError("isolated memory observations missing or duplicated")
    return groups, representative, memory


def report_io(rows):
    """Include raw delegate non-OK statuses; sentinel short reads are not append failures."""
    operations = sorted({(phase, op) for r in rows
                         for phase, metrics in r["io"].items() for op in metrics})
    for phase, op in operations:
        metrics = [r["io"].get(phase, {}).get(op, {}) for r in rows]
        calls = [m.get("calls", 0) for m in metrics]
        byte_counts = [m.get("bytes", 0) for m in metrics]
        elapsed = [m.get("elapsed_ns", 0) / 1_000_000 for m in metrics]
        statuses = [m.get("non_ok_statuses", {}) for m in metrics]
        print(f"  io {phase}/{op}: calls={min(calls)}..{max(calls)} "
              f"bytes={min(byte_counts)}..{max(byte_counts)} elapsed_ms={stats(elapsed)} "
              f"non_ok_statuses={statuses}")


def main(names):
    groups, representative, memory = {}, [], []
    for name in names:
        new_groups, new_representative, new_memory = load(name)
        if groups.keys() & new_groups.keys():
            raise ValueError("overlapping experiments; analyze pilots/repeats separately")
        groups.update(new_groups)
        representative.extend(new_representative)
        memory.extend(new_memory)
    print(f"complete_runs={len(names)} receiver_samples={sum(map(len, groups.values()))} "
          f"representative_samples={len(representative)} isolated_memory_children={len(memory)}")
    print("Milliseconds: median [minimum, maximum]. Every observation retained; no p95/p99 claim.")
    for (history, size, mode), rows in sorted(groups.items()):
        print(f"history={history} entries={size} mode={mode}")
        paired(rows, ("pipeline_ms", "durable_ms"))
        for policy in POLICIES:
            data = sorted((r for r in rows if r["policy"] == policy), key=lambda r: r["pair"])
            print(f" policy={policy} n={len(data)}")
            for field in ("pipeline_ms", "durable_ms", "staging_ms", "copy_ms", "drop_ms", "reopen_ms"):
                values = [r[field] for r in data]
                print(f"  {field}: {stats(values)}")
                if field in ("pipeline_ms", "durable_ms"):
                    print(f"  all_{field}_in_pair_order: {[round(v, 3) for v in values]}")
            if mode != "stock":
                for field in data[0]["sql"]:
                    print(f"  {field}: {stats([r['sql'][field] for r in data])}")
                print(f"  phase_residual_ms: {stats([r['phase_residual_ms'] for r in data])}")
            for field in data[0]["sqlite_cache"]:
                print(f"  sqlite_{field}: {stats([r['sqlite_cache'][field] for r in data])}")
            print(f"  queried_spill_thresholds: {sorted({r['spill_enabled_reported_threshold'] for r in data})}")
            if mode == "passive":
                report_io(data)
    if representative:
        print("representative history=100000 entries=3000")
        paired(representative, ("producer_pipeline_ms", "reopen_total_ms", "unpublished_recovery_ms"))
        for policy in POLICIES:
            data = [r for r in representative if r["policy"] == policy]
            print(f" policy={policy} n={len(data)}")
            for field in ("producer_pipeline_ms", "reopen_total_ms", "unpublished_recovery_ms"):
                print(f"  {field}: {stats([r[field] for r in data])}")
            for phase in ("reopen", "recovery"):
                for field in data[0][phase]:
                    print(f"  {phase}/{field}: {stats([r[phase][field] for r in data])}")
            for field in data[0]["producer_sql"]:
                print(f"  producer/{field}: {stats([r['producer_sql'][field] for r in data])}")
    print("isolated memory: KiB RSS and fresh-process cumulative HWM, not a hard memory limit")
    for row in memory:
        print(json.dumps(row, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("provide completed actual cache comparison output logs")
    try:
        main(sys.argv[1:])
    except (ValueError, KeyError) as error:
        raise SystemExit(str(error)) from error
