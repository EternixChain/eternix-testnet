#!/usr/bin/env python3
"""Summarize actual JSON benchmark logs (including partially completed commands) without estimates.

This read-only report helper preserves medians/maxima from successful workload rows, reports missing
rows and command completion markers, and never invents a successful overall run from partial output.
"""
import json
import sys
from pathlib import Path


def main():
    rows = {}
    complete = 0
    for name in sys.argv[1:]:
        for line in Path(name).read_text().splitlines():
            if not line.startswith("{"):
                continue
            value = json.loads(line)
            if value.get("kind") == "complete":
                complete += 1
            if value.get("kind") != "result":
                continue
            key = value["case"], value["entries"], value["recovery_kind"]
            if key in rows:
                raise ValueError(f"duplicate row {key}: choose logs explicitly rather than discard samples")
            rows[key] = value
    print(f"workload_rows={len(rows)} complete_command_markers={complete}")
    present = {(case, size) for case, size, kind in rows if kind == "explicit_ready_refresh"}
    print(f"missing_regular_matrix_rows={[(c, n) for c in range(13) for n in (0, 1, 3000) if (c, n) not in present]}")
    print("| Case | A | H start | T start | Entries | Receiver ms med/max | Producer med/max | Commit med/max | Cache prep med/max | Destroy med/max | Stored comparison med/max | Reopen med/max | Audit med/max | Recover med/max |")
    print("|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for (case, size, kind), v in sorted(rows.items()):
        def pair(key):
            s = v[key]
            return f"{s['median_ms']:.3f}/{s['max_ms']:.3f}"
        print(f"| {case} | {v['accounts']} | {v['retained_blocks_start']} | {v['retained_transactions_start']} | {size} | "
              + " | ".join(pair(k) for k in ("receiver_pipeline", "producer_pipeline", "durable_commit", "cache_preparation", "cache_destruction", "stored_comparison", "reopen_total", "reopen_audit", "recovery_total")) + " |")
    if rows:
        for metric in ("receiver_pipeline", "producer_pipeline", "cache_preparation", "cache_destruction", "reopen_total", "recovery_total"):
            winner = max(rows.values(), key=lambda v: v[metric]["max_ms"])
            print(f"worst_{metric}_ms={winner[metric]['max_ms']:.3f} case={winner['case']} entries={winner['entries']}")
        print(f"max_process_hwm_kib={max(v['memory']['process_cumulative_hwm_kib'] or 0 for v in rows.values())}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("provide actual benchmark output log paths")
    main()
