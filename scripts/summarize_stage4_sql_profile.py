#!/usr/bin/env python3
"""Read-only analysis of actual phase-profile JSONL output; no fabricated or discarded samples."""
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def stats(v):
    return f"{statistics.median(v):.3f} [{min(v):.3f}, {max(v):.3f}]"


def main():
    rows = defaultdict(list)
    complete = 0
    for name in sys.argv[1:]:
        for line in Path(name).read_text().splitlines():
            if not line.startswith("{"):
                continue
            data = json.loads(line)
            if data.get("kind") == "profile_complete":
                complete += 1
            if data.get("kind") == "sql_sample":
                rows[(data["history"], data["body_size"], data["mode"])].append(data)
    print(f"complete_runs={complete} samples={sum(map(len, rows.values()))}")
    phases = ["acquisition_ms", "metadata_base_ms", "account_comparison_ms", "uniqueness_probes_ms",
              "changed_account_writes_ms", "accounting_write_ms", "block_insertion_ms", "body_insertion_ms",
              "transaction_index_insertion_ms", "revision_tip_ms", "commit_return_ms"]
    print("Values: median [minimum, maximum] ms; no sample discarded.")
    for (history, size, mode), data in sorted(rows.items()):
        print(f"history={history} entries={size} mode={mode} n={len(data)}")
        for field in ["pipeline_ms", "durable_ms", "staging_ms", "copy_ms", "drop_ms"]:
            print(f"  {field}: {stats([r[field] for r in data])}")
        if mode != "stock":
            for phase in phases:
                print(f"  {phase}: {stats([r['sql'][phase] for r in data])}")
            print(f"  phase_residual_ms: {stats([r['phase_residual_ms'] for r in data])}")
        for field in ["hits", "misses", "writes", "spills"]:
            values = [r["sqlite_cache"][field] for r in data]
            print(f"  sqlite_{field}: median={statistics.median(values)} range={min(values)}..{max(values)}")
        if mode == "passive":
            for phase in ["checks_and_accounts", "accounting", "block", "body", "transaction_indexes", "revision_tip", "commit"]:
                for operation in ["journal_sync", "database_sync", "journal_write", "database_write", "database_read", "delete_including_directory_sync"]:
                    metrics = [r["io"].get(phase, {}).get(operation, {}) for r in data]
                    calls = [m.get("calls", 0) for m in metrics]
                    if not any(calls):
                        continue
                    ns_ms = [m.get("elapsed_ns", 0) / 1_000_000 for m in metrics]
                    print(f"  io {phase}/{operation}: calls={min(calls)}..{max(calls)} elapsed={stats(ns_ms)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("provide actual SQL profile output logs")
    main()
