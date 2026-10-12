#!/usr/bin/env python3
"""Analyze actual completed schema-3 paired runs; reject partial, duplicated or unbalanced members.

Reports all pipeline/durable observations and differences; medians/ranges are not tail guarantees.
The schema-2 SQL audit and external artifact pass remain separate from integrated schema-3 assurance.
"""
import json
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def stats(values):
    """Keep every finite observation; report range and median without inferring a tail bound."""
    if not values or not all(math.isfinite(v) for v in values):
        raise ValueError("missing/nonfinite observations")
    return f"{statistics.median(values):.3f} [{min(values):.3f}, {max(values):.3f}]"


def load(name):
    """Require a successful declared experiment and exact matched members before aggregation."""
    text = Path(name).read_text()
    if "test result: ok. 1 passed; 0 failed;" not in text or "panicked at" in text:
        raise ValueError(f"{name}: test did not finish successfully")
    records = [json.loads(line) for line in text.splitlines() if line.startswith("{")]
    methods = [r for r in records if r.get("kind") == "schema3_method"]
    complete = [r for r in records if r.get("kind") == "schema3_complete"]
    if len(methods) != 1 or len(complete) != 1 or complete[0]["failures"] != 0:
        raise ValueError(f"{name}: not one complete successful experiment")
    method = methods[0]
    if (method["cases"] != [[1000, 100, 0], [1000, 100, 100000], [10000, 0, 0], [1000, 1000, 0]]
            or method["phase_pairs"] <= 0 or method["ordinary_pairs"] <= 0
            or method["selected_case"] not in (None, 0, 1, 2, 3)
            or method["selected_body"] not in (None, 0, 1, 3000)
            or (method["selected_case"], method["selected_body"]) == (3, 3000)):
        raise ValueError("unknown matrix or empty measurement counts")
    cases = range(len(method["cases"])) if method["selected_case"] is None else [method["selected_case"]]
    bodies = [0, 1, 3000] if method["selected_body"] is None else [method["selected_body"]]
    expected = {(c, b, role, mode): 2 * method[field] for c in cases for b in bodies
                if not (c == 3 and b == 3000) for role in ("producer", "receiver")
                for mode, field in (("phases", "phase_pairs"), ("ordinary", "ordinary_pairs"))}
    groups = defaultdict(list)
    fixtures = [r for r in records if r.get("kind") == "schema3_fixture"]
    if sorted(r["case"] for r in fixtures) != list(cases):
        raise ValueError("missing/duplicated base fixture records")
    for row in records:
        if row.get("kind") == "schema3_sample":
            if row["producer_authentications"] != 1 or row["native_stages"] != 1:
                raise ValueError("unequal authentication/staging counts")
            groups[(row["case"], row["body_size"], row["role"], row["mode"])].append(row)
            if ([row["accounts"], row["history_blocks"], row["history_txs"]] != method["cases"][row["case"]]
                    or (row["observations"]["sql"] is None) != (row["mode"] == "ordinary")):
                raise ValueError("fixture or instrumentation mismatch")
            representative = (row["role"] == "receiver" and row["mode"] == "ordinary"
                              and row["body_size"] == (1 if row["case"] == 3 else 3000))
            if any((row[field] is not None) != representative for field in ("ready_recovery", "unpublished_recovery")):
                raise ValueError("missing or unexpected representative recovery")
            if row["evidence_payload_bytes"] != (97 * (row["history_blocks"] + 1 + int(representative)) if row["backend"] == 3 else 0):
                raise ValueError("wrong logical evidence growth")
    if ({k: len(v) for k, v in groups.items()} != expected
            or sum(map(len, groups.values())) != complete[0]["samples"]):
        raise ValueError("declared counts/matrix mismatch")
    for rows in groups.values():
        pairs = defaultdict(dict)
        for row in rows:
            order = (2, 3) if row["pair"] % 2 == 0 else (3, 2)
            if row["order_position"] not in (0, 1) or order[row["order_position"]] != row["backend"] or row["backend"] in pairs[row["pair"]]:
                raise ValueError("duplicated member or wrong backend ordering")
            pairs[row["pair"]][row["backend"]] = row
        if sorted(pairs) != list(range(len(pairs))) or any(set(v) != {2, 3} for v in pairs.values()):
            raise ValueError("incomplete paired identities")
    return groups, records


def main(names):
    """Reject overlapping groups and preserve raw pipeline/durable values alongside summaries."""
    groups, records = {}, []
    for name in names:
        new, extra = load(name)
        if groups.keys() & new.keys():
            raise ValueError("overlapping experiments; analyze pilots separately")
        groups.update(new)
        records.extend(extra)
    print(f"complete_runs={len(names)} samples={sum(map(len, groups.values()))} all_outliers_retained=true")
    for record in records:
        if record.get("kind") in ("schema3_fixture", "schema3_spilled_restoration", "schema3_complete"):
            print(json.dumps(record, sort_keys=True))
    for (case, body, role, mode), rows in sorted(groups.items()):
        print(f"case={case} N={body} role={role} mode={mode}")
        lookup = {(r["pair"], r["backend"]): r for r in rows}
        delta = [lookup[(p, 3)]["pipeline_ms"] - lookup[(p, 2)]["pipeline_ms"] for p in range(len(rows)//2)]
        print(f" paired_pipeline_schema3_minus_schema2_ms: {stats(delta)} all_pairs={[round(v,3) for v in delta]}")
        for backend in (2, 3):
            data = sorted((r for r in rows if r["backend"] == backend), key=lambda r: r["pair"])
            print(f" backend={backend} n={len(data)}")
            for field in ("pipeline_ms", "signing_encoding_ms", "attribution_or_signed_staging_ms", "policy_prefix_ms",
                          "post_sql_or_integrated_ms", "post_external_artifact_ms", "database_bytes"):
                print(f"  {field}: {stats([r[field] for r in data])}")
                if field == "pipeline_ms":
                    print(f"  all_pipeline_ms: {[round(r[field],3) for r in data]}")
            for field in ("durable_ms", "native_stage_ms", "cache_preparation_ms", "destruction_ms", "stored_comparison_ms"):
                print(f"  {field}: {stats([r['observations'][field] for r in data])}")
                if field == "durable_ms":
                    print(f"  all_durable_ms: {[round(r['observations'][field],3) for r in data]}")
            if mode == "phases":
                for field in data[0]["observations"]["sql"]:
                    print(f"  sql/{field}: {stats([r['observations']['sql'][field] for r in data])}")
            for phase in ("pre_load", "post_load"):
                for field in data[0][phase]:
                    print(f"  {phase}/{field}: {stats([r[phase][field] for r in data])}")
            for recovery in ("ready_recovery", "unpublished_recovery"):
                data_recovery = [r[recovery] for r in data if r[recovery] is not None]
                if data_recovery:
                    for field in ("sql_ms", "artifact_ms", "combined_nonatomic_ms") if backend == 2 else ("integrated_ms",):
                        print(f"  {recovery}/{field} n={len(data_recovery)}: {stats([r[field] for r in data_recovery])}")
    for mode in ("phases", "ordinary"):
        print(f"table_complete_pipeline mode={mode}")
        print("| A/H/T | N | Schema2 producer | Schema3 producer | Schema2 receiver | Schema3 receiver |")
        print("|---|---:|---:|---:|---:|---:|")
        for case, body in sorted({(k[0], k[1]) for k in groups}):
            base = groups[(case, body, "producer", mode)][0]
            cells = [stats([r["pipeline_ms"] for r in groups[(case, body, role, mode)] if r["backend"] == backend])
                     for role in ("producer", "receiver") for backend in (2, 3)]
            print(f"| {base['accounts']}/{base['history_blocks']}/{base['history_txs']} | {body} | " + " | ".join(cells) + " |")
    samples = [r for rows in groups.values() for r in rows]
    print(f"max_shared_rss_kib={max(r['memory']['rss_kib'] for r in samples)} cumulative_hwm_kib={max(r['memory']['cumulative_hwm_kib'] for r in samples)} not_backend_isolated_peaks=true")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("provide completed actual schema-3 measurement output logs")
    try:
        main(sys.argv[1:])
    except (KeyError, ValueError) as error:
        raise SystemExit(str(error)) from error
