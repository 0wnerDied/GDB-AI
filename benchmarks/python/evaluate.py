#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Aggregate GDB/AI Agent evaluation JSONL without external dependencies."""

from __future__ import annotations

import argparse
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path


SUCCESS_METRICS = ("resolved", "root_cause_localized")
METRICS = (
    "turns_to_breakpoint",
    "turns_to_evidence",
    "irrelevant_debugger_call_rate",
    "hypothesis_correction_rate",
    "tokens_to_root_cause",
    "debugger_calls",
    "raw_command_rate",
    "wall_time_seconds",
    "target_resumes",
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path)
    arguments = parser.parse_args()
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    with arguments.results.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"line {line_number}: result must be an object")
            variant = row.get("variant")
            task_class = row.get("task_class")
            if variant not in {"A", "B", "C", "D"}:
                raise ValueError(f"line {line_number}: variant must be A, B, C, or D")
            if task_class not in {"static-solvable", "runtime-helpful", "runtime-required"}:
                raise ValueError(f"line {line_number}: invalid task_class")
            for metric in SUCCESS_METRICS + METRICS:
                value = row.get(metric)
                if value is None:
                    continue
                if metric in SUCCESS_METRICS:
                    valid = isinstance(value, (int, float)) and value in (0, 1)
                else:
                    valid = (
                        type(value) in (int, float)
                        and math.isfinite(value)
                        and value >= 0
                        and (not metric.endswith("_rate") or value <= 1)
                    )
                if not valid:
                    raise ValueError(f"line {line_number}: invalid {metric}: {value!r}")
            grouped[str(variant)].append(row)

    report: dict[str, object] = {}
    for variant, rows in sorted(grouped.items()):
        metrics: dict[str, object] = {"tasks": len(rows)}
        # 2026-09-08: Binary medians reported 1,1,0 as 1.0. Count successes
        # over observed outcomes and expose missing trials separately.
        for metric in SUCCESS_METRICS:
            values = [int(row[metric]) for row in rows if row.get(metric) is not None]
            metrics[metric] = {
                "successes": sum(values),
                "total": len(values),
                "missing": len(rows) - len(values),
                "rate": sum(values) / len(values) if values else None,
            }
        for metric in METRICS:
            values = [float(row[metric]) for row in rows if row.get(metric) is not None]
            metrics[metric] = {
                "count": len(values),
                "missing": len(rows) - len(values),
                "median": statistics.median(values) if values else None,
                "p90": statistics.quantiles(values, n=10, method="inclusive")[8]
                if len(values) > 1 else values[0] if values else None,
            }
        report[variant] = metrics
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
