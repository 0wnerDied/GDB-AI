#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Aggregate GDB/AI Agent evaluation JSONL without external dependencies."""

from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path


METRICS = (
    "resolved",
    "root_cause_localized",
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
            variant = row.get("variant")
            task_class = row.get("task_class")
            if variant not in {"A", "B", "C", "D"}:
                raise ValueError(f"line {line_number}: variant must be A, B, C, or D")
            if task_class not in {"static-solvable", "runtime-helpful", "runtime-required"}:
                raise ValueError(f"line {line_number}: invalid task_class")
            grouped[str(variant)].append(row)

    report: dict[str, object] = {}
    for variant, rows in sorted(grouped.items()):
        metrics: dict[str, object] = {"tasks": len(rows)}
        for metric in METRICS:
            values = [float(row[metric]) for row in rows if row.get(metric) is not None]
            metrics[metric] = statistics.median(values) if values else None
        report[variant] = metrics
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
