# SPDX-License-Identifier: GPL-3.0-or-later

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class EvaluationTests(unittest.TestCase):
    def evaluate(self, rows):
        with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as source:
            for row in rows:
                source.write(json.dumps(row) + "\n")
            source.flush()
            return subprocess.run(
                [sys.executable, str(Path(__file__).with_name("evaluate.py")), source.name],
                capture_output=True, text=True,
            )

    def test_success_rates_and_cost_distribution(self):
        result = self.evaluate([
            {"variant": "D", "task_class": "runtime-required", "resolved": resolved,
             "root_cause_localized": bool(resolved), "wall_time_seconds": seconds}
            for resolved, seconds in [(1, 10), (1, 20), (0, 30)]
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)["D"]
        self.assertEqual(report["tasks"], 3)
        for metric in ("resolved", "root_cause_localized"):
            self.assertEqual(report[metric], {
                "successes": 2, "total": 3, "missing": 0, "rate": 2 / 3,
            })
        self.assertEqual(report["wall_time_seconds"], {
            "count": 3, "missing": 0, "median": 20, "p90": 28,
        })

    def test_missing_and_singleton_metrics_and_variants(self):
        result = self.evaluate([
            {"variant": "A", "task_class": "static-solvable", "resolved": 0,
             "debugger_calls": 0},
            {"variant": "A", "task_class": "static-solvable", "resolved": None},
            {"variant": "D", "task_class": "runtime-helpful", "resolved": 1},
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["D"]["resolved"]["rate"], 1)
        self.assertEqual(report["A"]["resolved"], {
            "successes": 0, "total": 1, "missing": 1, "rate": 0,
        })
        self.assertEqual(report["A"]["root_cause_localized"], {
            "successes": 0, "total": 0, "missing": 2, "rate": None,
        })
        self.assertEqual(report["A"]["debugger_calls"], {
            "count": 1, "missing": 1, "median": 0, "p90": 0,
        })
        self.assertEqual(report["A"]["tokens_to_root_cause"], {
            "count": 0, "missing": 2, "median": None, "p90": None,
        })
        self.assertEqual(json.loads(self.evaluate([]).stdout), {})

    def test_invalid_metrics_fail_with_line_and_field(self):
        for metric, value in [
            ("resolved", 2), ("root_cause_localized", 0.5), ("resolved", "1"),
            ("wall_time_seconds", -1), ("wall_time_seconds", float("inf")),
            ("tokens_to_root_cause", float("nan")), ("debugger_calls", True),
            ("raw_command_rate", 1.1),
        ]:
            with self.subTest(metric=metric, value=value):
                result = self.evaluate([
                    {"variant": "D", "task_class": "runtime-required", metric: value},
                ])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"line 1: invalid {metric}", result.stderr)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
