# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path
import unittest
from unittest.mock import patch

import compare_native


class NativeEvidenceTests(unittest.TestCase):
    def test_fixed_mi_variable_records_keep_values_and_empty_frames(self):
        output = (
            b'8^done,variables=[{name="input",arg="1",type="int",value="2"},'
            b'{name="counts",type="struct summary"}]\n(gdb) \n'
            b'9^done,variables=[]\n(gdb) \n'
            b'10^done,variables=[{name="counts",value="{accepted = 8, rejected = 1}"}]\n'
        )
        self.assertEqual(compare_native.mi_variable_lists(output), [
            [{"name": "input", "arg": "1", "type": "int", "value": "2"},
             {"name": "counts", "type": "struct summary"}],
            [], [{"name": "counts", "value": "{accepted = 8, rejected = 1}"}],
        ])
        for malformed in (
            b'1^done,variables="missing"\n',
            b'1^done,variables=[{name="x",value="1"},{name="x",value="2"}]\n',
        ):
            with self.assertRaises(AssertionError):
                compare_native.mi_variable_lists(malformed)

    def test_full_stack_requires_values_in_their_own_frames(self):
        output = (
            b'#0  finish (total=9) at stack.c:8\n        expected = 10\n'
            b'#1  0x123 in collect (requested=8) at stack.c:16\n'
            b'        counts = {accepted = 8, rejected = 1}\n        total = 9\n'
            b'#2  0x456 in main () at stack.c:22\n        requested = 8\n'
        )
        compare_native.verify_full_stack_cli(output)
        for before, after in (
            (b'expected = 10', b'expected = 9'),
            (b'counts = {accepted = 8, rejected = 1}', b'counts = {accepted = 8}'),
            (b'collect (requested=8)', b'other (requested=8)'),
            (b'        expected = 10\n', b''),
        ):
            with self.assertRaises(AssertionError):
                compare_native.verify_full_stack_cli(output.replace(before, after))

    def test_mi_errors_end_the_wait_without_becoming_timeouts(self):
        output = b'1^error,msg="invalid command"\n'

        def failed_exchange(process, payload, done):
            self.assertTrue(done(output), "an MI error must finish the pending exchange")
            return {}, output

        with patch.object(compare_native.subprocess, "Popen"), \
                patch.object(compare_native, "finish"), \
                patch.object(compare_native, "exchange", side_effect=failed_exchange):
            with self.assertRaisesRegex(AssertionError, "invalid command"):
                compare_native.native("gdb", Path("fixture"), "mi", "mi4", "signal")

    def test_native_latency_excludes_final_fixture_assertions(self):
        elapsed = 0

        def reply(process, payload, done):
            nonlocal elapsed
            elapsed += 1
            return {"seconds": 1, "request_bytes": len(payload),
                    "response_bytes": 7, "stdin_batches": 1}, b"SIGILL\n"

        def verify(output):
            nonlocal elapsed
            elapsed += 10

        with patch.object(compare_native.subprocess, "Popen"), \
                patch.object(compare_native, "finish"), \
                patch.object(compare_native.time, "perf_counter", side_effect=lambda: elapsed), \
                patch.object(compare_native, "exchange", side_effect=reply), \
                patch.object(compare_native, "verify_full_stack_cli", side_effect=verify):
            costs = compare_native.native("gdb", Path("fixture"), "cli", "mi4", "full-stack")
        self.assertEqual({phase: row["seconds"] for phase, row in costs.items()}, {
            "startup": 1, "cold": 2, "reused": 1,
        })
        self.assertEqual(elapsed, 23)


if __name__ == "__main__":
    unittest.main()
