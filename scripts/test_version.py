# SPDX-License-Identifier: GPL-3.0-or-later
"""Check version synchronization without modifying the working tree."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from version import ROOT, TEXT_TARGETS


class VersionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="gdb-ai-version-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.files = ["VERSION", *[target[0] for target in TEXT_TARGETS],
                      "sdk/typescript/package-lock.json"]
        for relative in [*self.files, "scripts/version.py"]:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)

    def run_script(self, *arguments):
        return subprocess.run(
            [sys.executable, str(self.root / "scripts/version.py"), *arguments],
            capture_output=True, text=True, check=False,
        )

    def snapshot(self):
        return {relative: (self.root / relative).read_bytes() for relative in self.files}

    def test_sync_is_idempotent_and_check_never_writes(self):
        before = self.snapshot()
        self.assertEqual(self.run_script("--check").returncode, 0)
        for invalid in ["", "1.2", "v1.2.3", "01.2.3", "1.2.3-rc.1", "1.2.3\u0661"]:
            self.assertNotEqual(self.run_script(invalid).returncode, 0, invalid)
            self.assertEqual(self.snapshot(), before)

        (self.root / "VERSION").write_text("99.98.97\n")
        changed = self.snapshot()
        self.assertNotEqual(self.run_script("--check").returncode, 0)
        self.assertEqual(self.snapshot(), changed)
        synchronized = self.run_script()
        self.assertEqual(synchronized.returncode, 0, synchronized.stderr)
        self.assertEqual(self.run_script("--check").returncode, 0)
        after = self.snapshot()
        for relative in self.files:
            self.assertIn(b"99.98.97", after[relative], relative)
        for relative in ("Cargo.lock", "fuzz/Cargo.lock"):
            old_dependencies = [block for block in before[relative].split(b"[[package]]")
                                if not block.startswith(b'\nname = "gdb-ai')]
            new_dependencies = [block for block in after[relative].split(b"[[package]]")
                                if not block.startswith(b'\nname = "gdb-ai')]
            self.assertEqual(old_dependencies, new_dependencies)
        lock = "sdk/typescript/package-lock.json"
        self.assertEqual(json.loads(after[lock])["packages"][""]["version"], "99.98.97")
        self.assertEqual(json.loads(after[lock])["packages"]["node_modules/typescript"],
                         json.loads(before[lock])["packages"]["node_modules/typescript"])
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(self.snapshot(), after)
        original = before["VERSION"].decode().strip()
        self.assertEqual(self.run_script(original).returncode, 0)
        self.assertEqual(self.snapshot(), before)

    def test_invalid_target_leaves_all_files_unchanged(self):
        target = self.root / "sdk/typescript/src/index.ts"
        target.write_text(target.read_text().replace("clientInfo:", "clientMetadata:"))
        before = self.snapshot()
        result = self.run_script("99.98.97")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected 1 version fields, found 0", result.stderr)
        self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
