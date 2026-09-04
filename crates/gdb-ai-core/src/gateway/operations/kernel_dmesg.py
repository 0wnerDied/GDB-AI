import gdb
import json
import os
import runpy
import sys


_PREFIX = "gdbai-kernel-dmesg:"


def _has_command(name):
    try:
        gdb.execute("help " + name, to_string=True)
        return True
    except gdb.error:
        return False


def _load_linux_helpers():
    if _has_command("lx-dmesg"):
        return "preloaded"

    executable = gdb.current_progspace().filename
    if not executable or not os.path.basename(executable).startswith("vmlinux"):
        raise RuntimeError("the current executable has no matching Linux GDB helpers")
    companion = executable + "-gdb.py"
    if not os.path.isfile(companion):
        raise RuntimeError("the current vmlinux has no matching vmlinux-gdb.py")

    runpy.run_path(companion, init_globals={"gdb": gdb, "sys": sys})
    if not _has_command("lx-dmesg"):
        raise RuntimeError("the matching Linux GDB helpers do not provide lx-dmesg")
    return "vmlinux-gdb.py"


def _gdbai_kernel_dmesg(limit):
    try:
        helper = _load_linux_helpers()
        lines = gdb.execute("lx-dmesg", to_string=True).splitlines()
        result = {
            "lines": lines[-limit:],
            "total_lines": len(lines),
            "truncated": len(lines) > limit,
            "helper": helper,
        }
    except Exception as error:
        result = {"error": str(error)}
    print(_PREFIX + json.dumps(result, separators=(",", ":")))
