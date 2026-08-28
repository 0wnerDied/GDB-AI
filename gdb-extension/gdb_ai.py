# SPDX-License-Identifier: GPL-3.0-or-later
"""Small, trusted GDB/MI extension for data absent from native MI."""

from __future__ import annotations

import gdb


PROTOCOL_VERSION = "1"


class Capabilities(gdb.MICommand):
    def __init__(self) -> None:
        super().__init__("-gdb-ai-capabilities")

    def invoke(self, argv: list[str]) -> dict[str, object]:
        if argv:
            raise gdb.GdbError("-gdb-ai-capabilities accepts no arguments")
        return {
            "protocol": PROTOCOL_VERSION,
            "commands": [
                "architecture",
                "inferior-configure",
                "safe-evaluate",
                "signal-policy",
                "value-metadata",
            ],
        }


class Architecture(gdb.MICommand):
    def __init__(self) -> None:
        super().__init__("-gdb-ai-architecture")

    def invoke(self, argv: list[str]) -> dict[str, str]:
        if argv:
            raise gdb.GdbError("-gdb-ai-architecture accepts no arguments")
        inferior = gdb.selected_inferior()
        architecture = inferior.architecture()
        return {
            "name": architecture.name(),
            "pointer-bits": str(gdb.lookup_type("void").pointer().sizeof * 8),
        }


class InferiorConfigure(gdb.MICommand):
    def __init__(self) -> None:
        super().__init__("-gdb-ai-inferior-configure")

    def invoke(self, argv: list[str]) -> dict[str, str]:
        if argv:
            raise gdb.GdbError("-gdb-ai-inferior-configure accepts no arguments")
        inferior = gdb.selected_inferior()
        return {"number": str(inferior.num), "pid": str(inferior.pid)}


class SafeEvaluate(gdb.MICommand):
    def __init__(self) -> None:
        super().__init__("-gdb-ai-safe-evaluate")

    def invoke(self, argv: list[str]) -> dict[str, str]:
        if len(argv) != 1:
            raise gdb.GdbError("-gdb-ai-safe-evaluate requires one expression")
        # The Rust worker disables calls and writes around this command.
        value = gdb.parse_and_eval(argv[0])
        return {"value": str(value), "type": str(value.type)}


class ValueMetadata(gdb.MICommand):
    def __init__(self) -> None:
        super().__init__("-gdb-ai-value-metadata")

    def invoke(self, argv: list[str]) -> dict[str, object]:
        if len(argv) != 1:
            raise gdb.GdbError("-gdb-ai-value-metadata requires one expression")
        value = gdb.parse_and_eval(argv[0])
        value_type = value.type.strip_typedefs()
        return {
            "type": str(value_type),
            "code": str(value_type.code),
            "sizeof": str(value_type.sizeof),
            "address": str(value.address) if value.address is not None else "",
        }


class SignalPolicy(gdb.MICommand):
    def __init__(self) -> None:
        super().__init__("-gdb-ai-signal-policy")

    def invoke(self, argv: list[str]) -> dict[str, str]:
        if len(argv) != 4:
            raise gdb.GdbError(
                "-gdb-ai-signal-policy requires SIGNAL STOP PRINT PASS"
            )
        signal, stop, print_value, pass_value = argv
        if not signal.startswith("SIG") or not signal[3:].isalnum():
            raise gdb.GdbError("invalid signal name")
        values = {"true": True, "false": False}
        try:
            stop_enabled = values[stop]
            print_enabled = values[print_value]
            pass_enabled = values[pass_value]
        except KeyError as error:
            raise gdb.GdbError("signal flags must be true or false") from error
        command = "handle {} {} {} {}".format(
            signal,
            "stop" if stop_enabled else "nostop",
            "print" if print_enabled else "noprint",
            "pass" if pass_enabled else "nopass",
        )
        gdb.execute(command, from_tty=False, to_string=True)
        return {
            "signal": signal,
            "stop": stop,
            "print": print_value,
            "pass": pass_value,
        }


Capabilities()
Architecture()
InferiorConfigure()
SafeEvaluate()
ValueMetadata()
SignalPolicy()
