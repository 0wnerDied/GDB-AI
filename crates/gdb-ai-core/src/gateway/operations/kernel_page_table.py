import json
import struct

import gdb


_PREFIX = "gdbai-kernel-page-table:"
_PHYSICAL_ADDRESS_MASK = 0x000FFFFFFFFFF000


def _flags(entry, level, leaf, huge):
    flags = []
    for bit, name in (
        (0, "present"),
        (1, "writable"),
        (2, "user"),
        (3, "write-through"),
        (4, "cache-disable"),
        (5, "accessed"),
    ):
        if entry & (1 << bit):
            flags.append(name)
    if leaf and entry & (1 << 6):
        flags.append("dirty")
    if huge:
        flags.append("huge")
        if entry & (1 << 12):
            flags.append("pat")
    elif level == "pt" and entry & (1 << 7):
        flags.append("pat")
    if leaf and entry & (1 << 8):
        flags.append("global")
    if entry & (1 << 63):
        flags.append("nx")
    return flags


def _walk(inferior, root, address, levels):
    table = root
    path = []
    writable = True
    user = True
    executable = True
    for level, shift in levels:
        index = (address >> shift) & 0x1FF
        entry_address = table + index * 8
        entry = struct.unpack("<Q", bytes(inferior.read_memory(entry_address, 8)))[0]
        present = bool(entry & 1)
        huge = level in ("pdpt", "pd") and bool(entry & (1 << 7))
        leaf = level == "pt" or huge
        page_size = 1 << shift if leaf else None
        target = None
        if present:
            writable = writable and bool(entry & (1 << 1))
            user = user and bool(entry & (1 << 2))
            executable = executable and not bool(entry & (1 << 63))
            target = entry & _PHYSICAL_ADDRESS_MASK
            if leaf:
                target &= -page_size
        path.append(
            {
                "level": level,
                "index": index,
                "entry_address": f"0x{entry_address:016x}",
                "entry": f"0x{entry:016x}",
                "flags": _flags(entry, level, leaf, huge),
                "target": None if target is None else f"0x{target:016x}",
                "target_kind": "page" if leaf else "table",
            }
        )
        if not present:
            return {"mapped": False, "levels": path}
        if leaf:
            offset = address & (page_size - 1)
            return {
                "mapped": True,
                "physical_address": f"0x{target + offset:016x}",
                "page_size": page_size,
                "page_offset": offset,
                "effective": {
                    "readable": True,
                    "writable": writable,
                    "user": user,
                    "executable": executable,
                },
                "levels": path,
            }
        table = target
    raise ValueError("page walk ended without a leaf entry")


def _gdbai_kernel_page_table(expression):
    physical_mode = False
    payload = None
    try:
        address = int(gdb.parse_and_eval(expression)) & ((1 << 64) - 1)
        cr3 = int(gdb.parse_and_eval("$cr3")) & ((1 << 64) - 1)
        cr4 = int(gdb.parse_and_eval("$cr4")) & ((1 << 64) - 1)
        virtual_bits = 57 if cr4 & (1 << 12) else 48
        upper = address >> virtual_bits
        if upper not in (0, (1 << (64 - virtual_bits)) - 1):
            raise ValueError(f"non-canonical {virtual_bits}-bit virtual address")

        levels = []
        if virtual_bits == 57:
            levels.append(("pml5", 48))
        levels.extend((("pml4", 39), ("pdpt", 30), ("pd", 21), ("pt", 12)))
        current_root = cr3 & _PHYSICAL_ADDRESS_MASK

        # QEMU's RSP physical-memory mode is connection-global. Toggle it and
        # restore virtual-memory mode inside this one serialized GDB command.
        physical_mode = True
        response = gdb.execute("maintenance packet Qqemu.PhyMemMode:1", to_string=True)
        if 'received: "OK"' not in response:
            raise RuntimeError("QEMU physical-memory RSP mode is unavailable")

        result = _walk(gdb.selected_inferior(), current_root, address, levels)
        root = current_root
        root_source = "current"
        paired_root = current_root & ~(1 << 12)
        if not result["mapped"] and address >> 63 and paired_root != current_root:
            result = _walk(gdb.selected_inferior(), paired_root, address, levels)
            root = paired_root
            root_source = "paired-kernel"
        payload = {
            "virtual_address": f"0x{address:016x}",
            "virtual_bits": virtual_bits,
            "root": f"0x{root:016x}",
            "root_source": root_source,
            **result,
        }
    except Exception as error:
        payload = {"error": f"{type(error).__name__}: {error}"}
    finally:
        if physical_mode:
            try:
                response = gdb.execute(
                    "maintenance packet Qqemu.PhyMemMode:0", to_string=True
                )
                if 'received: "OK"' not in response:
                    raise RuntimeError("QEMU virtual-memory RSP mode was not restored")
            except Exception as error:
                payload = {"error": f"{type(error).__name__}: {error}"}
    print(_PREFIX + json.dumps(payload, separators=(",", ":"), sort_keys=True))
