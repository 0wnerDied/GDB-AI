import array
import json
import re
import struct

import gdb


_PREFIX = "gdbai-kernel-symbols:"
_SYMBOL_TYPES = b"-?ABCDGINPRSTUVWabcdginprstuvw"
_MODULE_MEMORY_TYPES = (
    "text",
    "data",
    "rodata",
    "ro_after_init",
    "init_text",
    "init_data",
    "init_rodata",
)


def _aligned(value, alignment):
    return value + (-value % alignment)


def _tokens(image, table):
    result = []
    position = table
    for _ in range(256):
        end = image.index(0, position)
        result.append(image[position:end])
        position = end + 1
    return result


def _table_offsets(image, version):
    sequence = b"0\x001\x002\x003\x004\x005\x006\x007\x008\x009\x00"
    candidates = []
    position = image.find(sequence)
    while position >= 0:
        follow = image[position + len(sequence):position + len(sequence) + 1]
        if follow and (follow.isalnum() or follow in (b"_", b".")):
            candidates.append(position)
        position = image.find(sequence, position + 1)
    if len(candidates) != 1:
        raise ValueError("kallsyms token table is not unique")

    position = candidates[0] - 1
    if position < 0 or image[position] != 0:
        raise ValueError("invalid kallsyms token table prefix")
    for _ in range(ord("0")):
        for _ in range(50):
            position -= 1
            if position < 0:
                raise ValueError("kallsyms token table begins outside the image")
            if image[position] == 0 or image[position] > ord("z"):
                break
        else:
            raise ValueError("kallsyms token exceeds 50 bytes")
    token_table = _aligned(position + 1, 4)

    head = image[token_table:token_table + 256]
    token_offsets = [0]
    position = 0
    while True:
        position = head.find(b"\x00", position + 1)
        if position < 0:
            break
        token_offsets.append(position + 1)
    index_pattern = struct.pack("<" + "H" * len(token_offsets), *token_offsets)
    token_index = image.find(index_pattern, token_table)
    if token_index < 0:
        raise ValueError("kallsyms token index was not found")

    position = token_table - 1
    while position > 0 and image[position] == 0:
        position -= 1
    while position > 0:
        marker_table = image.rfind(b"\x00\x00\x00\x00", 0, position)
        if marker_table < 0:
            raise ValueError("kallsyms markers were not found")
        if marker_table % 4:
            position = marker_table
            continue
        # 2026-09-04: Linux 6.1.42 through 6.8 may place a name-sequence
        # table before the token table. Require the small monotonic marker
        # prefix so that table cannot be mistaken for kallsyms_markers.
        if not ((6, 1, 42) <= version < (6, 9, 0)) or all(
            value & 0xfff0000 == 0
            for (value,) in struct.iter_unpack(
                "<I", image[marker_table + 4:marker_table + 44]
            )
        ):
            break
        position = marker_table

    markers_end = token_table
    if (6, 1, 42) <= version < (6, 9, 0):
        markers_end = marker_table + 4
        while markers_end + 4 <= token_table and image[markers_end + 3] == 0:
            previous = struct.unpack_from("<I", image, markers_end - 4)[0]
            current = struct.unpack_from("<I", image, markers_end)[0]
            if previous > current or current - previous > 0x100000:
                break
            markers_end += 4

    markers = struct.iter_unpack("<I", image[marker_table:markers_end])
    last_marker = next((value for value in reversed([item[0] for item in markers]) if value), None)
    if last_marker is None:
        raise ValueError("kallsyms markers are empty")
    names = _aligned(marker_table - last_marker, 4)
    return token_table, token_index, marker_table, names


def _names_start(image, version, tokens, markers, candidate):
    # Work backwards once: each entry is valid exactly when its encoded length
    # lands on another valid entry. array('i') avoids a Python object per byte.
    valid = array.array("i")
    position = candidate
    while position >= 0:
        token = tokens[image[position + 1]] if position + 1 < markers else b""
        if token and token[0] in _SYMBOL_TYPES:
            for offset in range(markers - len(valid), position - 1, -1):
                length = image[offset]
                big = version >= (6, 1, 0) and bool(length & 0x80)
                if big:
                    length = ((image[offset + 1] << 7) | (length & 0x7f))
                if length == 0:
                    valid.append(0)
                    continue
                available = markers - offset - int(big)
                index = length + 1 + int(big)
                if length >= available or index > len(valid) or valid[-index] < 0:
                    valid.append(-1)
                else:
                    valid.append(valid[-index] + 1)
            count = valid[-1]
            if count >= 256:
                lower = max(0, position - 256)
                count_address = image.rfind(struct.pack("<I", count), lower, position)
                if count_address >= 0:
                    return position, count_address, count
        position -= 4
    raise ValueError("kallsyms names were not found")


def _address(image_start, image, version, offsets, relative_base, absolute_percpu, index):
    offset = struct.unpack_from("<i", image, offsets + index * 4)[0]
    if version >= (7, 0, 0):
        return (image_start + offsets + index * 4 + offset) & ((1 << 64) - 1)
    if absolute_percpu:
        return relative_base - 1 - offset if offset < 0 else offset
    return relative_base + offset


def _address_table(image, version, token_index, count_address, count):
    if version < (6, 4, 0):
        relative_address = count_address
        while image[relative_address - 8:relative_address] == b"\x00" * 8:
            relative_address -= 8
        relative_address -= 8
        offsets_end = relative_address
        while image[offsets_end - 4:offsets_end] == b"\x00" * 4:
            offsets_end -= 4
        offsets = offsets_end - count * 4
    else:
        offsets = token_index + 0x200
        relative_address = _aligned(offsets + count * 4, 8)

    if offsets < 0 or offsets + count * 4 > len(image):
        raise ValueError("kallsyms offsets exceed the kernel image")
    if version >= (7, 0, 0):
        return offsets, None, False

    relative_base = struct.unpack_from("<Q", image, relative_address)[0]
    if relative_base == 0 or relative_base & 0xfff:
        raise ValueError("invalid kallsyms relative base")
    negatives = sum(
        offset < 0
        for (offset,) in struct.iter_unpack("<i", image[offsets:offsets + count * 4])
    )
    return offsets, relative_base, negatives * 2 >= count


def _current_tasks(symbols):
    by_name = {}
    for symbol in symbols:
        by_name.setdefault(symbol["name"], []).append(int(symbol["address"], 16))
    init_task = next((address for address in by_name.get("init_task", []) if address >> 63), None)
    current = next(iter(by_name.get("pcpu_hot", []) or by_name.get("current_task", [])), None)
    if init_task is None or current is None:
        return []

    inferior = gdb.selected_inferior()
    init = bytes(inferior.read_memory(init_task, 4096))
    comm_offset = init.find(b"swapper/0\x00")
    if comm_offset < 0:
        return []
    original = gdb.selected_thread()
    tasks = []
    try:
        for fallback_cpu, thread in enumerate(sorted(inferior.threads(), key=lambda item: item.num)):
            thread.switch()
            gs_base = int(gdb.parse_and_eval("$gs_base")) & ((1 << 64) - 1)
            # 2026-09-04: Linux 7 kallsyms reports the linked per-CPU virtual
            # address instead of a small offset. x86 GS addition wraps at 64 bits.
            pointer_address = (gs_base + current) & ((1 << 64) - 1)
            pointer = bytes(inferior.read_memory(pointer_address, 8))
            task = struct.unpack("<Q", pointer)[0]
            comm = bytes(inferior.read_memory(task + comm_offset, 16)).split(b"\x00", 1)[0]
            if not comm or any(byte < 0x20 or byte > 0x7e for byte in comm):
                continue
            name = thread.name or ""
            match = re.search(r"CPU#(\d+)", name)
            tasks.append({
                "cpu": int(match.group(1)) if match else fallback_cpu,
                "task": f"0x{task:016x}",
                "comm": comm.decode("ascii"),
                "gs_base": f"0x{gs_base:016x}",
                "selected": thread == original,
            })
    finally:
        if original is not None:
            original.switch()
    return tasks


def _integer(data, offset, size):
    if offset < 0 or offset + size > len(data):
        return None
    return int.from_bytes(data[offset:offset + size], "little")


def _module_range(address, ranges):
    return next(((start, end) for start, end in ranges if start <= address < end), None)


def _module_span(address, size, ranges):
    end = address + size
    cursor = address
    for start, stop in ranges:
        if start > cursor:
            break
        if start <= cursor < stop:
            cursor = stop
            if cursor >= end:
                return True
    return False


def _module_name(data, offset):
    limit = offset + 56
    if limit > len(data):
        return None
    end = data.find(b"\x00", offset, limit)
    if end < 0:
        return None
    value = data[offset:end]
    # 2026-09-04: With one loaded module, incidental short ASCII could win the
    # RANDSTRUCT offset scan. Require the fixed module name field's zero fill.
    if (
        len(value) < 2
        or any(data[end + 1:limit])
        or re.fullmatch(rb"[A-Za-z0-9_-]+", value) is None
    ):
        return None
    return value.decode("ascii")


def _modern_module_layout(blobs, ranges, version):
    # module_memory gained rw_copy ahead of size in 6.13 and removed it in
    # 6.15. The optional lookup-tree node adds 56 bytes to each array entry.
    if version < (6, 13, 0):
        size_offset = 8
    elif version < (6, 15, 0):
        size_offset = 20
    else:
        size_offset = 12
    minimum_stride = _aligned(size_offset + 4, 8)
    for offset in range(0, min(2400, min(map(len, blobs))), 8):
        for stride in (minimum_stride, minimum_stride + 56):
            valid = True
            for data in blobs:
                for kind in range(3):
                    entry = offset + kind * stride
                    base = _integer(data, entry, 8)
                    size = _integer(data, entry + size_offset, 4)
                    mapping = _module_range(base, ranges) if base is not None else None
                    if mapping is None or not size or size > mapping[1] - base:
                        valid = False
                        break
                if not valid:
                    break
            if valid:
                return offset, size_offset, stride
    return None


def _legacy_module_layout(blobs, ranges):
    for offset in range(0, min(2400, min(map(len, blobs))) - 24, 8):
        valid = True
        for data in blobs:
            base = _integer(data, offset, 8)
            size = _integer(data, offset + 8, 4)
            text = _integer(data, offset + 12, 4)
            ro = _integer(data, offset + 16, 4)
            ro_after_init = _integer(data, offset + 20, 4)
            # 2026-09-04: Legacy module allocations are split into adjacent
            # read-only and writable QEMU mappings. Validate the complete span
            # instead of requiring core_layout to fit its first permission run.
            if (
                base is None
                or not text
                or not (text <= ro <= ro_after_init <= size)
                or not _module_span(base, size, ranges)
            ):
                valid = False
                break
        if valid:
            return offset
    return None


def _kernel_modules(symbols, version, ranges):
    modules = next(
        (int(symbol["address"], 16) for symbol in symbols if symbol["name"] == "modules"),
        None,
    )
    if modules is None:
        return []

    inferior = gdb.selected_inferior()
    cursor = struct.unpack("<Q", bytes(inferior.read_memory(modules, 8)))[0]
    seen = {modules}
    addresses = []
    blobs = []
    while cursor != modules and len(addresses) < 128:
        if cursor in seen or cursor < 8:
            raise ValueError("kernel module list is cyclic")
        seen.add(cursor)
        # list_head is at offset 8 in supported layouts; RANDSTRUCT may reorder
        # the following fields.
        module = cursor - 8
        try:
            data = bytes(inferior.read_memory(module, 4096))
        except gdb.MemoryError:
            data = bytes(inferior.read_memory(module, 4096 - (module & 0xfff)))
        addresses.append(module)
        blobs.append(data)
        cursor = struct.unpack("<Q", bytes(inferior.read_memory(cursor, 8)))[0]
    if cursor != modules:
        raise ValueError("kernel module list exceeds 128 entries")
    if not blobs:
        return []

    # 2026-09-04: RANDSTRUCT can move module->name beyond GEF's historical
    # 128-byte search window. Infer one common inline name offset across every
    # list member instead of requiring target debug types.
    name_offset = next(
        (
            offset
            for offset in range(0, min(2048, min(map(len, blobs))), 8)
            if all(_module_name(data, offset) is not None for data in blobs)
        ),
        None,
    )
    if name_offset is None:
        raise ValueError("module name layout was not found")

    layout = (
        _modern_module_layout(blobs, ranges, version)
        if version >= (6, 4, 0)
        else _legacy_module_layout(blobs, ranges)
    )
    result = []
    for module, data in zip(addresses, blobs):
        item = {
            "address": f"0x{module:016x}",
            "name": _module_name(data, name_offset),
            "base": None,
            "size": None,
            "layout": "unknown",
            "segments": [],
        }
        if layout is not None and version >= (6, 4, 0):
            offset, size_offset, stride = layout
            for index, kind in enumerate(_MODULE_MEMORY_TYPES):
                entry = offset + index * stride
                base = _integer(data, entry, 8)
                size = _integer(data, entry + size_offset, 4)
                if base and size and _module_range(base, ranges) is not None:
                    item["segments"].append({
                        "kind": kind,
                        "base": f"0x{base:016x}",
                        "size": size,
                    })
            if item["segments"]:
                item["base"] = item["segments"][0]["base"]
                item["size"] = sum(segment["size"] for segment in item["segments"])
                item["layout"] = "module_memory"
        elif layout is not None:
            base = _integer(data, layout, 8)
            size = _integer(data, layout + 8, 4)
            item.update({
                "base": f"0x{base:016x}",
                "size": size,
                "layout": "core_layout",
                "segments": [{"kind": "core", "base": f"0x{base:016x}", "size": size}],
            })
        result.append(item)
    return result


def _gdbai_kernel_symbols(ranges, module_ranges, requested):
    try:
        # 2026-09-04: Returning a raw kernel image through MI consumed tens of
        # MiB of journal data. Parse it inside GDB and emit only requested facts.
        failure = ValueError("Linux version was not found in the kernel image")
        for start, end in ranges:
            image = bytes(gdb.selected_inferior().read_memory(start, end - start))
            match = re.search(rb"Linux version (\d+)\.(\d+)\.(\d+)", image)
            if match is None:
                continue
            version = tuple(int(part) for part in match.groups())
            if version[:2] == (6, 1):
                finish = image.find(b"\x00", match.start(), min(len(image), match.start() + 1024))
                for patch in re.findall(rb" 6\.1\.(\d+)", image[match.start():finish]):
                    if int(patch) >= 42:
                        version = (6, 1, int(patch))
                        break
            try:
                token_table, token_index, markers, candidate = _table_offsets(image, version)
                break
            except ValueError as error:
                failure = error
        else:
            raise failure
        banners = []
        position = image.find(b"Linux version ")
        while position >= 0:
            finish = image.find(b"\x00", position, min(len(image), position + 512))
            if finish >= 0:
                banner = image[position:finish].rstrip(b"\r\n")
                if all(byte in (9, 10, 13) or 0x20 <= byte <= 0x7e for byte in banner):
                    banners.append((position, banner.decode("ascii")))
            position = image.find(b"Linux version ", position + 1)
        banner_address, banner = max(banners, key=lambda item: len(item[1]))
        tokens = _tokens(image, token_table)
        names, count_address, count = _names_start(image, version, tokens, markers, candidate)

        offsets, relative_base, absolute_percpu = _address_table(
            image, version, token_index, count_address, count
        )

        internal = {"init_task", "pcpu_hot", "current_task", "modules"}
        wanted = set(requested) | internal
        found = []
        position = names
        for index in range(count):
            length = image[position]
            position += 1
            if length & 0x80:
                length = (image[position] << 7) | (length & 0x7f)
                position += 1
            expanded = b"".join(tokens[item] for item in image[position:position + length])
            position += length
            if not expanded:
                continue
            name = expanded[1:].decode("ascii", "replace")
            if name in wanted:
                found.append({
                    "name": name,
                    "type": chr(expanded[0]),
                    "address": f"0x{_address(start, image, version, offsets, relative_base, absolute_percpu, index):016x}",
                })

        try:
            modules = _kernel_modules(found, version, module_ranges)
            module_error = None
        except (gdb.MemoryError, ValueError, struct.error) as error:
            modules = []
            module_error = str(error)

        payload = {
            "version": banner,
            "version_address": f"0x{start + banner_address:016x}",
            "symbols": [symbol for symbol in found if symbol["name"] in requested],
            "missing": sorted(set(requested) - {symbol["name"] for symbol in found}),
            "current_tasks": _current_tasks(found),
            "modules": modules,
            "module_error": module_error,
            "kallsyms": {
                "symbols": count,
                "names_address": f"0x{start + names:016x}",
                "count_address": f"0x{start + count_address:016x}",
                "relative_base": None if relative_base is None else f"0x{relative_base:016x}",
                "absolute_percpu": absolute_percpu,
            },
        }
    except Exception as error:
        payload = {"error": f"{type(error).__name__}: {error}"}
    print(_PREFIX + json.dumps(payload, separators=(",", ":"), sort_keys=True))
