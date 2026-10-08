import gdb
import json


_PREFIX = "gdbai-kernel-typed:"


def _list_page(head, pointer_type, member, offset, limit, include_head):
    sentinel = int(head.address)
    cursor = head.address if include_head else head["next"]
    member_offset = pointer_type.target()[member].bitpos // 8
    entries = []
    seen = set()
    # One extra entry determines continuation without reading the whole list.
    for index in range(offset + limit + 1):
        node = int(cursor)
        if node == sentinel and not (index == 0 and include_head):
            return entries, False
        if node in seen:
            label, name = ("task", "init_task") if include_head else ("module", "modules")
            raise gdb.GdbError("kernel %s list contains a cycle outside %s" % (label, name))
        seen.add(node)
        entry = gdb.Value(node - member_offset).cast(pointer_type)
        if index >= offset:
            entries.append(entry)
        cursor = entry[member]["next"]
    return entries[:limit], True


def _cstring(value):
    return value.string(length=value.type.sizeof, errors="replace").split("\0", 1)[0]


def _page_result(view, values, offset, limit, truncated):
    return {
        "view": view,
        view: values,
        "offset": offset,
        "limit": limit,
        "truncated": truncated,
        "continuation": {"offset": offset + len(values)} if truncated else None,
    }


def _output_limit(message):
    print(_PREFIX + json.dumps({"error": message, "error_code": "OUTPUT_LIMIT"}))


def _gdbai_kernel_tasks(offset, limit, current):
    init_task = gdb.parse_and_eval("&init_task")
    entries, truncated = _list_page(
        init_task["tasks"], init_task.type, "tasks", offset, limit, True
    )
    tasks = [
        {
            "address": "0x%016x" % int(task),
            "pid": int(task["pid"]),
            "tgid": int(task["tgid"]),
            "name": _cstring(task["comm"]),
            "current": int(task) == current if current is not None else None,
        }
        for task in entries
    ]
    result = _page_result("tasks", tasks, offset, limit, truncated)
    result["partial"] = current is None
    result["warnings"] = ["current task could not be resolved"] if current is None else []
    print(_PREFIX + json.dumps(result, separators=(",", ":")))


def _gdbai_kernel_modules(head_address, offset, limit):
    module_type = gdb.lookup_type("struct module")
    head = gdb.Value(head_address).cast(gdb.lookup_type("struct list_head").pointer())
    entries, truncated = _list_page(
        head.dereference(), module_type.pointer(), "list", offset, limit, False
    )
    modern = any(field.name == "mem" for field in module_type.fields())
    modules = []
    for module in entries:
        if modern:
            lower, upper = module["mem"].type.range()
            count = upper - lower + 1
            if not 1 <= count <= 32:
                _output_limit("kernel module memory layout count is invalid")
                return
            base = int(module["mem"][0]["base"])
            size = sum(int(module["mem"][index]["size"]) for index in range(count))
            if size > (1 << 64) - 1:
                _output_limit("kernel module size exceeds 64 bits")
                return
        else:
            base = int(module["core_layout"]["base"])
            size = int(module["core_layout"]["size"])
        modules.append({
            "address": "0x%016x" % int(module),
            "name": _cstring(module["name"]),
            "base": "0x%016x" % base,
            "size": size,
            "layout": "module_memory" if modern else "core_layout",
        })
    result = _page_result("modules", modules, offset, limit, truncated)
    print(_PREFIX + json.dumps(result, separators=(",", ":")))
