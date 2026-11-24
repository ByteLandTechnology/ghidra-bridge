#!/usr/bin/env python3

"""Check function mutations in an isolated headless Ghidra project."""

import argparse
import json
import os
import pathlib
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


TEXT_VADDR = 0x401000
TEXT_OFFSET = 0x1000

# x86-64 machine code fixture:
# 0x00 _start:         ret
# 0x01 func_a:         push %rbp; jmp shared
# 0x04 func_b:         push %rbx; jmp shared
# 0x07 shared:         nop; ret
# 0x09 jump_entry:     jmp jump_target
# 0x0b jump_target:    mov $1, %eax; ret
# 0x11 reserved_entry: nop; ret
# 0x13 label_only:     nop; ret
TEXT_BYTES = bytes.fromhex(
    "c3"
    "55eb03"
    "53eb00"
    "90c3"
    "eb00"
    "b801000000c3"
    "90c3"
    "90c3"
)

SYMBOL_OFFSETS = (
    ("_start", 0x00),
    ("func_a", 0x01),
    ("func_b", 0x04),
    ("shared", 0x07),
    ("jump_entry", 0x09),
    ("jump_target", 0x0B),
    ("reserved_entry", 0x11),
    ("label_only", 0x13),
)


def align_up(value, alignment):
    remainder = value % alignment
    return value if remainder == 0 else value + (alignment - remainder)


def build_fixture_elf(binary_path):
    strtab = bytearray(b"\x00")
    symtab = bytearray(struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0))
    symbols = {}

    for name, offset in SYMBOL_OFFSETS:
        name_offset = len(strtab)
        strtab.extend(name.encode("ascii") + b"\x00")
        address = TEXT_VADDR + offset
        symbols[name] = f"0x{address:016x}"
        # STB_GLOBAL (1 << 4) | STT_NOTYPE (0) keeps labels without pre-creating functions.
        symtab.extend(struct.pack("<IBBHQQ", name_offset, 0x10, 0, 1, address, 0))

    shstrtab = b"\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00"

    body = bytearray(TEXT_OFFSET)
    body.extend(TEXT_BYTES)

    symtab_offset = align_up(len(body), 8)
    body.extend(b"\x00" * (symtab_offset - len(body)))
    body.extend(symtab)

    strtab_offset = len(body)
    body.extend(strtab)

    shstrtab_offset = len(body)
    body.extend(shstrtab)

    shoff = align_up(len(body), 8)
    body.extend(b"\x00" * (shoff - len(body)))

    section_headers = b"".join(
        [
            struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            struct.pack(
                "<IIQQQQIIQQ",
                1,
                1,
                0x6,
                TEXT_VADDR,
                TEXT_OFFSET,
                len(TEXT_BYTES),
                0,
                0,
                16,
                0,
            ),
            struct.pack(
                "<IIQQQQIIQQ",
                7,
                2,
                0,
                0,
                symtab_offset,
                len(symtab),
                3,
                1,
                8,
                24,
            ),
            struct.pack(
                "<IIQQQQIIQQ",
                15,
                3,
                0,
                0,
                strtab_offset,
                len(strtab),
                0,
                0,
                1,
                0,
            ),
            struct.pack(
                "<IIQQQQIIQQ",
                23,
                3,
                0,
                0,
                shstrtab_offset,
                len(shstrtab),
                0,
                0,
                1,
                0,
            ),
        ]
    )
    body.extend(section_headers)

    ehdr = struct.pack(
        "<4sBBBBB7xHHIQQQIHHHHHH",
        b"\x7fELF",
        2,
        1,
        1,
        0,
        0,
        2,
        62,
        1,
        TEXT_VADDR,
        64,
        shoff,
        0,
        64,
        56,
        1,
        64,
        5,
        4,
    )
    phdr = struct.pack(
        "<IIQQQQQQ",
        1,
        5,
        TEXT_OFFSET,
        TEXT_VADDR,
        TEXT_VADDR,
        len(TEXT_BYTES),
        len(TEXT_BYTES),
        0x1000,
    )
    body[0:64] = ehdr
    body[64:120] = phdr

    binary_path.write_bytes(body)
    return symbols


def resolve_headless_launcher(headless):
    candidate = pathlib.Path(os.path.abspath(str(headless)))
    if os.name == "nt" and candidate.suffix == "":
        bat_candidate = candidate.with_suffix(".bat")
        if bat_candidate.is_file():
            candidate = bat_candidate
    if not candidate.is_file():
        raise FileNotFoundError(f"Ghidra headless launcher not found: {candidate}")
    return candidate


def start_headless_process(command, log):
    if os.name == "nt":
        quoted = " ".join('"' + part.replace('"', '""') + '"' for part in command)
        return subprocess.Popen(
            f'cmd.exe /d /s /c "{quoted}"',
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
    return subprocess.Popen(
        command,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )


def stop_headless_process(process, graceful_wait):
    if graceful_wait > 0:
        try:
            process.wait(timeout=graceful_wait)
            return
        except subprocess.TimeoutExpired:
            pass
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(process.pid)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        process.kill()
        process.wait(timeout=10)
        return
    if shutil.which("pkill"):
        subprocess.run(
            ["pkill", "-TERM", "-P", str(process.pid)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        if shutil.which("pkill"):
            subprocess.run(
                ["pkill", "-KILL", "-P", str(process.pid)],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        process.kill()
        process.wait(timeout=5)


def run_test(headless, root):
    project = root / "project"
    project.mkdir()
    binary = root / "fixture"
    symbols = build_fixture_elf(binary)

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    url = f"http://127.0.0.1:{port}/mcp"
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}

    def call(message):
        request = urllib.request.Request(url, json.dumps(message).encode(), headers, method="POST")
        with urllib.request.urlopen(request, timeout=5) as response:
            body = response.read().decode()
        if not body:
            return {}
        if body.startswith(("event:", "data:")):
            body = next(line[5:].strip() for line in body.splitlines() if line.startswith("data:"))
        return json.loads(body)

    def tool(call_id, name, arguments, success=True):
        message = {
            "jsonrpc": "2.0",
            "id": call_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
        result = call(message)["result"]
        if bool(result.get("isError", False)) == success:
            raise AssertionError(f"Unexpected result for {name}: {result}")
        return result.get("structuredContent", {})

    def function(call_id, operation, params, success=True):
        return tool(call_id, "ghidra_function", {"operation": operation, "params": params}, success)

    def selector(label):
        return {"selector": {"entry": symbols[label]}}

    repo_root = pathlib.Path(os.path.abspath(str(pathlib.Path(__file__).resolve().parents[1])))
    scripts = repo_root / "build" / "ghidra-script"
    command = [
        str(headless),
        str(project),
        "test",
        "-import",
        str(binary),
        "-noanalysis",
        "-scriptPath",
        str(scripts),
        "-postScript",
        "GhidraMcp.java",
        "host=127.0.0.1",
        f"port={port}",
    ]
    log_path = root / "headless.log"
    with log_path.open("w", encoding="utf-8", errors="replace") as log:
        process = start_headless_process(command, log)
        ready = False
        try:
            initialize = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "function-test", "version": "1"},
                },
            }
            deadline = time.monotonic() + 120.0
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(
                        "Ghidra stopped: "
                        + log_path.read_text(encoding="utf-8", errors="replace")[-2000:]
                    )
                try:
                    if call(initialize).get("result"):
                        ready = True
                        break
                except (OSError, TimeoutError, urllib.error.URLError):
                    time.sleep(0.5)
            if not ready:
                raise RuntimeError(
                    "Ghidra did not start: "
                    + log_path.read_text(encoding="utf-8", errors="replace")[-2000:]
                )
            call({"jsonrpc": "2.0", "method": "notifications/initialized"})

            first = function(
                2,
                "create",
                {
                    "resource": {"entry": symbols["func_a"], "name": "func_a"},
                    "disassemble": True,
                },
            )["result"]
            function(
                3,
                "create",
                {
                    "resource": {"entry": symbols["func_b"], "name": "func_b"},
                    "disassemble": True,
                },
                success=False,
            )
            assert function(4, "get", selector("func_a"))["result"]["body"] == first["body"]
            function(5, "get", selector("func_b"), success=False)
            tool(
                16,
                "ghidra_listing",
                {
                    "operation": "instruction.get",
                    "params": {"selector": {"address": symbols["func_b"]}},
                },
                success=False,
            )

            jump = function(
                6,
                "create",
                {
                    "resource": {"entry": symbols["jump_entry"], "name": "jump_name"},
                    "disassemble": True,
                },
            )["result"]
            assert jump["name"] == "jump_name"
            function(7, "get", selector("jump_target"), success=False)
            instruction = {
                "operation": "instruction.get",
                "params": {"selector": {"address": symbols["jump_entry"]}},
            }
            before = tool(8, "ghidra_listing", instruction)["result"]
            assert function(9, "delete", selector("jump_entry"))["result"] == {"deleted": True}
            assert tool(10, "ghidra_listing", instruction)["result"] == before
            function(11, "delete", selector("jump_entry"), success=False)
            recreated = function(
                12,
                "create",
                {
                    "resource": {"entry": symbols["jump_entry"], "name": "recreated"},
                },
            )["result"]
            assert recreated["name"] == "recreated"

            function(
                13,
                "create",
                {
                    "resource": {"entry": symbols["reserved_entry"], "name": "FUN_12345678"},
                    "disassemble": True,
                },
                success=False,
            )
            function(14, "get", selector("reserved_entry"), success=False)
            tool(
                17,
                "ghidra_listing",
                {
                    "operation": "instruction.get",
                    "params": {"selector": {"address": symbols["reserved_entry"]}},
                },
                success=False,
            )
            label = function(
                15,
                "create",
                {
                    "resource": {"entry": symbols["label_only"]},
                    "disassemble": True,
                },
            )["result"]
            assert label["name"] == "label_only"

            first_param = function(21, "parameter.create", {
                "selector": {"entry": symbols["func_a"]},
                "resource": {
                    "ordinal": 0,
                    "name": "first_param",
                    "data_type": {"kind": "named", "name": "/int"},
                },
            })["result"]
            assert first_param == {
                "ordinal": 0,
                "name": "first_param",
                "data_type": {"kind": "named", "name": "/int"},
                "storage": {"kind": "serialization", "serialization": "register:00000038:4"},
            }

            zero_param = function(22, "parameter.create", {
                "selector": {"entry": symbols["func_a"]},
                "resource": {
                    "ordinal": 0,
                    "name": "zero_param",
                    "data_type": {"kind": "pointer", "target": {"kind": "named", "name": "/char"}},
                },
            })["result"]
            assert zero_param == {
                "ordinal": 0,
                "name": "zero_param",
                "data_type": {"kind": "pointer", "target": {"kind": "named", "name": "/char"}},
                "storage": {"kind": "serialization", "serialization": "register:00000038:8"},
            }

            func_a_with_params = function(23, "get", selector("func_a"))["result"]
            assert func_a_with_params["has_custom_variable_storage"] is False
            assert func_a_with_params["parameter_count"] == 2
            assert func_a_with_params["parameters"] == [
                zero_param,
                {
                    "ordinal": 1,
                    "name": "first_param",
                    "data_type": {"kind": "named", "name": "/int"},
                    "storage": {"kind": "serialization", "serialization": "register:00000030:4"},
                },
            ]

            function(24, "parameter.create", {
                "selector": {"entry": symbols["func_a"]},
                "resource": {
                    "ordinal": 2,
                    "name": "first_param",
                    "data_type": {"kind": "named", "name": "/int"},
                },
            }, success=False)
            function(25, "parameter.create", {
                "selector": {"entry": symbols["func_a"]},
                "resource": {
                    "ordinal": 5,
                    "name": "out_of_range",
                    "data_type": {"kind": "named", "name": "/int"},
                },
            }, success=False)
            assert function(26, "get", selector("func_a"))["result"]["parameter_count"] == 2

            patched_recreated = function(27, "patch", {
                "selector": {"entry": symbols["jump_entry"]},
                "patch": {
                    "return_type": {"kind": "named", "name": "/int"},
                    "return_storage": {"kind": "register", "register": "EAX"},
                },
            })["result"]
            assert patched_recreated["has_custom_variable_storage"] is True

            custom_reg = function(28, "parameter.create", {
                "selector": {"entry": symbols["jump_entry"]},
                "resource": {
                    "ordinal": 0,
                    "name": "custom_reg",
                    "data_type": {"kind": "named", "name": "/longlong"},
                    "storage": {"kind": "register", "register": "R12"},
                },
            })["result"]
            assert custom_reg == {
                "ordinal": 0,
                "name": "custom_reg",
                "data_type": {"kind": "named", "name": "/longlong"},
                "storage": {"kind": "serialization", "serialization": "register:000000a0:8"},
            }

            unassigned_tail = function(29, "parameter.create", {
                "selector": {"entry": symbols["jump_entry"]},
                "resource": {
                    "ordinal": 1,
                    "name": "unassigned_tail",
                    "data_type": {"kind": "named", "name": "/int"},
                },
            })["result"]
            assert unassigned_tail == {
                "ordinal": 1,
                "name": "unassigned_tail",
                "data_type": {"kind": "named", "name": "/int"},
                "storage": {"kind": "serialization", "serialization": "<UNASSIGNED>"},
            }

            unassigned_head = function(30, "parameter.create", {
                "selector": {"entry": symbols["jump_entry"]},
                "resource": {
                    "ordinal": 0,
                    "name": "unassigned_head",
                    "data_type": {"kind": "named", "name": "/short"},
                },
            })["result"]
            assert unassigned_head == {
                "ordinal": 0,
                "name": "unassigned_head",
                "data_type": {"kind": "named", "name": "/short"},
                "storage": {"kind": "serialization", "serialization": "<UNASSIGNED>"},
            }

            custom_with_params = function(31, "get", selector("jump_entry"))["result"]
            assert custom_with_params["has_custom_variable_storage"] is True
            assert custom_with_params["return_storage"] == {
                "kind": "serialization",
                "serialization": "register:00000000:4",
            }
            assert custom_with_params["parameter_count"] == 3
            assert custom_with_params["parameters"] == [
                unassigned_head,
                {
                    "ordinal": 1,
                    "name": "custom_reg",
                    "data_type": {"kind": "named", "name": "/longlong"},
                    "storage": {"kind": "serialization", "serialization": "register:000000a0:8"},
                },
                {
                    "ordinal": 2,
                    "name": "unassigned_tail",
                    "data_type": {"kind": "named", "name": "/int"},
                    "storage": {"kind": "serialization", "serialization": "<UNASSIGNED>"},
                },
            ]

            tool(32, "ghidra_data_type", {
                "operation": "create",
                "params": {"resource": {"kind": "struct", "name": "big_ret", "size": 24}},
            })
            auto_patched = function(33, "patch", {
                "selector": {"entry": symbols["label_only"]},
                "patch": {"return_type": {"kind": "named", "name": "/big_ret"}},
            })["result"]
            assert auto_patched["parameter_count"] == 1
            assert auto_patched["parameters"][0]["name"] == "__return_storage_ptr__"

            function(34, "parameter.create", {
                "selector": {"entry": symbols["label_only"]},
                "resource": {
                    "ordinal": 0,
                    "name": "before_auto",
                    "data_type": {"kind": "named", "name": "/int"},
                },
            }, success=False)

            after_auto = function(35, "parameter.create", {
                "selector": {"entry": symbols["label_only"]},
                "resource": {
                    "ordinal": 1,
                    "name": "after_auto",
                    "data_type": {"kind": "named", "name": "/int"},
                },
            })["result"]
            assert after_auto == {
                "ordinal": 1,
                "name": "after_auto",
                "data_type": {"kind": "named", "name": "/int"},
                "storage": {"kind": "serialization", "serialization": "register:00000030:4"},
            }
            auto_with_params = function(36, "get", selector("label_only"))["result"]
            assert auto_with_params["has_custom_variable_storage"] is False
            assert auto_with_params["parameter_count"] == 2
            assert [p["name"] for p in auto_with_params["parameters"]] == [
                "__return_storage_ptr__",
                "after_auto",
            ]
            print("Function mutation regression checks passed")
        finally:
            if ready:
                try:
                    tool(20, "ghidra_bridge", {"operation": "shutdown"})
                except (OSError, TimeoutError, urllib.error.URLError):
                    pass
            stop_headless_process(process, 20 if ready else 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("headless", type=pathlib.Path, help="path to analyzeHeadless")
    args = parser.parse_args()
    headless = resolve_headless_launcher(args.headless)
    with tempfile.TemporaryDirectory(prefix="ghidra-function-test-") as directory:
        run_test(headless, pathlib.Path(os.path.abspath(directory)))


if __name__ == "__main__":
    main()
