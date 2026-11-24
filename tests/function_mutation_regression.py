#!/usr/bin/env python3

"""Check function mutations in an isolated headless Ghidra project."""

import argparse
import json
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


FIXTURE = """
.global _start
_start: ret
.global func_a
func_a: push %rbp
 jmp shared
.global func_b
func_b: push %rbx
 jmp shared
.global shared
shared: nop
 ret
.global jump_entry
jump_entry: jmp jump_target
.global jump_target
jump_target: mov $1, %eax
 ret
.global reserved_entry
reserved_entry: nop
 ret
.global label_only
label_only: nop
 ret
.global patch_target
patch_target: mov $0x12345678, %eax
 ret
.global rogue_fn
rogue_fn: jmp 1f
 .byte 0xe8
1:
 xor %eax, %eax
 ret
.section .data
.global global_val
global_val: .long 0x11223344
"""


def run_test(headless, root):
    project = root / "project"
    project.mkdir()
    source = root / "fixture.s"
    source.write_text(FIXTURE)
    binary = root / "fixture"
    subprocess.run(
        ["gcc", "-nostdlib", "-no-pie", "-Wl,-e,_start", "-o", str(binary), str(source)],
        check=True,
    )
    symbols = {}
    for line in subprocess.check_output(["nm", str(binary)], text=True).splitlines():
        parts = line.split()
        if len(parts) == 3:
            symbols[parts[2]] = "0x" + parts[0]

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    url = f"http://127.0.0.1:{port}/mcp"
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}

    def call(message):
        request = urllib.request.Request(url, json.dumps(message).encode(), headers, method="POST")
        with urllib.request.urlopen(request, timeout=90) as response:
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

    scripts = pathlib.Path(__file__).resolve().parents[1] / "build" / "ghidra-script"
    command = [
        str(headless), str(project), "test", "-import", str(binary), "-noanalysis",
        "-scriptPath", str(scripts), "-postScript", "GhidraMcp.java",
        "host=127.0.0.1", f"port={port}",
    ]
    log_path = root / "headless.log"
    with log_path.open("w") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        ready = False
        try:
            initialize = {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                           "clientInfo": {"name": "function-test", "version": "1"}},
            }
            for _ in range(120):
                if process.poll() is not None:
                    raise RuntimeError("Ghidra stopped: " + log_path.read_text()[-2000:])
                try:
                    if call(initialize).get("result"):
                        ready = True
                        break
                except (OSError, TimeoutError, urllib.error.URLError):
                    time.sleep(0.5)
            if not ready:
                raise RuntimeError("Ghidra did not start")
            call({"jsonrpc": "2.0", "method": "notifications/initialized"})

            first = function(2, "create", {
                "resource": {"entry": symbols["func_a"], "name": "func_a"},
                "disassemble": True,
            })["result"]
            function(3, "create", {
                "resource": {"entry": symbols["func_b"], "name": "func_b"},
                "disassemble": True,
            }, success=False)
            assert function(4, "get", selector("func_a"))["result"]["body"] == first["body"]
            function(5, "get", selector("func_b"), success=False)
            tool(16, "ghidra_listing", {
                "operation": "instruction.get",
                "params": {"selector": {"address": symbols["func_b"]}},
            }, success=False)

            jump = function(6, "create", {
                "resource": {"entry": symbols["jump_entry"], "name": "jump_name"},
                "disassemble": True,
            })["result"]
            assert jump["name"] == "jump_name"
            function(7, "get", selector("jump_target"), success=False)
            instruction = {"operation": "instruction.get",
                           "params": {"selector": {"address": symbols["jump_entry"]}}}
            before = tool(8, "ghidra_listing", instruction)["result"]
            assert function(9, "delete", selector("jump_entry"))["result"] == {"deleted": True}
            assert tool(10, "ghidra_listing", instruction)["result"] == before
            function(11, "delete", selector("jump_entry"), success=False)
            recreated = function(12, "create", {
                "resource": {"entry": symbols["jump_entry"], "name": "recreated"},
            })["result"]
            assert recreated["name"] == "recreated"

            function(13, "create", {
                "resource": {"entry": symbols["reserved_entry"], "name": "FUN_12345678"},
                "disassemble": True,
            }, success=False)
            function(14, "get", selector("reserved_entry"), success=False)
            tool(17, "ghidra_listing", {
                "operation": "instruction.get",
                "params": {"selector": {"address": symbols["reserved_entry"]}},
            }, success=False)
            label = function(15, "create", {
                "resource": {"entry": symbols["label_only"]}, "disassemble": True,
            })["result"]
            assert label["name"] == "label_only"

            # Standalone instruction.disassemble decodes func_b (shared tail with func_a).
            dis_func_b = tool(30, "ghidra_listing", {
                "operation": "instruction.disassemble",
                "params": {"selector": {"kind": "address", "address": symbols["func_b"]}},
            })["result"]
            assert len(dis_func_b["items"]) >= 2
            assert tool(31, "ghidra_listing", {
                "operation": "instruction.get",
                "params": {"selector": {"address": symbols["func_b"]}},
            })["result"]["mnemonic"] == "PUSH"

            # Rogue-byte cleanup with code_unit.clear + instruction.disassemble.
            rogue_base = int(symbols["rogue_fn"], 16)
            rogue_byte = hex(rogue_base + 2)
            rogue_real = hex(rogue_base + 3)
            tool(32, "ghidra_listing", {
                "operation": "instruction.disassemble",
                "params": {
                    "selector": {"kind": "address", "address": symbols["rogue_fn"]},
                    "follow_flow": False,
                },
            })
            tool(33, "ghidra_listing", {
                "operation": "instruction.disassemble",
                "params": {"selector": {"kind": "address", "address": rogue_byte}},
            })
            cleared_rogue = tool(34, "ghidra_listing", {
                "operation": "code_unit.clear",
                "params": {"selector": {"kind": "address", "address": rogue_byte}},
            })["result"]
            assert cleared_rogue["length"] >= 1
            redecoded = tool(35, "ghidra_listing", {
                "operation": "instruction.disassemble",
                "params": {"selector": {"kind": "address", "address": rogue_real}},
            })["result"]["items"]
            assert [item["mnemonic"] for item in redecoded[:2]] == ["XOR", "RET"]

            # instruction.assemble with pad_nop and non-fallthrough RET padding.
            tool(36, "ghidra_listing", {
                "operation": "instruction.disassemble",
                "params": {"selector": {"kind": "address", "address": symbols["patch_target"]}},
            })
            assembled_xor = tool(37, "ghidra_listing", {
                "operation": "instruction.assemble",
                "params": {
                    "selector": {"address": symbols["patch_target"]},
                    "instructions": ["xor EAX, EAX"],
                    "pad_nop": True,
                },
            })["result"]["items"]
            assert [item["mnemonic"] for item in assembled_xor] == ["XOR", "NOP", "NOP", "NOP"]
            cached_start = time.monotonic()
            tool(38, "ghidra_listing", {
                "operation": "instruction.assemble",
                "params": {
                    "selector": {"address": symbols["patch_target"]},
                    "instructions": ["MOV EAX, 0x12345678"],
                },
            })
            assert time.monotonic() - cached_start < 2.0, "Assembler cache did not reuse Sleigh grammar"
            assembled_ret = tool(39, "ghidra_listing", {
                "operation": "instruction.assemble",
                "params": {
                    "selector": {"address": symbols["patch_target"]},
                    "instructions": ["RET"],
                    "pad_nop": True,
                },
            })["result"]["items"]
            assert [item["mnemonic"] for item in assembled_ret] == ["RET", "NOP", "NOP", "NOP", "NOP"]

            # Invalid Sleigh mnemonic and unmapped address fail cleanly.
            tool(40, "ghidra_listing", {
                "operation": "instruction.assemble",
                "params": {
                    "selector": {"address": symbols["patch_target"]},
                    "instructions": ["not_a_real_mnemonic 1, 2"],
                },
            }, success=False)
            tool(41, "ghidra_listing", {
                "operation": "instruction.assemble",
                "params": {
                    "selector": {"address": "0xdeadbeef"},
                    "instructions": ["NOP"],
                },
            }, success=False)

            # code_unit.clear clears defined global data without global_variable.delete restrictions.
            tool(42, "ghidra_global_variable", {
                "operation": "create",
                "params": {
                    "resource": {
                        "address": symbols["global_val"],
                        "name": "g_val",
                        "data_type": {"kind": "named", "name": "uint"},
                    },
                },
            })
            cleared_data = tool(43, "ghidra_listing", {
                "operation": "code_unit.clear",
                "params": {"selector": {"kind": "address", "address": symbols["global_val"]}},
            })["result"]
            assert cleared_data["length"] == 4

            # memory.write fails over defined instructions unless clear_existing=True, and disassembles.
            tool(44, "ghidra_memory", {
                "operation": "write",
                "params": {
                    "selector": {"address": symbols["patch_target"]},
                    "patch": {
                        "bytes": {"encoding": "hex", "data": "31c0c3", "length": 3},
                    },
                },
            }, success=False)
            tool(45, "ghidra_memory", {
                "operation": "write",
                "params": {
                    "selector": {"address": symbols["patch_target"]},
                    "patch": {
                        "bytes": {"encoding": "hex", "data": "31c0c3", "length": 3},
                        "clear_existing": True,
                        "disassemble": True,
                    },
                },
            })
            assert tool(46, "ghidra_listing", {
                "operation": "instruction.get",
                "params": {"selector": {"address": symbols["patch_target"]}},
            })["result"]["mnemonic"] == "XOR"

            # Atomic batch.execute all_or_none rolls back listing and memory mutations on failure.
            batch_err = tool(47, "ghidra_batch", {
                "operation": "execute",
                "params": {
                    "transaction_mode": "all_or_none",
                    "items": [
                        {
                            "id": "clear-1",
                            "method": "code_unit.clear",
                            "arguments": {
                                "selector": {"kind": "address", "address": symbols["patch_target"]},
                            },
                        },
                        {
                            "id": "write-2",
                            "method": "memory.write",
                            "arguments": {
                                "selector": {"address": symbols["patch_target"]},
                                "patch": {
                                    "bytes": {"encoding": "hex", "data": "9090", "length": 2},
                                    "clear_existing": True,
                                },
                            },
                        },
                        {
                            "id": "asm-3",
                            "method": "instruction.assemble",
                            "arguments": {
                                "selector": {"address": symbols["patch_target"]},
                                "instructions": ["bad_sleigh_op"],
                            },
                        },
                    ],
                },
            }, success=False)
            assert batch_err["code"] == "batch_rolled_back"
            assert tool(48, "ghidra_listing", {
                "operation": "instruction.get",
                "params": {"selector": {"address": symbols["patch_target"]}},
            })["result"]["mnemonic"] == "XOR"

            batch_ok = tool(49, "ghidra_batch", {
                "operation": "execute",
                "params": {
                    "transaction_mode": "all_or_none",
                    "items": [
                        {
                            "id": "clear-ok",
                            "method": "code_unit.clear",
                            "arguments": {
                                "selector": {"kind": "address", "address": symbols["patch_target"]},
                            },
                        },
                        {
                            "id": "asm-ok",
                            "method": "instruction.assemble",
                            "arguments": {
                                "selector": {"address": symbols["patch_target"]},
                                "instructions": ["NOP", "NOP"],
                            },
                        },
                    ],
                },
            })["result"]
            assert len(batch_ok["items"]) == 2 and "result" in batch_ok["items"][1]
            assert tool(50, "ghidra_listing", {
                "operation": "instruction.get",
                "params": {"selector": {"address": symbols["patch_target"]}},
            })["result"]["mnemonic"] == "NOP"

            print("Function mutation regression checks passed")
        finally:
            if ready:
                try:
                    tool(20, "ghidra_bridge", {"operation": "shutdown"})
                except (OSError, TimeoutError, urllib.error.URLError):
                    pass
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("headless", type=pathlib.Path, help="path to analyzeHeadless")
    args = parser.parse_args()
    if shutil.which("gcc") is None or shutil.which("nm") is None:
        parser.error("gcc and nm are required")
    with tempfile.TemporaryDirectory(prefix="ghidra-function-test-") as directory:
        run_test(args.headless.resolve(), pathlib.Path(directory))


if __name__ == "__main__":
    main()
