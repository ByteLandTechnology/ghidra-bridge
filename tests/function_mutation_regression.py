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
.global obfuscated_fn
obfuscated_fn:
 push %rbp
 .byte 0xeb, 0x01, 0xe8
 xor %eax, %eax
 pop %rbp
 ret
.global patch_target
patch_target:
 mov $0x12345678, %eax
 ret
.global raw_code_buf
raw_code_buf:
 .byte 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3
.global data_slot
data_slot:
 .long 0xdeadbeef
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

    def call(message, timeout=90):
        request = urllib.request.Request(url, json.dumps(message).encode(), headers, method="POST")
        with urllib.request.urlopen(request, timeout=timeout) as response:
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

            listing_ops = tool(41, "ghidra_help", {"domain": "listing"})["operations"]
            for expected_op in ("instruction.assemble", "instruction.disassemble", "code_unit.clear"):
                assert expected_op in listing_ops, listing_ops
            mem_write_help = tool(42, "ghidra_help", {"domain": "memory", "operation": "write"})
            mem_write_props = mem_write_help["inputSchema"]["properties"]
            assert "clear_existing" in mem_write_props and "disassemble" in mem_write_props

            func_b_decoded = tool(43, "ghidra_listing", {
                "operation": "instruction.disassemble",
                "params": {
                    "selector": {"kind": "address", "address": symbols["func_b"]},
                    "follow_flow": True,
                },
            })["result"]["items"]
            assert [item["mnemonic"] for item in func_b_decoded] == ["PUSH", "JMP"], func_b_decoded

            obf_base = int(symbols["obfuscated_fn"], 16)
            rogue_addr = hex(obf_base + 3)
            rogue_end = hex(obf_base + 7)
            rogue = tool(44, "ghidra_listing", {
                "operation": "instruction.disassemble",
                "params": {
                    "selector": {"kind": "address", "address": rogue_addr},
                    "follow_flow": False,
                },
            })["result"]["items"]
            assert len(rogue) == 1 and rogue[0]["mnemonic"] == "CALL", rogue

            batch_items = tool(45, "ghidra_batch", {
                "operation": "execute",
                "params": {
                    "transaction_mode": "all_or_none",
                    "items": [
                        {
                            "id": "clear-rogue",
                            "method": "code_unit.clear",
                            "arguments": {
                                "selector": {"kind": "range", "start": rogue_addr, "end": rogue_end}
                            },
                        },
                        {
                            "id": "nop-rogue",
                            "method": "instruction.assemble",
                            "arguments": {
                                "selector": {"address": rogue_addr},
                                "instructions": ["NOP"],
                            },
                        },
                        {
                            "id": "decode-obf",
                            "method": "instruction.disassemble",
                            "arguments": {
                                "selector": {"kind": "address", "address": symbols["obfuscated_fn"]},
                                "follow_flow": True,
                            },
                        },
                        {
                            "id": "create-obf",
                            "method": "function.create",
                            "arguments": {
                                "resource": {"entry": symbols["obfuscated_fn"], "name": "obfuscated_fn"}
                            },
                        },
                    ],
                },
            })["result"]["items"]
            assert batch_items[0]["result"]["cleared"] is True
            assert [item["mnemonic"] for item in batch_items[1]["result"]["items"]] == ["NOP"]
            assert batch_items[3]["result"]["name"] == "obfuscated_fn"
            obf_list = tool(46, "ghidra_listing", {
                "operation": "instruction.list",
                "params": {"scan": {"range": {"start": symbols["obfuscated_fn"], "end": rogue_end}}},
            })["result"]["items"]
            assert [item["mnemonic"] for item in obf_list] == ["PUSH", "JMP", "NOP", "XOR", "POP", "RET"], obf_list

            patch_base = int(symbols["patch_target"], 16)
            patched_initial = tool(47, "ghidra_listing", {
                "operation": "instruction.disassemble",
                "params": {
                    "selector": {"kind": "address", "address": symbols["patch_target"]},
                    "follow_flow": True,
                },
            })["result"]["items"]
            assert [item["mnemonic"] for item in patched_initial] == ["MOV", "RET"], patched_initial

            cached_start = time.monotonic()
            padded = tool(48, "ghidra_listing", {
                "operation": "instruction.assemble",
                "params": {
                    "selector": {"address": symbols["patch_target"]},
                    "instructions": ["XOR EAX, EAX"],
                    "pad_nop": True,
                },
            })["result"]["items"]
            cached_elapsed = time.monotonic() - cached_start
            assert cached_elapsed < 2.0, f"Assembler was not cached ({cached_elapsed:.2f}s)"
            assert [item["mnemonic"] for item in padded] == ["XOR", "NOP", "NOP", "NOP"], padded
            assert tool(49, "ghidra_listing", {
                "operation": "instruction.get",
                "params": {"selector": {"address": hex(patch_base + 5)}},
            })["result"]["mnemonic"] == "RET"

            restored = tool(50, "ghidra_listing", {
                "operation": "instruction.assemble",
                "params": {
                    "selector": {"address": symbols["patch_target"]},
                    "instructions": ["MOV EAX, 0x12345678"],
                },
            })["result"]["items"]
            assert len(restored) == 1 and restored[0]["length"] == 5, restored

            unpadded = tool(51, "ghidra_listing", {
                "operation": "instruction.assemble",
                "params": {
                    "selector": {"address": symbols["patch_target"]},
                    "instructions": ["XOR EAX, EAX"],
                    "pad_nop": False,
                },
            })["result"]["items"]
            assert [item["mnemonic"] for item in unpadded] == ["XOR"], unpadded
            tool(52, "ghidra_listing", {
                "operation": "instruction.get",
                "params": {"selector": {"address": hex(patch_base + 2)}},
            }, success=False)

            bad_asm = tool(53, "ghidra_listing", {
                "operation": "instruction.assemble",
                "params": {
                    "selector": {"address": symbols["patch_target"]},
                    "instructions": ["NOT_A_SLEIGH_MNEMONIC 123"],
                },
            }, success=False)
            assert bad_asm.get("status") == 400 and bad_asm.get("code") == "invalid_request", bad_asm

            tool(54, "ghidra_global_variable", {
                "operation": "upsert",
                "params": {
                    "resource": {
                        "address": symbols["data_slot"],
                        "name": "data_slot",
                        "data_type": {"kind": "named", "name": "uint"},
                    }
                },
            })
            cleared_data = tool(55, "ghidra_listing", {
                "operation": "code_unit.clear",
                "params": {"selector": {"kind": "address", "address": symbols["data_slot"]}},
            })["result"]
            assert cleared_data["cleared"] is True
            data_units = tool(56, "ghidra_listing", {
                "operation": "data_unit.list",
                "params": {"scan": {"range": {"start": symbols["data_slot"], "end": symbols["data_slot"]}}},
            })["result"]["items"]
            assert len(data_units) == 0, data_units
            kept_symbols = tool(57, "ghidra_symbol", {
                "operation": "list",
                "params": {"scan": {"range": {"start": symbols["data_slot"], "end": symbols["data_slot"]}}},
            })["result"]["items"]
            assert any(sym["name"] == "data_slot" for sym in kept_symbols), kept_symbols

            raw_base = int(symbols["raw_code_buf"], 16)
            tool(58, "ghidra_listing", {
                "operation": "instruction.disassemble",
                "params": {
                    "selector": {"kind": "address", "address": symbols["raw_code_buf"]},
                    "follow_flow": False,
                },
            })
            tool(59, "ghidra_memory", {
                "operation": "write",
                "params": {
                    "selector": {"address": symbols["raw_code_buf"]},
                    "patch": {"bytes": {"encoding": "hex", "data": "31c0c3", "length": 3}},
                    "clear_existing": False,
                },
            }, success=False)
            tool(60, "ghidra_memory", {
                "operation": "write",
                "params": {
                    "selector": {"address": symbols["raw_code_buf"]},
                    "patch": {"bytes": {"encoding": "hex", "data": "31c0c3", "length": 3}},
                    "clear_existing": True,
                    "disassemble": True,
                },
            })
            assert tool(61, "ghidra_listing", {
                "operation": "instruction.get",
                "params": {"selector": {"address": symbols["raw_code_buf"]}},
            })["result"]["mnemonic"] == "XOR"
            assert tool(62, "ghidra_listing", {
                "operation": "instruction.get",
                "params": {"selector": {"address": hex(raw_base + 2)}},
            })["result"]["mnemonic"] == "RET"
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
