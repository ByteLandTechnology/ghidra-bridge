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
.global helper_calc
helper_calc:
 mov (%rdi), %eax
 imul $3, %eax, %eax
 add $7, %eax
 ret
.global locals_target
locals_target:
 push %rbp
 mov %rsp, %rbp
 push %rbx
 sub $0x18, %rsp
 movl %edi, -0x14(%rbp)
 lea -0x14(%rbp), %rdi
 call helper_calc
 movl %eax, %ebx
 lea -0x14(%rbp), %rdi
 call helper_calc
 addl %ebx, %eax
 addl -0x14(%rbp), %eax
 mov -0x8(%rbp), %rbx
 leave
 ret
.global hash_target
hash_target:
 mov $5, %eax
 xchg %eax, (%rdi)
 imul $3, %eax, %eax
 add (%rdi), %eax
 ret
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

            function(21, "create", {
                "resource": {"entry": symbols["helper_calc"], "name": "helper_calc"},
                "disassemble": True,
            })
            function(22, "create", {
                "resource": {"entry": symbols["locals_target"], "name": "locals_target"},
                "disassemble": True,
            })
            function(23, "parameter.create", {
                "selector": {"entry": symbols["locals_target"]},
                "resource": {
                    "ordinal": 0,
                    "name": "input_arg",
                    "data_type": {"kind": "named", "name": "/int"},
                },
            })

            listed_before = function(24, "list", {
                "filter": {"entry": symbols["locals_target"]},
            })["result"]["items"]
            assert len(listed_before) == 1
            assert listed_before[0]["local_variables"] == []

            got_before = function(25, "get", selector("locals_target"))["result"]
            uncommitted_locals = got_before["local_variables"]
            assert len(uncommitted_locals) >= 2, uncommitted_locals

            decomp_before = tool(26, "ghidra_decompilation", {
                "operation": "get",
                "params": {
                    "selector": {"entry": symbols["locals_target"]},
                    "format": "document",
                },
            })["result"]
            assert decomp_before["local_variables"] == uncommitted_locals

            token_symbols = [
                tok["symbol"]
                for line in decomp_before["lines"]
                for tok in line["tokens"]
                if "symbol" in tok
            ]
            assert any(sym["id"].startswith("parameter:0") for sym in token_symbols), token_symbols
            assert any(sym["id"].startswith("local:") for sym in token_symbols), token_symbols

            stack_local = next(
                loc for loc in uncommitted_locals
                if loc["storage"]["serialization"].startswith("Stack[")
            )
            non_stack_local = next(
                loc for loc in uncommitted_locals
                if not loc["storage"]["serialization"].startswith("Stack[")
            )

            patched_stack = function(27, "local_variable.patch", {
                "selector": {
                    "entry": symbols["locals_target"],
                    "name": stack_local["name"],
                    "storage": stack_local["storage"],
                },
                "patch": {"name": "saved_slot"},
            })["result"]
            assert patched_stack["name"] == "saved_slot"
            assert patched_stack["storage"] == stack_local["storage"]

            listed_after_one = function(28, "list", {
                "filter": {"entry": symbols["locals_target"]},
            })["result"]["items"][0]["local_variables"]
            assert [v["name"] for v in listed_after_one] == ["saved_slot"], listed_after_one

            patched_dynamic = function(29, "local_variable.patch", {
                "selector": {
                    "entry": symbols["locals_target"],
                    "name": non_stack_local["name"],
                    "storage": non_stack_local["storage"],
                },
                "patch": {
                    "name": "calc_temp",
                    "data_type": {"kind": "named", "name": "/int"},
                },
            })["result"]
            assert patched_dynamic["name"] == "calc_temp"
            assert patched_dynamic["storage"]["serialization"].split(":")[0] == (
                non_stack_local["storage"]["serialization"].split(":")[0]
            )

            for idx, category in enumerate(("/CatA", "/CatB"), start=30):
                tool(idx * 2, "ghidra_data_type", {
                    "operation": "create",
                    "params": {
                        "resource": {
                            "kind": "struct",
                            "category_path": category,
                            "name": "Packet",
                            "size": 0,
                        },
                    },
                })
                tool(idx * 2 + 1, "ghidra_data_type", {
                    "operation": "patch",
                    "params": {
                        "selector": {"path": f"{category}/Packet"},
                        "patch": {
                            "kind": "struct",
                            "add_fields": [{
                                "name": "val",
                                "data_type": {"kind": "named", "name": "/int"},
                            }],
                        },
                    },
                })

            retyped_a = function(40, "local_variable.patch", {
                "selector": {"entry": symbols["locals_target"], "name": "saved_slot"},
                "patch": {"data_type": {"kind": "named", "name": "/CatA/Packet"}},
            })["result"]
            assert retyped_a["data_type"] == {"kind": "named", "name": "/CatA/Packet"}, retyped_a

            retyped_b = function(41, "local_variable.patch", {
                "selector": {
                    "entry": symbols["locals_target"],
                    "name": "saved_slot",
                    "storage": retyped_a["storage"],
                },
                "patch": {"data_type": {"kind": "named", "name": "/CatB/Packet"}},
            })["result"]
            assert retyped_b["data_type"] == {"kind": "named", "name": "/CatB/Packet"}, retyped_b

            decomp_after = tool(42, "ghidra_decompilation", {
                "operation": "get",
                "params": {
                    "selector": {"entry": symbols["locals_target"]},
                    "format": "document",
                },
            })["result"]
            field_tokens = [
                tok for line in decomp_after["lines"]
                for tok in line["tokens"]
                if tok.get("text") == "val"
            ]
            assert field_tokens, decomp_after["lines"]
            assert all("symbol" not in tok for tok in field_tokens), field_tokens

            function(43, "create", {
                "resource": {"entry": symbols["hash_target"], "name": "hash_target"},
                "disassemble": True,
            })
            hash_locals = function(44, "get", selector("hash_target"))["result"]["local_variables"]
            hash_local = next(
                (loc for loc in hash_locals if loc["storage"]["serialization"].startswith("HASH:")),
                None,
            )
            assert hash_local is not None, hash_locals
            patched_hash = function(45, "local_variable.patch", {
                "selector": {
                    "entry": symbols["hash_target"],
                    "name": hash_local["name"],
                    "storage": hash_local["storage"],
                },
                "patch": {"name": "branch_val"},
            })["result"]
            assert patched_hash["name"] == "branch_val"
            assert patched_hash["storage"]["serialization"].startswith("HASH:"), patched_hash

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
