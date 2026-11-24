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

            created_dt = tool(21, "ghidra_data_type", {
                "operation": "create",
                "params": {
                    "category_path": "/pkg",
                    "declaration": "struct Item { int id; const char *label; };",
                },
            })["result"]
            assert created_dt["path"] == "/pkg/Item"
            assert created_dt["kind"] == "struct"
            tool(22, "ghidra_data_type", {
                "operation": "create",
                "params": {"declaration": "struct A { int x; }; struct B { int y; };"},
            }, success=False)
            tool(23, "ghidra_data_type", {
                "operation": "create",
                "params": {"declaration": ";"},
            }, success=False)
            upserted_dt = tool(24, "ghidra_data_type", {
                "operation": "upsert",
                "params": {
                    "category_path": "/pkg",
                    "declaration": "struct Item { long id; const char *label; int flags[4]; };",
                },
            })["result"]
            assert upserted_dt["path"] == "/pkg/Item"

            patched_custom = function(25, "patch", {
                "selector": {"entry": symbols["label_only"]},
                "patch": {
                    "return_type": "unsigned int",
                    "return_storage": {"kind": "register", "register": "EAX"},
                    "has_custom_variable_storage": True,
                    "parameters": [
                        {
                            "name": "item",
                            "data_type": "/pkg/Item *",
                            "storage": {"kind": "register", "register": "R8"},
                        },
                        {
                            "name": "cb",
                            "data_type": "void (*)(int)",
                            "storage": {"kind": "register", "register": "R9"},
                        },
                    ],
                },
            })["result"]
            assert patched_custom["has_custom_variable_storage"] is True
            assert [p["name"] for p in patched_custom["parameters"]] == ["item", "cb"]
            s0 = patched_custom["parameters"][0]["storage"]
            s1 = patched_custom["parameters"][1]["storage"]

            swapped = function(26, "patch", {
                "selector": {"entry": symbols["label_only"]},
                "patch": {
                    "parameters": [
                        {"name": "cb", "data_type": "void (*)(int)", "storage": s1},
                        {"name": "item", "data_type": "/pkg/Item *", "storage": s0},
                    ],
                },
            })["result"]
            assert swapped["has_custom_variable_storage"] is True
            assert [p["name"] for p in swapped["parameters"]] == ["cb", "item"]
            assert swapped["parameters"][0]["storage"] == s1
            assert swapped["parameters"][1]["storage"] == s0

            sig_patched = function(27, "patch", {
                "selector": {"entry": symbols["label_only"]},
                "patch": {
                    "signature": "int label_sig(const char *msg, /pkg/Item *item)",
                },
            })["result"]
            assert sig_patched["name"] == "label_sig"
            assert sig_patched["has_custom_variable_storage"] is True
            assert [p["name"] for p in sig_patched["parameters"]] == ["msg", "item"]
            assert sig_patched["parameters"][0]["storage"] == s1
            assert sig_patched["parameters"][1]["storage"] == s0
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
