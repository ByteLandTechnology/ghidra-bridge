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


FIXTURE_C = """
__attribute__((noinline)) int helper_val(int v) {
    return (v * 5) ^ 0x1234;
}

int compute_temp(int x) {
    int temp = helper_val(x);
    if (temp > 10) {
        return temp * temp + (temp ^ 0x55aa);
    }
    return temp - x;
}

int forward_param(int y) {
    int box = helper_val(y);
    return box + y;
}
"""


def run_test(headless, root):
    project = root / "project"
    project.mkdir()
    source = root / "fixture.s"
    source.write_text(FIXTURE)
    c_source = root / "fixture_temp.c"
    c_source.write_text(FIXTURE_C)
    binary = root / "fixture"
    subprocess.run(
        [
            "gcc", "-O1", "-fno-inline", "-fno-stack-protector",
            "-nostdlib", "-no-pie", "-Wl,-e,_start",
            "-o", str(binary), str(source), str(c_source),
        ],
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

            listed = function(31, "list", {
                "filter": {"name": "compute_temp"},
            })["result"]["items"]
            assert len(listed) == 1
            assert listed[0]["parameters"] == []
            assert listed[0]["local_variables"] == []

            doc = tool(32, "ghidra_decompilation", {
                "operation": "get",
                "params": {
                    "selector": {"entry": symbols["compute_temp"]},
                    "format": "document",
                },
            })["result"]
            doc_tokens = [tok for line in doc["lines"] for tok in line["tokens"]]
            param_tokens = [
                tok for tok in doc_tokens
                if tok.get("symbol", {}).get("type") == "Parameter"
            ]
            local_tokens = [
                tok for tok in doc_tokens
                if tok.get("symbol", {}).get("type") == "Local Var"
            ]
            assert param_tokens, f"Expected parameter symbol tokens in {doc_tokens}"
            assert local_tokens, f"Expected local variable symbol tokens in {doc_tokens}"

            fetched = function(33, "get", selector("compute_temp"))["result"]
            assert len(fetched["parameters"]) >= 1, fetched
            assert len(fetched["local_variables"]) >= 1, fetched
            inferred_param = fetched["parameters"][0]
            temp_local = next(
                (v for v in fetched["local_variables"] if v["name"].startswith(("uVar", "iVar"))),
                fetched["local_variables"][0],
            )

            patched_local = function(34, "local_variable.patch", {
                "selector": {"entry": symbols["compute_temp"], "name": temp_local["name"]},
                "patch": {
                    "name": "masked_temp",
                    "data_type": {"kind": "named", "name": "uint"},
                },
            })["result"]
            assert patched_local["name"] == "masked_temp"
            assert patched_local["data_type"] == {"kind": "named", "name": "/uint"}

            patched_param = function(35, "parameter.patch", {
                "selector": {
                    "entry": symbols["compute_temp"],
                    "ordinal": inferred_param["ordinal"],
                },
                "patch": {
                    "name": "seed_arg",
                    "data_type": {"kind": "named", "name": "uint"},
                },
            })["result"]
            assert patched_param["name"] == "seed_arg"
            assert patched_param["data_type"] == {"kind": "named", "name": "/uint"}

            function(36, "local_variable.patch", {
                "selector": {"entry": symbols["compute_temp"], "name": "masked_temp"},
                "patch": {"name": "seed_arg"},
            }, success=False)

            forward_info = function(38, "get", selector("forward_param"))["result"]
            assert len(forward_info["parameters"]) >= 1, forward_info
            forward_param_name = forward_info["parameters"][0]["name"]
            patched_via_local = function(39, "local_variable.patch", {
                "selector": {"entry": symbols["forward_param"], "name": forward_param_name},
                "patch": {
                    "name": "forwarded_value",
                    "data_type": {"kind": "named", "name": "int"},
                },
            })["result"]
            assert patched_via_local["name"] == "forwarded_value"

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
