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

            # Verify multi-type C header parsing and atomic rollback on invalid C headers.
            parsed = tool(30, "ghidra_data_type", {
                "operation": "parse_c",
                "params": {
                    "category_path": "/c_test",
                    "source": (
                        "enum Mode { MODE_A = 1, MODE_B = 2 };\n"
                        "struct Packet { struct Packet *next; const char * restrict tag; uint32_t words[4]; };\n"
                        "typedef struct Packet Packet_t;\n"
                        "union Cell { uint32_t raw; Packet_t *pkt; };\n"
                        "int handle_packet(const Packet_t *pkt, enum Mode mode);\n"
                    ),
                },
            })["result"]
            parsed_paths = {item["path"] for item in parsed["items"]}
            assert parsed_paths == {
                "/c_test/Mode",
                "/c_test/Packet",
                "/c_test/Packet_t",
                "/c_test/Cell",
                "/c_test/handle_packet",
            }, parsed_paths

            tool(31, "ghidra_data_type", {
                "operation": "parse_c",
                "params": {
                    "category_path": "/c_test",
                    "source": "#include <stdio.h>\nstruct ShouldNotExist { int x; };",
                },
            }, success=False)
            tool(32, "ghidra_data_type", {
                "operation": "parse_c",
                "params": {
                    "category_path": "/c_test",
                    "source": "struct PartialOk { int x; }; struct Broken { UnknownType y; };",
                },
            }, success=False)
            tool(33, "ghidra_data_type", {
                "operation": "get",
                "params": {"selector": {"path": "/c_test/PartialOk"}},
            }, success=False)

            # Verify conflicting_fields rejection when mixing signature with return_type/parameters/calling_convention.
            bad_sig = function(34, "patch", {
                "selector": {"entry": symbols["label_only"]},
                "patch": {"signature": "int f(int x)", "return_type": "int"},
            }, success=False)
            assert bad_sig.get("status") == 400 and bad_sig.get("code") == "conflicting_fields", bad_sig

            # Verify one-line C signature patch including const, struct tag, pointer-to-array, and function pointer.
            sig_updated = function(35, "patch", {
                "selector": {"entry": symbols["label_only"]},
                "patch": {
                    "signature": (
                        "int process_items(const struct Packet *pkt, "
                        "int (*matrix)[4], void (*cb)(int))"
                    ),
                },
            })["result"]
            assert sig_updated["name"] == "process_items", sig_updated
            assert len(sig_updated["parameters"]) == 3, sig_updated["parameters"]
            assert sig_updated["parameters"][0]["data_type"] == {
                "kind": "pointer",
                "target": {"kind": "named", "name": "/c_test/Packet"},
            }
            assert sig_updated["parameters"][1]["data_type"] == {
                "kind": "pointer",
                "target": {
                    "kind": "array",
                    "element": {"kind": "named", "name": "/int"},
                    "count": 4,
                },
            }
            assert sig_updated["parameters"][2]["data_type"]["kind"] == "pointer"

            # Verify atomic parameters list replacement and custom VariableStorageReference preservation on swap.
            custom_init = function(36, "patch", {
                "selector": {"entry": symbols["label_only"]},
                "patch": {
                    "return_type": "uint64_t",
                    "return_storage": {"kind": "register", "register": "RAX"},
                    "has_custom_variable_storage": True,
                    "parameters": [
                        {
                            "name": "first",
                            "data_type": "uint64_t",
                            "storage": {"kind": "register", "register": "R12"},
                        },
                        {
                            "name": "second",
                            "data_type": "const char *",
                            "storage": {"kind": "register", "register": "R13"},
                        },
                    ],
                },
            })["result"]
            assert custom_init["has_custom_variable_storage"] is True
            r12_storage = custom_init["parameters"][0]["storage"]
            r13_storage = custom_init["parameters"][1]["storage"]

            swapped = function(37, "patch", {
                "selector": {"entry": symbols["label_only"]},
                "patch": {
                    "parameters": [
                        {"name": "second", "data_type": "const char *", "storage": r13_storage},
                        {"name": "first", "data_type": "uint64_t", "storage": r12_storage},
                    ],
                },
            })["result"]
            assert [p["name"] for p in swapped["parameters"]] == ["second", "first"]
            assert swapped["parameters"][0]["storage"] == r13_storage
            assert swapped["parameters"][1]["storage"] == r12_storage
            assert swapped["parameters"][0]["data_type"] == {
                "kind": "pointer",
                "target": {"kind": "named", "name": "/char"},
            }
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
