#!/usr/bin/env python3

"""Verify scoped list queries and relation fields in headless Ghidra."""

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
.section .text
.global _start
_start:
  call caller_multi
  call split_entry
  ret

.global callee_target
callee_target:
  mov global_value(%rip), %eax
  ret

.global caller_multi
caller_multi:
  push %rbp
  call callee_target
  nop
  call callee_target
  pop %rbp
  ret

.global split_entry
split_entry:
  push %rbp
  test %edi, %edi
  jz .Lsplit_cold
  mov $1, %eax
  pop %rbp
  ret

.global gap_interleaved
gap_interleaved:
  mov $42, %eax
  ret

.Lsplit_cold:
  lea greeting_text(%rip), %rdi
  call callee_target
  pop %rbp
  ret

.section .data
.global greeting_text
greeting_text:
  .asciz "hello-bridge"
.global global_value
global_value:
  .long 0x12345678
.global raw_pad
raw_pad:
  .byte 0xaa, 0xbb
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
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read().decode()
        if not body:
            return {}
        if body.startswith(("event:", "data:")):
            body = next(line[5:].strip() for line in body.splitlines() if line.startswith("data:"))
        return json.loads(body)

    next_id = 10

    def tool(name, operation, params=None):
        nonlocal next_id
        next_id += 1
        arguments = {"operation": operation}
        if params is not None:
            arguments["params"] = params
        message = {
            "jsonrpc": "2.0",
            "id": next_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
        result = call(message)["result"]
        if result.get("isError", False):
            raise AssertionError(f"Tool error for {name}.{operation}: {result}")
        return result["structuredContent"]["result"]

    def paginate(name, operation, params):
        items = []
        cursor = None
        while True:
            page_params = dict(params)
            page = dict(page_params.get("page", {}))
            if cursor is not None:
                page["cursor"] = cursor
            if page:
                page_params["page"] = page
            res = tool(name, operation, page_params)
            items.extend(res["items"])
            cursor = res.get("next_cursor")
            if not cursor:
                return items, res

    scripts = pathlib.Path(__file__).resolve().parents[1] / "build" / "ghidra-script"
    command = [
        str(headless), str(project), "test", "-import", str(binary),
        "-scriptPath", str(scripts), "-postScript", "GhidraMcp.java",
        "host=127.0.0.1", f"port={port}",
    ]
    log_path = root / "headless.log"
    with log_path.open("w") as log:
        process = subprocess.Popen(
            command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True
        )
        ready = False
        try:
            initialize = {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                           "clientInfo": {"name": "scopes-test", "version": "1"}},
            }
            for _ in range(160):
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

            # Define global string and 32-bit int so code_unit.list and data_unit.list see DATA.
            tool("ghidra_global_variable", "upsert", {
                "resource": {
                    "address": symbols["greeting_text"],
                    "name": "greeting_text",
                    "data_type": {"kind": "named", "name": "/string"},
                }
            })
            tool("ghidra_global_variable", "upsert", {
                "resource": {
                    "address": symbols["global_value"],
                    "name": "global_value",
                    "data_type": {"kind": "named", "name": "/int"},
                }
            })

            # Create split_entry and gap_interleaved as separate functions.
            try:
                tool("ghidra_function", "get", {"selector": {"entry": symbols["gap_interleaved"]}})
            except AssertionError:
                tool("ghidra_function", "create", {
                    "resource": {"entry": symbols["gap_interleaved"], "name": "gap_interleaved"},
                    "disassemble": True,
                })
            try:
                split_fn = tool("ghidra_function", "get", {"selector": {"entry": symbols["split_entry"]}})
            except AssertionError:
                split_fn = tool("ghidra_function", "create", {
                    "resource": {"entry": symbols["split_entry"], "name": "split_entry"},
                    "disassemble": True,
                })

            gap_instrs, _ = paginate("ghidra_listing", "instruction.list", {
                "filter": {"selector": {"kind": "function", "entry": symbols["gap_interleaved"]}},
                "page": {"limit": 1},
            })
            gap_addrs = {item["address"] for item in gap_instrs}
            assert len(gap_addrs) >= 2

            # 1. Scoped instruction.list omits interleaved gap instructions across discontiguous body.
            scoped_instrs, last_scan = paginate("ghidra_listing", "instruction.list", {
                "filter": {"selector": {"kind": "function", "entry": symbols["split_entry"]}},
                "page": {"limit": 1},
            })
            scoped_addrs = [item["address"] for item in scoped_instrs]
            assert len(scoped_addrs) >= 5, scoped_addrs
            assert gap_addrs.isdisjoint(scoped_addrs), (gap_addrs, scoped_addrs)
            assert last_scan["scan"]["complete"] is True

            # Compare against naive start..end instruction.list, which DOES include gap_addrs.
            span_instrs, _ = paginate("ghidra_listing", "instruction.list", {
                "scan": {"range": {
                    "start": split_fn["body"]["start"],
                    "end": split_fn["body"]["end"],
                }},
            })
            span_addrs = {item["address"] for item in span_instrs}
            assert gap_addrs.issubset(span_addrs)

            # 2. code_unit.list matches data_unit.list byte-for-byte on defined data items.
            data_range = {
                "start": symbols["greeting_text"],
                "end": hex(int(symbols["raw_pad"], 16) + 1),
            }
            code_units, _ = paginate("ghidra_listing", "code_unit.list", {
                "scan": {"range": data_range},
            })
            data_units, _ = paginate("ghidra_listing", "data_unit.list", {
                "scan": {"range": data_range},
            })
            defined_from_code = [
                {
                    "address": u["address"],
                    "length": u["length"],
                    "data_type": u["data_type"],
                    "value": u["value"],
                    "representation": u["representation"],
                    "bytes": u["bytes"],
                }
                for u in code_units
                if u["kind"] == "data"
            ]
            assert len(defined_from_code) == 2
            assert defined_from_code == data_units
            undefined_units = [u for u in code_units if u["kind"] == "undefined"]
            assert len(undefined_units) >= 2
            for u in undefined_units:
                assert "value" not in u and "representation" not in u

            # 3. reference.list supports selector, scan.range, single-anchor, and function summaries.
            split_out_refs, ref_meta = paginate("ghidra_reference", "list", {
                "filter": {
                    "direction": "from",
                    "selector": {"kind": "function", "entry": symbols["split_entry"]},
                },
                "page": {"limit": 1},
                "scan": {"timeout_ms": 5000},
            })
            assert ref_meta["scan"]["complete"] is True
            assert len(split_out_refs) >= 2
            for ref in split_out_refs:
                assert ref["from"] not in gap_addrs
                assert ref["from_function"]["name"] == split_fn["name"]

            callee_in_refs, _ = paginate("ghidra_reference", "list", {
                "filter": {"direction": "to", "to": symbols["callee_target"]},
                "page": {"limit": 1},
            })
            call_in_refs = [r for r in callee_in_refs if r["type"] == "UNCONDITIONAL_CALL"]
            assert len(call_in_refs) == 3, callee_in_refs
            for ref in call_in_refs:
                assert "from_function" in ref
                assert ref["to_function"]["name"] == "callee_target"

            range_in_refs, _ = paginate("ghidra_reference", "list", {
                "filter": {"direction": "to"},
                "scan": {"range": {
                    "start": symbols["callee_target"],
                    "end": split_fn["body"]["end"],
                }, "timeout_ms": 5000},
                "page": {"limit": 2},
            })
            assert len(range_in_refs) >= 4

            # 4. function_call.list populates call_site in deterministic order across pages.
            callees, _ = paginate("ghidra_function", "call.list", {
                "filter": {"entry": symbols["caller_multi"], "direction": "callees"},
                "page": {"limit": 1},
            })
            assert len(callees) == 2, callees
            assert callees[0]["name"] == "callee_target"
            assert callees[1]["name"] == "callee_target"
            assert callees[0]["call_site"] < callees[1]["call_site"]

            callers, _ = paginate("ghidra_function", "call.list", {
                "filter": {"entry": symbols["callee_target"], "direction": "callers"},
                "page": {"limit": 1},
            })
            multi_sites = [c["call_site"] for c in callers if c["name"] == "caller_multi"]
            assert len(multi_sites) == 2, callers
            assert multi_sites == [callees[0]["call_site"], callees[1]["call_site"]]

            print("List scopes and relations regression checks passed")
        finally:
            if ready:
                try:
                    tool("ghidra_bridge", "shutdown")
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
    with tempfile.TemporaryDirectory(prefix="ghidra-scopes-test-") as directory:
        run_test(args.headless.resolve(), pathlib.Path(directory))


if __name__ == "__main__":
    main()
