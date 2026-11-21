#!/usr/bin/env python3

"""Check string.list and memory.find in an isolated headless Ghidra project."""

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


FIXTURE_S = """
.section .text
.global _start
_start:
  mov $0x1234, %eax
  ret

.section .block_a,"a",@progbits
.global boundary_start
boundary_start:
  .byte 0x48, 0x8b

.section .block_b,"a",@progbits
.global boundary_tail
boundary_tail:
  .byte 0x7f, 0x10, 0x90, 0x48, 0x8b, 0x22, 0x10

.section .rodata
.global defined_banner
defined_banner:
  .asciz "https://update.example.invalid/v1"
  .byte 0xff, 0xfe
.global candidate_secret
candidate_secret:
  .byte 'c', 'a', 'n', 'd', 'i', 'd', 'a', 't', 'e', '_', 'f', 'l', 'a', 'g', 0
  .byte 0xff, 0xfe
.global sized_undef_blob
.type sized_undef_blob, @object
sized_undef_blob:
  .byte 0xfd, 0xfc, 's', 'i', 'z', 'e', 'd', '_', 'b', 'l', 'o', 'b', '_', 'f', 'l', 'a', 'g', 0, 0xfb, 0xfa
.size sized_undef_blob, . - sized_undef_blob

.section .bss
.global uninit_buf
uninit_buf:
  .space 4096
"""

LINKER_LD = """
SECTIONS
{
  . = 0x401000;
  .text : { *(.text) }
  . = 0x402000;
  .block_a : { *(.block_a) }
  .block_b 0x402002 : { *(.block_b) }
  . = 0x403000;
  .rodata : { *(.rodata) }
  . = 0x404000;
  .bss : { *(.bss) }
}
"""


def run_test(headless, root):
    project = root / "project"
    project.mkdir()
    source = root / "fixture.s"
    source.write_text(FIXTURE_S)
    linker = root / "fixture.ld"
    linker.write_text(LINKER_LD)
    binary = root / "fixture"
    subprocess.run(
        [
            "gcc",
            "-nostdlib",
            "-no-pie",
            "-Wl,-T," + str(linker),
            "-o",
            str(binary),
            str(source),
        ],
        check=True,
    )

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

    scripts = pathlib.Path(__file__).resolve().parents[1] / "build" / "ghidra-script"
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
    with log_path.open("w") as log:
        process = subprocess.Popen(
            command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True
        )
        ready = False
        try:
            initialize = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "search-test", "version": "1"},
                },
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

            # Define only the banner string at 0x403000; leave candidate_secret undefined.
            tool(
                2,
                "ghidra_global_variable",
                {
                    "operation": "upsert",
                    "params": {
                        "resource": {
                            "address": "0x403000",
                            "name": "defined_banner",
                            "data_type": {"kind": "named", "name": "string"},
                        }
                    },
                },
            )

            defined_only = tool(
                3,
                "ghidra_listing",
                {"operation": "string.list", "params": {"scan": {"range": {"start": "0x403000", "end": "0x403100"}}}},
            )["result"]
            defined_values = [item["value"] for item in defined_only["items"]]
            assert defined_values == ["https://update.example.invalid/v1"], defined_only
            assert all("bytes" not in item and item["defined"] is True for item in defined_only["items"])

            with_candidates = tool(
                4,
                "ghidra_listing",
                {
                    "operation": "string.list",
                    "params": {
                        "scan": {"range": {"start": "0x403000", "end": "0x403100"}},
                        "filter": {"include_candidates": True, "regex": "EXAMPLE|flag", "case_sensitive": False},
                    },
                },
            )["result"]
            values_and_flags = [(item["value"], item["defined"]) for item in with_candidates["items"]]
            assert values_and_flags == [
                ("https://update.example.invalid/v1", True),
                ("candidate_flag", False),
                ("sized_blob_flag", False),
            ], with_candidates

            # Invalid regex must fail before scan.
            tool(
                5,
                "ghidra_listing",
                {"operation": "string.list", "params": {"filter": {"regex": "[invalid"}}},
                success=False,
            )

            # All-wildcard pattern must fail before scan.
            tool(
                6,
                "ghidra_memory",
                {"operation": "find", "params": {"filter": {"pattern": "?? ??"}}},
                success=False,
            )

            # Cross-block wildcard pattern match + pagination + .bss skip without errors.
            page1 = tool(
                7,
                "ghidra_memory",
                {
                    "operation": "find",
                    "params": {
                        "scan": {"range": {"start": "0x401000", "end": "0x405000"}},
                        "filter": {"pattern": "48 8B ?? 10"},
                        "page": {"limit": 1},
                    },
                },
            )["result"]
            assert len(page1["items"]) == 1, page1
            assert page1["items"][0]["address"].endswith("00402000"), page1
            assert page1["items"][0]["bytes"] == {
                "encoding": "hex",
                "data": "488b7f10",
                "length": 4,
            }, page1
            assert page1.get("next_cursor"), page1

            page2 = tool(
                8,
                "ghidra_memory",
                {
                    "operation": "find",
                    "params": {
                        "scan": {"range": {"start": "0x401000", "end": "0x405000"}},
                        "filter": {"pattern": "48 8B ?? 10"},
                        "page": {"limit": 5, "cursor": page1["next_cursor"]},
                    },
                },
            )["result"]
            assert len(page2["items"]) == 1, page2
            assert page2["items"][0]["address"].endswith("00402005"), page2
            assert page2["items"][0]["bytes"] == {
                "encoding": "hex",
                "data": "488b2210",
                "length": 4,
            }, page2
            assert page2.get("next_cursor") is None, page2

            print("Search regression checks passed")
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
    if shutil.which("gcc") is None:
        parser.error("gcc is required")
    with tempfile.TemporaryDirectory(prefix="ghidra-search-test-") as directory:
        run_test(args.headless.resolve(), pathlib.Path(directory))


if __name__ == "__main__":
    main()
