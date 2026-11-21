#!/usr/bin/env python3

"""Check import, export, entry-point, and external function operations in headless Ghidra."""

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


CPP_FIXTURE = """
#include <cstdio>
#include <cstring>

namespace demo {
__attribute__((visibility("default")))
int compute_length(const char* text) {
    if (text == nullptr) {
        return 0;
    }
    std::puts(text);
    return static_cast<int>(std::strlen(text));
}
}

extern "C" __attribute__((visibility("default")))
int c_api_entry(const char* input) {
    return demo::compute_length(input);
}

__attribute__((visibility("hidden")))
int internal_helper(int x) {
    return x + 1;
}
"""


def run_test(headless, root):
    project = root / "project"
    project.mkdir()
    source = root / "fixture.cpp"
    source.write_text(CPP_FIXTURE)
    binary = root / "libfixture.so"
    subprocess.run(
        ["g++", "-shared", "-fPIC", "-O1", "-o", str(binary), str(source)],
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
        return result.get("structuredContent", result)

    scripts = pathlib.Path(__file__).resolve().parents[1] / "build" / "ghidra-script"
    command = [
        str(headless), str(project), "test", "-import", str(binary), "-noanalysis",
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
                           "clientInfo": {"name": "program-entry-test", "version": "1"}},
            }
            for _ in range(180):
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

            for idx, op in enumerate(["import.list", "export.list", "entry_point.list"], start=2):
                help_info = tool(idx, "ghidra_help", {"domain": "ghidra_program", "operation": op})
                effects = help_info.get("effects") or help_info["result"]["effects"]
                assert effects["read_only"] is True

            imports_all = []
            cursor = None
            call_id = 10
            while True:
                page_arg = {"limit": 1}
                if cursor is not None:
                    page_arg["cursor"] = cursor
                res = tool(call_id, "ghidra_program", {
                    "operation": "import.list",
                    "params": {"page": page_arg},
                })
                page = res.get("result", res)
                call_id += 1
                imports_all.extend(page["items"])
                cursor = page.get("next_cursor")
                if not cursor:
                    break

            import_names = {item["name"]: item for item in imports_all}
            assert "puts" in import_names, import_names
            assert "strlen" in import_names, import_names
            puts_item = import_names["puts"]
            assert puts_item["address"].startswith("EXTERNAL:"), puts_item
            assert puts_item["is_function"] is True
            assert len(puts_item["thunk_addresses"]) >= 1, puts_item
            assert puts_item["signature"]

            regex_imports = tool(30, "ghidra_program", {
                "operation": "import.list",
                "params": {"filter": {"name": "^(puts|strlen)$", "regex": True}},
            })["result"]["items"]
            assert {item["name"] for item in regex_imports} == {"puts", "strlen"}

            bad_regex = tool(31, "ghidra_program", {
                "operation": "import.list",
                "params": {"filter": {"name": "[invalid", "regex": True}},
            }, success=False)
            err_obj = bad_regex.get("error", bad_regex)
            assert err_obj["status"] == 400
            assert err_obj["code"] == "invalid_regex"

            exports = tool(40, "ghidra_program", {
                "operation": "export.list",
                "params": {},
            })["result"]["items"]
            export_names = {item["name"]: item for item in exports}
            assert "c_api_entry" in export_names, export_names
            assert "internal_helper" not in export_names, export_names
            mangled = [item for item in exports if "compute_length" in item["name"]]
            assert len(mangled) == 1, exports
            assert "compute_length" in (mangled[0].get("demangled_name") or ""), mangled[0]
            assert mangled[0]["is_function"] is True

            entry_points = tool(41, "ghidra_program", {
                "operation": "entry_point.list",
                "params": {},
            })["result"]["items"]
            assert any(item["name"] == "c_api_entry" for item in entry_points), entry_points

            ext_functions = tool(50, "ghidra_function", {
                "operation": "list",
                "params": {"filter": {"external": True}},
            })["result"]["items"]
            ext_fn_names = {item["name"]: item for item in ext_functions}
            assert "puts" in ext_fn_names, ext_fn_names
            assert ext_fn_names["puts"]["entry"].startswith("EXTERNAL:")

            resolved_ext = tool(51, "ghidra_function", {
                "operation": "get",
                "params": {"selector": {"entry": puts_item["address"]}},
            })["result"]
            assert resolved_ext["name"] == "puts"
            assert resolved_ext["external"] is True
            assert resolved_ext["entry"] == puts_item["address"]

            mem_page = tool(52, "ghidra_function", {
                "operation": "list",
                "params": {"page": {"limit": 1}},
            })["result"]
            assert len(mem_page["items"]) == 1
            assert not mem_page["items"][0]["entry"].startswith("EXTERNAL:")
            print("Program entry regression checks passed")
        finally:
            if ready:
                try:
                    tool(99, "ghidra_bridge", {"operation": "shutdown"})
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
    if shutil.which("g++") is None:
        parser.error("g++ is required")
    with tempfile.TemporaryDirectory(prefix="ghidra-program-entry-test-") as directory:
        run_test(args.headless.resolve(), pathlib.Path(directory))


if __name__ == "__main__":
    main()
