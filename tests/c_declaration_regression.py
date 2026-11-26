#!/usr/bin/env python3

"""Check C declarations, C type strings, and C function prototypes in headless Ghidra."""

import argparse
import json
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


STARTUP_POLL_ATTEMPTS = 120
STARTUP_POLL_INTERVAL_SECONDS = 0.5
SHUTDOWN_WAIT_SECONDS = 20
SIGTERM_WAIT_SECONDS = 10
SIGKILL_WAIT_SECONDS = 5
LOG_TAIL_LINES = 100


def archive_and_print_headless_log(log_path, report_log, tail_lines=LOG_TAIL_LINES):
    report_log.parent.mkdir(parents=True, exist_ok=True)
    if log_path.is_file():
        shutil.copyfile(log_path, report_log)
        text = log_path.read_text(encoding="utf-8", errors="replace")
    else:
        report_log.write_text("", encoding="utf-8")
        text = ""
    tail = "\n".join(text.splitlines()[-tail_lines:])
    print(
        f"=== headless.log (last {tail_lines} lines; saved full log to {report_log}) ===",
        file=sys.stderr,
    )
    print(tail if tail else "<headless.log is empty>", file=sys.stderr, flush=True)


def terminate_headless_process(process, ready, shutdown_fn):
    used_sigkill = False
    try:
        if ready:
            try:
                shutdown_fn()
            except Exception:
                pass
            try:
                process.wait(timeout=SHUTDOWN_WAIT_SECONDS)
                return False
            except subprocess.TimeoutExpired:
                pass
        elif process.poll() is not None:
            return False

        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

        try:
            process.wait(timeout=SIGTERM_WAIT_SECONDS)
        except subprocess.TimeoutExpired:
            used_sigkill = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=SIGKILL_WAIT_SECONDS)
        return used_sigkill
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


FIXTURE = """
.section .text
.global _start
_start:
 ret
.global recv_packet
recv_packet:
 push %rbp
 mov %rsp, %rbp
 xor %eax, %eax
 pop %rbp
 ret
.global log_packet
log_packet:
 xor %eax, %eax
 ret
.global custom_packet
custom_packet:
 xor %eax, %eax
 ret

.section .data
.global packet_ring
packet_ring:
 .zero 32
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

    def tool(call_id, name, arguments, success=True):
        message = {
            "jsonrpc": "2.0",
            "id": call_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
        result = call(message)["result"]
        if bool(result.get("isError", False)) == success:
            raise AssertionError(f"Unexpected result for {name} ({arguments}): {result}")
        return result.get("structuredContent", {})

    repo_root = pathlib.Path(__file__).resolve().parents[1]
    scripts = repo_root / "build" / "ghidra-script"
    report_log = (
        repo_root / "build" / "reports" / "headless-regression" / "c-declaration-headless.log"
    )
    report_log.unlink(missing_ok=True)
    command = [
        str(headless), str(project), "test", "-import", str(binary), "-noanalysis",
        "-scriptPath", str(scripts), "-postScript", "GhidraMcp.java",
        "host=127.0.0.1", f"port={port}",
    ]
    log_path = root / "headless.log"
    primary_error = None
    used_sigkill = False
    with log_path.open("w", encoding="utf-8") as log:
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
                    "clientInfo": {"name": "c-declaration-test", "version": "1"},
                },
            }
            for _ in range(STARTUP_POLL_ATTEMPTS):
                if process.poll() is not None:
                    raise RuntimeError(f"Ghidra stopped with exit code {process.returncode}")
                try:
                    if call(initialize).get("result"):
                        ready = True
                        break
                except (OSError, TimeoutError, urllib.error.URLError):
                    time.sleep(STARTUP_POLL_INTERVAL_SECONDS)
            if not ready:
                raise RuntimeError("Ghidra did not start")
            call({"jsonrpc": "2.0", "method": "notifications/initialized"})

            # 1. Verify tools/list compact schemas and ghidra_help expose parse_c & signature
            listed_tools = call(
                {"jsonrpc": "2.0", "id": 100, "method": "tools/list", "params": {}}
            )["result"]["tools"]
            dt_tool = next(item for item in listed_tools if item["name"] == "ghidra_data_type")
            assert "parse_c" in dt_tool["inputSchema"]["properties"]["operation"]["enum"]
            help_dt = tool(2, "ghidra_help", {"domain": "data_type", "operation": "parse_c"})
            assert help_dt["method"] == "data_type.parse_c"
            help_fn = tool(3, "ghidra_help", {"domain": "function", "operation": "patch"})
            assert "signature" in help_fn["inputSchema"]["properties"]["patch"]["properties"]
            assert "parameters" in help_fn["inputSchema"]["properties"]["patch"]["properties"]

            # 2. Parse multi-type C header declarations in one transaction
            declarations = """
            enum SocketState { SOCK_CLOSED = 0, SOCK_OPEN = 1 };
            union AddrValue { uint32_t ipv4; uint8_t octets[4]; };
            struct Socket {
                int fd;
                uint8_t flags : 4;
                uint8_t version : 4;
                enum SocketState state;
                union AddrValue addr;
            };
            typedef struct Socket Socket;
            typedef int (*packet_hook_t)(Socket *sock, const uint8_t *buf, size_t len);
            """
            parsed = tool(
                4,
                "ghidra_data_type",
                {
                    "operation": "parse_c",
                    "params": {
                        "declarations": declarations,
                        "category_path": "/net",
                        "conflict_mode": "replace",
                    },
                },
            )["result"]["items"]
            names = {item["name"] for item in parsed}
            assert {"SocketState", "AddrValue", "Socket", "packet_hook_t"}.issubset(names)

            # Read back data_type.get and verify canonical structured references
            socket_dt = tool(
                5,
                "ghidra_data_type",
                {"operation": "get", "params": {"selector": {"path": "/net/Socket"}}},
            )["result"]
            assert socket_dt["kind"] == "struct"
            assert all(isinstance(field["data_type"], dict) for field in socket_dt["fields"])

            # 3. Conflict modes: keep and rename
            kept = tool(
                6,
                "ghidra_data_type",
                {
                    "operation": "parse_c",
                    "params": {
                        "declarations": "struct Socket { uint64_t replaced; };",
                        "category_path": "/net",
                        "conflict_mode": "keep",
                    },
                },
            )["result"]["items"]
            assert kept[0]["length"] == socket_dt["length"]

            renamed = tool(
                7,
                "ghidra_data_type",
                {
                    "operation": "parse_c",
                    "params": {
                        "declarations": "struct Socket { uint64_t replaced; };",
                        "category_path": "/net",
                        "conflict_mode": "rename",
                    },
                },
            )["result"]["items"]
            assert renamed[0]["name"].startswith("Socket.conflict")

            # 4. Invalid C declarations abort cleanly with 400 and leave program intact
            bad_decl = tool(
                8,
                "ghidra_data_type",
                {
                    "operation": "parse_c",
                    "params": {
                        "declarations": "struct PartialOk { int x; }; struct Bad { UnknownT y; };",
                        "category_path": "/net",
                    },
                },
                success=False,
            )
            assert bad_decl["status"] == 400
            assert bad_decl["target"] == "/declarations"
            assert "<html>" not in bad_decl["message"]
            tool(
                9,
                "ghidra_data_type",
                {"operation": "get", "params": {"selector": {"path": "/net/PartialOk"}}},
                success=False,
            )

            # 5. Create functions and apply full C prototypes via function.patch signature
            tool(
                10,
                "ghidra_function",
                {
                    "operation": "create",
                    "params": {
                        "resource": {"entry": symbols["recv_packet"], "name": "orig_recv"},
                        "disassemble": True,
                    },
                },
            )
            patched_fn = tool(
                11,
                "ghidra_function",
                {
                    "operation": "patch",
                    "params": {
                        "selector": {"entry": symbols["recv_packet"]},
                        "patch": {
                            "signature": (
                                "int recv_packet(Socket *sock, const uint8_t *buf, size_t len)"
                            ),
                            "comment": "Receive one packet.",
                        },
                    },
                },
            )["result"]
            assert patched_fn["name"] == "recv_packet"
            assert patched_fn["comment"] == "Receive one packet."
            assert patched_fn["return_type"]["kind"] == "named"
            assert patched_fn["parameter_count"] == 3
            params = patched_fn["parameters"]
            assert [p["name"] for p in params] == ["sock", "buf", "len"]
            assert params[0]["data_type"]["kind"] == "pointer"
            assert params[0]["data_type"]["target"]["name"] == "/net/Socket"
            assert params[1]["data_type"]["kind"] == "pointer"

            # Verify function.get also returns canonical structured data_type_reference objects
            fetched_fn = tool(
                12,
                "ghidra_function",
                {"operation": "get", "params": {"selector": {"entry": symbols["recv_packet"]}}},
            )["result"]
            assert isinstance(fetched_fn["return_type"], dict)
            assert all(isinstance(p["data_type"], dict) for p in fetched_fn["parameters"])

            # Varargs prototype via function.patch
            tool(
                13,
                "ghidra_function",
                {
                    "operation": "create",
                    "params": {
                        "resource": {"entry": symbols["log_packet"], "name": "log_packet"},
                        "disassemble": True,
                    },
                },
            )
            varargs_fn = tool(
                14,
                "ghidra_function",
                {
                    "operation": "patch",
                    "params": {
                        "selector": {"entry": symbols["log_packet"]},
                        "patch": {"signature": "int log_packet(const char *fmt, ...)"},
                    },
                },
            )["result"]
            assert varargs_fn["has_var_args"] is True
            assert varargs_fn["parameter_count"] == 1
            assert varargs_fn["parameters"][0]["name"] == "fmt"

            # 6. Conflicting signature + return_type or calling_convention returns 400
            conflict_err = tool(
                15,
                "ghidra_function",
                {
                    "operation": "patch",
                    "params": {
                        "selector": {"entry": symbols["recv_packet"]},
                        "patch": {
                            "signature": "int recv_packet(void)",
                            "return_type": "int",
                        },
                    },
                },
                success=False,
            )
            assert conflict_err["status"] == 400
            assert conflict_err["code"] == "conflicting_fields"
            assert conflict_err["target"] == "/patch/signature"

            # Invalid signature aborts transaction cleanly and preserves recv_packet
            bad_sig_err = tool(
                16,
                "ghidra_function",
                {
                    "operation": "patch",
                    "params": {
                        "selector": {"entry": symbols["recv_packet"]},
                        "patch": {"signature": "MissingReturn recv_packet(UnknownParam x)"},
                    },
                },
                success=False,
            )
            assert bad_sig_err["status"] == 400
            assert bad_sig_err["target"] == "/patch/signature"

            still_valid_fn = tool(
                17,
                "ghidra_function",
                {"operation": "get", "params": {"selector": {"entry": symbols["recv_packet"]}}},
            )["result"]
            assert still_valid_fn["parameter_count"] == 3

            # 7. C type strings in parameter.patch, global_variable.upsert, and data_type.patch
            patched_param = tool(
                18,
                "ghidra_function",
                {
                    "operation": "parameter.patch",
                    "params": {
                        "selector": {"entry": symbols["recv_packet"], "ordinal": 1},
                        "patch": {"name": "handler", "data_type": "int (*)(void *)"},
                    },
                },
            )["result"]
            assert patched_param["name"] == "handler"
            assert patched_param["data_type"]["kind"] == "pointer"

            created_global = tool(
                19,
                "ghidra_global_variable",
                {
                    "operation": "upsert",
                    "params": {
                        "resource": {
                            "address": symbols["packet_ring"],
                            "name": "packet_ring_words",
                            "data_type": "const uint32_t[4]",
                        }
                    },
                },
            )["result"]
            assert created_global["data_type"]["kind"] == "array"
            assert created_global["data_type"]["count"] == 4

            fetched_global = tool(
                20,
                "ghidra_global_variable",
                {"operation": "get", "params": {"selector": {"address": symbols["packet_ring"]}}},
            )["result"]
            assert isinstance(fetched_global["data_type"], dict)

            patched_dt = tool(
                21,
                "ghidra_data_type",
                {
                    "operation": "patch",
                    "params": {
                        "selector": {"path": "/net/Socket"},
                        "patch": {
                            "kind": "struct",
                            "add_fields": [
                                {"name": "rx_buf", "data_type": "volatile uint8_t *"},
                            ],
                        },
                    },
                },
            )["result"]
            rx_fields = [f for f in patched_dt["fields"] if f["name"] == "rx_buf"]
            assert len(rx_fields) == 1
            assert rx_fields[0]["data_type"]["kind"] == "pointer"

            # 8. Atomic function.patch parameters and custom VariableStorageReference preservation
            tool(
                22,
                "ghidra_function",
                {
                    "operation": "create",
                    "params": {
                        "resource": {"entry": symbols["custom_packet"], "name": "custom_packet"},
                        "disassemble": True,
                    },
                },
            )
            sig_params_conflict = tool(
                23,
                "ghidra_function",
                {
                    "operation": "patch",
                    "params": {
                        "selector": {"entry": symbols["custom_packet"]},
                        "patch": {
                            "signature": "int custom_packet(void)",
                            "parameters": [],
                        },
                    },
                },
                success=False,
            )
            assert sig_params_conflict["status"] == 400
            assert sig_params_conflict["code"] == "conflicting_fields"
            assert sig_params_conflict["target"] == "/patch/signature"

            custom_patched = tool(
                24,
                "ghidra_function",
                {
                    "operation": "patch",
                    "params": {
                        "selector": {"entry": symbols["custom_packet"]},
                        "patch": {
                            "return_type": "uint64_t",
                            "return_storage": {"kind": "register", "register": "RAX"},
                            "parameters": [
                                {
                                    "name": "first",
                                    "data_type": "uint64_t",
                                    "storage": {"kind": "register", "register": "R12"},
                                },
                                {
                                    "name": "second",
                                    "data_type": "const uint8_t (*)[16]",
                                    "storage": {"kind": "register", "register": "R13"},
                                },
                            ],
                        },
                    },
                },
            )["result"]
            assert custom_patched["has_custom_variable_storage"] is True
            r12_ser = custom_patched["parameters"][0]["storage"]["serialization"]
            r13_ser = custom_patched["parameters"][1]["storage"]["serialization"]
            assert r12_ser != r13_ser
            assert custom_patched["parameters"][1]["data_type"]["kind"] == "pointer"
            assert custom_patched["parameters"][1]["data_type"]["target"]["kind"] == "array"
            assert custom_patched["parameters"][1]["data_type"]["target"]["count"] == 16

            # Swap [first, second] -> [second, first] without explicit storage and verify R13/R12 stay paired
            reordered_custom = tool(
                25,
                "ghidra_function",
                {
                    "operation": "patch",
                    "params": {
                        "selector": {"entry": symbols["custom_packet"]},
                        "patch": {
                            "parameters": [
                                {"name": "second", "data_type": "const uint8_t (*)[16]"},
                                {"name": "first", "data_type": "uint64_t"},
                            ],
                        },
                    },
                },
            )["result"]
            assert reordered_custom["has_custom_variable_storage"] is True
            assert [p["name"] for p in reordered_custom["parameters"]] == ["second", "first"]
            assert reordered_custom["parameters"][0]["storage"]["serialization"] == r13_ser
            assert reordered_custom["parameters"][1]["storage"]["serialization"] == r12_ser

            # Apply full C signature and verify custom storage stays attached to first/second
            sig_custom = tool(
                26,
                "ghidra_function",
                {
                    "operation": "patch",
                    "params": {
                        "selector": {"entry": symbols["custom_packet"]},
                        "patch": {
                            "signature": (
                                "uint64_t custom_packet("
                                "uint64_t first, const uint8_t (*second)[16], size_t extra)"
                            )
                        },
                    },
                },
            )["result"]
            assert sig_custom["has_custom_variable_storage"] is True
            assert [p["name"] for p in sig_custom["parameters"]] == ["first", "second", "extra"]
            assert sig_custom["parameters"][0]["storage"]["serialization"] == r12_ser
            assert sig_custom["parameters"][1]["storage"]["serialization"] == r13_ser

            # Clear parameters and disable custom storage
            cleared_custom = tool(
                27,
                "ghidra_function",
                {
                    "operation": "patch",
                    "params": {
                        "selector": {"entry": symbols["custom_packet"]},
                        "patch": {
                            "return_type": "void",
                            "parameters": [],
                            "has_custom_variable_storage": False,
                        },
                    },
                },
            )["result"]
            assert cleared_custom["has_custom_variable_storage"] is False
            assert cleared_custom["parameter_count"] == 0

            # 9. Reject oversized declarations, signatures, and C type strings with 400
            oversized_decl = tool(
                28,
                "ghidra_data_type",
                {
                    "operation": "parse_c",
                    "params": {"declarations": "a" * 65537},
                },
                success=False,
            )
            assert oversized_decl["status"] == 400
            assert oversized_decl["code"] == "invalid_value"
            assert oversized_decl["target"] == "/declarations"

            oversized_sig = tool(
                29,
                "ghidra_function",
                {
                    "operation": "patch",
                    "params": {
                        "selector": {"entry": symbols["custom_packet"]},
                        "patch": {"signature": "int custom_packet(" + (" " * 8192) + ")"},
                    },
                },
                success=False,
            )
            assert oversized_sig["status"] == 400
            assert oversized_sig["code"] == "invalid_value"
            assert oversized_sig["target"] == "/patch/signature"

            oversized_type = tool(
                30,
                "ghidra_function",
                {
                    "operation": "parameter.patch",
                    "params": {
                        "selector": {"entry": symbols["recv_packet"], "ordinal": 0},
                        "patch": {"data_type": "/* " + ("\u00e9" * 2050) + " */ int"},
                    },
                },
                success=False,
            )
            assert oversized_type["status"] == 400
            assert oversized_type["code"] == "invalid_value"
            assert oversized_type["target"] == "/patch/data_type"

            print("C declaration and prototype regression checks passed")
        except BaseException as exc:
            primary_error = exc
            raise
        finally:
            try:
                used_sigkill = terminate_headless_process(
                    process,
                    ready,
                    lambda: tool(99, "ghidra_bridge", {"operation": "shutdown"}),
                )
            except BaseException:
                if primary_error is None:
                    log.flush()
                    archive_and_print_headless_log(log_path, report_log)
                    raise
            log.flush()
            if primary_error is not None:
                archive_and_print_headless_log(log_path, report_log)
            elif used_sigkill:
                archive_and_print_headless_log(log_path, report_log)
                raise RuntimeError(
                    "Ghidra ignored SIGTERM during shutdown and required SIGKILL"
                )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("headless", type=pathlib.Path, help="path to analyzeHeadless")
    args = parser.parse_args()
    if shutil.which("gcc") is None or shutil.which("nm") is None:
        parser.error("gcc and nm are required")
    with tempfile.TemporaryDirectory(prefix="ghidra-c-decl-test-") as directory:
        run_test(args.headless.resolve(), pathlib.Path(directory))


if __name__ == "__main__":
    main()
