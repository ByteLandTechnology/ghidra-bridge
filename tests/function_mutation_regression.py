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
.global caller_entry
caller_entry: call label_only
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

    repo_root = pathlib.Path(__file__).resolve().parents[1]
    scripts = repo_root / "build" / "ghidra-script"
    report_log = repo_root / "build" / "reports" / "headless-regression" / "headless.log"
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
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        ready = False
        try:
            initialize = {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                           "clientInfo": {"name": "function-test", "version": "1"}},
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

            initial_history = tool(100, "ghidra_program", {
                "operation": "history",
                "params": {},
            })["result"]
            assert initial_history == {
                "can_undo": False,
                "can_redo": False,
                "undo_list": [],
                "redo_list": [],
            }, f"unexpected initial_history: {initial_history}"
            tool(101, "ghidra_program", {"operation": "undo", "params": {}}, success=False)

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

            decomp_initial = tool(37, "ghidra_decompilation", {
                "operation": "get",
                "params": {"selector": {"entry": symbols["func_a"]}},
            })["result"]
            assert "func_a" in decomp_initial["c"]
            decomp_repeat = tool(38, "ghidra_decompilation", {
                "operation": "get",
                "params": {"selector": {"entry": symbols["func_a"]}},
            })["result"]
            assert decomp_repeat["c"] == decomp_initial["c"]

            sym_items = tool(39, "ghidra_symbol", {
                "operation": "list",
                "params": {"filter": {"name": "func_a", "address": symbols["func_a"]}},
            })["result"]["items"]
            assert len(sym_items) == 1
            renamed_sym = tool(40, "ghidra_symbol", {
                "operation": "patch",
                "params": {
                    "selector": {"id": sym_items[0]["id"]},
                    "patch": {"name": "func_a_renamed"},
                },
            })["result"]
            assert renamed_sym["name"] == "func_a_renamed"
            decomp_after_rename = tool(41, "ghidra_decompilation", {
                "operation": "get",
                "params": {"selector": {"entry": symbols["func_a"]}},
            })["result"]
            assert "func_a_renamed" in decomp_after_rename["c"]

            caller = function(42, "create", {
                "resource": {"entry": symbols["caller_entry"], "name": "caller_entry"},
                "disassemble": True,
            })["result"]
            assert caller["name"] == "caller_entry"
            caller_before = tool(43, "ghidra_decompilation", {
                "operation": "get",
                "params": {"selector": {"entry": symbols["caller_entry"]}},
            })["result"]
            assert "label_only(" in caller_before["c"]
            caller_repeat = tool(44, "ghidra_decompilation", {
                "operation": "get",
                "params": {"selector": {"entry": symbols["caller_entry"]}},
            })["result"]
            assert caller_repeat["c"] == caller_before["c"]

            callee_syms = tool(45, "ghidra_symbol", {
                "operation": "list",
                "params": {"filter": {"name": "label_only", "address": symbols["label_only"]}},
            })["result"]["items"]
            assert len(callee_syms) == 1
            tool(46, "ghidra_symbol", {
                "operation": "patch",
                "params": {
                    "selector": {"id": callee_syms[0]["id"]},
                    "patch": {"name": "label_renamed"},
                },
            })
            caller_after = tool(47, "ghidra_decompilation", {
                "operation": "get",
                "params": {"selector": {"entry": symbols["caller_entry"]}},
            })["result"]
            assert "label_renamed(" in caller_after["c"]
            assert "label_only(" not in caller_after["c"]

            history_before_batch = tool(48, "ghidra_program", {
                "operation": "history",
                "params": {},
            })["result"]
            assert history_before_batch["can_undo"] is True
            assert history_before_batch["undo_name"] == "symbol.patch"
            assert history_before_batch["can_redo"] is False

            undone_rename = tool(49, "ghidra_program", {
                "operation": "undo",
                "params": {},
            })["result"]
            assert undone_rename["action"] == "undo"
            assert undone_rename["transaction_name"] == "symbol.patch"
            assert undone_rename["can_redo"] is True
            caller_after_undo = tool(50, "ghidra_decompilation", {
                "operation": "get",
                "params": {"selector": {"entry": symbols["caller_entry"]}},
            })["result"]
            assert "label_only(" in caller_after_undo["c"]
            assert "label_renamed(" not in caller_after_undo["c"]

            redone_rename = tool(51, "ghidra_program", {
                "operation": "redo",
                "params": {},
            })["result"]
            assert redone_rename["action"] == "redo"
            assert redone_rename["transaction_name"] == "symbol.patch"
            assert redone_rename["can_redo"] is False
            caller_after_redo = tool(52, "ghidra_decompilation", {
                "operation": "get",
                "params": {"selector": {"entry": symbols["caller_entry"]}},
            })["result"]
            assert "label_renamed(" in caller_after_redo["c"]

            tool(53, "ghidra_program", {"operation": "redo", "params": {}}, success=False)

            tool(54, "ghidra_batch", {
                "operation": "execute",
                "params": {
                    "transaction_mode": "all_or_none",
                    "items": [
                        {
                            "id": "b1",
                            "method": "comment.create",
                            "arguments": {
                                "resource": {
                                    "address": symbols["func_a"],
                                    "type": "plate",
                                    "text": "batch plate note",
                                }
                            },
                        },
                        {
                            "id": "b2",
                            "method": "function.patch",
                            "arguments": {
                                "selector": {"entry": symbols["func_a"]},
                                "patch": {"name": "func_a_batched"},
                            },
                        },
                    ],
                },
            })
            history_after_batch = tool(55, "ghidra_program", {
                "operation": "history",
                "params": {},
            })["result"]
            assert history_after_batch["can_undo"] is True
            assert history_after_batch["undo_name"] == "batch.execute"

            undone_batch = tool(56, "ghidra_program", {
                "operation": "undo",
                "params": {},
            })["result"]
            assert undone_batch["transaction_name"] == "batch.execute"
            assert function(57, "get", selector("func_a"))["result"]["name"] == "func_a_renamed"
            tool(58, "ghidra_comment", {
                "operation": "get",
                "params": {"selector": {"address": symbols["func_a"], "type": "plate"}},
            }, success=False)

            tool(59, "ghidra_program", {"operation": "save", "params": {}})
            history_after_save = tool(60, "ghidra_program", {
                "operation": "history",
                "params": {},
            })["result"]
            assert history_after_save["can_undo"] is False
            assert history_after_save["can_redo"] is False
            tool(61, "ghidra_program", {"operation": "undo", "params": {}}, success=False)
            print("Function mutation regression checks passed")
        except BaseException as exc:
            primary_error = exc
            raise
        finally:
            try:
                used_sigkill = terminate_headless_process(
                    process,
                    ready,
                    lambda: tool(20, "ghidra_bridge", {"operation": "shutdown"}),
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
    with tempfile.TemporaryDirectory(prefix="ghidra-function-test-") as directory:
        run_test(args.headless.resolve(), pathlib.Path(directory))


if __name__ == "__main__":
    main()
