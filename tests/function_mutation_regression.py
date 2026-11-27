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

            function(50, "create", {
                "resource": {"entry": symbols["helper_calc"], "name": "helper_calc"},
                "disassemble": True,
            })
            function(51, "create", {
                "resource": {"entry": symbols["locals_target"], "name": "locals_target"},
                "disassemble": True,
            })
            function(52, "parameter.create", {
                "selector": {"entry": symbols["locals_target"]},
                "resource": {
                    "ordinal": 0,
                    "name": "input_arg",
                    "data_type": {"kind": "named", "name": "/int"},
                },
            })

            listed_before = function(53, "list", {
                "filter": {"entry": symbols["locals_target"]},
            })["result"]["items"]
            assert len(listed_before) == 1
            assert listed_before[0]["local_variables"] == []

            got_before = function(54, "get", selector("locals_target"))["result"]
            uncommitted_locals = got_before["local_variables"]
            assert len(uncommitted_locals) >= 2, uncommitted_locals

            decomp_before = tool(55, "ghidra_decompilation", {
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

            patched_stack = function(56, "local_variable.patch", {
                "selector": {
                    "entry": symbols["locals_target"],
                    "name": stack_local["name"],
                    "storage": stack_local["storage"],
                },
                "patch": {"name": "saved_slot"},
            })["result"]
            assert patched_stack["name"] == "saved_slot"
            assert patched_stack["storage"] == stack_local["storage"]

            listed_after_one = function(57, "list", {
                "filter": {"entry": symbols["locals_target"]},
            })["result"]["items"][0]["local_variables"]
            assert [v["name"] for v in listed_after_one] == ["saved_slot"], listed_after_one

            patched_dynamic = function(58, "local_variable.patch", {
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

            retyped_a = function(65, "local_variable.patch", {
                "selector": {"entry": symbols["locals_target"], "name": "saved_slot"},
                "patch": {"data_type": {"kind": "named", "name": "/CatA/Packet"}},
            })["result"]
            assert retyped_a["data_type"] == {"kind": "named", "name": "/CatA/Packet"}, retyped_a

            retyped_b = function(66, "local_variable.patch", {
                "selector": {
                    "entry": symbols["locals_target"],
                    "name": "saved_slot",
                    "storage": retyped_a["storage"],
                },
                "patch": {"data_type": {"kind": "named", "name": "/CatB/Packet"}},
            })["result"]
            assert retyped_b["data_type"] == {"kind": "named", "name": "/CatB/Packet"}, retyped_b

            decomp_after = tool(67, "ghidra_decompilation", {
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

            function(68, "create", {
                "resource": {"entry": symbols["hash_target"], "name": "hash_target"},
                "disassemble": True,
            })
            hash_locals = function(69, "get", selector("hash_target"))["result"]["local_variables"]
            hash_local = next(
                (loc for loc in hash_locals if loc["storage"]["serialization"].startswith("HASH:")),
                None,
            )
            assert hash_local is not None, hash_locals
            patched_hash = function(70, "local_variable.patch", {
                "selector": {
                    "entry": symbols["hash_target"],
                    "name": hash_local["name"],
                    "storage": hash_local["storage"],
                },
                "patch": {"name": "branch_val"},
            })["result"]
            assert patched_hash["name"] == "branch_val"
            assert patched_hash["storage"]["serialization"].startswith("HASH:"), patched_hash

            helper_before = function(71, "get", selector("helper_calc"))["result"]
            assert helper_before["parameter_count"] == 0, helper_before
            assert helper_before["parameters"] == [], helper_before

            helper_decomp_before = tool(72, "ghidra_decompilation", {
                "operation": "get",
                "params": {
                    "selector": {"entry": symbols["helper_calc"]},
                    "format": "document",
                },
            })["result"]
            helper_param_tokens = [
                tok["symbol"]
                for line in helper_decomp_before["lines"]
                for tok in line["tokens"]
                if tok.get("symbol", {}).get("id") == "parameter:0"
            ]
            assert helper_param_tokens, helper_decomp_before["lines"]

            function(73, "parameter.patch", {
                "selector": {"entry": symbols["helper_calc"], "ordinal": 4},
                "patch": {"name": "out_of_range_param"},
            }, success=False)
            assert function(74, "get", selector("helper_calc"))["result"]["parameter_count"] == 0

            patched_inferred = function(75, "parameter.patch", {
                "selector": {"entry": symbols["helper_calc"], "ordinal": 0},
                "patch": {
                    "name": "factor_ptr",
                    "data_type": {
                        "kind": "pointer",
                        "target": {"kind": "named", "name": "/CatA/Packet"},
                    },
                },
            })["result"]
            assert patched_inferred == {
                "ordinal": 0,
                "name": "factor_ptr",
                "data_type": {
                    "kind": "pointer",
                    "target": {"kind": "named", "name": "/CatA/Packet"},
                },
                "storage": {"kind": "serialization", "serialization": "register:00000038:8"},
            }, patched_inferred

            helper_after = function(76, "get", selector("helper_calc"))["result"]
            assert helper_after["parameter_count"] == 1, helper_after
            assert helper_after["parameters"] == [patched_inferred], helper_after

            helper_decomp_after = tool(77, "ghidra_decompilation", {
                "operation": "get",
                "params": {
                    "selector": {"entry": symbols["helper_calc"]},
                    "format": "text",
                },
            })["result"]
            assert "factor_ptr" in helper_decomp_after["c"], helper_decomp_after["c"]
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
