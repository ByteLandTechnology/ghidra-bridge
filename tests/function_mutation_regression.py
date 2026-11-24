#!/usr/bin/env python3

"""Check function mutations in an isolated headless Ghidra project."""

import argparse
import json
import os
import pathlib
import platform
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


TEXT_VADDR = 0x401000
TEXT_OFFSET = 0x1000
EM_X86_64 = 62
EM_AARCH64 = 183


def detect_native_arch():
    raw = (
        os.environ.get("PROCESSOR_ARCHITEW6432")
        or os.environ.get("PROCESSOR_ARCHITECTURE")
        or platform.machine()
    ).strip().lower()
    if raw in {"x86_64", "amd64", "x64"}:
        return "x86_64"
    if raw in {"aarch64", "arm64"}:
        return "aarch64"
    raise RuntimeError(f"Unsupported host CPU architecture: {raw}")


def build_code_and_offsets(arch):
    if arch == "x86_64":
        # _start (+0): ret
        # func_a (+1): push rbp; jmp shared (+7)
        # func_b (+4): push rbx; jmp shared (+7)
        # shared (+7): nop; ret
        # jump_entry (+9): jmp jump_target (+11)
        # jump_target (+11): mov eax, 1; ret
        # reserved_entry (+17): nop; ret
        # label_only (+19): nop; ret
        code = bytes([
            0xC3,
            0x55, 0xEB, 0x03,
            0x53, 0xEB, 0x00,
            0x90, 0xC3,
            0xEB, 0x00,
            0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3,
            0x90, 0xC3,
            0x90, 0xC3,
        ])
        offsets = {
            "_start": 0,
            "func_a": 1,
            "func_b": 4,
            "shared": 7,
            "jump_entry": 9,
            "jump_target": 11,
            "reserved_entry": 17,
            "label_only": 19,
        }
        return EM_X86_64, code, offsets

    if arch == "aarch64":
        # _start (+0): ret
        # func_a (+4): movz x9, #1; b shared (+20)
        # func_b (+12): movz x10, #2; b shared (+20)
        # shared (+20): nop; ret
        # jump_entry (+28): b jump_target (+32)
        # jump_target (+32): movz w0, #1; ret
        # reserved_entry (+40): nop; ret
        # label_only (+48): nop; ret
        words = [
            0xD65F03C0,
            0xD2800029, 0x14000003,
            0xD280004A, 0x14000001,
            0xD503201F, 0xD65F03C0,
            0x14000001,
            0x52800020, 0xD65F03C0,
            0xD503201F, 0xD65F03C0,
            0xD503201F, 0xD65F03C0,
        ]
        code = b"".join(struct.pack("<I", word) for word in words)
        offsets = {
            "_start": 0,
            "func_a": 4,
            "func_b": 12,
            "shared": 20,
            "jump_entry": 28,
            "jump_target": 32,
            "reserved_entry": 40,
            "label_only": 48,
        }
        return EM_AARCH64, code, offsets

    raise ValueError(f"Unsupported target architecture: {arch}")


def write_elf_fixture(path, arch):
    machine, code, offsets = build_code_and_offsets(arch)
    symbol_order = [
        "_start",
        "func_a",
        "func_b",
        "shared",
        "jump_entry",
        "jump_target",
        "reserved_entry",
        "label_only",
    ]

    strtab = bytearray(b"\x00")
    sym_entries = [struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)]
    symbols = {}
    for name in symbol_order:
        name_offset = len(strtab)
        strtab.extend(name.encode("ascii") + b"\x00")
        vaddr = TEXT_VADDR + offsets[name]
        symbols[name] = hex(vaddr)
        # STB_GLOBAL (1 << 4) | STT_NOTYPE (0) in section 1 (.text)
        sym_entries.append(struct.pack("<IBBHQQ", name_offset, 0x10, 0, 1, vaddr, 0))
    symtab = b"".join(sym_entries)

    shstrtab = bytearray(b"\x00")
    section_name_offsets = {}
    for sec_name in (".text", ".symtab", ".strtab", ".shstrtab"):
        section_name_offsets[sec_name] = len(shstrtab)
        shstrtab.extend(sec_name.encode("ascii") + b"\x00")

    blob = bytearray(TEXT_OFFSET)
    blob.extend(code)
    while len(blob) % 8:
        blob.append(0)
    symtab_offset = len(blob)
    blob.extend(symtab)
    strtab_offset = len(blob)
    blob.extend(strtab)
    shstrtab_offset = len(blob)
    blob.extend(shstrtab)
    while len(blob) % 8:
        blob.append(0)
    shoff = len(blob)

    # Program header: PT_LOAD = 1, PF_R | PF_X = 5
    phdr = struct.pack(
        "<IIQQQQQQ",
        1,
        5,
        TEXT_OFFSET,
        TEXT_VADDR,
        TEXT_VADDR,
        len(code),
        len(code),
        0x1000,
    )

    shdrs = [
        struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        struct.pack(
            "<IIQQQQIIQQ",
            section_name_offsets[".text"],
            1,  # SHT_PROGBITS
            6,  # SHF_ALLOC | SHF_EXECINSTR
            TEXT_VADDR,
            TEXT_OFFSET,
            len(code),
            0,
            0,
            16,
            0,
        ),
        struct.pack(
            "<IIQQQQIIQQ",
            section_name_offsets[".symtab"],
            2,  # SHT_SYMTAB
            0,
            0,
            symtab_offset,
            len(symtab),
            3,  # .strtab section index
            1,  # first global symbol index
            8,
            24,
        ),
        struct.pack(
            "<IIQQQQIIQQ",
            section_name_offsets[".strtab"],
            3,  # SHT_STRTAB
            0,
            0,
            strtab_offset,
            len(strtab),
            0,
            0,
            1,
            0,
        ),
        struct.pack(
            "<IIQQQQIIQQ",
            section_name_offsets[".shstrtab"],
            3,  # SHT_STRTAB
            0,
            0,
            shstrtab_offset,
            len(shstrtab),
            0,
            0,
            1,
            0,
        ),
    ]
    blob.extend(b"".join(shdrs))

    e_ident = struct.pack("<4sBBBB8x", b"\x7fELF", 2, 1, 1, 0)
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # ET_EXEC
        machine,
        1,
        TEXT_VADDR + offsets["_start"],
        64,
        shoff,
        0,
        64,
        56,
        1,
        64,
        len(shdrs),
        4,
    )
    assert len(ehdr) == 64 and len(phdr) == 56
    blob[0:64] = ehdr
    blob[64:120] = phdr
    path.write_bytes(bytes(blob))
    return symbols


def resolve_headless_launcher(headless_arg):
    candidate = pathlib.Path(os.path.abspath(str(headless_arg)))
    if candidate.is_dir():
        launcher = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
        candidate = candidate / "support" / launcher
    elif os.name == "nt" and not candidate.is_file() and candidate.suffix.lower() != ".bat":
        bat_candidate = candidate.with_name(candidate.name + ".bat")
        if bat_candidate.is_file():
            candidate = bat_candidate
    if not candidate.is_file():
        raise FileNotFoundError(f"Ghidra headless launcher not found: {candidate}")
    return candidate


def start_headless_process(command, log_handle):
    if os.name == "nt":
        if str(command[0]).lower().endswith((".bat", ".cmd")):
            # Quote every argument for cmd.exe so '=' in key=value args is never split.
            quoted = " ".join(f'"{arg}"' for arg in command)
            comspec = os.environ.get("COMSPEC", "cmd.exe")
            cmdline = f'"{comspec}" /d /s /c "{quoted}"'
        else:
            cmdline = command
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(
            subprocess, "CREATE_NO_WINDOW", 0
        )
        return subprocess.Popen(
            cmdline,
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            creationflags=flags,
        )

    return subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )


def stop_headless_process(process):
    if process.poll() is not None:
        return
    try:
        process.wait(timeout=20)
        return
    except subprocess.TimeoutExpired:
        pass

    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(process.pid)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        try:
            process.wait(timeout=10)
            return
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            return

    for sig, timeout in ((signal.SIGTERM, 10), (signal.SIGKILL, 5)):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            break
        try:
            process.wait(timeout=timeout)
            return
        except subprocess.TimeoutExpired:
            continue
    process.wait(timeout=5)


def remove_tree_with_retry(root):
    for attempt in range(6):
        try:
            shutil.rmtree(root)
            return
        except FileNotFoundError:
            return
        except PermissionError:
            if attempt == 5:
                raise
            time.sleep(0.25)


def run_test(headless, root, arch):
    project = root / "project"
    project.mkdir()
    binary = root / f"fixture-{arch}.elf"
    symbols = write_elf_fixture(binary, arch)

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

    repo_root = pathlib.Path(os.path.abspath(str(pathlib.Path(__file__).parents[1])))
    scripts = repo_root / "build" / "ghidra-script"
    command = [
        str(headless), str(project), "test", "-import", str(binary), "-noanalysis",
        "-scriptPath", str(scripts), "-postScript", "GhidraMcp.java",
        "host=127.0.0.1", f"port={port}",
    ]
    log_path = root / "headless.log"
    with log_path.open("w", encoding="utf-8") as log:
        process = start_headless_process(command, log)
        ready = False
        try:
            initialize = {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                           "clientInfo": {"name": "function-test", "version": "1"}},
            }
            for _ in range(180):
                if process.poll() is not None:
                    raise RuntimeError(
                        "Ghidra stopped: " + log_path.read_text(encoding="utf-8", errors="replace")[-2000:]
                    )
                try:
                    if call(initialize).get("result"):
                        ready = True
                        break
                except (OSError, TimeoutError, urllib.error.URLError):
                    time.sleep(0.5)
            if not ready:
                raise RuntimeError(
                    "Ghidra did not start: " + log_path.read_text(encoding="utf-8", errors="replace")[-2000:]
                )
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
            print(f"Function mutation regression checks passed ({arch})")
        finally:
            if ready:
                try:
                    tool(20, "ghidra_bridge", {"operation": "shutdown"})
                except (OSError, TimeoutError, urllib.error.URLError):
                    pass
            stop_headless_process(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("headless", type=pathlib.Path, help="path to analyzeHeadless or analyzeHeadless.bat")
    parser.add_argument(
        "--arch",
        choices=("native", "x86_64", "aarch64"),
        default="native",
        help="target ELF ISA fixture to verify (default: native host CPU)",
    )
    args = parser.parse_args()
    headless = resolve_headless_launcher(args.headless)
    arch = detect_native_arch() if args.arch == "native" else args.arch
    directory = pathlib.Path(os.path.abspath(tempfile.mkdtemp(prefix="ghidra-function-test-")))
    try:
        run_test(headless, directory, arch)
    finally:
        remove_tree_with_retry(directory)


if __name__ == "__main__":
    main()
