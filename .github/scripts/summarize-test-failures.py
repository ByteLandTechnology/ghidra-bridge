#!/usr/bin/env python3

"""Summarize failed JUnit XML reports and headless Ghidra logs for GitHub Actions."""

from __future__ import annotations

import argparse
import dataclasses
import os
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

MAX_SUMMARY_FILE_BYTES = 950 * 1024
MAX_DETAIL_CHARS = 8_000
MAX_STREAM_CHARS = 12_000
MAX_HEADLESS_LINES = 80
MAX_HEADLESS_CHARS = 12_000
MAX_CELL_CHARS = 160

ANSI_CSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
WORKFLOW_CMD_LINE_RE = re.compile(r"^(\s*)::", re.MULTILINE)
WORKFLOW_CMD_TOKEN_RE = re.compile(
    r"::(error|warning|notice|debug|group|endgroup|add-mask|add-matcher|"
    r"remove-matcher|stop-commands|save-state|set-output|add-path|set-env)\b",
    re.IGNORECASE,
)
STACK_FRAME_RE = re.compile(
    r"at\s+(?:[\w$.@-]*/){0,2}"
    r"(app\.byteland\.ghidra\.[\w$]+(?:\.[\w$]+)*)\.(?:[\w$]+|<init>|<clinit>)"
    r"\(([\w$]+\.java):(\d+)\)"
)
EXPECTED_ACTUAL_RE = re.compile(
    r"expected:\s*<(?P<expected>.*?)>\s*but was:\s*<(?P<actual>.*?)>",
    re.DOTALL,
)
HEADLESS_ERROR_RE = re.compile(
    r"\b(ERROR|Exception|Traceback|RuntimeError|AssertionError|FAILED)\b"
)


@dataclasses.dataclass(frozen=True)
class FailureCase:
    module: str
    suite: str
    test_name: str
    duration_s: str
    kind: str
    failure_type: str
    message: str
    details: str
    stdout: str
    stderr: str
    source_file: str | None
    source_line: int | None


def sanitize_text(value: str | None) -> str:
    if not value:
        return ""
    cleaned = value.replace("\r\n", "\n").replace("\r", "\n")
    cleaned = ANSI_CSI_RE.sub("", cleaned)
    out: list[str] = []
    for ch in cleaned:
        code = ord(ch)
        if ch in ("\n", "\t"):
            out.append(ch)
        elif code < 0x20 or (0x7F <= code <= 0x9F):
            out.append(f"\\x{code:02x}")
        elif ch in ("\u2028", "\u2029"):
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    sanitized = "".join(out)
    sanitized = WORKFLOW_CMD_LINE_RE.sub(r"\1:\\:", sanitized)
    sanitized = WORKFLOW_CMD_TOKEN_RE.sub(r":\\:\1", sanitized)
    return sanitized


def escape_table_cell(value: str, limit: int = MAX_CELL_CHARS) -> str:
    single_line = " ".join(sanitize_text(value).split())
    if len(single_line) > limit:
        single_line = single_line[: limit - 3] + "..."
    return (
        single_line.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def fenced_block(content: str, language: str = "text") -> str:
    body = sanitize_text(content).rstrip("\n")
    longest_run = max((len(match.group(0)) for match in re.finditer(r"`+", body)), default=0)
    fence = "`" * max(3, longest_run + 1)
    return f"{fence}{language}\n{body}\n{fence}\n"


def truncate_middle(text: str, max_chars: int) -> str:
    cleaned = sanitize_text(text).strip()
    if len(cleaned) <= max_chars:
        return cleaned
    head = max_chars // 2
    tail = max_chars - head - 40
    return f"{cleaned[:head]}\n... [truncated] ...\n{cleaned[-max(tail, 0):]}"


def escape_workflow_data(value: str) -> str:
    cleaned = sanitize_text(value)
    return cleaned.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_workflow_property(value: str) -> str:
    return (
        escape_workflow_data(value)
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def infer_module(repo_root: pathlib.Path, xml_path: pathlib.Path) -> str:
    try:
        rel = xml_path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return "unknown"
    marker = "/build/test-results/"
    if rel.startswith("modules/") and marker in rel:
        mod_path = rel[len("modules/") : rel.index(marker)]
        return ":" + mod_path.replace("/", ":")
    return rel


def build_source_index(repo_root: pathlib.Path) -> dict[str, str]:
    index: dict[str, str] = {}
    modules_dir = repo_root / "modules"
    if not modules_dir.is_dir():
        return index
    for java_file in sorted(modules_dir.rglob("*.java")):
        rel = java_file.relative_to(repo_root).as_posix()
        for marker in ("/src/test/java/", "/src/main/java/"):
            if marker in rel:
                pkg_rel = rel.split(marker, 1)[1]
                index.setdefault(pkg_rel, rel)
                break
    return index


def resolve_stack_location(
    details: str, preferred_class: str, source_index: dict[str, str]
) -> tuple[str | None, int | None]:
    preferred_prefix = preferred_class.split("$", 1)[0]
    fallback: tuple[str, int] | None = None
    for match in STACK_FRAME_RE.finditer(details):
        fqcn, file_name, line_str = match.group(1), match.group(2), match.group(3)
        pkg = fqcn.rsplit(".", 1)[0] if "." in fqcn else ""
        pkg_rel = f"{pkg.replace('.', '/')}/{file_name}" if pkg else file_name
        repo_file = source_index.get(pkg_rel)
        if repo_file is None:
            continue
        line_no = int(line_str)
        if fqcn == preferred_class or fqcn.startswith(preferred_prefix + "$"):
            return repo_file, line_no
        if fallback is None:
            fallback = (repo_file, line_no)
    return fallback if fallback is not None else (None, None)


def parse_xml_reports(
    repo_root: pathlib.Path, xml_paths: list[pathlib.Path]
) -> tuple[int, int, list[FailureCase]]:
    source_index = build_source_index(repo_root)
    total_tests = 0
    total_suites = 0
    failures: list[FailureCase] = []

    for xml_path in sorted(xml_paths):
        total_suites += 1
        module = infer_module(repo_root, xml_path)
        try:
            tree = ET.parse(xml_path)
        except ET.ParseError as exc:
            try:
                rel_xml = xml_path.resolve().relative_to(repo_root.resolve()).as_posix()
            except ValueError:
                rel_xml = str(xml_path)
            failures.append(
                FailureCase(
                    module=module,
                    suite=xml_path.stem,
                    test_name="<xml-parse-error>",
                    duration_s="0",
                    kind="error",
                    failure_type="ParseError",
                    message=f"Malformed JUnit XML in {rel_xml}: {exc}",
                    details=str(exc),
                    stdout="",
                    stderr="",
                    source_file=rel_xml,
                    source_line=1,
                )
            )
            continue

        root = tree.getroot()
        suites = [root] if root.tag == "testsuite" else list(root.findall(".//testsuite"))
        for suite in suites:
            suite_name = suite.attrib.get("name", xml_path.stem)
            suite_out = suite.findtext("system-out") or ""
            suite_err = suite.findtext("system-err") or ""
            for case in suite.findall("testcase"):
                total_tests += 1
                case_class = case.attrib.get("classname", suite_name)
                case_name = case.attrib.get("name", "<unnamed>")
                duration_s = case.attrib.get("time", "0")
                case_out = case.findtext("system-out") or ""
                case_err = case.findtext("system-err") or ""

                problem_nodes = [( "failure", node) for node in case.findall("failure")] + [
                    ("error", node) for node in case.findall("error")
                ]
                for kind, node in problem_nodes:
                    raw_details = (node.text or "").strip()
                    raw_message = (node.attrib.get("message") or "").strip()
                    failure_type = (node.attrib.get("type") or kind).strip()
                    if not raw_message and raw_details:
                        raw_message = raw_details.splitlines()[0]
                    source_file, source_line = resolve_stack_location(
                        raw_details, case_class, source_index
                    )
                    effective_out = case_out if case_out.strip() else suite_out
                    effective_err = case_err if case_err.strip() else suite_err
                    failures.append(
                        FailureCase(
                            module=module,
                            suite=case_class,
                            test_name=case_name,
                            duration_s=duration_s,
                            kind=kind,
                            failure_type=failure_type,
                            message=raw_message or failure_type,
                            details=raw_details,
                            stdout=effective_out,
                            stderr=effective_err,
                            source_file=source_file,
                            source_line=source_line,
                        )
                    )
    return total_suites, total_tests, failures


def read_headless_tail(log_path: pathlib.Path) -> str:
    if not log_path.is_file():
        return ""
    raw = log_path.read_text(encoding="utf-8", errors="replace")
    lines = raw.splitlines()[-MAX_HEADLESS_LINES:]
    tail = "\n".join(lines)
    if len(tail) > MAX_HEADLESS_CHARS:
        tail = tail[-MAX_HEADLESS_CHARS:]
    return sanitize_text(tail).strip()


def emit_annotations(
    failures: list[FailureCase], headless_tail: str, headless_rel: str
) -> None:
    for item in failures:
        props: list[str] = []
        if item.source_file:
            props.append(f"file={escape_workflow_property(item.source_file)}")
            if item.source_line:
                props.append(f"line={item.source_line}")
        title = f"{item.module} {item.suite.rsplit('.', 1)[-1]}.{item.test_name}"
        props.append(f"title={escape_workflow_property(title)}")
        first_line = sanitize_text(item.message).splitlines()[0] if item.message else item.kind
        prop_str = ",".join(props)
        print(f"::error {prop_str}::{escape_workflow_data(first_line)}")

    if not failures and headless_tail and HEADLESS_ERROR_RE.search(headless_tail):
        last_line = headless_tail.splitlines()[-1]
        props = (
            "file=tests/function_mutation_regression.py,"
            f"title={escape_workflow_property('Headless Ghidra regression')}"
        )
        msg = f"{last_line} (see {headless_rel})"
        print(f"::error {props}::{escape_workflow_data(msg)}")


def render_case_section(index: int, item: FailureCase) -> str:
    short_suite = item.suite.rsplit(".", 1)[-1]
    heading = sanitize_text(f"{index}. `{item.module}` - `{short_suite}.{item.test_name}`")
    parts = [f"### {heading}\n\n"]
    if item.source_file:
        loc = f"{item.source_file}:{item.source_line}" if item.source_line else item.source_file
        parts.append(f"- **Location**: `{sanitize_text(loc)}`\n")
    parts.append(
        f"- **Type**: `{sanitize_text(item.failure_type)}` ({sanitize_text(item.duration_s)}s)\n\n"
    )

    diff_match = EXPECTED_ACTUAL_RE.search(item.details or item.message)
    if diff_match:
        expected = truncate_middle(diff_match.group("expected"), 1_500)
        actual = truncate_middle(diff_match.group("actual"), 1_500)
        diff_text = f"--- expected\n+++ actual\n- {expected}\n+ {actual}"
        parts.append("**Assertion Diff**\n\n")
        parts.append(fenced_block(diff_text, "diff") + "\n")

    if item.details.strip():
        parts.append("**Stack Trace**\n\n")
        parts.append(fenced_block(truncate_middle(item.details, MAX_DETAIL_CHARS), "text") + "\n")
    elif item.message.strip():
        parts.append("**Failure Message**\n\n")
        parts.append(fenced_block(truncate_middle(item.message, MAX_DETAIL_CHARS), "text") + "\n")

    if item.stdout.strip():
        parts.append("**Captured stdout**\n\n")
        parts.append(fenced_block(truncate_middle(item.stdout, MAX_STREAM_CHARS), "text") + "\n")

    if item.stderr.strip():
        parts.append("**Captured stderr**\n\n")
        parts.append(fenced_block(truncate_middle(item.stderr, MAX_STREAM_CHARS), "text") + "\n")

    return "".join(parts)


def build_markdown_summary(
    total_suites: int,
    total_tests: int,
    failures: list[FailureCase],
    headless_tail: str,
    headless_rel: str,
    byte_budget: int,
) -> str:
    truncation_footer = (
        "\n_Output truncated to stay within the 1 MiB GitHub Actions step summary limit. "
        "Download the failure report artifact for complete XML, HTML, and headless logs._\n"
    )
    footer_bytes = len(truncation_footer.encode("utf-8"))
    usable_budget = max(4_096, byte_budget - footer_bytes)

    chunks: list[str] = []
    used_bytes = 0
    truncated = False

    def try_append(piece: str) -> bool:
        nonlocal used_bytes, truncated
        encoded_len = len(piece.encode("utf-8"))
        if used_bytes + encoded_len > usable_budget:
            truncated = True
            return False
        chunks.append(piece)
        used_bytes += encoded_len
        return True

    try_append("## Test Failure Summary\n\n")
    try_append(
        f"Parsed **{total_tests}** test case(s) across **{total_suites}** JUnit XML suite(s); "
        f"found **{len(failures)}** failure(s).\n\n"
    )

    if failures:
        table_header = (
            "| Module | Test | Location | Type | Message |\n"
            "| --- | --- | --- | --- | --- |\n"
        )
        if try_append(table_header):
            for item in failures:
                short_suite = item.suite.rsplit(".", 1)[-1]
                test_label = f"{short_suite}.{item.test_name}"
                loc_label = (
                    f"{item.source_file}:{item.source_line}"
                    if item.source_file and item.source_line
                    else (item.source_file or "-")
                )
                short_type = item.failure_type.rsplit(".", 1)[-1]
                row = (
                    f"| `{escape_table_cell(item.module, 48)}` "
                    f"| `{escape_table_cell(test_label, 80)}` "
                    f"| `{escape_table_cell(loc_label, 96)}` "
                    f"| `{escape_table_cell(short_type, 48)}` "
                    f"| {escape_table_cell(item.message)} |\n"
                )
                if not try_append(row):
                    break
            try_append("\n")

    if headless_tail:
        headless_section = (
            f"### Headless Ghidra Log Tail (`{sanitize_text(headless_rel)}`)\n\n"
            + fenced_block(headless_tail, "text")
            + "\n"
        )
        try_append(headless_section)

    for idx, item in enumerate(failures, start=1):
        section = render_case_section(idx, item)
        if not try_append(section):
            break

    if not failures and not headless_tail:
        try_append(
            "_No failed JUnit test cases or headless regression logs were found. "
            "Check earlier build, compilation, or repository hygiene step logs._\n"
        )

    if truncated:
        chunks.append(truncation_footer)

    return "".join(chunks)


def main() -> int:
    default_root = pathlib.Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=default_root,
        help="repository root directory",
    )
    parser.add_argument(
        "--xml-glob",
        default="modules/**/build/test-results/test/TEST-*.xml",
        help="glob pattern (relative to --root) for JUnit XML result files",
    )
    parser.add_argument(
        "--headless-log",
        type=pathlib.Path,
        default=None,
        help="path to headless.log (defaults to <root>/build/reports/headless-regression/headless.log)",
    )
    parser.add_argument(
        "--summary-file",
        type=pathlib.Path,
        default=None,
        help="output Markdown summary file (defaults to $GITHUB_STEP_SUMMARY, or stdout if unset)",
    )
    parser.add_argument(
        "--no-annotations",
        action="store_true",
        help="suppress GitHub Actions ::error workflow annotations on stdout",
    )
    args = parser.parse_args()

    repo_root = args.root.resolve()
    headless_log = (
        args.headless_log.resolve()
        if args.headless_log is not None
        else (repo_root / "build" / "reports" / "headless-regression" / "headless.log")
    )
    try:
        headless_rel = headless_log.relative_to(repo_root).as_posix()
    except ValueError:
        headless_rel = str(headless_log)

    xml_paths = list(repo_root.glob(args.xml_glob))
    total_suites, total_tests, failures = parse_xml_reports(repo_root, xml_paths)
    headless_tail = read_headless_tail(headless_log)

    env_summary = os.environ.get("GITHUB_STEP_SUMMARY", "").strip()
    summary_path = (
        args.summary_file
        if args.summary_file is not None
        else (pathlib.Path(env_summary) if env_summary else None)
    )

    if not args.no_annotations:
        emit_annotations(failures, headless_tail, headless_rel)

    existing_bytes = 0
    if summary_path is not None and summary_path.exists():
        existing_bytes = summary_path.stat().st_size
    remaining_budget = max(0, MAX_SUMMARY_FILE_BYTES - existing_bytes)

    if summary_path is not None and remaining_budget == 0:
        return 0

    budget = remaining_budget if summary_path is not None else MAX_SUMMARY_FILE_BYTES
    markdown = build_markdown_summary(
        total_suites=total_suites,
        total_tests=total_tests,
        failures=failures,
        headless_tail=headless_tail,
        headless_rel=headless_rel,
        byte_budget=budget,
    )

    if summary_path is not None:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        with summary_path.open("a", encoding="utf-8") as handle:
            handle.write(markdown)
    else:
        sys.stdout.write(markdown)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
