#!/usr/bin/env python3
"""Validate commit messages against Ghidra Bridge Conventional Commit rules."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

MAX_LINE_LENGTH = 72

ALLOWED_TYPES = frozenset(
    {
        "build",
        "chore",
        "ci",
        "docs",
        "feat",
        "fix",
        "perf",
        "refactor",
        "revert",
        "style",
        "test",
    }
)

ALLOWED_SCOPES = frozenset(
    {
        "adapter",
        "build",
        "ci",
        "contracts",
        "docs",
        "domain",
        "launcher",
        "mcp",
        "runtime",
        "test",
        "transport",
        "websocket",
        "wire",
    }
)

HEADER_RE = re.compile(r"^(?P<type>[a-z]+)(?:\((?P<scope>[a-z]+)\))?!?: (?P<summary>.+)$")
MERGE_RE = re.compile(r"^Merge\b")
RELEASE_PLEASE_RE = re.compile(r"^chore\(main\): release(?:\s|$)")
SQUASH_PR_SUFFIX_RE = re.compile(r" \(#[0-9]+\)$")
SQUASH_TRAILER_RE = re.compile(
    r"^(?:Co-authored-by|Signed-off-by|Reviewed-by|Acked-by|Tested-by|Helped-by|Reported-by|Suggested-by|On-behalf-of): .+$",
    re.IGNORECASE,
)
ATTRIBUTION_RE = re.compile(r"^co-authored-by:", re.IGNORECASE)
FOOTER_RE = re.compile(r"^(?:BREAKING[ -]CHANGE: |(?:Fixes|Closes|Resolves|Refs)(?:: | #))\S.*$")
VERBOSE_CUT_RE = re.compile(r"^# -{24} >8 -{24}\n.*\Z", re.DOTALL | re.MULTILINE)
COMMENT_LINE_RE = re.compile(r"^#.*(?:\n|$)", re.MULTILINE)


def strip_git_comments(raw: str) -> str:
    text = raw.replace("\r\n", "\n").replace("\r", "\n")
    text = VERBOSE_CUT_RE.sub("", text)
    text = COMMENT_LINE_RE.sub("", text)
    return text.rstrip("\n")


def is_exempt_header(header: str) -> bool:
    return bool(MERGE_RE.match(header) or RELEASE_PLEASE_RE.match(header))


def strip_squash_trailers(text: str) -> str:
    lines = text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n").split("\n")
    if not lines or not lines[0]:
        return ""

    lines[0] = SQUASH_PR_SUFFIX_RE.sub("", lines[0])

    idx = len(lines) - 1
    saw_trailer = False
    while idx >= 1:
        candidate = lines[idx]
        if SQUASH_TRAILER_RE.match(candidate):
            saw_trailer = True
            idx -= 1
            continue
        if saw_trailer and candidate == "":
            idx -= 1
            continue
        break

    if saw_trailer:
        lines = lines[: idx + 1]

    return "\n".join(lines)


def validate_message(text: str) -> list[str]:
    errors: list[str] = []
    if not text:
        return ["commit message is empty"]

    lines = text.split("\n")
    header = lines[0]

    if is_exempt_header(header):
        return []

    for index, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_LENGTH:
            errors.append(
                f"line {index} has {len(line)} characters (maximum {MAX_LINE_LENGTH}): {line}"
            )
        if ATTRIBUTION_RE.match(line):
            errors.append(f"line {index} contains an attribution trailer: {line}")

    match = HEADER_RE.match(header)
    if not match:
        scopes = ", ".join(sorted(ALLOWED_SCOPES))
        types = ", ".join(sorted(ALLOWED_TYPES))
        errors.append(
            "header must follow '<type>[optional (<scope>)][!]: <summary>' in lowercase "
            f"(types: {types}; scopes: {scopes})"
        )
    else:
        commit_type = match.group("type")
        scope = match.group("scope")
        summary = match.group("summary")

        if commit_type not in ALLOWED_TYPES:
            errors.append(
                f"unknown commit type '{commit_type}'; allowed types: {', '.join(sorted(ALLOWED_TYPES))}"
            )
        if scope is not None and scope not in ALLOWED_SCOPES:
            errors.append(
                f"unknown commit scope '{scope}'; allowed scopes: {', '.join(sorted(ALLOWED_SCOPES))}"
            )
        if summary.startswith(" "):
            errors.append("header summary must have one space after ':'")
        elif not summary[0].islower():
            errors.append("header summary must start with a lowercase letter")
        if summary.endswith("."):
            errors.append("header summary must not end with a period")

    if len(lines) == 1:
        return errors

    if lines[1] != "":
        errors.append("line 2 must be blank between the header and the body")
        remainder_lines = lines[1:]
    else:
        remainder_lines = lines[2:]

    if not remainder_lines:
        errors.append("commit message has a trailing blank line after the header")
        return errors

    remainder = "\n".join(remainder_lines)
    if "\n\n\n" in remainder or remainder.startswith("\n") or remainder.endswith("\n"):
        errors.append("commit message must not contain consecutive or trailing blank lines")

    paragraphs = [p for p in remainder.split("\n\n") if p != ""]
    if paragraphs and all(FOOTER_RE.match(line) for line in paragraphs[-1].split("\n")):
        body_paragraphs = paragraphs[:-1]
    else:
        body_paragraphs = paragraphs

    if len(body_paragraphs) > 1:
        errors.append("do not put blank lines in the commit body")

    for paragraph in body_paragraphs:
        for line in paragraph.split("\n"):
            if not line.startswith("- "):
                errors.append(
                    f"body line must start with '- ' (no prose paragraphs or nested lists): {line}"
                )
                continue
            item_text = line[2:]
            if not item_text or item_text.startswith(" "):
                errors.append(f"body list item must have one space after '-': {line}")
            elif not item_text[0].isupper():
                errors.append(f"body list item must start with a capital letter: {line}")

    return errors


def prepare_ci(allow_squash_arg: str, output_path: str) -> int:
    raw = os.environ.get("RAW_MESSAGE", "")
    normalized = raw.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")
    first_line = normalized.split("\n", 1)[0] if normalized else ""

    if is_exempt_header(first_line):
        print("EXEMPT")
        return 0

    if allow_squash_arg == "true":
        normalized = strip_squash_trailers(normalized)
        first_line_after = normalized.split("\n", 1)[0] if normalized else ""
        if is_exempt_header(first_line_after):
            print("EXEMPT")
            return 0

    Path(output_path).write_text(normalized + "\n", encoding="utf-8")
    print("CHECK")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) == 4 and argv[1] == "--prepare-ci":
        return prepare_ci(argv[2], argv[3])

    if len(argv) != 2:
        print(
            "usage: verify-commit-message.py <commit-msg-file>\n"
            "   or: verify-commit-message.py --prepare-ci <true|false> <output-file>",
            file=sys.stderr,
        )
        return 2

    try:
        raw = Path(argv[1]).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"commit message check failed: cannot read {argv[1]}: {exc}", file=sys.stderr)
        return 1
    except UnicodeDecodeError:
        print("commit message check failed: commit message must be valid UTF-8", file=sys.stderr)
        return 1

    cleaned = strip_git_comments(raw)
    errors = validate_message(cleaned)
    if errors:
        print("commit message check failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
