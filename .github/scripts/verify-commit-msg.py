#!/usr/bin/env python3
"""Verify repository commit message rules."""

from __future__ import annotations

import pathlib
import re
import sys

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
        "transport",
        "transport:mcp",
        "transport:websocket",
        "websocket",
        "wire",
    }
)

CUT_LINE = "# ------------------------ >8 ------------------------"

HEADER_RE = re.compile(
    r"^(?P<type>[a-z]+)(?:\((?P<scope>[^)]*)\))?(?P<breaking>!)?: (?P<summary>.+)$"
)

FOOTER_START_RE = re.compile(
    r"^(?:BREAKING[ -]CHANGE: |[A-Za-z0-9-]+(?:: | #)).+"
)

ATTRIBUTION_RE = re.compile(r"^co-authored-by\s*:", re.IGNORECASE)


def strip_git_comments(raw_text: str) -> list[str]:
    """Remove Git cut-lines, comment lines, and final blank lines."""
    lines: list[str] = []
    for raw_line in raw_text.splitlines():
        if raw_line.strip() == CUT_LINE:
            break
        if raw_line.startswith("#"):
            continue
        lines.append(raw_line.rstrip("\r"))
    while lines and lines[-1] == "":
        lines.pop()
    return lines


def split_sections(lines: list[str]) -> list[list[str]] | None:
    """Split lines after the blank separator into non-empty blocks."""
    sections: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if line == "":
            if not current:
                return None
            sections.append(current)
            current = []
        else:
            current.append(line)
    if current:
        sections.append(current)
    return sections


def validate_body_block(body_lines: list[str]) -> list[str]:
    """Check that each body line is a top-level capitalized list item."""
    errors: list[str] = []
    for index, line in enumerate(body_lines, start=3):
        if line.startswith((" ", "\t")):
            errors.append(
                f"line {index}: do not use nested lists or indented lines"
            )
            continue
        if not line.startswith("- "):
            errors.append(
                f"line {index}: write each body item with '- ' at the start"
            )
            continue
        item = line[2:]
        if not item or item[0].isspace():
            errors.append(f"line {index}: write text after '- '")
            continue
        if not (item[0].isascii() and item[0].isupper()):
            errors.append(
                f"line {index}: start each body list item with a capital letter"
            )
    return errors


def validate_message(raw_text: str) -> list[str]:
    """Return a list of commit message violations."""
    lines = strip_git_comments(raw_text)
    if not lines or not lines[0].strip():
        return ["commit message must not be empty"]

    header = lines[0]

    # Exempt Git merge commits and release-please release commits.
    if re.match(r"^Merge\b", header) or re.match(
        r"^chore\(main\): release\b", header
    ):
        return []

    errors: list[str] = []

    for index, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_LENGTH:
            errors.append(
                f"line {index}: length is {len(line)} characters; "
                f"maximum is {MAX_LINE_LENGTH}"
            )
        if ATTRIBUTION_RE.match(line):
            errors.append(
                f"line {index}: do not add attribution lines such as "
                "Co-Authored-By"
            )

    match = HEADER_RE.match(header)
    if not match:
        errors.append(
            "line 1: header must match '<type>[optional (<scope>)][!]: "
            "<summary>' in lowercase"
        )
    else:
        commit_type = match.group("type")
        scope = match.group("scope")
        summary = match.group("summary")

        if commit_type not in ALLOWED_TYPES:
            allowed = ", ".join(sorted(ALLOWED_TYPES))
            errors.append(
                f"line 1: unknown commit type '{commit_type}'; "
                f"expected one of: {allowed}"
            )

        if scope is not None:
            if not scope or scope not in ALLOWED_SCOPES:
                allowed = ", ".join(sorted(ALLOWED_SCOPES))
                errors.append(
                    f"line 1: invalid scope '{scope}'; "
                    f"expected one of: {allowed}"
                )

        if summary != summary.strip():
            errors.append(
                "line 1: summary must not have extra spaces at the start or end"
            )
        elif not (summary[0].isascii() and summary[0].islower()):
            errors.append(
                "line 1: start the summary with a lowercase letter"
            )

        if summary.endswith("."):
            errors.append("line 1: do not put a period at the end of the summary")

    if len(lines) > 1:
        if lines[1] != "":
            errors.append(
                "line 2: put one blank line between the header and the body"
            )
        else:
            sections = split_sections(lines[2:])
            if sections is None or not sections:
                errors.append(
                    "body: do not put extra blank lines in the commit message"
                )
            elif len(sections) == 1:
                if not FOOTER_START_RE.match(sections[0][0]):
                    errors.extend(validate_body_block(sections[0]))
            elif len(sections) == 2:
                if FOOTER_START_RE.match(sections[0][0]):
                    errors.append(
                        "body: do not put body text after the footer block"
                    )
                elif not FOOTER_START_RE.match(sections[1][0]):
                    errors.append("body: do not put blank lines in the body")
                else:
                    errors.extend(validate_body_block(sections[0]))
            else:
                errors.append("body: do not put blank lines in the body")

    return errors


def main(argv: list[str] | None = None) -> int:
    """Validate the commit message file given as the first CLI argument."""
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print(
            "usage: verify-commit-msg.py <commit-msg-file>",
            file=sys.stderr,
        )
        return 2

    path = pathlib.Path(args[0])
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"commit-msg check failed: {exc}", file=sys.stderr)
        return 1
    except UnicodeDecodeError:
        print(
            "commit-msg check failed: commit message must be valid UTF-8",
            file=sys.stderr,
        )
        return 1

    errors = validate_message(raw_text)
    if errors:
        print("commit message check failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
