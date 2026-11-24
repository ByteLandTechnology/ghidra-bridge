#!/usr/bin/env python3

"""Check automated Simplified Technical English rules in repository files."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
from typing import Any

INSTRUCTION_WORD_LIMIT = 20
DESCRIPTION_WORD_LIMIT = 25
PARAGRAPH_SENTENCE_LIMIT = 6

FORBIDDEN_WORDS = (
    "allow",
    "allows",
    "allowed",
    "allowing",
    "could",
    "ensure",
    "ensures",
    "ensured",
    "ensuring",
    "may",
    "might",
    "obtain",
    "obtains",
    "obtained",
    "obtaining",
    "should",
    "utilize",
    "utilizes",
    "utilized",
    "utilizing",
    "via",
    "would",
)

CONTRACTIONS = (
    "aren't",
    "can't",
    "couldn't",
    "didn't",
    "doesn't",
    "don't",
    "hadn't",
    "hasn't",
    "haven't",
    "isn't",
    "mustn't",
    "shouldn't",
    "wasn't",
    "weren't",
    "won't",
    "wouldn't",
)

PHRASAL_VERBS = (
    "carry out",
    "check out",
    "clean up",
    "come back",
    "find out",
    "get rid of",
    "go away",
    "look at",
    "look for",
    "put together",
    "set up",
    "shut down",
    "start up",
    "try again",
    "turn off",
    "turn on",
)

ING_EXCEPTIONS = frozenset(
    {
        "coding",
        "contributing",
        "during",
        "encoding",
        "engineering",
        "formatting",
        "ing",
        "launching",
        "nothing",
        "operating",
        "ping",
        "rebinding",
        "starting",
        "string",
        "troubleshooting",
        "warning",
    }
)

INSTRUCTION_VERBS = frozenset(
    {
        "add",
        "build",
        "call",
        "check",
        "choose",
        "clone",
        "close",
        "configure",
        "connect",
        "copy",
        "create",
        "define",
        "delete",
        "describe",
        "download",
        "edit",
        "enter",
        "examine",
        "give",
        "include",
        "install",
        "keep",
        "limit",
        "list",
        "make",
        "merge",
        "open",
        "pass",
        "put",
        "read",
        "register",
        "remove",
        "replace",
        "report",
        "review",
        "run",
        "save",
        "select",
        "send",
        "set",
        "start",
        "stop",
        "submit",
        "use",
        "verify",
        "wait",
        "write",
    }
)

IGNORED_DIRS = frozenset(
    {
        ".agents",
        ".claude",
        ".fleet",
        ".git",
        ".gradle",
        ".idea",
        ".kotlin",
        ".settings",
        ".vscode",
        ".worktrees",
        ".zcode",
        "__pycache__",
        "bin",
        "build",
        "ghidra-dist",
        "ja",
        "node_modules",
        "out",
        "target",
        "zh",
    }
)

CHECKED_EXTENSIONS = frozenset(
    {
        "gradle",
        "java",
        "json",
        "md",
        "rs",
        "sh",
        "svg",
        "template",
        "toml",
        "yaml",
        "yml",
    }
)

WORD_TOKEN_RE = re.compile(r"[A-Za-z'-]+")


class Violation:
    """Store one Simplified Technical English rule violation."""

    def __init__(self, path: Path, line: int, message: str) -> None:
        self.path = path
        self.line = line
        self.message = message


class YamlToken:
    """Store one token from a YAML contract document."""

    def __init__(self, kind: str, value: Any, line: int, column: int) -> None:
        self.kind = kind
        self.value = value
        self.line = line
        self.column = column


def display_path(root: Path, path: Path) -> str:
    """Return path relative to root with forward slashes."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def iter_lines(source: str) -> list[str]:
    """Split lines on LF and CRLF boundaries like Rust str::lines."""
    if not source:
        return []
    parts = source.split("\n")
    if parts[-1] == "":
        parts.pop()
    return [part[:-1] if part.endswith("\r") else part for part in parts]


def trim_start_str(text: str, prefix: str) -> str:
    """Remove repeated occurrences of prefix from the start of text."""
    while text.startswith(prefix):
        text = text[len(prefix) :]
    return text


def trim_end_str(text: str, suffix: str) -> str:
    """Remove repeated occurrences of suffix from the end of text."""
    while text.endswith(suffix):
        text = text[: -len(suffix)]
    return text


def is_checked_file(path: Path) -> bool:
    """Return True when path is in scope for automated prose checks."""
    name = path.name
    if name == "CHANGELOG.md" or ".ja-" in name or ".zh-" in name:
        return False
    dot = name.rfind(".")
    if dot <= 0:
        return False
    return name[dot + 1 :] in CHECKED_EXTENSIONS


def collect_files(root: Path, directory: Path, files: list[Path]) -> None:
    """Collect regular files in directory that match checked extensions."""
    try:
        entries = list(os.scandir(directory))
    except OSError as error:
        raise RuntimeError(f"{display_path(root, directory)}: {error}") from error
    for entry in entries:
        entry_path = Path(entry.path)
        try:
            is_dir = entry.is_dir(follow_symlinks=False)
            is_file = entry.is_file(follow_symlinks=False)
        except OSError as error:
            raise RuntimeError(f"{display_path(root, entry_path)}: {error}") from error
        if is_dir:
            if entry.name not in IGNORED_DIRS:
                collect_files(root, entry_path, files)
        elif is_file and is_checked_file(entry_path):
            files.append(entry_path)


def is_table_separator(text: str) -> bool:
    """Return True when text is a Markdown table separator row."""
    value = text.strip("|").strip()
    return bool(value) and all(ch in "-:| " for ch in value)


def has_numbered_prefix(text: str) -> bool:
    """Return True when text begins with an ASCII numbered list marker."""
    digits = 0
    for ch in text:
        if "0" <= ch <= "9":
            digits += 1
        else:
            break
    if digits == 0:
        return False
    rest = text[digits:]
    return rest.startswith(". ") or rest.startswith(") ")


def is_separate_markdown_line(text: str) -> bool:
    """Return True when one Markdown line forms a standalone prose unit."""
    return (
        text.startswith("- ")
        or text.startswith("* ")
        or text.startswith("+ ")
        or text.startswith("> ")
        or text.startswith("<!--")
        or has_numbered_prefix(text)
    )


def trim_markdown_prefix(text: str) -> str:
    """Remove a Markdown list, quote, or HTML comment prefix."""
    if text.startswith("<!--"):
        return trim_end_str(trim_start_str(text, "<!--"), "-->").strip()
    if text and text[0] in "-+>*" and text[0].isascii():
        return text[1:].lstrip()
    digits = 0
    for ch in text:
        if "0" <= ch <= "9":
            digits += 1
        else:
            break
    rest = text[digits:]
    if rest.startswith(". ") or rest.startswith(") "):
        return rest[2:]
    return rest


def visible_text(text: str) -> str:
    """Replace inline code, double-quoted strings, link URLs, and tags."""
    out: list[str] = []
    index = 0
    length = len(text)
    code = False
    quote = False
    tag = False
    while index < length:
        ch = text[index]
        index += 1
        if tag:
            if ch == ">":
                tag = False
                out.append(" ")
            continue
        if not code and not quote and ch == "<":
            tag = True
            continue
        if not quote and ch == "`":
            code = not code
            if not code:
                out.append(" CODE ")
            continue
        if not code and ch == '"':
            quote = not quote
            if not quote:
                out.append(" QUOTE ")
            continue
        if code or quote:
            continue
        if ch == "]" and index < length and text[index] == "(":
            index += 1
            while index < length:
                next_ch = text[index]
                index += 1
                if next_ch == ")":
                    break
            out.append(" ")
            continue
        out.append(ch)
    return "".join(out)


def split_sentences(text: str) -> list[str]:
    """Split prose text into sentence slices."""
    sentences: list[str] = []
    start = 0
    length = len(text)
    for index, ch in enumerate(text):
        if ch not in ".!?":
            continue
        end = index + 1
        if end < length and not text[end].isspace():
            continue
        sentence = text[start:end].strip()
        if sentence:
            sentences.append(sentence)
        start = end
    tail = text[start:].strip()
    if tail:
        sentences.append(tail)
    return sentences


def extract_words(text: str) -> list[str]:
    """Return lowercase ASCII words with internal hyphens and apostrophes."""
    result: list[str] = []
    for token in WORD_TOKEN_RE.findall(text):
        if not any(("A" <= ch <= "Z") or ("a" <= ch <= "z") for ch in token):
            continue
        cleaned = token.strip("-'").lower()
        if cleaned:
            result.append(cleaned)
    return result


def contains_phrase(word_list: list[str], phrase: str) -> bool:
    """Return True when word_list contains all words of phrase in order."""
    target = phrase.split()
    size = len(target)
    if size == 0 or len(word_list) < size:
        return False
    return any(word_list[i : i + size] == target for i in range(len(word_list) - size + 1))


def add_violation(
    path: Path, line: int, message: str, violations: list[Violation]
) -> None:
    """Append one violation record."""
    violations.append(Violation(path, line, message))


def check_vocabulary(
    path: Path, line: int, text: str, violations: list[Violation]
) -> None:
    """Check one prose unit against vocabulary rules."""
    visible = visible_text(text)
    lower = "".join(ch.lower() if "A" <= ch <= "Z" else ch for ch in visible)
    word_list = extract_words(lower)
    for forbidden in FORBIDDEN_WORDS:
        if forbidden in word_list:
            add_violation(path, line, f"prohibited word: {forbidden}", violations)
    for contraction in CONTRACTIONS:
        if contraction in word_list:
            add_violation(path, line, f"contraction: {contraction}", violations)
    for phrase in PHRASAL_VERBS:
        if contains_phrase(word_list, phrase):
            add_violation(path, line, f"phrasal verb: {phrase}", violations)
    for abbreviation in ("e.g.", "i.e.", "etc."):
        if abbreviation in lower:
            add_violation(
                path, line, f"Latin abbreviation: {abbreviation}", violations
            )
    for word in word_list:
        if word.endswith("ing") and word not in ING_EXCEPTIONS:
            add_violation(path, line, f"nontechnical -ing form: {word}", violations)


def check_lengths(
    path: Path, line: int, text: str, violations: list[Violation]
) -> None:
    """Check sentence word counts and paragraph sentence counts."""
    sentences = split_sentences(text)
    if len(sentences) > PARAGRAPH_SENTENCE_LIMIT:
        add_violation(
            path,
            line,
            f"paragraph has {len(sentences)} sentences; maximum is {PARAGRAPH_SENTENCE_LIMIT}",
            violations,
        )
    for sentence in sentences:
        marker = sentence.find("**:")
        if marker != -1:
            sentence = sentence[marker + 3 :]
        sentence_words = extract_words(sentence)
        if not sentence_words:
            continue
        limit = (
            INSTRUCTION_WORD_LIMIT
            if sentence_words[0] in INSTRUCTION_VERBS
            else DESCRIPTION_WORD_LIMIT
        )
        if len(sentence_words) > limit:
            add_violation(
                path,
                line,
                f"sentence has {len(sentence_words)} words; maximum is {limit}",
                violations,
            )


def check_text(path: Path, line: int, text: str, violations: list[Violation]) -> None:
    """Check vocabulary and length rules on one prose unit."""
    visible = visible_text(text)
    check_vocabulary(path, line, text, violations)
    check_lengths(path, line, visible, violations)


def flush_paragraph(
    path: Path, line: int, paragraph: list[str], violations: list[Violation]
) -> None:
    """Check accumulated paragraph lines and reset paragraph buffer."""
    if not paragraph:
        return
    check_text(path, line, " ".join(paragraph), violations)
    paragraph.clear()


def check_markdown(path: Path, source: str, violations: list[Violation]) -> None:
    """Check prose in a Markdown document."""
    paragraph: list[str] = []
    paragraph_line = 0
    in_fence = False
    for index, line in enumerate(iter_lines(source)):
        number = index + 1
        trimmed = line.strip()
        if trimmed.startswith("```") or trimmed.startswith("~~~"):
            flush_paragraph(path, paragraph_line, paragraph, violations)
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if not trimmed or trimmed.startswith("#") or is_table_separator(trimmed):
            flush_paragraph(path, paragraph_line, paragraph, violations)
            continue
        if trimmed.startswith("|"):
            flush_paragraph(path, paragraph_line, paragraph, violations)
            for cell in trimmed.strip("|").split("|"):
                check_text(path, number, cell, violations)
            continue
        if is_separate_markdown_line(trimmed):
            flush_paragraph(path, paragraph_line, paragraph, violations)
            check_text(path, number, trim_markdown_prefix(trimmed), violations)
            continue
        if not paragraph:
            paragraph_line = number
        paragraph.append(trimmed)
    flush_paragraph(path, paragraph_line, paragraph, violations)


def push_comment_text(
    path: Path,
    line: int,
    text: str,
    paragraph_line: list[int],
    paragraph: list[str],
    violations: list[Violation],
) -> None:
    """Append one comment line to paragraph or check it standalone."""
    if not text:
        flush_paragraph(path, paragraph_line[0], paragraph, violations)
        return
    if text.startswith("|"):
        flush_paragraph(path, paragraph_line[0], paragraph, violations)
        if not is_table_separator(text):
            for cell in text.strip("|").split("|"):
                check_text(path, line, cell, violations)
        return
    if text.startswith("@") or is_separate_markdown_line(text) or text.startswith("#"):
        flush_paragraph(path, paragraph_line[0], paragraph, violations)
        check_text(path, line, trim_markdown_prefix(text), violations)
        return
    if not paragraph:
        paragraph_line[0] = line
    paragraph.append(text)


def check_slash_comments(path: Path, source: str, violations: list[Violation]) -> None:
    """Check whole-line slash and block comments in C-family source files."""
    paragraph: list[str] = []
    paragraph_line = [0]
    in_block = False
    in_fence = False
    for index, line in enumerate(iter_lines(source)):
        number = index + 1
        trimmed = line.strip()
        comment: str | None = None
        if in_block:
            value = trimmed.removesuffix("*/").strip()
            value = value.lstrip("*").strip()
            comment = value
            if "*/" in trimmed:
                in_block = False
        elif trimmed.startswith("//"):
            comment = trimmed[2:].lstrip("/!").strip()
        elif trimmed.startswith("/*"):
            in_block = "*/" not in trimmed
            comment = trim_end_str(trimmed[2:].lstrip("*"), "*/").strip()
        if comment is None:
            flush_paragraph(path, paragraph_line[0], paragraph, violations)
            continue
        if comment.startswith("```"):
            flush_paragraph(path, paragraph_line[0], paragraph, violations)
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        push_comment_text(
            path, number, comment, paragraph_line, paragraph, violations
        )
    flush_paragraph(path, paragraph_line[0], paragraph, violations)


def check_hash_comments(path: Path, source: str, violations: list[Violation]) -> None:
    """Check whole-line hash comments in shell, TOML, and YAML files."""
    paragraph: list[str] = []
    paragraph_line = [0]
    for index, line in enumerate(iter_lines(source)):
        number = index + 1
        trimmed = line.strip()
        if trimmed.startswith("#!"):
            continue
        if trimmed.startswith("#"):
            push_comment_text(
                path, number, trimmed[1:].strip(), paragraph_line, paragraph, violations
            )
        else:
            flush_paragraph(path, paragraph_line[0], paragraph, violations)
    flush_paragraph(path, paragraph_line[0], paragraph, violations)


def check_toml(path: Path, source: str, violations: list[Violation]) -> None:
    """Check hash comments and package descriptions in a TOML file."""
    check_hash_comments(path, source, violations)
    for index, line in enumerate(iter_lines(source)):
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == "description":
            check_text(path, index + 1, value.strip().strip('"'), violations)


def check_yaml(path: Path, source: str, violations: list[Violation]) -> None:
    """Check comments and human-readable fields in a YAML file."""
    check_hash_comments(path, source, violations)
    block_indent: int | None = None
    for index, line in enumerate(iter_lines(source)):
        trimmed = line.strip()
        indent = len(line) - len(line.lstrip())
        if block_indent is not None:
            if not trimmed:
                continue
            if indent > block_indent:
                check_text(path, index + 1, trimmed, violations)
                continue
            block_indent = None
        if ":" not in trimmed:
            continue
        raw_key, raw_value = trimmed.split(":", 1)
        key = trim_start_str(raw_key, "- ").strip()
        value = raw_value.strip()
        if key in ("description", "placeholder", "value") and value in (
            "|",
            ">",
            "|-",
            ">-",
        ):
            block_indent = indent
        elif key in ("about", "description", "label", "name") and value:
            check_text(path, index + 1, value, violations)


def check_json_value(path: Path, value: Any, violations: list[Violation]) -> None:
    """Check description and title fields recursively in a parsed structure."""
    if isinstance(value, dict):
        for key in sorted(value.keys(), key=str):
            child = value[key]
            if key in ("description", "title") and isinstance(child, str):
                check_vocabulary(path, 1, child, violations)
            check_json_value(path, child, violations)
    elif isinstance(value, list):
        for child in value:
            check_json_value(path, child, violations)


def check_json(path: Path, source: str, violations: list[Violation]) -> None:
    """Check description and title strings in a JSON document."""
    try:
        value = json.loads(source)
    except json.JSONDecodeError:
        return
    check_json_value(path, value, violations)


def tokenize_yaml(source: str) -> list[YamlToken]:
    """Tokenize a YAML document with standard library primitives."""
    tokens: list[YamlToken] = []
    index = 0
    length = len(source)
    line = 1
    line_start = 0
    flow_depth = 0
    yaml_escapes = {
        '"': '"',
        "\\": "\\",
        "/": "/",
        " ": " ",
        "t": "\t",
        "\t": "\t",
        "n": "\n",
        "r": "\r",
        "b": "\b",
        "f": "\f",
        "0": "\0",
        "a": "\a",
        "v": "\v",
        "e": "\x1b",
    }

    while index < length:
        ch = source[index]
        if ch == " ":
            index += 1
            continue
        if ch == "\r":
            index += 1
            continue
        if ch == "\n":
            index += 1
            line += 1
            line_start = index
            continue
        if ch == "\t":
            raise ValueError(f"tab character at line {line}")
        if ch == "#":
            while index < length and source[index] != "\n":
                index += 1
            continue

        column = index - line_start
        start_line = line

        if ch in "{}[],":
            if ch in "{[":
                flow_depth += 1
            elif ch in "}]":
                flow_depth -= 1
                if flow_depth < 0:
                    raise ValueError(f"unmatched '{ch}' at line {line}")
            tokens.append(YamlToken(ch, ch, start_line, column))
            index += 1
            continue

        if ch == ":" and (
            index + 1 == length
            or source[index + 1] in " \n\r\t"
            or (flow_depth > 0 and source[index + 1] in "}],")
        ):
            tokens.append(YamlToken(":", ":", start_line, column))
            index += 1
            continue

        if ch == "-" and (index + 1 == length or source[index + 1] in " \n\r\t"):
            tokens.append(YamlToken("-", "-", start_line, column))
            index += 1
            continue

        if ch == "!" and index + 1 < length and source[index + 1] == "!":
            end = index + 2
            while end < length and source[end] not in " \n\r\t":
                end += 1
            tag = source[index:end]
            if len(tag) <= 2:
                raise ValueError(f"invalid tag at line {line}")
            tokens.append(YamlToken("TAG", tag, start_line, column))
            index = end
            continue

        if ch == '"':
            index += 1
            chars: list[str] = []
            while True:
                if index >= length:
                    raise ValueError(f"unterminated double-quoted string at line {start_line}")
                cur = source[index]
                index += 1
                if cur == '"':
                    break
                if cur == "\\":
                    if index >= length:
                        raise ValueError(f"unterminated escape at line {line}")
                    esc = source[index]
                    index += 1
                    if esc == "\r":
                        if index < length and source[index] == "\n":
                            index += 1
                        esc = "\n"
                    if esc == "\n":
                        line += 1
                        line_start = index
                        while index < length and source[index] in " \t":
                            index += 1
                        continue
                    if esc in yaml_escapes:
                        chars.append(yaml_escapes[esc])
                    elif esc == "x" and index + 2 <= length:
                        chars.append(chr(int(source[index : index + 2], 16)))
                        index += 2
                    elif esc == "u" and index + 4 <= length:
                        chars.append(chr(int(source[index : index + 4], 16)))
                        index += 4
                    elif esc == "U" and index + 8 <= length:
                        chars.append(chr(int(source[index : index + 8], 16)))
                        index += 8
                    else:
                        raise ValueError(f"unsupported escape '\\{esc}' at line {line}")
                    continue
                if cur == "\r":
                    continue
                if cur == "\n":
                    while chars and chars[-1] in " \t":
                        chars.pop()
                    newlines = 1
                    line += 1
                    line_start = index
                    while True:
                        while index < length and source[index] in " \t\r":
                            index += 1
                        if index < length and source[index] == "\n":
                            index += 1
                            newlines += 1
                            line += 1
                            line_start = index
                        else:
                            break
                    chars.append(" " if newlines == 1 else "\n" * (newlines - 1))
                    continue
                chars.append(cur)
            tokens.append(YamlToken("SCALAR", "".join(chars), start_line, column))
            continue

        if ch == "'":
            index += 1
            chars = []
            while True:
                if index >= length:
                    raise ValueError(f"unterminated single-quoted string at line {start_line}")
                cur = source[index]
                index += 1
                if cur == "'":
                    if index < length and source[index] == "'":
                        chars.append("'")
                        index += 1
                        continue
                    break
                if cur == "\r":
                    continue
                if cur == "\n":
                    while chars and chars[-1] in " \t":
                        chars.pop()
                    newlines = 1
                    line += 1
                    line_start = index
                    while True:
                        while index < length and source[index] in " \t\r":
                            index += 1
                        if index < length and source[index] == "\n":
                            index += 1
                            newlines += 1
                            line += 1
                            line_start = index
                        else:
                            break
                    chars.append(" " if newlines == 1 else "\n" * (newlines - 1))
                    continue
                chars.append(cur)
            tokens.append(YamlToken("SCALAR", "".join(chars), start_line, column))
            continue

        end = index
        while end < length:
            cur = source[end]
            if cur in "\r\n":
                break
            if flow_depth > 0 and cur in "{}[],":
                break
            if cur == "#" and end > index and source[end - 1] in " \t":
                break
            if cur == ":" and (
                end + 1 == length
                or source[end + 1] in " \n\r\t"
                or (flow_depth > 0 and source[end + 1] in "}],")
            ):
                break
            end += 1
        raw = source[index:end].rstrip(" \t")
        if not raw:
            raise ValueError(f"unexpected character '{ch}' at line {line}")
        tokens.append(YamlToken("PLAIN", raw, start_line, column))
        index = end

    if flow_depth != 0:
        raise ValueError("unclosed flow collection")
    return tokens


def coerce_yaml_scalar(token: YamlToken, tag: str | None) -> Any:
    """Convert a YAML scalar token with an optional tag to a Python value."""
    raw = token.value
    if tag is not None:
        if tag == "!!bool":
            if raw in ("true", "True", "TRUE"):
                return True
            if raw in ("false", "False", "FALSE"):
                return False
            raise ValueError(f"invalid boolean '{raw}' at line {token.line}")
        if tag == "!!int":
            return int(raw)
        if tag == "!!float":
            return float(raw)
        if tag == "!!null":
            return None
        if tag == "!!str":
            return str(raw)
        return raw
    if token.kind == "SCALAR":
        return raw
    if raw in ("null", "Null", "NULL", "~"):
        return None
    if raw in ("true", "True", "TRUE"):
        return True
    if raw in ("false", "False", "FALSE"):
        return False
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        return raw


def parse_yaml_contract(source: str) -> Any:
    """Parse a YAML contract document into nested Python dicts and lists."""
    tokens = tokenize_yaml(source)
    if not tokens:
        return None
    pos = 0
    total = len(tokens)

    def parse_flow_seq() -> list[Any]:
        nonlocal pos
        pos += 1
        items: list[Any] = []
        while pos < total and tokens[pos].kind != "]":
            items.append(parse_flow_value())
            if pos < total and tokens[pos].kind == ",":
                pos += 1
            elif pos < total and tokens[pos].kind != "]":
                raise ValueError(f"expected ',' or ']' at line {tokens[pos].line}")
        if pos >= total:
            raise ValueError("unterminated flow sequence")
        pos += 1
        return items

    def parse_flow_map() -> dict[str, Any]:
        nonlocal pos
        pos += 1
        mapping: dict[str, Any] = {}
        while pos < total and tokens[pos].kind != "}":
            key = str(parse_flow_value())
            if pos >= total or tokens[pos].kind != ":":
                raise ValueError("expected ':' in flow mapping")
            pos += 1
            mapping[key] = parse_flow_value()
            if pos < total and tokens[pos].kind == ",":
                pos += 1
            elif pos < total and tokens[pos].kind != "}":
                raise ValueError(f"expected ',' or '}}' at line {tokens[pos].line}")
        if pos >= total:
            raise ValueError("unterminated flow mapping")
        pos += 1
        return mapping

    def parse_flow_value() -> Any:
        nonlocal pos
        if pos >= total:
            raise ValueError("unexpected end of YAML flow value")
        tag: str | None = None
        if tokens[pos].kind == "TAG":
            tag = tokens[pos].value
            pos += 1
            if pos >= total:
                raise ValueError("tag without value")
        tok = tokens[pos]
        if tok.kind == "[":
            return parse_flow_seq()
        if tok.kind == "{":
            return parse_flow_map()
        if tok.kind in ("SCALAR", "PLAIN"):
            pos += 1
            return coerce_yaml_scalar(tok, tag)
        raise ValueError(f"unexpected token '{tok.kind}' at line {tok.line}")

    def parse_block_seq(seq_indent: int) -> list[Any]:
        nonlocal pos
        items: list[Any] = []
        while pos < total and tokens[pos].kind == "-" and tokens[pos].column == seq_indent:
            dash = tokens[pos]
            pos += 1
            if pos >= total or tokens[pos].column < seq_indent:
                items.append(None)
                continue
            if tokens[pos].column == seq_indent and tokens[pos].line > dash.line:
                items.append(None)
                continue
            items.append(parse_block_node(seq_indent))
        return items

    def parse_block_map(map_indent: int) -> dict[str, Any]:
        nonlocal pos
        mapping: dict[str, Any] = {}
        while pos < total:
            tok = tokens[pos]
            if tok.column != map_indent or tok.kind not in ("SCALAR", "PLAIN"):
                break
            if pos + 1 >= total or tokens[pos + 1].kind != ":":
                break
            key = str(coerce_yaml_scalar(tok, None))
            colon = tokens[pos + 1]
            pos += 2
            tag: str | None = None
            if pos < total and tokens[pos].kind == "TAG" and (
                tokens[pos].line == colon.line or tokens[pos].column > map_indent
            ):
                tag = tokens[pos].value
                pos += 1
            if pos >= total:
                mapping[key] = None
                break
            nxt = tokens[pos]
            if nxt.line == colon.line:
                if nxt.kind == "[":
                    mapping[key] = parse_flow_seq()
                elif nxt.kind == "{":
                    mapping[key] = parse_flow_map()
                elif nxt.kind in ("SCALAR", "PLAIN"):
                    pos += 1
                    mapping[key] = coerce_yaml_scalar(nxt, tag)
                else:
                    raise ValueError(f"unexpected token '{nxt.kind}' at line {nxt.line}")
            elif nxt.column > map_indent:
                if tag is not None and nxt.kind in ("SCALAR", "PLAIN"):
                    pos += 1
                    mapping[key] = coerce_yaml_scalar(nxt, tag)
                else:
                    mapping[key] = parse_block_node(map_indent)
            elif nxt.column == map_indent and nxt.kind == "-":
                mapping[key] = parse_block_seq(map_indent)
            else:
                mapping[key] = None
        return mapping

    def parse_block_node(parent_indent: int) -> Any:
        nonlocal pos
        if pos >= total:
            return None
        tag: str | None = None
        if tokens[pos].kind == "TAG":
            tag = tokens[pos].value
            pos += 1
            if pos >= total:
                raise ValueError("tag without value")
        tok = tokens[pos]
        if tok.column <= parent_indent:
            raise ValueError(f"invalid indentation at line {tok.line}")
        if tok.kind == "[":
            return parse_flow_seq()
        if tok.kind == "{":
            return parse_flow_map()
        if tok.kind == "-":
            return parse_block_seq(tok.column)
        if (
            tok.kind in ("SCALAR", "PLAIN")
            and pos + 1 < total
            and tokens[pos + 1].kind == ":"
            and tag is None
        ):
            return parse_block_map(tok.column)
        if tok.kind in ("SCALAR", "PLAIN"):
            pos += 1
            return coerce_yaml_scalar(tok, tag)
        raise ValueError(f"unexpected token '{tok.kind}' at line {tok.line}")

    root_value = parse_block_node(-1)
    if pos != total:
        raise ValueError(f"unexpected content at line {tokens[pos].line}")
    return root_value


def check_yaml_contract(
    root: Path, path: Path, source: str, violations: list[Violation]
) -> None:
    """Parse asyncapi.yaml and check all description and title fields."""
    try:
        value = parse_yaml_contract(source)
    except ValueError as error:
        raise RuntimeError(f"{display_path(root, path)}: invalid YAML: {error}") from error
    check_json_value(path, value, violations)


def check_svg(path: Path, source: str, violations: list[Violation]) -> None:
    """Check comments and text elements in an SVG file."""
    for index, line in enumerate(iter_lines(source)):
        number = index + 1
        comment_start = line.find("<!--")
        if comment_start != -1:
            text = trim_end_str(line[comment_start + 4 :], "-->").strip()
            check_text(path, number, text, violations)
        if "<text" in line:
            check_text(path, number, line, violations)


def run_check(root: Path) -> int:
    """Run all automated English checks under root and return an exit status."""
    files: list[Path] = []
    collect_files(root, root, files)
    files.sort()

    contract_paths = {
        root / "docs" / "asyncapi.yaml",
        root / "bridge" / "docs" / "asyncapi.yaml",
    }
    violations: list[Violation] = []

    for path in files:
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as error:
            raise RuntimeError(f"{display_path(root, path)}: {error}") from error
        except UnicodeDecodeError as error:
            raise RuntimeError(f"{display_path(root, path)}: {error}") from error

        ext = path.name.rsplit(".", 1)[-1]
        if ext == "md":
            check_markdown(path, source, violations)
        elif ext in ("rs", "java", "template", "gradle"):
            check_slash_comments(path, source, violations)
        elif ext == "sh":
            check_hash_comments(path, source, violations)
        elif ext == "toml":
            check_toml(path, source, violations)
        elif ext == "json":
            check_json(path, source, violations)
        elif ext == "yaml" and path in contract_paths:
            check_yaml_contract(root, path, source, violations)
        elif ext in ("yml", "yaml") and source.lstrip().startswith("{"):
            check_json(path, source, violations)
        elif ext in ("yml", "yaml"):
            check_yaml(path, source, violations)
        elif ext == "svg":
            check_svg(path, source, violations)

    if not violations:
        print("Simplified English: OK")
        return 0

    details = "\n".join(
        f"  {display_path(root, item.path)}:{item.line}: {item.message}"
        for item in violations
    )
    print(
        f"Simplified English: found {len(violations)} violation(s):\n{details}",
        file=sys.stderr,
    )
    return 1


def main(argv: list[str]) -> int:
    """Parse optional root directory argument and run checks."""
    if len(argv) > 2:
        print("usage: verify-ste.py [repository_root]", file=sys.stderr)
        return 2
    root = (
        Path(argv[1]).resolve()
        if len(argv) == 2
        else Path(__file__).resolve().parents[2]
    )
    try:
        return run_check(root)
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
