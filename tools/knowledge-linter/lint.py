#!/usr/bin/env python3
"""Validate the curated knowledge-base contract.

The validator deliberately parses only frontmatter. Markdown bodies are data,
not instructions, and may contain quoted security examples. The official
knowledge directories are scanned fail-closed for malformed entries, unsafe
provenance, lifecycle/path mismatches, and duplicate IDs.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

KNOWLEDGE_DIRS = ("canonical", "research", "methodology", "false-positives", "reviewed")
STATES = {"captured", "normalized", "proposed", "reviewed", "trusted", "stale", "archived"}
TRUSTS = {"trusted", "untrusted"}
ID_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
YAML_NUMBER_RE = re.compile(r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$")
REQUIRED = ("id", "title", "category", "source", "confidence", "state", "last_reviewed")


class Violation:
    def __init__(self, path: Path, message: str) -> None:
        self.path = path
        self.message = message

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


def scalar(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    comment = re.search(r"\s+#", value)
    if comment:
        value = value[: comment.start()].rstrip()
    return value


def is_unquoted_typed(raw: str) -> bool:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return False
    comment = re.search(r"\s+#", value)
    if comment:
        value = value[: comment.start()].rstrip()
    return value.casefold() in {"true", "false", "null", "~"} or bool(YAML_NUMBER_RE.fullmatch(value))


def is_rfc3339(value: str) -> bool:
    if not RFC3339_RE.fullmatch(value):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def parse_frontmatter(
    path: Path,
) -> tuple[dict[str, str], dict[str, str], set[str], set[str], str | None]:
    lines = path.read_text(encoding="utf-8").splitlines()
    empty = ({}, {}, set(), set())
    if not lines or lines[0].strip() != "---":
        return (*empty, "frontmatter must start with '---'")
    try:
        end = next(i for i in range(1, len(lines)) if lines[i].strip() == "---")
    except StopIteration:
        return (*empty, "frontmatter must close with '---'")

    top: dict[str, str] = {}
    nested: dict[str, str] = {}
    typed_top: set[str] = set()
    typed_nested: set[str] = set()
    current_map: str | None = None
    provenance_seen = False
    for line_no, line in enumerate(lines[1:end], start=2):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        leading = line[: len(line) - len(line.lstrip(" \t"))]
        if "\t" in leading:
            return (*empty, f"line {line_no}: tab indentation is forbidden")
        indent = len(line) - len(line.lstrip(" "))
        if indent and current_map == "provenance":
            raw = line.strip()
            if ":" not in raw:
                return (*empty, f"line {line_no}: malformed nested field")
            key, value = raw.split(":", 1)
            key = key.strip()
            if key not in {"source", "trust"}:
                return (*empty, f"line {line_no}: unknown provenance field {key!r}")
            if key in nested:
                return (*empty, f"line {line_no}: duplicate provenance field {key!r}")
            nested[key] = scalar(value)
            if is_unquoted_typed(value):
                typed_nested.add(key)
            continue
        if indent:
            return (*empty, f"line {line_no}: unexpected indentation")
        if ":" not in line:
            return (*empty, f"line {line_no}: expected key: value")
        key, value = line.split(":", 1)
        key = key.strip()
        if key == "provenance":
            if provenance_seen:
                return (*empty, f"line {line_no}: duplicate field 'provenance'")
            if scalar(value):
                return (*empty, f"line {line_no}: provenance must be a map")
            provenance_seen = True
            current_map = "provenance"
            continue
        current_map = None
        if key in top:
            return (*empty, f"line {line_no}: duplicate field {key!r}")
        top[key] = scalar(value)
        if is_unquoted_typed(value):
            typed_top.add(key)
    return top, nested, typed_top, typed_nested, None


def validate_entry(path: Path, directory: str) -> tuple[str | None, list[str]]:
    errors: list[str] = []
    try:
        top, provenance, typed_top, typed_nested, error = parse_frontmatter(path)
    except (OSError, UnicodeError) as exc:
        return None, [f"cannot read entry: {exc}"]
    if error:
        return None, [error]

    for key in {"id", "title", "category", "source", "state", "last_reviewed", "expires_at"}:
        if key in typed_top:
            errors.append(f"{key} must be a string")
    for key in {"source", "trust"}:
        if key in typed_nested:
            errors.append(f"provenance.{key} must be a string")

    for key in REQUIRED:
        if not top.get(key, "").strip():
            errors.append(f"missing required field {key}")
    entry_id = top.get("id", "").strip()
    if entry_id and not ID_RE.fullmatch(entry_id):
        errors.append("id must be a lowercase slug")
    if top.get("confidence", ""):
        try:
            confidence = float(top["confidence"])
            if not 0 <= confidence <= 1:
                errors.append("confidence must be between 0 and 1")
        except ValueError:
            errors.append("confidence must be numeric")
    state = top.get("state", "").strip().lower()
    if state and state not in STATES:
        errors.append(f"invalid state {state!r}")
    reviewed = top.get("last_reviewed", "").strip()
    if reviewed and not is_rfc3339(reviewed):
        errors.append("last_reviewed must be RFC3339")
    if "expires_at" in top and not is_rfc3339(top["expires_at"].strip()):
        errors.append("expires_at must be RFC3339")

    source = provenance.get("source", "").strip()
    source_marker = source.casefold()
    trust = provenance.get("trust", "").strip().casefold()
    if not source:
        errors.append("missing required field provenance.source")
    if trust not in TRUSTS:
        errors.append("provenance.trust must be trusted or untrusted")
    if source_marker == "target-controlled" or trust == "untrusted":
        errors.append("untrusted or target-controlled provenance is forbidden")

    allowed = {
        "canonical": {"trusted", "stale", "archived"},
        "reviewed": {"reviewed", "stale", "archived"},
        "research": {"captured", "normalized", "proposed", "stale", "archived"},
        "methodology": {"reviewed", "trusted", "stale", "archived"},
        "false-positives": {"reviewed", "trusted", "stale", "archived"},
    }
    if state and state not in allowed[directory]:
        errors.append(f"state {state!r} is inconsistent with directory {directory!r}")
    return entry_id or None, errors


def collect_entries(root: Path) -> tuple[list[tuple[Path, str, str]], list[Violation]]:
    entries: list[tuple[Path, str, str]] = []
    violations: list[Violation] = []
    for directory in KNOWLEDGE_DIRS:
        current = root / directory
        if current.is_symlink():
            violations.append(Violation(current, "symlink official knowledge directories are forbidden"))
            continue
        if not current.exists():
            continue
        if not current.is_dir():
            violations.append(Violation(current, "official knowledge path is not a directory"))
            continue
        try:
            children = sorted(current.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            violations.append(Violation(current, f"cannot enumerate directory: {exc}"))
            continue
        for path in children:
            if path.is_symlink():
                violations.append(Violation(path, "symlink entries are forbidden"))
                continue
            if path.is_dir():
                violations.append(Violation(path, "nested directories are forbidden"))
                continue
            if path.name in {"README.md", ".gitkeep"}:
                continue
            if path.suffix != ".md":
                violations.append(Violation(path, "unexpected non-markdown file"))
                continue
            entry_id, errors = validate_entry(path, directory)
            for error in errors:
                violations.append(Violation(path, error))
            if entry_id:
                if path.stem != entry_id:
                    violations.append(Violation(path, f"filename stem must match id {entry_id!r}"))
                entries.append((path, directory, entry_id))
    return entries, violations


def lint(root: Path) -> list[Violation]:
    entries, violations = collect_entries(root)
    seen: dict[str, Path] = {}
    for path, _directory, entry_id in entries:
        if entry_id in seen:
            violations.append(Violation(path, f"duplicate id {entry_id!r}; already defined at {seen[entry_id]}"))
        else:
            seen[entry_id] = path
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="knowledge/ directory")
    args = parser.parse_args(argv)
    root = args.path
    if root.is_symlink() or not root.exists() or not root.is_dir():
        print(f"knowledge-linter: path is not a non-symlink directory: {root}", file=sys.stderr)
        return 2
    violations = lint(root)
    if violations:
        for violation in violations:
            print(f"[knowledge-contract] {violation}")
        print(f"knowledge-linter: {len(violations)} violation(s)")
        return 1
    count = sum(1 for directory in KNOWLEDGE_DIRS if (root / directory).is_dir() for path in (root / directory).glob("*.md") if path.name != "README.md")
    print(f"knowledge-linter: passed ({count} entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
