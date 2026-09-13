#!/usr/bin/env python3
"""skill-linter - validator format skill untuk Hermes Security Skills.

Memvalidasi file SKILL.md terhadap format standar (ROADMAP.md §7) dan
aturan linter (ROADMAP.md §7.1):

  1. frontmatter        name (lowercase-kebab), version (semver),
                        description (non-kosong), risk (low|medium|high|critical)
  2. required sections  semua H2 wajib ada persis; section
                        "Required Credentials" wajib hanya bila frontmatter
                        requires_credentials: true
  3. credential literal dilarang: token/secret/password/api_key yang diisi
                        nilai literal (panjang > 8, bukan placeholder)
  4. hardcode tool      instruksi "gunakan curl/nmap/nuclei/sqlmap/burp/caido"
                        dilarang - skill meminta capability, bukan tool (§4.1)
  5. capability         capability yang dirujuk di section "Required
                        Capabilities" harus terdaftar di allowlist

Implementasi Python 3 stdlib-only: frontmatter (subset YAML "key: value")
di-parse manual, tanpa dependensi PyYAML.

Pemakaian:
    python tools/skill-linter/lint.py <FILE.md | DIREKTORI> [...]

Direktori discan rekursif untuk semua file *.md.

Exit code:
    0  semua file lolos
    1  ada pelanggaran aturan
    2  error pemakaian (path tidak ditemukan / tidak ada file .md)
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Konstanta aturan (ROADMAP.md §7, §7.1)
# ---------------------------------------------------------------------------

REQUIRED_SECTIONS = (
    "Purpose",
    "When To Use",
    "When Not To Use",
    "Authorization Preconditions",
    "Required Context",
    "Required Capabilities",
    "Core Concepts",
    "Reasoning Workflow",
    "Allowed Operations",
    "Approval Requirements",
    "Forbidden Operations",
    "Evidence Requirements",
    "False Positive Checks",
    "Severity Guidance",
    "Stop Conditions",
    "Output Format",
    "Related Skills",
)

CREDENTIALS_SECTION = "Required Credentials"

# Allowlist capability - hardcode, disamakan dengan capabilities/registry.yaml
# (ROADMAP §5). Bila registry berubah, sinkronkan daftar ini.
ALLOWED_CAPABILITIES = (
    "inspect_request",
    "request_replay",
    "response_comparison",
    "list_history",
    "json_diff",
    "openapi_analysis",
)

VALID_RISKS = ("low", "medium", "high", "critical")

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SEMVER_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)

H2_RE = re.compile(r"^##\s+(.+?)\s*$")
FENCE_RE = re.compile(r"^\s*(?:```|~~~)")

# (d) instruksi hardcode tool (ROADMAP §4.1)
HARDTOOL_RE = re.compile(
    r"\bgunakan\s+(curl|nmap|nuclei|sqlmap|burp|caido)\b", re.IGNORECASE
)

# (c) credential literal - bentuk quoted setelah token/secret/password/api_key
CRED_KEY = r"token|secret|password|api_key|apikey|api-key"
CRED_QUOTED_RE = re.compile(
    r"\b(?P<key>" + CRED_KEY + r")\b\s*[:=]\s*"
    r"(?:\"(?P<dq>[^\"\s]{9,})\"|'(?P<sq>[^'\s]{9,})')",
    re.IGNORECASE,
)
# (c) credential literal - bentuk assignment tanpa kutip (kode/konfigurasi)
CRED_UNQUOTED_RE = re.compile(
    r"\b(?P<key>" + CRED_KEY + r")\b\s*=\s*(?P<val>[^\s'\"]{9,})",
    re.IGNORECASE,
)

# (e) kandidat capability: identifier snake_case di section Required Capabilities
SNAKE_CASE_RE = re.compile(r"\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b")

# Nilai yang jelas placeholder (bukan literal sungguhan)
PLACEHOLDER_HINTS = (
    "example",
    "contoh",
    "placeholder",
    "changeme",
    "dummy",
    "your-",
    "sample",
)
ALLCAPS_PLACEHOLDER_RE = re.compile(r"^[A-Z0-9_]+$")

FRONTMATTER_KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.*)$")
FOLDED_MARKERS = {">", "|", ">-", "|-", ">+", "|+"}
_TRUE_WORDS = {"true", "yes", "on"}
_FALSE_WORDS = {"false", "no", "off"}


class Violation:
    """Satu temuan linter pada sebuah file."""

    __slots__ = ("rule", "message")

    def __init__(self, rule: str, message: str) -> None:
        self.rule = rule
        self.message = message

    def __str__(self) -> str:
        return f"[{self.rule}] {self.message}"


# ---------------------------------------------------------------------------
# Parser frontmatter (subset YAML, tanpa PyYAML)
# ---------------------------------------------------------------------------


def _parse_scalar(raw: str) -> str:
    """Normalisasi nilai scalar frontmatter sederhana."""
    if raw[:1] in ('"', "'"):
        # nilai quoted sederhana: buang pasangan kutip pembuka/penutup
        if len(raw) >= 2 and raw[-1] == raw[0]:
            return raw[1:-1].strip()
        return raw
    # buang komentar inline " # ..." (konvensi §7, mis. requires_credentials: true    # BARU)
    cut = raw.find(" #")
    if cut != -1:
        raw = raw[:cut]
    return raw.strip()


def _parse_bool(value: str):
    v = value.strip().lower()
    if v in _TRUE_WORDS:
        return True
    if v in _FALSE_WORDS:
        return False
    return None


def split_frontmatter(lines):
    """Pisahkan blok frontmatter.

    Kembalikan (baris_frontmatter | None, index_baris_penutup | None, error | None).
    """
    if not lines or lines[0].strip() != "---":
        return None, None, "frontmatter tidak ditemukan (file harus diawali baris '---')"
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            return lines[1:i], i, None
    return None, None, "frontmatter tidak ditutup (baris '---' kedua tidak ditemukan)"


def parse_frontmatter(fm_lines):
    """Parse subset YAML 'key: value' dari baris frontmatter.

    Mendukung: komentar full-line, komentar inline " # ...", scalar quoted
    sederhana, dan folded/literal scalar ('>' atau '|' diikuti baris indent).
    Kembalikan (data: dict, errors: list[str]).
    """
    data = {}
    errors = []
    i = 0
    n = len(fm_lines)
    while i < n:
        line = fm_lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        m = FRONTMATTER_KEY_RE.match(line)
        if m is None:
            errors.append(f"baris frontmatter tidak valid: {stripped!r}")
            i += 1
            continue
        key = m.group(1)
        raw = m.group(2).strip()
        i += 1
        if raw in FOLDED_MARKERS:
            block = []
            while i < n and fm_lines[i][:1] in (" ", "\t"):
                text = fm_lines[i].strip()
                if text:
                    block.append(text)
                i += 1
            data[key] = " ".join(block)
        else:
            data[key] = _parse_scalar(raw)
    return data, errors


# ---------------------------------------------------------------------------
# Ekstraksi section H2 (fence-aware: '## ' di dalam code fence diabaikan)
# ---------------------------------------------------------------------------


def extract_sections(body_lines, line_offset):
    """Kumpulkan section H2 dari body dokumen.

    Kembalikan dict: title -> {"start": nomor baris absolut heading,
    "lines": [(nomor baris absolut, teks), ...]}.
    """
    sections = {}
    current = None
    in_fence = False
    for i, line in enumerate(body_lines):
        abs_no = line_offset + i + 1
        if FENCE_RE.match(line):
            in_fence = not in_fence
        if not in_fence:
            m = H2_RE.match(line)
            if m:
                title = m.group(1).strip()
                if title not in sections:
                    sections[title] = {"start": abs_no, "lines": []}
                current = title
                continue
        if current is not None:
            sections[current]["lines"].append((abs_no, line))
    return sections


# ---------------------------------------------------------------------------
# Aturan isi
# ---------------------------------------------------------------------------


def is_placeholder(value: str) -> bool:
    """True bila nilai credential jelas placeholder, bukan literal sungguhan."""
    v = value.strip()
    if v.startswith("<") and v.endswith(">"):
        return True
    if ALLCAPS_PLACEHOLDER_RE.match(v):
        return True
    low = v.lower()
    return any(hint in low for hint in PLACEHOLDER_HINTS)


def lint_text(text):
    """Lint satu konten skill. Kembalikan (violations: list[Violation], data_frontmatter)."""
    violations = []
    lines = text.splitlines()

    # ---- frontmatter ----
    fm_lines, close_idx, fm_error = split_frontmatter(lines)
    data = {}
    if fm_error is not None:
        violations.append(Violation("frontmatter", fm_error))
    else:
        data, fm_errors = parse_frontmatter(fm_lines)
        for err in fm_errors:
            violations.append(Violation("frontmatter", err))

    # ---- (a) skema frontmatter ----
    name = data.get("name")
    if name is None:
        violations.append(Violation("frontmatter", "field 'name' wajib ada"))
    elif not NAME_RE.match(str(name)):
        violations.append(
            Violation(
                "frontmatter",
                f"name '{name}' harus lowercase-kebab, mis. 'idor-and-bola'",
            )
        )

    version = data.get("version")
    if version is None:
        violations.append(Violation("frontmatter", "field 'version' wajib ada"))
    elif not SEMVER_RE.match(str(version)):
        violations.append(
            Violation("frontmatter", f"version '{version}' bukan semver, mis. '0.1.0'")
        )

    description = data.get("description")
    if description is None or not str(description).strip():
        violations.append(
            Violation(
                "frontmatter", "field 'description' wajib ada dan tidak boleh kosong"
            )
        )

    risk = data.get("risk")
    if risk is None:
        violations.append(Violation("frontmatter", "field 'risk' wajib ada"))
    elif str(risk).strip().lower() not in VALID_RISKS:
        violations.append(
            Violation(
                "frontmatter",
                f"risk '{risk}' harus salah satu dari: {' | '.join(VALID_RISKS)}",
            )
        )

    raw_creds = data.get("requires_credentials")
    needs_credentials_section = False
    if raw_creds is not None:
        parsed_bool = _parse_bool(str(raw_creds))
        if parsed_bool is None:
            violations.append(
                Violation(
                    "frontmatter",
                    f"requires_credentials harus true/false, dapat: '{raw_creds}'",
                )
            )
        else:
            needs_credentials_section = parsed_bool

    # ---- (b) required sections H2 ----
    body_offset = (close_idx + 1) if close_idx is not None else 0
    body_lines = lines[body_offset:] if close_idx is not None else lines
    sections = extract_sections(body_lines, body_offset)

    for required in REQUIRED_SECTIONS:
        if required not in sections:
            violations.append(
                Violation(
                    "missing-section",
                    f"Section H2 wajib tidak ditemukan: '{required}'",
                )
            )
    if needs_credentials_section and CREDENTIALS_SECTION not in sections:
        violations.append(
            Violation(
                "missing-section",
                f"frontmatter requires_credentials: true tetapi section "
                f"'{CREDENTIALS_SECTION}' tidak ada",
            )
        )

    # ---- (c) credential literal ----
    for idx, line in enumerate(lines, start=1):
        for m in CRED_QUOTED_RE.finditer(line):
            value = m.group("dq") or m.group("sq")
            if not is_placeholder(value):
                violations.append(
                    Violation(
                        "credential-literal",
                        f"baris {idx}: kemungkinan credential literal pada "
                        f"'{m.group('key')}' (nilai quoted). Simpan di credential "
                        f"store dan rujuk sebagai reference (ROADMAP §23)",
                    )
                )
        for m in CRED_UNQUOTED_RE.finditer(line):
            if not is_placeholder(m.group("val")):
                violations.append(
                    Violation(
                        "credential-literal",
                        f"baris {idx}: kemungkinan credential literal pada "
                        f"'{m.group('key')}' (assignment tanpa kutip). Simpan di "
                        f"credential store dan rujuk sebagai reference (ROADMAP §23)",
                    )
                )

    # ---- (d) instruksi hardcode tool ----
    for idx, line in enumerate(lines, start=1):
        for m in HARDTOOL_RE.finditer(line):
            violations.append(
                Violation(
                    "hardcoded-tool",
                    f"baris {idx}: instruksi hardcode tool 'gunakan "
                    f"{m.group(1).lower()}' - skill meminta capability, bukan tool "
                    f"(ROADMAP §4.1)",
                )
            )

    # ---- (e) capability harus terdaftar di allowlist ----
    cap_section = sections.get("Required Capabilities")
    if cap_section is not None:
        reported = set()
        for abs_no, line_text in cap_section["lines"]:
            for m in SNAKE_CASE_RE.finditer(line_text):
                token = m.group(0)
                if token in reported:
                    continue
                reported.add(token)
                if token not in ALLOWED_CAPABILITIES:
                    violations.append(
                        Violation(
                            "unknown-capability",
                            f"baris {abs_no}: capability '{token}' tidak terdaftar "
                            f"di allowlist ({', '.join(ALLOWED_CAPABILITIES)}) - "
                            f"sinkronkan capabilities/registry.yaml atau perbaiki referensi",
                        )
                    )

    return violations, data


def lint_file(path: Path):
    """Lint satu file. Kembalikan (violations, warnings)."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        return [Violation("io", f"gagal membaca file: {exc}")], []

    violations, data = lint_text(text)

    warnings = []
    name = data.get("name")
    if path.name == "SKILL.md" and isinstance(name, str) and NAME_RE.match(name):
        parent = path.parent.name
        if parent and NAME_RE.match(parent) and parent != name:
            warnings.append(
                Violation(
                    "naming-hint",
                    f"name frontmatter '{name}' berbeda dari nama direktori "
                    f"'{parent}' (peringatan, tidak fatal)",
                )
            )
    return violations, warnings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def collect_files(paths):
    """Kumpulkan file .md dari daftar path (file langsung atau direktori rekursif).

    Kembalikan (files, errors).
    """
    files = []
    errors = []
    seen = set()
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            found = sorted(
                (f for f in p.rglob("*") if f.is_file() and f.suffix.lower() == ".md"),
                key=lambda x: str(x).lower(),
            )
            for f in found:
                key = f.resolve()
                if key not in seen:
                    seen.add(key)
                    files.append(f)
        elif p.is_file():
            key = p.resolve()
            if key not in seen:
                seen.add(key)
                files.append(p)
        else:
            errors.append(f"path tidak ditemukan: {p}")
    return files, errors


def print_report(path: Path, violations, warnings) -> None:
    print(str(path))
    if not violations and not warnings:
        print("   OK")
        return
    for w in warnings:
        print(f"   WARN {w}")
    for v in violations:
        print(f"   {v}")


def _force_utf8_stdio() -> None:
    # Windows: stdout/stderr untuk pipe default memakai encoding locale
    # (mis. cp1252) dan bisa gagal pada karakter seperti '§' atau '—'.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv=None) -> int:
    _force_utf8_stdio()
    parser = argparse.ArgumentParser(
        prog="skill-linter",
        description=(
            "Validator format SKILL.md untuk Hermes Security Skills "
            "(ROADMAP.md §7, §7.1)."
        ),
    )
    parser.add_argument(
        "paths",
        nargs="+",
        metavar="PATH",
        help="file .md atau direktori (discan rekursif untuk *.md)",
    )
    args = parser.parse_args(argv)

    files, path_errors = collect_files(args.paths)
    for err in path_errors:
        print(f"ERROR: {err}", file=sys.stderr)
    if path_errors:
        return 2
    if not files:
        print("ERROR: tidak ada file .md yang ditemukan pada target", file=sys.stderr)
        return 2

    failed = 0
    for path in files:
        violations, warnings = lint_file(path)
        print_report(path, violations, warnings)
        if violations:
            failed += 1

    total = len(files)
    passed = total - failed
    print("")
    print(f"Ringkasan: {total} file diperiksa, {passed} lolos, {failed} gagal")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
