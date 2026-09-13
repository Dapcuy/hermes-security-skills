"""Unit test untuk tools/skill-linter/lint.py (ROADMAP §7.1).

Jalankan dari root project:

    python -m unittest tests.test_skill_linter
    python -m unittest discover tests
"""

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINT_SCRIPT = ROOT / "tools" / "skill-linter" / "lint.py"
CORE_SKILLS_DIR = ROOT / "skills" / "core"
FIXTURES_DIR = ROOT / "tests" / "fixtures"

VALID_FIXTURE = FIXTURES_DIR / "valid" / "skill-example-good" / "SKILL.md"
BAD_SECTIONS_FIXTURE = FIXTURES_DIR / "invalid" / "skill-bad-sections" / "SKILL.md"
BAD_CREDENTIAL_FIXTURE = FIXTURES_DIR / "invalid" / "skill-bad-credential" / "SKILL.md"


def _load_lint_module():
    spec = importlib.util.spec_from_file_location("hermes_lint_under_test", LINT_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lint = _load_lint_module()


def run_linter(*targets):
    """Jalankan linter sebagai CLI (subprocess) dari root project."""
    return subprocess.run(
        [sys.executable, str(LINT_SCRIPT)] + [str(t) for t in targets],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(ROOT),
    )


def make_skill_text(
    *,
    name="inline-test-skill",
    risk="low",
    sections=None,
    extra_frontmatter="",
    capabilities_body="Tidak ada. Fixture ini tidak meminta capability apa pun.",
):
    """Susun teks SKILL.md minimal yang valid untuk pengujian aturan tunggal."""
    names = list(lint.REQUIRED_SECTIONS) if sections is None else list(sections)
    parts = []
    for section in names:
        body = (
            capabilities_body if section == "Required Capabilities" else f"- isi {section}"
        )
        parts.append(f"## {section}\n\n{body}")
    frontmatter = (
        "---\n"
        f"name: {name}\n"
        "description: >\n  Skill inline untuk unit test linter.\n"
        "version: 0.1.0\n"
        f"risk: {risk}\n"
        f"{extra_frontmatter}"
        "---\n"
    )
    return frontmatter + "\n# Inline Test Skill\n\n" + "\n\n".join(parts) + "\n"


class FrontmatterPatternTest(unittest.TestCase):
    """Pola regex dasar: name kebab-case, semver, placeholder."""

    def test_name_rules(self):
        for good in ("idor-and-bola", "skill-example-good", "api", "a1-b2"):
            self.assertTrue(lint.NAME_RE.match(good), good)
        for bad in ("Idor-And-Bola", "idor_and_bola", "-leading-dash", "trailing-", "double--dash"):
            self.assertFalse(lint.NAME_RE.match(bad), bad)

    def test_semver_rules(self):
        for good in ("0.1.0", "1.2.3", "2.1.0", "1.0.0-rc.1", "1.0.0+build.5"):
            self.assertTrue(lint.SEMVER_RE.match(good), good)
        for bad in ("1.0", "v1.0.0", "1.0.0.0", "abc", "01.0.0", ""):
            self.assertFalse(lint.SEMVER_RE.match(bad), bad)

    def test_placeholder_detection(self):
        for placeholder in ("<CONTOH>", "<EXAMPLE>", "example-value", "YOUR_API_KEY", "CHANGEME"):
            self.assertTrue(lint.is_placeholder(placeholder), placeholder)
        for literal in ("sk-live-9f8e7d6c5b4a3210", "ghp_ReallyLongToken1234", "P@ssw0rd-Prod-2026"):
            self.assertFalse(lint.is_placeholder(literal), literal)


class FrontmatterParserTest(unittest.TestCase):
    """Parser frontmatter subset YAML tanpa PyYAML."""

    def test_split_and_parse_basic(self):
        lines = ["---", "name: idor-and-bola", "version: 0.1.0", "risk: medium", "---", "# T"]
        fm, close_idx, err = lint.split_frontmatter(lines)
        self.assertIsNone(err)
        data, errors = lint.parse_frontmatter(fm)
        self.assertEqual(errors, [])
        self.assertEqual(data["name"], "idor-and-bola")
        self.assertEqual(data["risk"], "medium")
        self.assertEqual(close_idx, 4)

    def test_folded_description_and_inline_comment(self):
        lines = [
            "---",
            "name: idor-and-bola",
            "description: >",
            "  Use when analyzing object-level",
            "  authorization or tenant isolation.",
            "requires_credentials: true    # BARU: jika butuh test account",
            "---",
        ]
        fm, _, err = lint.split_frontmatter(lines)
        self.assertIsNone(err)
        data, errors = lint.parse_frontmatter(fm)
        self.assertEqual(errors, [])
        self.assertEqual(
            data["description"],
            "Use when analyzing object-level authorization or tenant isolation.",
        )
        self.assertEqual(data["requires_credentials"], "true")

    def test_missing_and_unclosed_frontmatter(self):
        _, _, err = lint.split_frontmatter(["# tanpa frontmatter"])
        self.assertIn("frontmatter tidak ditemukan", err)
        _, _, err2 = lint.split_frontmatter(["---", "name: x"])
        self.assertIn("tidak ditutup", err2)


class InlineRuleTest(unittest.TestCase):
    """Aturan tunggal diuji langsung lewat lint_text()."""

    @staticmethod
    def rules(violations):
        return {v.rule for v in violations}

    def lint_text(self, text):
        violations, _data = lint.lint_text(text)
        return violations

    def test_minimal_skill_passes(self):
        violations = self.lint_text(make_skill_text())
        self.assertEqual([str(v) for v in violations], [])

    def test_missing_sections_detected(self):
        sections = [
            s for s in lint.REQUIRED_SECTIONS if s not in ("Stop Conditions", "Severity Guidance")
        ]
        violations = self.lint_text(make_skill_text(sections=sections))
        self.assertIn("missing-section", self.rules(violations))
        messages = " ".join(v.message for v in violations)
        self.assertIn("Stop Conditions", messages)
        self.assertIn("Severity Guidance", messages)

    def test_requires_credentials_true_needs_section(self):
        violations = self.lint_text(
            make_skill_text(extra_frontmatter="requires_credentials: true\n")
        )
        self.assertIn("missing-section", self.rules(violations))
        messages = " ".join(v.message for v in violations)
        self.assertIn("Required Credentials", messages)

    def test_requires_credentials_true_with_section_passes(self):
        violations = self.lint_text(
            make_skill_text(
                sections=list(lint.REQUIRED_SECTIONS) + ["Required Credentials"],
                extra_frontmatter="requires_credentials: true\n",
                capabilities_body="- `list_history` — baca riwayat event store.",
            )
        )
        self.assertEqual(self.rules(violations) & {"missing-section", "frontmatter"}, set())
        self.assertEqual(self.rules(violations) & {"unknown-capability"}, set())

    def test_credential_literal_detected(self):
        text = make_skill_text().replace(
            "- isi Evidence Requirements", '- api_key = "sk-live-9f8e7d6c5b4a3210"'
        )
        violations = self.lint_text(text)
        self.assertIn("credential-literal", self.rules(violations))

    def test_credential_literal_in_code_fence_detected(self):
        text = make_skill_text().replace(
            "- isi Evidence Requirements",
            "- Contoh yang salah:\n\n  ```\n  password=SuperSecretProdValue1\n  ```",
        )
        violations = self.lint_text(text)
        self.assertIn("credential-literal", self.rules(violations))

    def test_credential_placeholder_not_flagged(self):
        text = make_skill_text().replace(
            "- isi Evidence Requirements", '- api_key = "example-value"'
        )
        violations = self.lint_text(text)
        self.assertNotIn("credential-literal", self.rules(violations))

    def test_hardcoded_tool_detected(self):
        text = make_skill_text().replace(
            "- isi Allowed Operations", "- Gunakan curl untuk mengirim request uji."
        )
        violations = self.lint_text(text)
        self.assertIn("hardcoded-tool", self.rules(violations))
        messages = " ".join(v.message for v in violations)
        self.assertIn("curl", messages)

    def test_hardcoded_tool_case_insensitive(self):
        text = make_skill_text().replace(
            "- isi Forbidden Operations", "- GUNAKAN SQLMAP terhadap target produksi."
        )
        violations = self.lint_text(text)
        self.assertIn("hardcoded-tool", self.rules(violations))

    def test_unknown_capability_detected(self):
        violations = self.lint_text(
            make_skill_text(capabilities_body="- `free_port_scan` — pemindaian port bebas.")
        )
        self.assertIn("unknown-capability", self.rules(violations))
        messages = " ".join(v.message for v in violations)
        self.assertIn("free_port_scan", messages)

    def test_allowed_capabilities_not_flagged(self):
        body = "\n".join(f"- `{cap}` — capability resmi." for cap in lint.ALLOWED_CAPABILITIES)
        violations = self.lint_text(make_skill_text(capabilities_body=body))
        self.assertNotIn("unknown-capability", self.rules(violations))

    def test_invalid_risk_rejected(self):
        violations = self.lint_text(make_skill_text(risk="medium-high"))
        self.assertIn("frontmatter", self.rules(violations))

    def test_invalid_name_rejected(self):
        violations = self.lint_text(make_skill_text(name="Bad_Name"))
        self.assertIn("frontmatter", self.rules(violations))

    def test_missing_frontmatter_reports_frontmatter_rule(self):
        violations = self.lint_text("# Tanpa frontmatter\n\n## Purpose\n\n- isi\n")
        self.assertIn("frontmatter", self.rules(violations))


class CliFixtureTest(unittest.TestCase):
    """Perilaku CLI end-to-end terhadap fixture."""

    def test_valid_fixture_exits_zero(self):
        res = run_linter(VALID_FIXTURE)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("skill-example-good", res.stdout)
        self.assertIn("1 file diperiksa, 1 lolos, 0 gagal", res.stdout)

    def test_invalid_fixtures_exit_one_with_expected_rule(self):
        cases = (
            (BAD_SECTIONS_FIXTURE, "missing-section", "Stop Conditions"),
            (BAD_CREDENTIAL_FIXTURE, "credential-literal", "api_key"),
        )
        for fixture, rule, needle in cases:
            with self.subTest(fixture=fixture.parent.name):
                res = run_linter(fixture)
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn(rule, res.stdout)
                self.assertIn(needle, res.stdout)
                self.assertIn("0 lolos, 1 gagal", res.stdout)

    def test_bad_sections_fixture_fails_precisely_on_sections(self):
        res = run_linter(BAD_SECTIONS_FIXTURE)
        self.assertEqual(res.returncode, 1)
        self.assertNotIn("credential-literal", res.stdout)
        self.assertNotIn("unknown-capability", res.stdout)
        self.assertNotIn("hardcoded-tool", res.stdout)
        self.assertIn("False Positive Checks", res.stdout)

    def test_bad_credential_fixture_fails_precisely_on_credential(self):
        res = run_linter(BAD_CREDENTIAL_FIXTURE)
        self.assertEqual(res.returncode, 1)
        self.assertNotIn("missing-section", res.stdout)
        self.assertNotIn("hardcoded-tool", res.stdout)
        self.assertNotIn("unknown-capability", res.stdout)
        # Nilai literal tidak boleh di-echo di laporan linter.
        self.assertNotIn("sk-live", res.stdout)

    def test_directory_scan_and_missing_path_exit_codes(self):
        res = run_linter(FIXTURES_DIR / "valid")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("1 file diperiksa, 1 lolos, 0 gagal", res.stdout)

        res_missing = run_linter(FIXTURES_DIR / "tidak-ada")
        self.assertEqual(res_missing.returncode, 2)


class CoreSkillsTest(unittest.TestCase):
    """Guard: seluruh core skills Tier 1 harus lolos linter (ROADMAP §32)."""

    def test_all_core_skills_pass(self):
        self.assertTrue(CORE_SKILLS_DIR.is_dir(), "skills/core harus ada")
        res = run_linter(CORE_SKILLS_DIR)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("7 file diperiksa, 7 lolos, 0 gagal", res.stdout)


if __name__ == "__main__":
    unittest.main()
