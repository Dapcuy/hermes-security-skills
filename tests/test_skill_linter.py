"""Unit test untuk tools/skill-linter/lint.py (ROADMAP §7.1).

Jalankan dari root project:

    python -m unittest tests.test_skill_linter
    python -m unittest discover tests
"""

import importlib.util
import subprocess
import sys
import tempfile
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
                capabilities_body="- `inspect_request` — baca detail request.",
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

    def test_list_history_is_control_tool_not_capability(self):
        violations = self.lint_text(
            make_skill_text(capabilities_body="- `list_history` — baca riwayat event store.")
        )
        self.assertIn("unknown-capability", self.rules(violations))

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


class RoutingReferenceUnitTest(unittest.TestCase):
    """Unit test helper routing-reference check (FORWARD + REVERSE)."""

    def test_extract_routing_tokens(self):
        text = (
            "| a | `idor-and-bola` | `granted` |\n"
            "| b | `scope validation` | `ROADMAP.md` |\n"
            "| c | `request_replay` | `bfla` |\n"
        )
        tokens = lint.extract_routing_tokens(text)
        self.assertEqual(tokens, {"idor-and-bola", "granted", "bfla"})

    def test_referenced_skills_exclude_deferred_category_state_capability(self):
        text = (
            "`cloud-security` `mobile-security` `binary-analysis` `firmware-analysis` "
            "`web` `api` `granted` `pending` `confirmed` `suspected` `offline-lab` "
            "`request_replay` `ssrf-analysis`"
        )
        referenced = lint.routing_referenced_skills(text)
        self.assertEqual(referenced, {"ssrf-analysis"})

    def test_forward_missing_folder_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            skills = root / "skills" / "web" / "real-skill"
            skills.mkdir(parents=True)
            (skills / "SKILL.md").write_text(
                make_skill_text(name="real-skill"), encoding="utf-8"
            )
            (root / "ROUTING.md").write_text(
                "# Routing\n\n| x | `real-skill` | — |\n| y | `phantom-skill` | — |\n",
                encoding="utf-8",
            )
            violations = lint.check_routing_references(
                root / "skills", root / "ROUTING.md"
            )
            self.assertEqual(len(violations), 1, [str(v) for v in violations])
            self.assertEqual(violations[0].rule, "routing-reference")
            self.assertIn("FORWARD", violations[0].message)
            self.assertIn("phantom-skill", violations[0].message)

    def test_reverse_unrouted_skill_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            routed = root / "skills" / "web" / "routed-skill"
            orphan = root / "skills" / "web" / "orphan-skill"
            orphan.mkdir(parents=True)
            routed.mkdir(parents=True)
            (routed / "SKILL.md").write_text(
                make_skill_text(name="routed-skill"), encoding="utf-8"
            )
            (orphan / "SKILL.md").write_text(
                make_skill_text(name="orphan-skill"), encoding="utf-8"
            )
            (root / "ROUTING.md").write_text(
                "# Routing\n\n| x | `routed-skill` | — |\n", encoding="utf-8"
            )
            violations = lint.check_routing_references(
                root / "skills", root / "ROUTING.md"
            )
            self.assertEqual(len(violations), 1, [str(v) for v in violations])
            self.assertIn("REVERSE", violations[0].message)
            self.assertIn("orphan-skill", violations[0].message)

    def test_happy_path_and_deferred_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "skills" / "web" / "real-skill"
            real.mkdir(parents=True)
            (real / "SKILL.md").write_text(
                make_skill_text(name="real-skill"), encoding="utf-8"
            )
            (root / "ROUTING.md").write_text(
                # deferred skill dirujuk tapi memang belum punya SKILL.md -
                # ditunda sesuai keputusan maintainer, tidak boleh error.
                "# Routing\n\n| x | `real-skill` | — |\n"
                "| y | `cloud-security` | `mobile-security` |\n"
                "| z | `binary-analysis` | `firmware-analysis` |\n"
                "| w | `granted` `pending` `offline-lab` `web` | — |\n",
                encoding="utf-8",
            )
            violations = lint.check_routing_references(
                root / "skills", root / "ROUTING.md"
            )
            self.assertEqual(violations, [], [str(v) for v in violations])


class RoutingReferenceCliTest(unittest.TestCase):
    """Perilaku CLI end-to-end untuk routing-reference check."""

    def _make_repo(self, root: Path, routing_rows: str, skills=("real-skill",)):
        skills_root = root / "skills" / "web"
        skills_root.mkdir(parents=True)
        for name in skills:
            d = skills_root / name
            d.mkdir()
            (d / "SKILL.md").write_text(make_skill_text(name=name), encoding="utf-8")
        (root / "ROUTING.md").write_text(
            "# Routing\n\n" + routing_rows, encoding="utf-8"
        )
        return skills_root

    def test_phantom_route_fails_with_clear_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            skills_root = self._make_repo(
                Path(tmp),
                "| x | `real-skill` | — |\n| y | `phantom-skill` | — |\n",
            )
            res = run_linter(skills_root)
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            self.assertIn("routing-reference", res.stdout)
            self.assertIn("FORWARD", res.stdout)
            self.assertIn("phantom-skill", res.stdout)
            self.assertIn("1 pelanggaran", res.stdout)

    def test_unrouted_skill_fails_with_clear_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            skills_root = self._make_repo(
                Path(tmp),
                "| x | `real-skill` | — |\n",
                skills=("real-skill", "orphan-skill"),
            )
            res = run_linter(skills_root)
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            self.assertIn("routing-reference", res.stdout)
            self.assertIn("REVERSE", res.stdout)
            self.assertIn("orphan-skill", res.stdout)

    def test_deferred_tokens_excluded_and_consistent_repo_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            skills_root = self._make_repo(
                Path(tmp),
                "| x | `real-skill` | — |\n"
                "| y | `cloud-security` `mobile-security` | — |\n"
                "| z | `binary-analysis` `firmware-analysis` | — |\n"
                "| w | `granted` `offline-lab` | — |\n",
            )
            res = run_linter(skills_root)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn("routing-reference check (FORWARD + REVERSE)", res.stdout)
            self.assertIn("routing-reference: OK", res.stdout)
            self.assertIn("1 file diperiksa, 1 lolos, 0 gagal; routing-reference: OK", res.stdout)


if __name__ == "__main__":
    unittest.main()
