"""Contract tests for the curated knowledge linter."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from os import symlink
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LINTER = ROOT / "tools" / "knowledge-linter" / "lint.py"


def write_entry(root: Path, directory: str, name: str, *, entry_id: str, state: str = "reviewed", trust: str = "trusted") -> None:
    path = root / directory / f"{name}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"""---
id: {entry_id}
title: Example reviewed reference
category: methodology
source: manual-reference
confidence: 0.9
state: {state}
last_reviewed: 2026-09-15T00:00:00Z
provenance:
  source: manual
  trust: {trust}
---

Body contains a reviewed reference.
""",
        encoding="utf-8",
    )


class KnowledgeLinterTests(unittest.TestCase):
    def run_linter(self, path: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(LINTER), str(path)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_repository_knowledge_passes(self) -> None:
        result = self.run_linter(ROOT / "knowledge")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_duplicate_ids_fail_closed_across_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_entry(root, "reviewed", "one", entry_id="same-id")
            write_entry(root, "canonical", "two", entry_id="same-id", state="trusted")
            result = self.run_linter(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate", result.stdout.lower())

    def test_untrusted_entry_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_entry(root, "research", "candidate", entry_id="candidate", state="proposed", trust="untrusted")
            result = self.run_linter(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("untrusted", result.stdout.lower())

    def test_state_directory_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_entry(root, "research", "trusted", entry_id="trusted", state="trusted")
            result = self.run_linter(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("directory", result.stdout.lower())

    def test_duplicate_nested_provenance_keys_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "reviewed" / "duplicate-provenance.md"
            path.parent.mkdir(parents=True)
            path.write_text(
                "---\n"
                "id: duplicate-provenance\n"
                "title: Example\n"
                "category: methodology\n"
                "source: manual\n"
                "confidence: 0.9\n"
                "state: reviewed\n"
                "last_reviewed: 2026-09-15T00:00:00Z\n"
                "provenance:\n"
                "  source: target-controlled\n"
                "  source: manual\n"
                "  trust: trusted\n"
                "---\n\nBody.\n",
                encoding="utf-8",
            )
            result = self.run_linter(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate", result.stdout.lower())

    def test_target_controlled_case_variant_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_entry(root, "reviewed", "case-variant", entry_id="case-variant")
            path = root / "reviewed" / "case-variant.md"
            path.write_text(path.read_text(encoding="utf-8").replace("source: manual", "source: TARGET-CONTROLLED"), encoding="utf-8")
            result = self.run_linter(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("target-controlled", result.stdout.lower())

    def test_strict_rfc3339_timestamps_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_entry(root, "reviewed", "bad-time", entry_id="bad-time")
            path = root / "reviewed" / "bad-time.md"
            path.write_text(path.read_text(encoding="utf-8").replace("2026-09-15T00:00:00Z", "2026-09-15"), encoding="utf-8")
            result = self.run_linter(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rfc3339", result.stdout.lower())

    def test_malformed_expires_at_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_entry(root, "reviewed", "bad-expiry", entry_id="bad-expiry")
            path = root / "reviewed" / "bad-expiry.md"
            text = path.read_text(encoding="utf-8").replace(
                "last_reviewed: 2026-09-15T00:00:00Z",
                "last_reviewed: 2026-09-15T00:00:00Z\nexpires_at: 2026-09-15",
            )
            path.write_text(text, encoding="utf-8")
            result = self.run_linter(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expires_at", result.stdout.lower())

    def test_nested_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_entry(root, "reviewed/nested", "entry", entry_id="entry")
            result = self.run_linter(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nested", result.stdout.lower())

    def test_target_controlled_inline_comment_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_entry(root, "reviewed", "inline-comment", entry_id="inline-comment")
            path = root / "reviewed" / "inline-comment.md"
            text = path.read_text(encoding="utf-8").replace(
                "  source: manual",
                "  source: target-controlled # reviewer note",
            )
            path.write_text(text, encoding="utf-8")
            result = self.run_linter(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("target-controlled", result.stdout.lower())

    def test_duplicate_provenance_blocks_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "reviewed" / "duplicate-block.md"
            path.parent.mkdir(parents=True)
            path.write_text(
                "---\n"
                "id: duplicate-block\n"
                "title: Example\n"
                "category: methodology\n"
                "source: manual\n"
                "confidence: 0.9\n"
                "state: reviewed\n"
                "last_reviewed: 2026-09-15T00:00:00Z\n"
                "provenance:\n"
                "  source: manual\n"
                "provenance:\n"
                "  trust: trusted\n"
                "---\n\nBody.\n",
                encoding="utf-8",
            )
            result = self.run_linter(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate", result.stdout.lower())

    def test_tab_indented_scalar_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "reviewed" / "tabbed.md"
            path.parent.mkdir(parents=True)
            path.write_text(
                "---\n"
                "id: tabbed\n"
                "\ttitle: Example\n"
                "category: methodology\n"
                "source: manual\n"
                "confidence: 0.9\n"
                "state: reviewed\n"
                "last_reviewed: 2026-09-15T00:00:00Z\n"
                "provenance:\n"
                "  source: manual\n"
                "  trust: trusted\n"
                "---\n\nBody.\n",
                encoding="utf-8",
            )
            result = self.run_linter(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tab", result.stdout.lower())

    def test_yaml_typed_string_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_entry(root, "reviewed", "typed-title", entry_id="typed-title")
            path = root / "reviewed" / "typed-title.md"
            path.write_text(path.read_text(encoding="utf-8").replace("title: Example reviewed reference", "title: true"), encoding="utf-8")
            result = self.run_linter(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("string", result.stdout.lower())

    def test_symlinked_official_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = Path(tmp).parent / f"{root.name}-outside"
            outside.mkdir()
            write_entry(outside, "reviewed", "outside", entry_id="outside")
            link = root / "reviewed"
            root.mkdir(exist_ok=True)
            try:
                symlink(outside / "reviewed", link, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            result = self.run_linter(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
