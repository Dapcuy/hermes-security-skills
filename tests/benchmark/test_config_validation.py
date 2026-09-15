import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class BenchmarkConfigValidationTests(unittest.TestCase):
    def test_metric_schema_declares_explicit_statuses(self):
        schema = json.loads((ROOT / "benchmarks/metrics.schema.json").read_text())
        self.assertEqual(schema["$defs"]["measurement"]["properties"]["status"]["enum"], [
            "measured", "unknown", "unmeasured"
        ])
        self.assertIn("measurements", schema["required"])

    def test_go_ci_covers_platforms(self):
        workflow = (ROOT / ".github/workflows/ci-go.yml").read_text()
        for runner in ("ubuntu-latest", "windows-latest", "macos-latest"):
            self.assertIn(runner, workflow)
        self.assertIn("go build ./...", workflow)
        self.assertIn("go test ./...", workflow)
        self.assertIn("go vet ./...", workflow)

    def test_docker_pipeline_is_not_the_platform_matrix(self):
        workflow = (ROOT / ".github/workflows/images.yml").read_text()
        self.assertIn("runs-on: ubuntu-latest", workflow)
        self.assertNotIn("windows-latest", workflow)
        self.assertNotIn("macos-latest", workflow)


if __name__ == "__main__":
    unittest.main()
