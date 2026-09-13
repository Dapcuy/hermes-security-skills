#!/usr/bin/env python3
"""hermes-validator-python — specialized validator, stdlib only.

Kontrak Docker Execution Contract (ROADMAP §17):
    input  : /workspace/input/validation-task.json
    output : /workspace/output/validation-result.json

Status hasil SELALU "observed" — validator hanya mengamati/mengukur;
penentuan status vulnerability dilakukan Hermes (§17), bukan validator.

Desain (§13, §15):
    - stdlib only: image python:3.12-slim tanpa dependency tambahan,
      SBOM kecil dan deterministik.
    - non-root (UID 10001), read_only filesystem: satu-satunya tulisan
      adalah file validation-result.json di /workspace/output.
    - network=none ditegakkan oleh runtime adapter (§16); validator ini
      tidak melakukan akses jaringan apa pun.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

VALIDATOR_ID = "hermes-validator-python"
VALIDATOR_VERSION = "0.1.0"

DEFAULT_INPUT = "/workspace/input/validation-task.json"
DEFAULT_OUTPUT = "/workspace/output/validation-result.json"

# Exit code kontrak (selaras wrapper tool-nuclei):
#   0 = validation-result.json berhasil ditulis
#   2 = fail-closed (task hilang / tidak valid) — tidak menulis result
EXIT_POLICY = 2


def fail_closed(message: str) -> int:
    """Cetak error ke stderr dan keluar tanpa menulis result (fail-closed)."""
    print(f"validator-python: fail-closed: {message}", file=sys.stderr)
    return EXIT_POLICY


def load_task(path: str) -> dict:
    """Baca validation-task.json; error apa pun = fail-closed."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"task file tidak ditemukan: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        try:
            task = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(f"task bukan JSON valid: {exc}") from exc
    if not isinstance(task, dict):
        raise ValueError("task harus berupa JSON object")
    return task


def extract_response(task: dict) -> dict:
    """Ambil objek HTTP response dari task.

    Diterima dua penempatan (kontrak §17 menyisakan bentuk input longgar):
      task.input.response  atau  task.response
    """
    candidate = task.get("input")
    if isinstance(candidate, dict) and isinstance(candidate.get("response"), dict):
        return candidate["response"]
    if isinstance(task.get("response"), dict):
        return task["response"]
    raise ValueError(
        "task tidak memuat objek response "
        "(harapkan task.input.response atau task.response)"
    )


def compute_stats(response: dict) -> dict:
    """Hitung statistik sederhana: panjang body dan jumlah header.

    Ini contoh observasi pasif — tidak ada side effect, tidak ada network.
    """
    body = response.get("body", "")
    if not isinstance(body, str):
        body = "" if body is None else str(body)
    headers = response.get("headers", {})
    if not isinstance(headers, dict):
        headers = {}
    return {
        "body_length": len(body),
        "header_count": len(headers),
    }


def write_result(path: str, task_id: str, stats: dict) -> None:
    """Tulis validation-result.json (status: observed, sesuai §17)."""
    result = {
        "task_id": task_id,
        "validator": {
            "id": VALIDATOR_ID,
            "version": VALIDATOR_VERSION,
        },
        "status": "observed",
        "result": stats,
        "evidence": [],
    }
    out_dir = os.path.dirname(path)
    if out_dir:
        # Pada baseline read_only (§15) baris ini hanya berhasil jika
        # /workspace/output di-mount oleh runtime adapter.
        os.makedirs(out_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
        fh.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="hermes-validator-python: observasi statistik response (§17)"
    )
    parser.add_argument(
        "--input",
        default=DEFAULT_INPUT,
        help=f"path validation-task.json (default: {DEFAULT_INPUT})",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"path validation-result.json (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()

    try:
        task = load_task(args.input)
    except (OSError, ValueError) as exc:
        return fail_closed(f"gagal membaca task: {exc}")

    task_id = task.get("task_id")
    if not isinstance(task_id, str) or not task_id:
        return fail_closed("task_id wajib ada dan berupa string non-kosong")

    try:
        response = extract_response(task)
        stats = compute_stats(response)
    except ValueError as exc:
        return fail_closed(str(exc))

    try:
        write_result(args.output, task_id, stats)
    except OSError as exc:
        return fail_closed(f"gagal menulis result: {exc}")

    print(f"validator-python: result ditulis ke {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
