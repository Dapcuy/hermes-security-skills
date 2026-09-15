#!/usr/bin/env python3
"""Fail-closed checks for the production Compose image contract."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

IMAGE_RE = re.compile(r"^ghcr\.io/[a-z0-9][a-z0-9_.-]*/hermes-proxy@sha256:[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compose", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--bundle-sha256", required=True)
    args = parser.parse_args()

    if not IMAGE_RE.fullmatch(args.image):
        raise SystemExit("compose policy: image must be approved ghcr.io/.../hermes-proxy@sha256:<64 lowercase hex>")
    if not SHA_RE.fullmatch(args.bundle_sha256):
        raise SystemExit("compose policy: bundle SHA-256 must be 64 lowercase hex characters")
    text = args.compose.read_text(encoding="utf-8")
    if re.search(r"(?m)^\s+ports:\s*$", text):
        raise SystemExit("compose policy: production profile must not publish host ports")
    if "--healthcheck" not in text:
        raise SystemExit("compose policy: native readiness healthcheck is required")
    if "cap_drop: [ALL]" not in text or "no-new-privileges:true" not in text:
        raise SystemExit("compose policy: runtime isolation controls are required")
    print("production Compose policy: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
