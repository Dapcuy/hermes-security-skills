#!/usr/bin/env python3
"""Fail closed when Dockerfiles use mutable base-image tags."""
from pathlib import Path
import re
import sys

FROM = re.compile(r"^\s*FROM\s+(\S+)", re.MULTILINE)
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}(?:$|\s+AS\s+)")


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    files = sorted(root.rglob("Dockerfile"))
    errors: list[str] = []
    for path in files:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = FROM.match(line)
            if match and not DIGEST.search(match.group(1) + line[match.end(1):]):
                errors.append(f"{path}:{number}: base image must be pinned by @sha256 digest: {match.group(1)}")
    if errors:
        print("Dockerfile base-image pinning failed:", file=sys.stderr)
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Dockerfile base-image pinning passed ({len(files)} Dockerfiles checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
