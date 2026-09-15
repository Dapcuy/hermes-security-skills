# =============================================================================
# hermes-validator-python — curated validator image (specialized, Python)
#
# Spesifikasi: ROADMAP §13 (curated image, dependency minimum), §13.1
# (base image python:slim), §14 (versioning + digest pinning), §15
# (non-root + security baseline), §19 (konvensi path /workspace/*).
#
# Build context WAJIB = ROOT repo:
#   docker build -f runtimes/docker/images/python-validator/Dockerfile \
#     -t hermes-validator-python:0.1.0 .
#
# Validator script: validators/python/validator.py — stdlib only, tanpa
# dependency tambahan, sehingga SBOM kecil dan deterministik (§13, §37).
# =============================================================================

# -----------------------------------------------------------------------------
# Base image di-PIN per tag: python:3.12-slim (Debian bookworm).
# §14 — sebelum publish production, naikkan ke digest pinning permanen:
#   FROM python:3.12-slim@sha256:<digest>
#   (ambil digest: docker buildx imagetools inspect python:3.12-slim)
# -----------------------------------------------------------------------------
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

# User non-root khusus (§15): UID/GID tetap 10001, tanpa home directory,
# tanpa login shell — mengikuti pola distroless nonroot.
RUN groupadd --gid 10001 hermes \
    && useradd --uid 10001 --gid 10001 --no-create-home \
       --shell /usr/sbin/nologin hermes

# Copy validator script. Image ini TIDAK berisi tool/library lain (§13:
# satu image = satu tujuan; dilarang menambahkan toolbox).
COPY validators/python/validator.py /validator/validator.py

# Konvensi path runtime lintas platform (§19):
#   /workspace/input  — validation-task.json  (bind mount read-only)
#   /workspace/output — validation-result.json (bind mount)
# WORKDIR otomatis membuat /workspace (owned root). Dengan baseline
# read_only: true (§15), satu-satunya tulisan yang sah adalah file result
# di /workspace/output yang disediakan adapter sebagai mount.
WORKDIR /workspace

USER 10001:10001

# Default --input/--output ada di validator.py; docker runtime adapter
# boleh meng-override dengan argumen tambahan setelah entrypoint (§17).
ENTRYPOINT ["python", "/validator/validator.py"]
