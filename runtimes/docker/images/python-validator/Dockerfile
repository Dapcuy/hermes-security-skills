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
# Base image: python:3.13-slim-trixie, immutable digest pinned.
# Refresh the digest with `docker buildx imagetools inspect python:3.13-slim-trixie`.
# The validator uses only the Python standard library; pip is removed below.
# -----------------------------------------------------------------------------
FROM python:3.13-slim-trixie@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285

# Refresh fixed Debian security packages without retaining apt metadata.
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade \
       gzip=1.13-1+deb13u1 \
       libc6=2.41-12+deb13u4 \
       libc-bin=2.41-12+deb13u4 \
       libpcre2-8-0=10.46-1~deb13u2 \
       libsqlite3-0=3.46.1-7+deb13u2 \
       perl-base=5.40.1-6+deb13u1 \
    && rm -rf /var/lib/apt/lists/*

# User non-root khusus (§15): UID/GID tetap 10001, tanpa home directory,
# tanpa login shell — mengikuti pola distroless nonroot.
RUN groupadd --gid 10001 hermes \
    && useradd --uid 10001 --gid 10001 --no-create-home \
       --shell /usr/sbin/nologin hermes

# Tidak ada dependency Python pihak ketiga; hapus pip dan metadata-nya dari
# runtime agar surface/package CVE yang tidak dibutuhkan tidak ikut terbawa.
RUN rm -rf /usr/local/lib/python3.13/site-packages/pip \
           /usr/local/lib/python3.13/site-packages/pip-*.dist-info \
           /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.13

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
