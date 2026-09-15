# =============================================================================
# hermes-validator-http — curated validator image (HTTP response comparison)
#
# Spesifikasi: ROADMAP §13 (curated image, tujuan sempit), §13.1 (base image
# distroless), §14 (versioning + digest pinning), §15 (security baseline),
# §16 (network=none — ditegakkan oleh runtime adapter, bukan image),
# §19 (konvensi path /workspace/{input,output}).
#
# Build context WAJIB = ROOT repo (semua path COPY relatif terhadap root):
#   docker build -f runtimes/docker/images/http-validator/Dockerfile \
#     -t hermes-validator-http:0.1.0 .
#
# Binary dibangun dari cmd/validator-http (module hermes-security-skills,
# source control plane Go). Pipeline lengkap (Trivy + SBOM + cosign) ada di
# .github/workflows/images.yml (§37).
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 — build
# Base image di-PIN per tag: golang:1.23.
# §14 — sebelum publish production, naikkan ke digest pinning permanen:
#   FROM golang:1.23@sha256:<digest>
#   (ambil digest: docker buildx imagetools inspect golang:1.23)
# -----------------------------------------------------------------------------
FROM golang:1.23@sha256:60deed95d3888cc5e4d9ff8a10c54e5edc008c6ae3fba6187be6fb592e19e8c0 AS build

# TARGETARCH di-set otomatis oleh buildx untuk multi-platform build (§19).
# Pada `docker build` biasa variabel ini kosong; GOARCH="" berarti Go
# memakai arsitektur host sebagai fallback.
ARG TARGETARCH

WORKDIR /src

# Layer cache dependencies: go.mod wajib ada, go.sum opsional saat bootstrap
# (glob go.* tetap berhasil walau go.sum belum dibuat).
COPY go.* ./
RUN go mod download

# Copy full context root: layout source Go dapat mencakup cmd/ + internal/
# (ditentukan oleh agent control plane). Rekomendasi: tambahkan .dockerignore
# di root agar context tidak membawa labs/, knowledge/, memory/, dsb.
COPY . .

# Build statis untuk distroless:
#   CGO_ENABLED=0 → binary tanpa libc (cocok distroless/static)
#   -trimpath     → path absolut dihapus (reproducible build)
#   -ldflags "-s -w" → strip symbol table & DWARF (binary kecil)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" \
    -o /out/validator-http ./cmd/validator-http

# -----------------------------------------------------------------------------
# Stage 2 — runtime
# distroless/static:nonroot — tanpa shell, tanpa package manager, tanpa user
# root (UID 65532). Selaras §13.1 dan §15 (minimal image + non-root).
# §14 — digest pinning saat publish:
#   FROM gcr.io/distroless/static-debian12:nonroot@sha256:<digest>
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --from=build /out/validator-http /validator-http

# Konvensi path runtime lintas platform (§19):
#   /workspace/input  — validation-task.json  (bind mount read-only)
#   /workspace/output — validation-result.json (bind mount)
# TIDAK perlu mkdir (distroless tidak punya shell): direktori disediakan
# lewat bind mount oleh Docker runtime adapter (§18), dan main.go menerima
# flag --input/--output sebagai passthrough argumen setelah ENTRYPOINT.
# Jangan publish port; container dijalankan dengan network=none oleh
# adapter (§16) — image tidak membuka/konfigurasi network sendiri.

# Tag :nonroot sudah default USER nonroot (65532:65532); dinyatakan
# eksplisit agar audit security mudah (§15).
USER 65532:65532

ENTRYPOINT ["/validator-http"]
