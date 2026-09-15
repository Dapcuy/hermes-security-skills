# =============================================================================
# hermes-proxy — ephemeral interception proxy (SATU-SATUNYA komponen egress)
#
# Spesifikasi: ROADMAP §11 (arsitektur proxy: policy in-line, fail-closed,
# control channel internal), §13.1 (base image distroless), §14 (versioning
# + digest pinning), §15 (security baseline), §16 (satu-satunya pengecualian
# network), §19 (konvensi path).
#
# Build context WAJIB = ROOT repo:
#   docker build -f runtimes/docker/images/proxy/Dockerfile \
#     -t hermes-proxy:0.1.0 .
#
# Image ini di-package lewat CI (scan + SBOM + sign, §37) dengan pola sama
# seperti validator image: curated, versioned, signed (§11).
# =============================================================================

# §14 — immutable manifest pin: golang:1.27-bookworm@sha256:<digest>
FROM golang:1.27-bookworm@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b AS build

# TARGETARCH di-set otomatis oleh buildx; kosong = fallback arsitektur host.
ARG TARGETARCH

WORKDIR /src

# Cache dependencies lebih dulu (go.sum opsional saat bootstrap).
COPY go.* ./
RUN go mod download

# Copy full context root (source Go dapat mencakup cmd/ + internal/).
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" \
    -o /out/hermes-proxy ./cmd/hermes-proxy

# §14 — digest pinning saat publish:
#   FROM gcr.io/distroless/static-debian12:nonroot@sha256:<digest>
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --from=build /out/hermes-proxy /hermes-proxy

# Konvensi path runtime (§19): /workspace/input + /workspace/output via
# bind mount dari adapter. Policy bundle di-mount READ-ONLY dan di-verifikasi
# hash oleh proxy itu sendiri — fail-closed: bundle tidak valid / tidak
# ter-mount = proxy menolak SEMUA operasi (§11).

# -----------------------------------------------------------------------------
# EXPOSE hanya DOKUMENTASI port control channel.
# §11 — control channel HANYA listen di Docker network INTERNAL:
#   - JANGAN publish port ke host (`-p` / `ports:` dilarang untuk image ini)
#   - JANGAN pakai network_mode: host
#   - Satu-satunya egress yang sah adalah koneksi ke target yang diizinkan
#     policy bundle, dievaluasi in-line per request (TOCTOU guard, §11).
# Adapter menjalankan container tanpa port mapping, di network internal.
# -----------------------------------------------------------------------------
EXPOSE 8080

# Tag :nonroot sudah default USER nonroot (65532:65532); dinyatakan
# eksplisit agar audit security mudah (§15).
USER 65532:65532

ENTRYPOINT ["/hermes-proxy"]
