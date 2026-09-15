# =============================================================================
# hermes-validator-json — curated validator image (JSON diff / json-diff)
#
# Spesifikasi: ROADMAP §13, §13.1, §14, §15, §16, §19 — pola identik dengan
# http-validator; hanya paket/binary yang berbeda (tujuan sempit per image).
#
# Build context WAJIB = ROOT repo:
#   docker build -f runtimes/docker/images/json-validator/Dockerfile \
#     -t hermes-validator-json:0.1.0 .
# =============================================================================

# §14 — tag pinning; naikkan ke digest pinning saat publish:
#   FROM golang:1.23@sha256:<digest>
FROM golang:1.23@sha256:60deed95d3888cc5e4d9ff8a10c54e5edc008c6ae3fba6187be6fb592e19e8c0 AS build

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
    -o /out/validator-json ./cmd/validator-json

# §14 — digest pinning saat publish:
#   FROM gcr.io/distroless/static-debian12:nonroot@sha256:<digest>
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --from=build /out/validator-json /validator-json

# Konvensi path runtime (§19): /workspace/input + /workspace/output via
# bind mount dari adapter; tidak perlu mkdir (distroless, tanpa shell).
# main.go menerima flag --input/--output; network=none ditegakkan adapter (§16).
USER 65532:65532

ENTRYPOINT ["/validator-json"]
