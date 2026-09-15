# =============================================================================
# hermes-tool-httpx — third-party tool image (§13.1)
#
# ATURAN KERAS §13.1:
#   1. SATU TOOL = SATU IMAGE TERPISAH — tidak ada tool lain di image ini.
#   2. INSTALL SAAT BUILD (CI), BUKAN SAAT RUNTIME — versi di-pin di
#      Dockerfile, di-build CI, di-sign, di-publish. Runtime container:
#      non-root, tanpa shell, read-only (§15).
#   3. Tool tidak pernah jalan "telanjang" — dibungkus wrapper fail-closed
#      yang memverifikasi policy bundle, scope check SETIAP URL, menerapkan
#      budget/rate limit, dan menormalisasi output ke validation-result.json
#      + provenance (§13.1, §39).
#
# Build context WAJIB = ROOT repo:
#   docker build -f runtimes/docker/images/tool-httpx/Dockerfile \
#     -t hermes/tool-httpx:dev .
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 — install httpx versi TER-PIN (pola persis §13.1).
# JANGAN mengubah versi tanpa review supply chain: versi ini juga di-hardcode
# di wrapper (const toolVersion) untuk provenance — keduanya WAJIB diganti
# bersamaan. httpx v1.12.0 butuh Go >= 1.26 (go.mod) → image golang:1.26.
# §14 — naikkan ke digest pinning saat publish: golang:1.26@sha256:<digest>
# -----------------------------------------------------------------------------
FROM golang:1.26@sha256:3c3e25a4da13fd0478eed2df1eb35a0e667094a7124d3993a6a1d30f71c17e79 AS build
# CGO_ENABLED=0 — httpx harus static binary: base runtime distroless STATIC
# tidak punya dynamic loader (glibc), exec binary dinamis gagal
# "no such file or directory" saat fork/exec.
RUN CGO_ENABLED=0 go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0

# -----------------------------------------------------------------------------
# Stage 1b — build wrapper fail-closed (module kecil terpisah, stdlib only).
# Wrapper di-build dari source di runtimes/docker/images/tool-httpx/wrapper.
# -----------------------------------------------------------------------------
# TARGETARCH di-set otomatis oleh buildx; kosong = fallback arsitektur host.
ARG TARGETARCH
WORKDIR /wrapper-src
COPY runtimes/docker/images/tool-httpx/wrapper/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/wrapper .

# -----------------------------------------------------------------------------
# Stage 2 — runtime
# distroless/static:nonroot — tanpa shell, tanpa package manager, non-root;
# runtime tidak punya kemampuan install apapun (§13.1).
# §14 — digest pinning saat publish:
#   FROM gcr.io/distroless/static-debian12:nonroot@sha256:<digest>
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --from=build /go/bin/httpx /usr/bin/httpx
COPY --from=build /out/wrapper /wrapper

# httpx menulis config/cache ke $HOME; di runtime read-only, arahkan ke /tmp
# (di-mount tmpfs oleh control plane).
ENV HOME=/tmp

# ENTRYPOINT = wrapper (BUKAN httpx). Semua pemanggilan tool lewat wrapper:
# verifikasi bundle (fail-closed) -> scope check SETIAP URL target
# -> budget/rate limit -> eksekusi httpx -> normalisasi output ke
# validation-result.json + provenance.
ENTRYPOINT ["/wrapper"]
