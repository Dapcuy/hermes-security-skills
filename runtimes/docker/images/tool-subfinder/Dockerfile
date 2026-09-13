# =============================================================================
# hermes-tool-subfinder — third-party tool image (§13.1)
#
# ATURAN KERAS §13.1:
#   1. SATU TOOL = SATU IMAGE TERPISAH — tidak ada tool lain di image ini.
#   2. INSTALL SAAT BUILD (CI), BUKAN SAAT RUNTIME — versi di-pin di
#      Dockerfile, di-build CI, di-sign, di-publish. Runtime container:
#      non-root, tanpa shell, read-only (§15).
#   3. Tool tidak pernah jalan "telanjang" — dibungkus wrapper fail-closed
#      yang memverifikasi policy bundle, menerapkan budget (deadline), dan
#      menormalisasi output ke validation-result.json + provenance (§13.1).
#
# Build context WAJIB = ROOT repo:
#   docker build -f runtimes/docker/images/tool-subfinder/Dockerfile \
#     -t hermes/tool-subfinder:dev .
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 — install subfinder versi TER-PIN (pola persis §13.1).
# JANGAN mengubah versi tanpa review supply chain: versi ini juga di-hardcode
# di wrapper (const toolVersion) untuk provenance — keduanya WAJIB diganti
# bersamaan. subfinder v2.16.0 butuh Go >= 1.25 (go.mod) → image golang:1.25.
# §14 — naikkan ke digest pinning saat publish: golang:1.25@sha256:<digest>
# -----------------------------------------------------------------------------
FROM golang:1.25 AS build
# CGO_ENABLED=0 — subfinder harus static binary: base runtime distroless STATIC
# tidak punya dynamic loader (glibc), exec binary dinamis gagal
# "no such file or directory" saat fork/exec.
RUN CGO_ENABLED=0 go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.16.0

# -----------------------------------------------------------------------------
# Stage 1b — build wrapper fail-closed (module kecil terpisah, stdlib only).
# Wrapper di-build dari source di runtimes/docker/images/tool-subfinder/wrapper.
# -----------------------------------------------------------------------------
# TARGETARCH di-set otomatis oleh buildx; kosong = fallback arsitektur host.
ARG TARGETARCH
WORKDIR /wrapper-src
COPY runtimes/docker/images/tool-subfinder/wrapper/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/wrapper .

# -----------------------------------------------------------------------------
# Stage 2 — runtime
# distroless/static:nonroot — tanpa shell, tanpa package manager, non-root;
# runtime tidak punya kemampuan install apapun (§13.1).
# §14 — digest pinning saat publish:
#   FROM gcr.io/distroless/static-debian12:nonroot@sha256:<digest>
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /go/bin/subfinder /usr/bin/subfinder
COPY --from=build /out/wrapper /wrapper

# Subfinder menulis config/cache ke $HOME; di runtime read-only, arahkan ke
# /tmp (di-mount tmpfs oleh control plane). Tanpa provider-config.yaml pun
# subfinder tetap jalan dengan sources publik yang tidak butuh API key.
ENV HOME=/tmp

# ENTRYPOINT = wrapper (BUKAN subfinder). Semua pemanggilan tool lewat wrapper:
# verifikasi bundle (fail-closed) -> scope check domain -> budget/deadline
# -> eksekusi subfinder -> normalisasi output ke validation-result.json
# + provenance.
ENTRYPOINT ["/wrapper"]
