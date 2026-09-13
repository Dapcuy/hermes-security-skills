# =============================================================================
# hermes-tool-nuclei — third-party tool image (§13.1)
#
# ATURAN KERAS §13.1:
#   1. SATU TOOL = SATU IMAGE TERPISAH — tidak ada tool lain di image ini.
#   2. INSTALL SAAT BUILD (CI), BUKAN SAAT RUNTIME — versi di-pin di
#      Dockerfile, di-build CI, di-sign, di-publish (images.yml, §37).
#      Runtime container: non-root, tanpa shell, read-only (§15).
#   3. Tool tidak pernah jalan "telanjang" — dibungkus wrapper fail-closed
#      yang memverifikasi policy bundle, menerapkan budget, dan menormalisasi
#      output ke validation-result.json + provenance (§13.1, §39).
#
# Build context WAJIB = ROOT repo:
#   docker build -f runtimes/docker/images/tool-nuclei/Dockerfile \
#     -t hermes-tool-nuclei:0.1.0 .
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 — install nuclei versi TER-PIN (pola persis §13.1).
# JANGAN mengubah versi tanpa review supply chain: versi ini juga
# di-hardcode di wrapper (const toolVersion) untuk provenance —
# keduanya WAJIB diganti bersamaan.
# §14 — naikkan ke digest pinning saat publish: golang:1.23@sha256:<digest>
# -----------------------------------------------------------------------------
FROM golang:1.23 AS build
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.9

# -----------------------------------------------------------------------------
# Stage 1b — build wrapper fail-closed (module kecil terpisah, stdlib only).
# Wrapper di-build dari source di runtimes/docker/images/tool-nuclei/wrapper.
# -----------------------------------------------------------------------------
# TARGETARCH di-set otomatis oleh buildx; kosong = fallback arsitektur host.
ARG TARGETARCH
WORKDIR /wrapper-src
COPY runtimes/docker/images/tool-nuclei/wrapper/ ./
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

COPY --from=build /go/bin/nuclei /usr/bin/nuclei
COPY --from=build /out/wrapper /wrapper

# ENTRYPOINT = wrapper (BUKAN nuclei). Semua pemanggilan tool lewat wrapper:
# verifikasi bundle (fail-closed) -> budget/rate limit -> eksekusi nuclei
# -> normalisasi output ke validation-result.json + provenance.
ENTRYPOINT ["/wrapper"]

# -----------------------------------------------------------------------------
# PERINGATAN TEMPLATE PINNING (§13.1) — BACA SEBELUM PAKAI:
#
#   Nuclei templates adalah SUPPLY CHAIN VECTOR — template community pernah
#   menjadi jalur serangan. Kebijakan:
#     - Template TIDAK PERNAH di-download / di-update otomatis saat runtime.
#       Wrapper menjalankan nuclei dengan -duc (disable update check), dan
#       baseline read_only + nonroot membuat download template mustahil.
#     - Template di-pin per versi/commit, diverifikasi SEBELUM dipakai,
#       lalu di-mount READ-ONLY oleh control plane (mis. /templates:ro)
#       dan diteruskan ke nuclei via argumen tambahan (-t /templates),
#       atau di-bake ke image saat build.
#     - Provenance evidence wajib mencatat versi tool (v3.3.9) + versi
#       template/aset yang dipakai (ditangani wrapper + control plane).
#
#   Risk classification: active scanning = MEDIUM–HIGH (§8) → wajib approval,
#   budget ketat, dan stop conditions aktif.
# -----------------------------------------------------------------------------
