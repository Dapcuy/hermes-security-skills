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
# NUCLEI TEMPLATES — PIN VERSI (§13.1, supply chain vector).
# [ARG GLOBAL — dideklarasikan sebelum FROM pertama agar bisa diwariskan
#  ke stage "templates"; dipakai ulang via re-deklarasi ARG di stage tsb.]
#
#   NUCLEI_TEMPLATES_TAG di-pin di sini dan template di-BAKE ke image saat
#   build — BUKAN di-download / di-update saat runtime (runtime read-only,
#   nonroot, tanpa shell; wrapper memakai -duc = disable update check).
#
#   UBAH TAG = REVIEW SUPPLY CHAIN (§13.1) wajib:
#     1. Pilih tag rilis stabil terkini (git ls-remote --tags
#        https://github.com/projectdiscovery/nuclei-templates).
#     2. Review diff template antar versi (template community pernah menjadi
#        jalur serangan — periksa penambahan template mencurigakan).
#     3. Rebuild image + jalankan verifikasi wrapper (lihat README.md di
#        direktori ini), lalu update ci provenance/manifest bila diperlukan.
#   Versi tag ini dicatat ke /nuclei-templates/.hermes-templates-version
#   saat build dan dibaca wrapper untuk provenance evidence (§13.1: provenance
#   wajib mencatat versi tool + versi template/aset).
# -----------------------------------------------------------------------------
ARG NUCLEI_TEMPLATES_TAG=v10.4.8

# -----------------------------------------------------------------------------
# Stage 1 — install nuclei versi TER-PIN (pola persis §13.1).
# JANGAN mengubah versi tanpa review supply chain: versi ini juga
# di-hardcode di wrapper (const toolVersion) untuk provenance —
# keduanya WAJIB diganti bersamaan.
# §14 — naikkan ke digest pinning saat publish: golang:1.23@sha256:<digest>
# -----------------------------------------------------------------------------
FROM golang:1.23 AS build
# CGO_ENABLED=0 — nuclei harus static binary: base runtime distroless STATIC
# tidak punya dynamic loader (glibc), exec binary dinamis gagal
# "no such file or directory" saat fork/exec.
RUN CGO_ENABLED=0 go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.9

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
# Stage 1c — bake nuclei templates versi TER-PIN (§13.1).
# Clone --depth 1 pada tag terpin (bukan master/HEAD yang bergerak), buang
# .git, dan FAIL-CLOSED saat build jika hasil clone tidak memuat satu .yaml
# pun — image tanpa template tidak boleh ter-generate.
# golang image dipakai lagi karena sudah ada di cache build dan menyertakan git.
# -----------------------------------------------------------------------------
FROM golang:1.23 AS templates
ARG NUCLEI_TEMPLATES_TAG
RUN git clone --depth 1 --branch "${NUCLEI_TEMPLATES_TAG}" \
      https://github.com/projectdiscovery/nuclei-templates /tmp/nuclei-templates \
 && rm -rf /tmp/nuclei-templates/.git \
 && test -n "$(find /tmp/nuclei-templates -name '*.yaml' -print -quit)" \
 || { echo "FAIL: template kosong / tag tidak ada: ${NUCLEI_TEMPLATES_TAG}"; exit 1; } \
 && printf '%s\n' "${NUCLEI_TEMPLATES_TAG}" > /tmp/nuclei-templates/.hermes-templates-version

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

# Template TER-BAKE saat build di /nuclei-templates — read-only by design
# (runtime read-only + nonroot, tidak ada jalur download/update saat runtime).
# Wrapper mewajibkan direktori ini ada & berisi .yaml (fail-closed exit 2)
# dan meneruskannya ke nuclei via -t. File .hermes-templates-version di
# dalamnya dipakai wrapper untuk provenance versi template.
COPY --from=templates /tmp/nuclei-templates /nuclei-templates

# Nuclei menulis cache/config ke $HOME; di runtime read-only, arahkan ke /tmp
# (di-mount tmpfs oleh control plane) agar tidak pernah menyentuh /nuclei-templates.
ENV HOME=/tmp

# ENTRYPOINT = wrapper (BUKAN nuclei). Semua pemanggilan tool lewat wrapper:
# verifikasi bundle (fail-closed) -> budget/rate limit -> eksekusi nuclei
# -> normalisasi output ke validation-result.json + provenance.
ENTRYPOINT ["/wrapper"]

# -----------------------------------------------------------------------------
# TEMPLATE PINNING (§13.1) — KEBIJAKAN YANG SUDAH DIIMPLEMENTASI DI IMAGE INI:
#
#   Nuclei templates adalah SUPPLY CHAIN VECTOR — template community pernah
#   menjadi jalur serangan. Kebijakan:
#     - Template di-BAKE ke image saat build pada tag terpin
#       (ARG NUCLEI_TEMPLATES_TAG) — lihat stage "templates" di atas.
#       UBAH TAG = REVIEW SUPPLY CHAIN (§13.1).
#     - Template TIDAK PERNAH di-download / di-update otomatis saat runtime.
#       Wrapper menjalankan nuclei dengan -duc (disable update check) dan
#       MENOLAK jalan (exit 2) bila /nuclei-templates tidak ada atau kosong —
#       bukti bahwa scan hanya berjalan dengan template ter-bake.
#       Baseline read_only + nonroot membuat download template mustahil.
#     - Versi tool (v3.3.9) + versi template (ARG NUCLEI_TEMPLATES_TAG →
#       .hermes-templates-version) dicatat wrapper di provenance evidence.
#
#   Risk classification: active scanning = MEDIUM–HIGH (§8) → wajib approval,
#   budget ketat, dan stop conditions aktif.
# -----------------------------------------------------------------------------
