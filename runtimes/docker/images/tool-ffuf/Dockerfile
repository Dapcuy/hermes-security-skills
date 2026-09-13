# =============================================================================
# hermes-tool-ffuf — third-party tool image (§13.1)
#
# ATURAN KERAS §13.1:
#   1. SATU TOOL = SATU IMAGE TERPISAH — tidak ada tool lain di image ini.
#   2. INSTALL SAAT BUILD (CI), BUKAN SAAT RUNTIME — versi tool DAN wordlist
#      di-pin di Dockerfile, di-build CI, di-sign, di-publish. Runtime
#      container: non-root, tanpa shell, read-only (§15).
#   3. Tool tidak pernah jalan "telanjang" — dibungkus wrapper fail-closed
#      yang memverifikasi policy bundle, scope check target URL, menerapkan
#      budget/rate limit, mewajibkan wordlist ter-bake, dan menormalisasi
#      output ke validation-result.json + provenance (§13.1, §39).
#
# Build context WAJIB = ROOT repo:
#   docker build -f runtimes/docker/images/tool-ffuf/Dockerfile \
#     -t hermes/tool-ffuf:dev .
# =============================================================================

# -----------------------------------------------------------------------------
# SECLISTS TAG — PIN VERSI (§13.1, aset template/wordlist = aset ter-bake).
# [ARG GLOBAL — dideklarasikan sebelum FROM pertama agar bisa diwariskan
#  ke stage "wordlists"; dipakai ulang via re-deklarasi ARG di stage tsb.]
#
#   SECLISTS_TAG di-pin di sini dan wordlist di-BAKE ke image saat build —
#   BUKAN di-download saat runtime (runtime read-only, nonroot, tanpa shell).
#
#   UBAH TAG = REVIEW SUPPLY CHAIN (§13.1) wajib:
#     1. Pilih tag rilis stabil terkini (git ls-remote --tags
#        https://github.com/danielmiessler/SecLists).
#     2. Review isi wordlist yang di-bake (wordlist bisa memuat path
#        "berbahaya" sebagai payload — pastikan hanya wordlist terkurasi
#        yang masuk).
#     3. Rebuild image + jalankan verifikasi wrapper (lihat README.md di
#        direktori ini).
#   Versi tag ini dicatat ke /wordlists/.hermes-wordlists-version saat build
#   dan dibaca wrapper untuk provenance evidence (§13.1: provenance wajib
#   mencatat versi tool + versi template/aset).
# -----------------------------------------------------------------------------
ARG SECLISTS_TAG=2026.1

# -----------------------------------------------------------------------------
# Stage 1 — install ffuf versi TER-PIN (pola persis §13.1).
# JANGAN mengubah versi tanpa review supply chain: versi ini juga di-hardcode
# di wrapper (const toolVersion) untuk provenance — keduanya WAJIB diganti
# bersamaan. ffuf v2.3.0 butuh Go >= 1.20 (go.mod) → image golang:1.25.
# §14 — naikkan ke digest pinning saat publish: golang:1.25@sha256:<digest>
# -----------------------------------------------------------------------------
FROM golang:1.25 AS build
# CGO_ENABLED=0 — ffuf harus static binary: base runtime distroless STATIC
# tidak punya dynamic loader (glibc), exec binary dinamis gagal
# "no such file or directory" saat fork/exec.
RUN CGO_ENABLED=0 go install -v github.com/ffuf/ffuf/v2@v2.3.0

# -----------------------------------------------------------------------------
# Stage 1b — build wrapper fail-closed (module kecil terpisah, stdlib only).
# Wrapper di-build dari source di runtimes/docker/images/tool-ffuf/wrapper.
# -----------------------------------------------------------------------------
# TARGETARCH di-set otomatis oleh buildx; kosong = fallback arsitektur host.
ARG TARGETARCH
WORKDIR /wrapper-src
COPY runtimes/docker/images/tool-ffuf/wrapper/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/wrapper .

# -----------------------------------------------------------------------------
# Stage 1c — bake wordlists versi TER-PIN (§13.1).
# Clone SecLists --depth 1 pada tag terpin (bukan master/HEAD yang bergerak),
# buang .git, lalu salin SUBSET KECIL TERKURASI ke /tmp/wordlists — JANGAN
# seluruh repo (jaga ukuran image; satu image = satu tool + aset minimal).
# FAIL-CLOSED saat build jika ada wordlist kosong/tidak ada — image tanpa
# wordlist tidak boleh ter-generate.
# golang image dipakai lagi karena sudah ada di cache build dan menyertakan
# git. Subset terkurasi (Discovery/Web-Content): common.txt (~38 KB) dan
# raft-small-words.txt (~340 KB). Catatan: small.txt tidak ada lagi pada tag
# 2026.1 — padanannya raft-small-words.txt.
# -----------------------------------------------------------------------------
FROM golang:1.25 AS wordlists
ARG SECLISTS_TAG
RUN git clone --depth 1 --branch "${SECLISTS_TAG}" \
      https://github.com/danielmiessler/SecLists /tmp/seclists \
 && rm -rf /tmp/seclists/.git \
 && mkdir -p /tmp/wordlists \
 && cp /tmp/seclists/Discovery/Web-Content/common.txt /tmp/wordlists/common.txt \
 && cp /tmp/seclists/Discovery/Web-Content/raft-small-words.txt /tmp/wordlists/raft-small-words.txt \
 && rm -rf /tmp/seclists \
 && for f in /tmp/wordlists/*.txt; do test -s "$f" \
      || { echo "FAIL: wordlist kosong / tidak ada: $f"; exit 1; }; done \
 && printf '%s\n' "${SECLISTS_TAG}" > /tmp/wordlists/.hermes-wordlists-version

# -----------------------------------------------------------------------------
# Stage 2 — runtime
# distroless/static:nonroot — tanpa shell, tanpa package manager, non-root;
# runtime tidak punya kemampuan install/download apapun (§13.1).
# §14 — digest pinning saat publish:
#   FROM gcr.io/distroless/static-debian12:nonroot@sha256:<digest>
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /go/bin/ffuf /usr/bin/ffuf
COPY --from=build /out/wrapper /wrapper

# Wordlists TER-BAKE saat build di /wordlists — read-only by design
# (runtime read-only + nonroot, tidak ada jalur download saat runtime).
# Wrapper MEWAJIBKAN --wordlist (fail-closed exit 2 kalau kosong — pola
# sama dengan --templates tool-nuclei) dan memverifikasi file ada & tidak
# kosong. File .hermes-wordlists-version dipakai wrapper untuk provenance
# versi wordlist.
COPY --from=wordlists /tmp/wordlists /wordlists

# ffuf menulis config ke $HOME; di runtime read-only, arahkan ke /tmp
# (di-mount tmpfs oleh control plane).
ENV HOME=/tmp

# ENTRYPOINT = wrapper (BUKAN ffuf). Semua pemanggilan tool lewat wrapper:
# verifikasi bundle (fail-closed) -> scope check target URL -> wordlist
# ter-bake wajib -> budget/rate limit -> eksekusi ffuf -> normalisasi output
# ke validation-result.json + provenance.
ENTRYPOINT ["/wrapper"]
