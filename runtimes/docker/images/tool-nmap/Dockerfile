# =============================================================================
# hermes-tool-nmap — third-party tool image (§13.1)
#
# ATURAN KERAS §13.1:
#   1. SATU TOOL = SATU IMAGE TERPISAH — tidak ada tool lain di image ini.
#   2. INSTALL SAAT BUILD (CI), BUKAN SAAT RUNTIME — versi di-pin di
#      Dockerfile (apt TER-PIN), di-build CI, di-sign, di-publish. Runtime
#      container: non-root, tanpa kemampuan install apapun.
#   3. Tool tidak pernah jalan "telanjang" — dibungkus wrapper fail-closed
#      yang memverifikasi policy bundle, scope check target, menerapkan
#      budget (max ports + max rate), dan menormalisasi output ke
#      validation-result.json + provenance (§13.1, §39).
#
# Build context WAJIB = ROOT repo:
#   docker build -f runtimes/docker/images/tool-nmap/Dockerfile \
#     -t hermes/tool-nmap:dev .
# =============================================================================

# -----------------------------------------------------------------------------
# NMAP VERSION PIN — versi apt TER-PIN (§13.1).
# 7.93+dfsg1-1 = versi nmap di repo Debian bookworm main (deb.debian.org).
# UBAH VERSI = REVIEW SUPPLY CHAIN (§13.1), dan versi ini juga di-hardcode
# di wrapper (const toolVersion) untuk provenance — keduanya WAJIB diganti
# bersamaan.
# -----------------------------------------------------------------------------
ARG NMAP_VERSION=7.93+dfsg1-1

# -----------------------------------------------------------------------------
# Stage 1 — build wrapper fail-closed (module kecil terpisah, stdlib only).
# Wrapper di-build dari source di runtimes/docker/images/tool-nmap/wrapper.
# -----------------------------------------------------------------------------
FROM golang:1.27-bookworm@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b AS build
# TARGETARCH di-set otomatis oleh buildx; kosong = fallback arsitektur host.
ARG TARGETARCH
WORKDIR /wrapper-src
COPY runtimes/docker/images/tool-nmap/wrapper/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/wrapper .

# -----------------------------------------------------------------------------
# Stage 2 — runtime: debian:bookworm-slim (BUKAN distroless — nmap butuh
# libc glibc + data files /usr/share/nmap dari paket nmap-common).
# §14 — digest pinning saat publish:
#   FROM debian:bookworm-slim@sha256:<digest>
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
ARG NMAP_VERSION

# Install nmap TER-PIN versi saat build (§13.1: install saat build, bukan
# runtime). --no-install-recommends = seminimal mungkin; nmap-common (data
# service probe) ter-install sebagai dependency wajib. Setelah install:
#   - buang index apt (jaga ukuran + bukan jalur install runtime), dan
#   - FAIL-CLOSED saat build bila versi ter-install != pin — image dengan
#     versi tool yang salah tidak boleh ter-generate.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      nmap="${NMAP_VERSION}" \
      libpcre2-8-0=10.42-1+deb12u1 \
 && rm -rf /var/lib/apt/lists/* \
 && [ "$(dpkg-query -W -f='${Version}' nmap)" = "${NMAP_VERSION}" ] \
 || { echo "FAIL: versi nmap ter-install tidak sama dengan pin: ${NMAP_VERSION}"; exit 1; }

# Non-root (§15). Mode scan WAJIB -sT (connect scan): TIDAK butuh NET_RAW /
# CAP_NET_RAW, kompatibel dengan cap_drop: ALL (§13.1). Escalation ke mode
# raw socket (-sS/-sU) butuh image khusus NET_RAW + approval tambahan,
# post-MVP — wrapper MENOLAK flag tersebut (fail-closed).
RUN groupadd --gid 65532 nonroot \
 && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin nonroot
USER nonroot

COPY --from=build /out/wrapper /wrapper

# ENTRYPOINT = wrapper (BUKAN nmap). Semua pemanggilan tool lewat wrapper:
# verifikasi bundle (fail-closed) -> scope check target -> budget (max
# ports via -p + --max-rate) -> eksekusi nmap -sT -> parse output greppable
# -> validation-result.json + provenance.
ENTRYPOINT ["/wrapper"]
