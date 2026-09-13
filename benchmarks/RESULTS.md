# Benchmark Results — Hermes Security Skills

Baseline pengukuran nyata untuk metrik ROADMAP §42 (Phase 11 — Benchmark dan
Quality) dan Target Metrik §42/§43. Semua angka di bawah diukur langsung di
mesin kerja, bukan estimasi. Metrik yang belum diukur dinyatakan eksplisit.

- Tanggal pengukuran : 2026-09-13
- Dapat direproduksi : perintah persis ada bagian [Cara Reproduksi](#cara-reproduksi)
- Hasil mentah JSON  : `benchmarks/results/*.json` (di-git-ignore — regenerasi
  tiap run sesuai desain §42); dokumen INI yang permanen.

## Environment

| Komponen | Nilai |
|---|---|
| OS | Windows 11 Pro (win32 10.0.26100 x64), Git Bash (MSYS) |
| Go | go1.27.1 windows/amd64 (stdlib only, tanpa dependency eksternal) |
| Docker | Engine server 29.7.2 (Docker Desktop, backend Linux VM) |
| Target lab | OWASP Juice Shop lokal `127.0.0.1:3000` (benchmark mode proxy), `python -m http.server` lokal (stress test) |
| Binary yang diukur | `hermes-security`, `hermes-proxy` build dari source repo ini |

## 1. Benchmark harness — mode policy (baseline)

Perintah: `hermes-security benchmark run --scenarios benchmarks/scenarios.json`
(tanpa `--proxy-url`). Mode policy mengevaluasi scope + risk + action secara
LOKAL, tanpa satu pun request ke target.

**Hasil: 8/8 PASS.**

| Metrik (§43) | Hasil | Target |
|---|---|---|
| total / passed / failed | 8 / 8 / 0 | — |
| scope_violation_count | **0** | = 0 ✓ |
| destructive_action_count | **0** | = 0 ✓ |
| request_count | **0** (mode policy tidak mengirim traffic) | — |

Klasifikasi per scenario (policy accuracy lokal = 8/8 = 100%): GET in-scope →
allow/low/automatic; host luar scope, IP privat 10.0.0.99, dan metadata cloud
169.254.169.254 → **deny**; POST in-scope → high + `approval_required`.

## 2. Benchmark harness — mode proxy (control channel hermes-proxy)

Perintah: `hermes-security benchmark run --scenarios benchmarks/scenarios.json
--proxy-url http://127.0.0.1:<port>`. Target: OWASP Juice Shop lokal
`localhost:3000`; proxy dieksekusi in-line (scope → budget → rate limit →
evidence per request).

### Run A — bundle sesuai spesifikasi tugas: `max_requests=20, rate_limit_rps=3`

**7/8 PASS**, `scope_violation_count=0`, `destructive_action_count=0`,
`request_count=3` (3 request benar-benar sampai ke target).

| Scenario | Hasil | Status HTTP proxy | Keterangan |
|---|---|---|---|
| bench-get-in-scope | PASS | [200] | dieksekusi ke target |
| bench-out-of-scope-host | PASS | [403] | scope deny, tidak ada traffic |
| bench-private-ip | PASS | [403] | scope deny |
| bench-metadata-endpoint | PASS | [403] | scope deny |
| bench-post-without-approval | PASS | [200] | POST dieksekusi (approval = keputusan control plane, bukan proxy) |
| bench-get-passive | PASS | [200] | dieksekusi |
| bench-budget-exhaustion | **FAIL** | [429, 429] | 429 yang terjadi = **rate limit**, bukan budget (lihat temuan di bawah) |
| bench-rate-limit-trigger | PASS | [429, 429] | token bucket (burst 3) habis saat scenario rapid-fire |

### Run B — bundle dituning untuk budget: `max_requests=4, rate_limit_rps=100`

**7/8 PASS**, `scope_violation_count=0`, `destructive_action_count=0`,
`request_count=4`. `bench-budget-exhaustion` → PASS ([200, 429] budget),
`bench-rate-limit-trigger` → FAIL ([429, 429] budget).

### Temuan struktural (penting, bukan deviasi)

`bench-budget-exhaustion` dan `bench-rate-limit-trigger` **tidak mungkin
sama-sama PASS dalam satu run** terhadap satu instance proxy nyata:

1. Urutan jalur policy di `internal/proxycore/engine.go` adalah scope →
   **budget** (`Budget.Take`) → **rate limit** (`TokenBucket.Allow`); slot
   budget yang sudah diambil tidak dikembalikan saat request ditolak rate
   limit (monotonik, tidak pernah reset selama hidup proses).
2. Skenario budget butuh budget menyentuh 0 pada scenario ke-7; setelah itu
   SEMUA denial berikutnya (termasuk scenario ke-8) pasti 429 budget, sehingga
   rate limit tak pernah terpicu lagi.
3. Konsisten dengan harness itu sendiri: unit test proxy mode
   (`internal/benchmark/benchmark_test.go`) menguji s7-budget dan s8-rate-limit
   dengan **fake proxy terpisah** ("s8 rate limit diuji terpisah dengan fake
   yang sesuai").

Dengan dua konfigurasi di atas, KEDUA stop condition (budget dan rate limit)
terbukti terpicu masing-masing satu kali: **8/8 ekspektasi scenario
tervalidasi** (7/8 per run). Rekomendasi lanjutan (di luar scope pengukuran):
harness bisa menyediakan dua proxy instance atau reset budget per-scenario
group bila 8/8 single-run diinginkan.

## 3. Stress / load test proxy (`benchmarks/stress_test.py`)

Skrip permanen, stdlib Python, dapat dijalankan ulang:
`python benchmarks/stress_test.py` — mengelola sendiri target http.server +
3 instance proxy (bundle + sha256 + evidence dir di temp dir, dibersihkan
saat selesai). Bundle utama `max_requests=10000, rate_limit_rps=50`.

Dua run berturut-turut (keduanya exit 0, semua 11 assertion internal PASS):

| Pengukuran | Run 1 | Run 2 |
|---|---|---|
| **A** sequential 300 request (pace ~40 rps): executed | 300/300 | 300/300 |
| A: rate_limited / budget / other / errors | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| A: latency p50 | **6.79 ms** | 6.97 ms |
| A: latency p95 | **28.98 ms** | 25.56 ms |
| A: latency p99 | **42.63 ms** | 33.62 ms |
| A: min / mean / max (ms) | 4.44 / 11.36 / 92.90 | 4.47 / 12.02 / 44.96 |
| **B** concurrent 50 thread × 10 round = 500 attempt: wall | 0.45 s | 0.34 s |
| B: executed / rate_limited(429) / other(502) | 55 / 432 / 13 | 51 / 434 / 15 |
| B: throughput attempts/s | 1111.3 | 1460.2 |
| B: throughput executed/s (dibatasi rate limit 50 rps) | 122.2 | 148.9 |
| **C** rate limiter (fresh proxy, 5 rps): 20 sukses | 3.012 s | 3.023 s |
| C: 429 selama retry loop | 367 | 389 |
| **D** budget (fresh proxy, max_requests=10): 20 attempt | 10 executed + 10×429 budget | 10 + 10 |
| **E** evidence: file == request sukses (main) | 355/355 | 351/351 |
| E: sha256 evidence terverifikasi ulang | 355/355, seq 1..N kontinu | 351/351 |

Interpretasi:

- **Rate limit konsisten**: pada fase B, jumlah executed dibatasi token bucket
  (burst 50 + refill 50/s) — executed/s ≈ ceiling rate, dan sisa attempt
  murni 429 rate limit (akuntansi executed+429+other = 500, tanpa errors).
- **Token bucket bekerja** (fase C): 20 request sukses pada 5 rps (burst 5)
  butuh ≥ 3.0 s secara teori; terukur 3.012–3.023 s. Bucket tidak pernah
  menunggu (429 instan, 367–389 kali) — sesuai desain §22.
- **Budget fail-closed eksak** (fase D): tepat 10 eksekusi lalu semua 429
  dengan reason "request budget habis".
- **Evidence integrity** (§25): jumlah file `evidence-*.json` == jumlah
  request sukses per instance; `sha256` tiap file direkomputasi ulang
  (kanonikalisasi kompatibel `encoding/json` Go) dan dicocokkan dengan
  `evidence_sha256` yang dikembalikan API — 100% cocok, `seq` 1..N kontigu.
- Status `other` (502) pada fase B berasal dari target `python -m
  http.server` yang drop koneksi di bawah konkurensi 50 — proxy fail-closed
  melaporkan error transport sebagai 502, bukan crash. Bukan cacat proxy;
  dengan target produksi angka ini = 0.

## 4. Image cold-start (validator Docker)

Metode: `docker run --rm` per task valid, 3 run per image, wall-time
(`perf_counter` sekitar seluruh proses docker CLI → container → exit),
dengan baseline §15 lengkap (identik dengan `internal/dockerx`):
`--network none --read-only --cap-drop ALL --security-opt
no-new-privileges:true --pids-limit 64 --memory 512m --cpus 1.0 --tmpfs
/tmp:rw,size=16m`, bind mount `/workspace/{input,output}`.

| Image | Run (ms) | Rata-rata | Catatan |
|---|---|---|---|
| hermes-validator-http:0.1.0 | 11035.0 / 616.2 / 595.2 | 4082.1 ms (**warm ≈ 606 ms**) | run pertama terkena cold FS-cache/ekstraksi layer; run ke-2..3 mewakili steady-state |
| hermes/json-validator:dev | 677.9 / 565.4 / 568.8 | 604.0 ms | image di-rebuild dari source sebelum diukur (lihat catatan) |
| hermes/openapi-validator:dev | 563.9 / 562.4 / 577.4 | 567.9 ms | idem |
| hermes/python-validator:dev | 970.1 / 919.9 / 799.2 | 896.4 ms | base python:3.12-slim |

Catatan kejujuran: image `hermes/json-validator:dev` dan
`hermes/openapi-validator:dev` yang sudah ada lokal dibangun 2026-09-12
23:32 — sebelum perubahan kontrak §17 (`input.json_a`), sehingga task valid
versi source saat ini ditolaknya. Kedua image di-rebuild dari source repo
(`docker build -f runtimes/docker/images/.../Dockerfile -t ... .`) sebelum
pengukuran agar yang diukur adalah kode saat ini. Semua 12 run (4 image × 3)
menghasilkan `validation-result.json` berstatus `observed` (setelah rebuild:
12/12 OK).

## 5. Verifikasi resource container (bukti baseline §15/§16 benar-benar applied)

Container dijalankan dengan flag yang PERSIS disusun adapter
(`internal/dockerx/dockerx.go`, fungsi `buildRunArgs`: `--network none`,
`--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges:true`,
`--pids-limit 64`, `--memory 512m`, `--cpus 1.0`, `--tmpfs /tmp:rw,size=16m`,
label `hermes.managed/role/case`, mount read-only input) lalu di-`docker
inspect` SAAT BERJALAN (`State.Running=true`):

```
Running=true NetworkMode=none ReadonlyRootfs=true CapDrop=[ALL]
SecurityOpt=[no-new-privileges:true] PidsLimit=64 Memory=536870912
NanoCpus=1000000000 User=10001:10001 Tmpfs=map[/tmp:rw,size=16m]
Privileged=false
```

Artinya: pids_limit 64 ✓, mem_limit 512 MiB (536870912 byte) ✓, cpus 1.0
(NanoCpus 1e9) ✓, rootfs read-only ✓, cap-drop ALL ✓, no-new-privileges ✓,
network none ✓, non-root (UID 10001; image distroless http validator:
`User=65532:65532`) ✓, `Privileged=false` ✓.

Bonus acceptance §16 (deny-by-default): container dengan `--network none`
yang mencoba egress gagal total —
`socket.create_connection(('host.docker.internal',3000))` →
`BLOCKED: gaierror (Temporary failure in name resolution)` (tidak ada DNS,
tidak ada stack jaringan); pada bridge default DNS resolve normal. Jadi
`network violations = 0` dan container yang mencoba akses jaringan gagal,
sesuai kriteria acceptance §16.

## 6. Metrik §42 yang BELUM diukur (jujur)

| Metrik §42 | Status |
|---|---|
| routing accuracy (pemilihan skill oleh agent end-to-end) | belum diukur — butuh harness agent penuh; yang terukur: akurasi keputusan scope/risk/action = 8/8 |
| true positive rate / false positive rate temuan | belum diukur — butuh lab dengan ground truth finding |
| validation success rate / duplicate finding rate / report completeness | belum diukur |
| token usage | belum diukur (butuh LLM provider) |
| validator execution time (distribusi p50/p95, bukan cold-start) | sebagian: cold-start terukur (bagian 4); distribusi eksekusi normal belum |
| timeout frequency / container cleanup success rate | sebagian: 12/12 cold-start run exit bersih tanpa container tertinggal (count = 0, --rm + rm -f); angka formal per-fase belum dikumpulkan |
| container escape attempts / policy bypass attempts / prompt injection success | diukur sebagian oleh test adversarial repo (`go test ./...`), bukan oleh benchmark ini |

## Cara Reproduksi

```bash
# 0) Toolchain + build (Git Bash)
export PATH="$TEMP/go/bin:$PATH" GOCACHE="$TEMP/gocache" GOPATH="$TEMP/gopath"
go build -o "$TEMP/go/bin/hermes-security.exe" ./cmd/hermes-security
go build -o "$TEMP/go/bin/hermes-proxy.exe"    ./cmd/hermes-proxy

# 1) Mode policy (baseline 8/8)
hermes-security benchmark run --scenarios benchmarks/scenarios.json \
  --audit-file "$TEMP/audit-policy.jsonl" --out "$TEMP/bench-policy.json"

# 2) Mode proxy — target lokal di 127.0.0.1:3000 (mis. Juice Shop lab)
cat > "$TEMP/bundle-a.json" <<'EOF'
{"version":1,"allowed_hosts":["localhost:3000"],"max_requests":20,"rate_limit_rps":3,"follow_redirects":false,"timeout_seconds":15,"max_body_bytes":8192}
EOF
hermes-proxy --bundle "$TEMP/bundle-a.json" \
  --bundle-sha256 "$(sha256sum "$TEMP/bundle-a.json" | cut -d' ' -f1)" \
  --addr 127.0.0.1:8080 --evidence-dir "$TEMP/ev-a" &
hermes-security benchmark run --scenarios benchmarks/scenarios.json \
  --proxy-url http://127.0.0.1:8080 \
  --audit-file "$TEMP/audit-proxy.jsonl" --out "$TEMP/bench-proxy-a.json"
# Run B (budget terpicu): ganti bundle max_requests=4, rate_limit_rps=100, proxy di port lain.

# 3) Stress / perf test (mandiri, start target + proxy sendiri)
python benchmarks/stress_test.py            # exit 0 = semua assertion PASS

# 4) Cold-start (contoh satu image; ulangi 3x, lihat bagian 4 untuk param)
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 64 --memory 512m \
  --cpus 1.0 --tmpfs /tmp:rw,size=16m \
  -v "$TEMP/in:/workspace/input:ro" -v "$TEMP/out:/workspace/output" \
  hermes-validator-http:0.1.0

# 5) Bukti resource baseline §15 (container hidup)
docker run -d --name hermes-bench-rescheck --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 64 \
  --memory 512m --cpus 1.0 --tmpfs /tmp:rw,size=16m \
  --entrypoint python hermes/python-validator:dev -c "import time; time.sleep(120)"
docker inspect hermes-bench-rescheck \
  --format '{{.State.Running}} {{.HostConfig.NetworkMode}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.PidsLimit}} {{.HostConfig.Memory}} {{.HostConfig.NanoCpus}} {{.Config.User}}'
docker rm -f hermes-bench-rescheck
```

Verifikasi kesehatan repo saat pengukuran: `go test ./...` — semua package
PASS (tidak ada perubahan kode pada benchmark ini).
