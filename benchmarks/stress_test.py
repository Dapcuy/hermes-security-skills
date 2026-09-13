#!/usr/bin/env python3
"""Stress / performance test untuk hermes-proxy (ROADMAP §42, §43).

Standar: Python 3 stdlib only (urllib, threading, concurrent.futures,
hashlib, subprocess, tempfile). Dapat dijalankan ulang kapan pun; skrip
mengelola siklus hidup sendiri untuk semua proses yang ia start:

    target python http.server (localhost) + N instance hermes-proxy
    (bundle JSON + sha256 ditulis ke direktori temp, evidence dir terpisah).

Fase pengukuran (ROADMAP §42: request count, resource usage, timeout;
§11: rate limit token bucket + budget max_requests):

  A. sequential 300 request ke proxy (pace ~40 rps < rate_limit_rps 50)
     -> latency p50/p95/p99 request yang dieksekusi, error count.
  B. 50 concurrent x 10 round (thread pool, tanpa pace)
     -> throughput req/s, komposisi hasil (executed / rate-limited /
        budget), konsistensi token bucket (executed ~ burst + rate*t).
     CATATAN: status "other" (biasanya 502) = target python http.server
     yang drop koneksi di bawah konkurensi 50 — proxy fail-closed
     melaporkannya sebagai error transport, bukan crash. Bukan cacat
     proxy; gunakan target produksi untuk angka "other" = 0.
  C. verifikasi rate limiter: proxy fresh rate_limit_rps=5, kirim
     request instan (retry saat 429) sampai 20 request SUKSES -> durasi
     harus >= ~3s (20 sukses pada 5 rps dengan burst 5 = 3s minimum).
  D. verifikasi budget: proxy fresh max_requests=10, kirim 20 attempt
     -> tepat 10 executed + 10 denial 429 dengan reason "budget".

Verifikasi evidence (§25): jumlah file evidence-*.json == jumlah request
sukses per instance; setiap file di-parse, field sha256-nya diverifikasi
ulang (sha256 atas konten record tanpa field sha256 — kanonikalisasi
kompatibel encoding/json Go: key order file + escape HTML) DAN dibanding-
kan dengan evidence_sha256 yang dikembalikan API /execute.

Hasil dicetak sebagai tabel + satu blok JSON (mesin-readable). Exit code
0 bila semua assertion lulus, 1 bila tidak (CI-friendly).

Pemakaian:

    python benchmarks/stress_test.py [--proxy-bin PATH] [--target-port P]
                                     [--json-out FILE]

`--proxy-bin` default: env HERMES_PROXY_BIN, lalu $TEMP/go/bin/
hermes-proxy(.exe), lalu `hermes-proxy` di PATH. Build dulu:

    go build -o "$TEMP/go/bin/hermes-proxy" ./cmd/hermes-proxy
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------- konstanta

MAIN_BUNDLE = {"max_requests": 10000, "rate_limit_rps": 50}
RATE_BUNDLE = {"max_requests": 10000, "rate_limit_rps": 5}
BUDGET_BUNDLE = {"max_requests": 10, "rate_limit_rps": 100}

SEQ_TOTAL = 300          # fase A: request sequential
SEQ_PACE_S = 0.025       # fase A: jeda antar-start (~40 rps < 50 rps)
CONC_WORKERS = 50        # fase B: thread pool
CONC_ROUNDS = 10         # fase B: round per worker (50 x 10 = 500 attempt)
RATE_TARGET_OK = 20      # fase C: sukses yang diharapkan
RATE_MIN_SECONDS = 2.7   # fase C: 20 sukses @ 5 rps (burst 5) >= 3.0s + toleransi
BUDGET_TOTAL = 20        # fase D: attempt ke proxy budget 10
TIMEOUT_S = 30           # timeout per HTTP attempt
STARTUP_TIMEOUT_S = 30   # menunggu target/proxy siap


# ------------------------------------------------------------------ helpers

def percentile(sorted_vals, p):
    """Percentile linear-interpolation di atas list terurut."""
    if not sorted_vals:
        return None
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * (p / 100.0)
    lo, hi = int(k), min(int(k) + 1, len(sorted_vals) - 1)
    frac = k - lo
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * frac


def go_compat_json(obj) -> str:
    """Serialisasi kompatibel Go encoding/json (default Marshal):
    key order sesuai urutan dict (== urutan struct dari file), compact,
    HTML escape <, >, & dan escape U+2028/U+2029."""
    txt = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    return (txt
            .replace("&", "\\u0026")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029"))


def verify_evidence_file(path: str, api_sha: str | None):
    """Verifikasi satu evidence file. Return (ok, detail)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            rec = json.load(f)
    except Exception as exc:  # noqa: BLE001
        return False, "parse gagal: %s" % exc
    stored = rec.pop("sha256", None)
    if not stored:
        return False, "field sha256 tidak ada"
    try:
        recomputed = hashlib.sha256(
            go_compat_json(rec).encode("utf-8")).hexdigest()
    except Exception as exc:  # noqa: BLE001
        return False, "re-serialize gagal: %s" % exc
    if recomputed != stored:
        return False, "sha256 file != rekomputasi (%s != %s)" % (
            stored[:12], recomputed[:12])
    if api_sha is not None and api_sha != stored:
        return False, "sha256 file != evidence_sha256 API"
    # Sanitas minimal isi record (§25).
    for key in ("seq", "captured_at", "request", "response", "provenance"):
        if key not in rec:
            return False, "field %s tidak ada" % key
    if rec.get("provenance", {}).get("component") != "hermes-proxy":
        return False, "provenance.component != hermes-proxy"
    return True, "ok"


def post_execute(proxy_url: str, url: str, method: str = "GET"):
    """Satu POST /execute. Return dict {status, latency_ms, body}."""
    payload = json.dumps({"url": url, "method": method}).encode("utf-8")
    req = urllib.request.Request(
        proxy_url.rstrip("/") + "/execute", data=payload,
        headers={"Content-Type": "application/json"}, method="POST")
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            body = resp.read().decode("utf-8", "replace")
            code = resp.status
    except urllib.error.HTTPError as exc:  # 4xx/5xx tetap respons proxy
        body = exc.read().decode("utf-8", "replace")
        code = exc.code
    latency = (time.perf_counter() - t0) * 1000.0
    return {"status": code, "latency_ms": latency, "body": body}


def wait_proxy_alive(proxy_url: str):
    """Poll sampai control channel merespons (HTTP apapun = hidup)."""
    deadline = time.time() + STARTUP_TIMEOUT_S
    while time.time() < deadline:
        try:
            post_execute(proxy_url, "http://localhost:1/", "GET")
            return
        except (urllib.error.URLError, OSError, ConnectionError):
            time.sleep(0.1)
    raise RuntimeError("proxy %s tidak hidup dalam %ds"
                       % (proxy_url, STARTUP_TIMEOUT_S))


def wait_target_alive(target_url: str):
    deadline = time.time() + STARTUP_TIMEOUT_S
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(target_url, timeout=5) as resp:
                if resp.status == 200:
                    return
        except Exception:  # noqa: BLE001
            time.sleep(0.1)
    raise RuntimeError("target %s tidak hidup dalam %ds"
                       % (target_url, STARTUP_TIMEOUT_S))


def find_proxy_bin(explicit: str | None) -> str:
    if explicit:
        if not os.path.isfile(explicit):
            raise SystemExit("stress_test: --proxy-bin %s tidak ada" % explicit)
        return explicit
    env = os.environ.get("HERMES_PROXY_BIN")
    if env and os.path.isfile(env):
        return env
    temp = os.environ.get("TEMP") or tempfile.gettempdir()
    exe = "hermes-proxy.exe" if os.name == "nt" else "hermes-proxy"
    cand = os.path.join(temp, "go", "bin", exe)
    if os.path.isfile(cand):
        return cand
    which = shutil.which("hermes-proxy")
    if which:
        return which
    raise SystemExit(
        "stress_test: binary hermes-proxy tidak ditemukan — build dulu: "
        "go build -o \"$TEMP/go/bin/hermes-proxy\" ./cmd/hermes-proxy "
        "(atau set --proxy-bin / HERMES_PROXY_BIN)")


# ------------------------------------------------------------ proses hidup

class ManagedProcess:
    """Subprocess dengan cleanup terjamin (terminate -> kill)."""

    def __init__(self, args, label):
        self.label = label
        self.proc = subprocess.Popen(
            args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)


class Stack:
    """Target HTTP + satu instance proxy + bundle/evidence di temp dir."""

    def __init__(self, workdir, name, bundle, proxy_bin, proxy_port,
                 target_port):
        self.dir = os.path.join(workdir, name)
        os.makedirs(self.dir, exist_ok=True)
        self.evidence_dir = os.path.join(self.dir, "evidence")
        bundle_path = os.path.join(self.dir, "bundle.json")
        body = dict(bundle)
        body.update({
            "version": 1,
            "allowed_hosts": ["localhost:%d" % target_port],
            "follow_redirects": False,
            "timeout_seconds": 15,
            "max_body_bytes": 8192,
        })
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        with open(bundle_path, "wb") as f:
            f.write(data)
        sha = hashlib.sha256(data).hexdigest()
        self.proxy_url = "http://127.0.0.1:%d" % proxy_port
        self.proxy = ManagedProcess([
            proxy_bin, "--bundle", bundle_path, "--bundle-sha256", sha,
            "--addr", "127.0.0.1:%d" % proxy_port,
            "--evidence-dir", self.evidence_dir,
        ], "hermes-proxy/%s" % name)
        self.executed_refs = {}  # evidence_ref -> evidence_sha256 (dari API)

    def record(self, body_json):
        try:
            out = json.loads(body_json)
        except ValueError:
            return
        if out.get("evidence_ref") and out.get("evidence_sha256"):
            self.executed_refs[out["evidence_ref"]] = out["evidence_sha256"]

    def verify_evidence(self):
        files = sorted(f for f in os.listdir(self.evidence_dir)
                       if f.startswith("evidence-") and f.endswith(".json"))
        checked, failed = 0, []
        for name in files:
            ok, detail = verify_evidence_file(
                os.path.join(self.evidence_dir, name),
                self.executed_refs.get(name))
            checked += 1
            if not ok:
                failed.append("%s: %s" % (name, detail))
        seqs = []
        for name in files:
            try:
                with open(os.path.join(self.evidence_dir, name),
                          encoding="utf-8") as f:
                    seqs.append(json.load(f).get("seq"))
            except Exception:  # noqa: BLE001
                pass
        contiguous = seqs == list(range(1, len(files) + 1))
        return {
            "executed_from_api": len(self.executed_refs),
            "evidence_files": len(files),
            "verified": checked - len(failed),
            "verify_failed": failed,
            "seq_contiguous_1_to_n": contiguous,
            "count_matches_executed": len(files) == len(self.executed_refs),
        }

    def stop(self):
        self.proxy.stop()


# ------------------------------------------------------------- fase ujian

def phase_sequential(proxy_url, target_url, recorder=None):
    """Fase A — 300 request sequential, pace ~40 rps."""
    lat_ok, res = [], {"executed": 0, "rate_limited": 0, "budget": 0,
                       "other": 0, "errors": 0}
    for _ in range(SEQ_TOTAL):
        try:
            r = post_execute(proxy_url, target_url)
        except Exception:  # noqa: BLE001
            res["errors"] += 1
            time.sleep(SEQ_PACE_S)
            continue
        if r["status"] == 200:
            res["executed"] += 1
            lat_ok.append(r["latency_ms"])
            if recorder:
                recorder(r["body"])
        elif r["status"] == 429:
            if "budget" in r["body"]:
                res["budget"] += 1
            else:
                res["rate_limited"] += 1
        else:
            res["other"] += 1
        time.sleep(SEQ_PACE_S)
    lat_ok.sort()
    res["latency_ms"] = {
        "p50": round(percentile(lat_ok, 50), 2),
        "p95": round(percentile(lat_ok, 95), 2),
        "p99": round(percentile(lat_ok, 99), 2),
        "min": round(lat_ok[0], 2) if lat_ok else None,
        "max": round(lat_ok[-1], 2) if lat_ok else None,
        "mean": round(statistics.fmean(lat_ok), 2) if lat_ok else None,
    }
    return res


def phase_concurrent(proxy_url, target_url, rate_limit_rps, recorder=None):
    """Fase B — CONC_WORKERS x CONC_ROUNDS attempt tanpa pace."""
    res = {"attempts": CONC_WORKERS * CONC_ROUNDS, "executed": 0,
           "rate_limited": 0, "budget": 0, "other": 0, "errors": 0}
    lock = threading.Lock()

    def one():
        try:
            r = post_execute(proxy_url, target_url)
        except Exception:  # noqa: BLE001
            with lock:
                res["errors"] += 1
            return
        with lock:
            if r["status"] == 200:
                res["executed"] += 1
                if recorder:
                    recorder(r["body"])
            elif r["status"] == 429:
                if "budget" in r["body"]:
                    res["budget"] += 1
                else:
                    res["rate_limited"] += 1
            else:
                res["other"] += 1

    t0 = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=CONC_WORKERS) as pool:
        for _ in range(CONC_ROUNDS):
            pool.map(lambda _: one(), range(CONC_WORKERS))
    wall = time.perf_counter() - t0
    res["wall_seconds"] = round(wall, 3)
    res["throughput_attempts_per_s"] = round(res["attempts"] / wall, 1)
    res["throughput_executed_per_s"] = round(res["executed"] / wall, 1)
    # Konsistensi token bucket: yang dieksekusi tidak boleh melebihi
    # burst awal + refill selama window (token bucket = ceiling rate).
    ceiling = rate_limit_rps + rate_limit_rps * wall + 10
    res["rate_limit_consistent"] = res["executed"] <= ceiling
    res["accounting_ok"] = (
        res["executed"] + res["rate_limited"] + res["budget"]
        + res["other"] + res["errors"] == res["attempts"])
    return res


def phase_rate_limiter(proxy_url, target_url, recorder=None):
    """Fase C — rate limiter: 20 sukses instan pada 5 rps harus >= ~3s."""
    executed, denied, t_first = 0, 0, time.perf_counter()
    deadline = t_first + 60
    while executed < RATE_TARGET_OK and time.perf_counter() < deadline:
        r = post_execute(proxy_url, target_url)
        if r["status"] == 200:
            executed += 1
            if recorder:
                recorder(r["body"])
        elif r["status"] == 429:
            denied += 1
        else:
            return {"error": "status tak terduga %d: %s"
                    % (r["status"], r["body"][:80])}
    duration = time.perf_counter() - t_first
    return {
        "executed": executed,
        "denied_429": denied,
        "duration_seconds": round(duration, 3),
        "min_seconds": RATE_MIN_SECONDS,
        "ok": executed == RATE_TARGET_OK and duration >= RATE_MIN_SECONDS,
    }


def phase_budget(proxy_url, target_url, recorder=None):
    """Fase D — budget max_requests=10: 20 attempt -> 10 executed + 10 429."""
    executed, denied_budget, other = 0, 0, 0
    for _ in range(BUDGET_TOTAL):
        r = post_execute(proxy_url, target_url)
        if r["status"] == 200:
            executed += 1
            if recorder:
                recorder(r["body"])
        elif r["status"] == 429 and "budget" in r["body"]:
            denied_budget += 1
        else:
            other += 1
    return {
        "attempts": BUDGET_TOTAL, "executed": executed,
        "denied_budget_429": denied_budget, "other": other,
        "ok": executed == 10 and denied_budget == 10 and other == 0,
    }


# ------------------------------------------------------------------ driver

def main():
    ap = argparse.ArgumentParser(
        description="Stress/perf test hermes-proxy (ROADMAP §42)")
    ap.add_argument("--proxy-bin", default=None,
                    help="path binary hermes-proxy (default auto-detect)")
    ap.add_argument("--target-port", type=int, default=18123)
    ap.add_argument("--main-proxy-port", type=int, default=18200)
    ap.add_argument("--rate-proxy-port", type=int, default=18201)
    ap.add_argument("--budget-proxy-port", type=int, default=18202)
    ap.add_argument("--json-out", default=None,
                    help="tulis ringkasan JSON ke file ini juga")
    args = ap.parse_args()

    proxy_bin = find_proxy_bin(args.proxy_bin)
    workdir = tempfile.mkdtemp(prefix="hermes-stress-")
    target = None
    stacks = []
    report = {"started_at_utc": time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "proxy_bin": proxy_bin}
    ok = True
    try:
        docroot = os.path.join(workdir, "www")
        os.makedirs(docroot)
        with open(os.path.join(docroot, "index.html"), "w",
                  encoding="utf-8") as f:
            f.write("hermes stress target\n" * 4)
        target = ManagedProcess(
            [sys.executable, "-m", "http.server", str(args.target_port),
             "--bind", "127.0.0.1", "--directory", docroot],
            "python http.server")
        target_url = "http://localhost:%d/" % args.target_port
        wait_target_alive(target_url)

        # --- Instance utama: fase A + B (budget 10000, rate 50) ---
        main_stack = Stack(workdir, "main", MAIN_BUNDLE, proxy_bin,
                           args.main_proxy_port, args.target_port)
        stacks.append(main_stack)
        wait_proxy_alive(main_stack.proxy_url)
        report["phase_a_sequential"] = phase_sequential(
            main_stack.proxy_url, target_url, recorder=main_stack.record)
        report["phase_b_concurrent"] = phase_concurrent(
            main_stack.proxy_url, target_url, MAIN_BUNDLE["rate_limit_rps"],
            recorder=main_stack.record)
        report["evidence_main"] = main_stack.verify_evidence()

        # --- Instance rate limiter: fase C (rate 5) ---
        rate_stack = Stack(workdir, "rate", RATE_BUNDLE, proxy_bin,
                           args.rate_proxy_port, args.target_port)
        stacks.append(rate_stack)
        wait_proxy_alive(rate_stack.proxy_url)
        report["phase_c_rate_limiter"] = phase_rate_limiter(
            rate_stack.proxy_url, target_url, recorder=rate_stack.record)
        report["evidence_rate"] = rate_stack.verify_evidence()

        # --- Instance budget: fase D (max_requests 10) ---
        budget_stack = Stack(workdir, "budget", BUDGET_BUNDLE, proxy_bin,
                             args.budget_proxy_port, args.target_port)
        stacks.append(budget_stack)
        wait_proxy_alive(budget_stack.proxy_url)
        report["phase_d_budget"] = phase_budget(
            budget_stack.proxy_url, target_url, recorder=budget_stack.record)
        report["evidence_budget"] = budget_stack.verify_evidence()

        # --- Assertion agregat ---
        checks = {
            "a_executed_all": report["phase_a_sequential"]["executed"]
            == SEQ_TOTAL,
            "a_no_errors": (report["phase_a_sequential"]["errors"] == 0
                            and report["phase_a_sequential"]["other"] == 0),
            "b_accounting": report["phase_b_concurrent"]["accounting_ok"],
            "b_rate_consistent": report["phase_b_concurrent"]
            ["rate_limit_consistent"],
            "c_rate_limiter_ok": report["phase_c_rate_limiter"].get("ok",
                                                                    False),
            "d_budget_ok": report["phase_d_budget"]["ok"],
            "evidence_main_count": report["evidence_main"]
            ["count_matches_executed"],
            "evidence_main_sha": not report["evidence_main"]
            ["verify_failed"],
            "evidence_main_seq": report["evidence_main"]
            ["seq_contiguous_1_to_n"],
            "evidence_rate_count": report["evidence_rate"]
            ["count_matches_executed"],
            "evidence_budget_count": report["evidence_budget"]
            ["count_matches_executed"],
        }
        report["checks"] = checks
        ok = all(checks.values())
        report["result"] = "PASS" if ok else "FAIL"

        # --- Cetak ringkasan ---
        a, b = report["phase_a_sequential"], report["phase_b_concurrent"]
        c, d = report["phase_c_rate_limiter"], report["phase_d_budget"]
        em, er, eb = (report["evidence_main"], report["evidence_rate"],
                      report["evidence_budget"])
        print("=" * 64)
        print("stress_test hermes-proxy  —  %s" % report["result"])
        print("=" * 64)
        print("A sequential %d (pace %.0fms): executed=%d rate_limited=%d "
              "budget=%d other=%d errors=%d"
              % (SEQ_TOTAL, SEQ_PACE_S * 1000, a["executed"],
                 a["rate_limited"], a["budget"], a["other"], a["errors"]))
        la = a["latency_ms"]
        print("  latency executed: p50=%sms p95=%sms p99=%sms "
              "(min=%s max=%s mean=%s)"
              % (la["p50"], la["p95"], la["p99"], la["min"], la["max"],
                 la["mean"]))
        print("B concurrent %dx%d: executed=%d rate_limited=%d budget=%d "
              "other=%d errors=%d"
              % (CONC_WORKERS, CONC_ROUNDS, b["executed"],
                 b["rate_limited"], b["budget"], b["other"], b["errors"]))
        print("  wall=%ss throughput=%.1f attempts/s (%.1f executed/s) "
              "rate_consistent=%s"
              % (b["wall_seconds"], b["throughput_attempts_per_s"],
                 b["throughput_executed_per_s"], b["rate_limit_consistent"]))
        print("C rate limiter (5 rps): executed=%d denied=%d duration=%ss "
              "(min %ss) ok=%s"
              % (c.get("executed"), c.get("denied_429"),
                 c.get("duration_seconds"), c.get("min_seconds"),
                 c.get("ok")))
        print("D budget (max 10): executed=%d denied_budget=%d other=%d "
              "ok=%s"
              % (d["executed"], d["denied_budget_429"], d["other"],
                 d["ok"]))
        print("E evidence main: files=%d executed_api=%d verified=%d "
              "failed=%d seq_contiguous=%s"
              % (em["evidence_files"], em["executed_from_api"],
                 em["verified"], len(em["verify_failed"]),
                 em["seq_contiguous_1_to_n"]))
        for name, ev in (("rate", er), ("budget", eb)):
            print("  evidence %s: files=%d executed_api=%d count_match=%s"
                  % (name, ev["evidence_files"], ev["executed_from_api"],
                     ev["count_matches_executed"]))
        if em["verify_failed"]:
            print("  verify_failed:", *em["verify_failed"][:5], sep="\n    ")
        print("checks:", " ".join(
            "%s=%s" % (k, "ok" if v else "FAIL")
            for k, v in checks.items()))
    finally:
        for st in stacks:
            st.stop()
        if target:
            target.stop()
        shutil.rmtree(workdir, ignore_errors=True)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
    print("---")
    print(json.dumps(report, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
