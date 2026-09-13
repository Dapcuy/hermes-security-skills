// Command hermes-proxy: proxy provider dengan eksekusi HTTP nyata
// (ROADMAP §11, §38 — Phase 7).
//
// Mode 1 — Replay engine (MVP):
//
//	POST /execute {url, method, headers, body} -> eksekusi HTTP nyata ke target
//	dengan policy IN-LINE per request (scope via internal/scope, rate limit
//	token bucket, budget max_requests, redirect no-follow default), redaksi
//	header sensitif, context budget body, dan evidence file per eksekusi.
//
// Mode 2 — TLS MITM (EKSPERIMENTAL, flag --mitm):
//
//	CONNECT tunneling dengan CA ephemeral in-memory + leaf cert dinamis per
//	SNI; request hasil intercept melewati jalur policy yang sama dengan Mode 1.
//
// Fail-closed: bundle tidak ada / hash mismatch / tidak valid = proxy menolak
// semua operasi.
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"hermes-security-skills/internal/proxycore"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "alamat listen control channel (default loopback)")
	bind := flag.String("bind", "loopback", `"loopback" (default) atau "all" (0.0.0.0) — "all" HANYA untuk mode container di Docker network internal (§11); JANGAN pernah expose control channel ke luar`)
	bundlePath := flag.String("bundle", "", "path policy bundle JSON")
	bundleSHA := flag.String("bundle-sha256", "", "sha256 hex yang diharapkan untuk bundle (wajib)")
	evidenceDir := flag.String("evidence-dir", "./jobs/evidence", "direktori evidence file (§25)")
	maxBody := flag.Int("max-body-bytes", 0, "context budget inline body (0 = otomatis: bundle.max_body_bytes atau 8192; nilai flag hanya boleh memperketat)")
	mitm := flag.Bool("mitm", false, "aktifkan Mode 2 TLS MITM (EKSPERIMENTAL)")
	mitmAddr := flag.String("mitm-addr", "127.0.0.1:8081", "alamat listen MITM CONNECT (default loopback)")
	caOut := flag.String("ca-out", "", "opsional: ekspor sertifikat publik CA MITM ke file PEM (TIDAK menyertakan private key)")
	flag.Parse()

	if *bundlePath == "" {
		fmt.Fprintln(os.Stderr, "hermes-proxy: --bundle wajib diisi (fail-closed: tanpa policy bundle proxy menolak semua)")
		os.Exit(1)
	}
	bundle, err := proxycore.LoadBundle(*bundlePath, *bundleSHA)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hermes-proxy:", err)
		os.Exit(1)
	}
	engine, err := proxycore.NewEngine(bundle, proxycore.Options{
		EvidenceDir:  *evidenceDir,
		MaxBodyBytes: *maxBody,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "hermes-proxy:", err)
		os.Exit(1)
	}

	// §11 — control channel: default loopback. --bind=all hanya untuk
	// deployment container di Docker network internal.
	listenAddr := *addr
	switch *bind {
	case "loopback":
		if err := validateLoopbackAddr(listenAddr); err != nil {
			fmt.Fprintln(os.Stderr, "hermes-proxy:", err)
			os.Exit(1)
		}
	case "all":
		listenAddr, err = bindAllAddr(listenAddr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "hermes-proxy:", err)
			os.Exit(1)
		}
		fmt.Println("[PERINGATAN] --bind=all: control channel listen di 0.0.0.0 — HANYA sah untuk container ephemeral di Docker network INTERNAL (§11). JANGAN publish port ke host/luar.")
	default:
		fmt.Fprintf(os.Stderr, "hermes-proxy: --bind %q tidak dikenal (pakai \"loopback\" atau \"all\") — fail-closed\n", *bind)
		os.Exit(1)
	}

	srv := &Server{engine: engine}
	mux := http.NewServeMux()
	mux.HandleFunc("/execute", srv.HandleExecute)
	httpServer := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if *mitm {
		// Mode 2 — TLS MITM (EKSPERIMENTAL). CA ephemeral in-memory per
		// engagement; private key tidak pernah ditulis ke disk (§23).
		ca, err := proxycore.GenerateCA(time.Now())
		if err != nil {
			fmt.Fprintln(os.Stderr, "hermes-proxy:", err)
			os.Exit(1)
		}
		if *caOut != "" {
			// Hanya sertifikat PUBLIK yang diekspor (PEM), bukan private key.
			if err := os.WriteFile(*caOut, ca.CertPEM(), 0o644); err != nil {
				fmt.Fprintln(os.Stderr, "hermes-proxy: tulis --ca-out:", err)
				os.Exit(1)
			}
			fmt.Printf("hermes-proxy: sertifikat publik CA MITM diekspor ke %s\n", *caOut)
		}
		mitmSrv := &http.Server{
			Addr:              *mitmAddr,
			Handler:           proxycore.NewMITMProxy(ca, engine),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			if err := mitmSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Fprintln(os.Stderr, "hermes-proxy/mitm:", err)
				os.Exit(1)
			}
		}()
		fmt.Println("[PERINGATAN] Mode 2 TLS MITM EKSPERIMENTAL aktif — CA ephemeral in-memory, leaf cert dinamis per SNI.")
		fmt.Println("             Intersepsi hanya sah untuk target yang diizinkan policy bundle; pasang CA publik (--ca-out) secara eksplisit pada client uji.")
		fmt.Printf("hermes-proxy/mitm: listen CONNECT di %s\n", *mitmAddr)
	}

	fmt.Printf("hermes-proxy: control channel listen di %s (mode bind: %s)\n", listenAddr, *bind)
	fmt.Printf("hermes-proxy: policy in-line aktif — %d host di-allowlist, budget %d request, rate %d rps, redirect follow=%v, timeout %s\n",
		len(bundle.AllowedHosts), bundle.MaxRequests, bundle.RateLimitRPS, bundle.FollowRedirects, bundle.Timeout())
	fmt.Printf("hermes-proxy: evidence dir: %s (mode eksekusi: replay engine nyata)\n", engine.EvidenceDir())
	if err := httpServer.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "hermes-proxy:", err)
		os.Exit(1)
	}
}

// validateLoopbackAddr: control channel hanya boleh listen di interface
// loopback pada mode default (ROADMAP §11: channel tidak di-expose ke luar).
func validateLoopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("addr tidak valid %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("addr %q harus loopback 127.0.0.0/8 atau ::1 (fail-closed; pakai --bind all untuk mode container, §11)", addr)
	}
	return nil
}

// bindAllAddr mengubah host dari addr menjadi 0.0.0.0 (mode container),
// mempertahankan port-nya.
func bindAllAddr(addr string) (string, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("addr tidak valid %q: %w", addr, err)
	}
	return net.JoinHostPort("0.0.0.0", port), nil
}
