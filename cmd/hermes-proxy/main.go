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
//	Listener MITM juga menerima request HTTP plaintext absolute-form
//	("GET http://host/path HTTP/1.1") — kontrak HTTP proxy untuk target
//	http:// — lihat mitmplain.go.
//
// Fail-closed: bundle tidak ada / hash mismatch / tidak valid = proxy menolak
// semua operasi.
//
// Shutdown: SIGINT/SIGTERM (Ctrl-C) memicu graceful shutdown — listener
// ditutup, request in-flight diberi waktu maksimal 5 detik untuk selesai
// sehingga evidence tidak tertulis setengah (evidence selalu ditulis utuh
// SEBELUM response dikirim; drain menjamin response terakhir juga sampai).
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"hermes-security-skills/internal/proxycore"
)

// shutdownGrace: waktu maksimal untuk drain request in-flight saat
// SIGINT/SIGTERM sebelum koneksi dipaksa ditutup.
const shutdownGrace = 5 * time.Second

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
	targetCA := flag.String("target-ca", "", "opsional (lab/testing): PEM CA tambahan untuk VERIFIKASI TLS TERHADAP TARGET (mis. target python ssl self-signed); kosong = system roots. TIDAK berhubungan dengan trust client terhadap CA MITM")
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
	engineOpts := proxycore.Options{
		EvidenceDir:  *evidenceDir,
		MaxBodyBytes: *maxBody,
	}
	if *targetCA != "" {
		// Lab/testing: verifikasi TLS target memakai CA khusus (mis. target
		// python ssl self-signed). Ini BUKAN mekanisme trust client terhadap
		// CA MITM — client tetap harus memasang --ca-out secara eksplisit.
		pool, err := loadCAPool(*targetCA)
		if err != nil {
			fmt.Fprintln(os.Stderr, "hermes-proxy:", err)
			os.Exit(1)
		}
		engineOpts.TLSRootCAs = pool
	}
	engine, err := proxycore.NewEngine(bundle, engineOpts)
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
	controlServer := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Bind listener di main (bukan di dalam Serve) supaya kegagalan bind
	// (port dipakai) terdeteksi sebelum goroutine serve jalan, dan supaya
	// graceful shutdown tidak balapan dengan start (pola net.Listen + Serve).
	controlLn, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hermes-proxy: listen control channel:", err)
		os.Exit(1)
	}

	servers := []listenerServer{{srv: controlServer, ln: controlLn}}

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
			Handler:           &mitmPlainHandler{connect: proxycore.NewMITMProxy(ca, engine), engine: engine},
			ReadHeaderTimeout: 10 * time.Second,
		}
		mitmLn, err := net.Listen("tcp", *mitmAddr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "hermes-proxy: listen MITM:", err)
			os.Exit(1)
		}
		servers = append(servers, listenerServer{srv: mitmSrv, ln: mitmLn})
		fmt.Println("[PERINGATAN] Mode 2 TLS MITM EKSPERIMENTAL aktif — CA ephemeral in-memory, leaf cert dinamis per SNI.")
		fmt.Println("             Intersepsi hanya sah untuk target yang diizinkan policy bundle; pasang CA publik (--ca-out) secara eksplisit pada client uji.")
		fmt.Printf("hermes-proxy/mitm: listen CONNECT di %s\n", *mitmAddr)
	}

	fmt.Printf("hermes-proxy: control channel listen di %s (mode bind: %s)\n", controlLn.Addr(), *bind)
	fmt.Printf("hermes-proxy: policy in-line aktif — %d host di-allowlist, budget %d request, rate %d rps, redirect follow=%v, timeout %s\n",
		len(bundle.AllowedHosts), bundle.MaxRequests, bundle.RateLimitRPS, bundle.FollowRedirects, bundle.Timeout())
	fmt.Printf("hermes-proxy: evidence dir: %s (mode eksekusi: replay engine nyata)\n", engine.EvidenceDir())

	// SIGINT/SIGTERM -> graceful shutdown (lihat doc package). Context
	// dibatalkan otomatis saat sinyal datang; stop() mengembalikan
	// perilaku sinyal default setelah serveUntilSignal selesai.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serveUntilSignal(ctx, shutdownGrace, servers...); err != nil {
		fmt.Fprintln(os.Stderr, "hermes-proxy:", err)
		os.Exit(1)
	}
	fmt.Println("hermes-proxy: shutdown selesai — semua listener ditutup, request in-flight selesai (evidence utuh).")
}

// loadCAPool memuat satu atau lebih sertifikat PEM CA ke x509.CertPool
// untuk verifikasi TLS terhadap target (lab/testing).
func loadCAPool(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("baca --target-ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("--target-ca %q tidak berisi sertifikat PEM valid (fail-closed)", path)
	}
	return pool, nil
}

// listenerServer memasangkan http.Server dengan listener yang SUDAH di-bind
// (pola net.Listen + Serve): memastikan shutdown selalu menutup listener yang
// sama dan tidak ada celah start-vs-shutdown.
type listenerServer struct {
	srv *http.Server
	ln  net.Listener
}

// serveUntilSignal menjalankan semua server sampai ctx dibatalkan
// (SIGINT/SIGTERM) atau salah satu Serve mengembalikan error, lalu graceful
// shutdown: listener ditutup, request in-flight diberi waktu maksimal
// `grace` untuk selesai — evidence tidak pernah tertulis setengah karena
// evidence ditulis utuh sebelum response dikirim. Mengembalikan error Serve
// pertama yang bukan http.ErrServerClosed (mis. bind gagal).
func serveUntilSignal(ctx context.Context, grace time.Duration, servers ...listenerServer) error {
	errCh := make(chan error, len(servers))
	for _, ls := range servers {
		go func(ls listenerServer) { errCh <- ls.srv.Serve(ls.ln) }(ls)
	}
	var serveErr error
	select {
	case <-ctx.Done():
		// sinyal shutdown (atau parent context dibatalkan)
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			serveErr = err // mis. listener gagal (port dipakai) — laporkan
		}
	}
	graceCtx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	for _, ls := range servers {
		// Shutdown menutup listener + menunggu request in-flight selesai.
		if err := ls.srv.Shutdown(graceCtx); err != nil {
			_ = ls.srv.Close() // grace habis — paksa tutup sisa koneksi
		}
	}
	return serveErr
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
