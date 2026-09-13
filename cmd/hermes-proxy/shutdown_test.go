package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// freeListener: listener loopback dengan port ephemeral (aman paralel test).
func freeListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln
}

// TestServeUntilSignalStopsAccepting: context cancel (jalur SIGINT/SIGTERM —
// di Windows diuji via context cancel langsung) harus membuat server berhenti
// menerima koneksi baru setelah graceful shutdown.
func TestServeUntilSignalStopsAccepting(t *testing.T) {
	ln := freeListener(t)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveUntilSignal(ctx, 5*time.Second, listenerServer{srv: srv, ln: ln}) }()

	url := "http://" + ln.Addr().String() + "/"

	// 1) Sebelum shutdown: server melayani request.
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("request sebelum shutdown: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("sebelum shutdown: code=%d body=%q, mau 200/ok", resp.StatusCode, body)
	}

	// 2) Cancel (simulasi sinyal) -> serveUntilSignal selesai.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveUntilSignal = %v, mau nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serveUntilSignal tidak selesai setelah context cancel")
	}

	// 3) Setelah shutdown: koneksi baru ditolak (listener sudah ditutup).
	if resp2, err := http.Get(url); err == nil {
		resp2.Body.Close()
		t.Fatal("server masih menerima koneksi setelah shutdown — harusnya connection refused")
	}
}

// TestServeUntilSignalDrainsInFlight: request in-flight diberi kesempatan
// selesai saat graceful shutdown — analog dengan jaminan evidence tidak
// tertulis setengah (response terakhir tetap terkirim utuh).
func TestServeUntilSignalDrainsInFlight(t *testing.T) {
	ln := freeListener(t)
	release := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release // tahan handler sampai shutdown dimulai
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("in-flight selesai"))
	})}

	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- serveUntilSignal(ctx, 5*time.Second, listenerServer{srv: srv, ln: ln}) }()

	type reqResult struct {
		body string
		err  error
	}
	reqDone := make(chan reqResult, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String() + "/")
		if err != nil {
			reqDone <- reqResult{"", err}
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		reqDone <- reqResult{string(b), nil}
	}()

	// Beri waktu request menempel di server, lalu picu shutdown.
	time.Sleep(100 * time.Millisecond)
	cancel()
	close(release)

	select {
	case r := <-reqDone:
		if r.err != nil {
			t.Fatalf("request in-flight gagal saat shutdown: %v", r.err)
		}
		if r.body != "in-flight selesai" {
			t.Fatalf("request in-flight terpotong: body=%q", r.body)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("request in-flight tidak selesai dalam grace period")
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("serveUntilSignal = %v, mau nil", err)
	}
}

// TestServeUntilSignalListenerError: listener gagal (mis. sudah ditutup /
// port dipakai) = serveUntilSignal mengembalikan error, bukan diam.
func TestServeUntilSignalListenerError(t *testing.T) {
	ln := freeListener(t)
	ln.Close() // listener ditutup SEBELUM Serve -> Accept langsung error

	srv := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}
	err := serveUntilSignal(context.Background(), time.Second, listenerServer{srv: srv, ln: ln})
	if err == nil {
		t.Fatal("listener mati harus menghasilkan error")
	}
}
