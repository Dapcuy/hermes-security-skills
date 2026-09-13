// Package adversarial — E2E kill switch mid-execution (ROADMAP §10).
//
// Skenario serangan level sistem terhadap alur enforcement end-to-end:
//
//	target lambat (3s) → hermes-proxy (bundle+sha256) → hermes-security
//	serve --mcp (scope + risk + approval in-line) → request in-flight →
//	`hermes-security abort --case` dijalankan DI TENGAH eksekusi →
//	assert hasil: approval revoked, ABORTED marker, panggilan baru ditolak,
//	audit entry, dan validate --runtime docker menolak case aborted.
//
// Realitas in-flight yang terdokumentasi di laporan: eksekusi yang SUDAH
// berjalan di proxy tidak bisa dibatalkan di tengah jalan (tidak ada sinyal
// cancel dari abort ke proxy); yang dijamin adalah tidak ada eksekusi BARU
// setelah abort kembali. Test ini MENGECEK realitas itu secara eksplisit.
//
// Jalankan:
//
//	go test ./tests/adversarial/ -v -count=1
//
// Semua state (bundle, approvals, jobs, evidence, audit) berada di temp dir
// — test tidak pernah menulis ke direktori repo. Docker hanya dibutuhkan
// untuk sub-fase validate; bila daemon tidak tersedia, sub-fase itu di-skip.
package adversarial

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"hermes-security-skills/internal/approval"
	"hermes-security-skills/internal/jobs"
)

// repoRoot mengembalikan akar repo (file test ini berada di
// <root>/tests/adversarial/ — tiga level di atas file).
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller gagal")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	return root
}

// buildBinary meng-compile satu cmd repo ke temp dir dan mengembalikan path
// binary-nya (Windows: .exe).
func buildBinary(t *testing.T, root, pkg string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), filepath.Base(pkg)+".exe")
	cmd := exec.Command("go", "build", "-o", out, "./"+pkg)
	cmd.Dir = root
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, b)
	}
	return out
}

// freePort memberikan satu port loopback bebas.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// dockerOK melaporkan apakah daemon Docker merespons (untuk gate sub-fase
// validate yang butuh engine).
func dockerOK() bool {
	return exec.Command("docker", "info", "--format", "{{.ServerVersion}}").Run() == nil
}

// ---------------------------------------------------------------- rpc client

type rpcClient struct {
	cmd    *exec.Cmd
	stdin  chan string
	respCh chan map[string]any // setiap baris JSON dari stdout serve
	pend   map[int]chan map[string]any
	mu     sync.Mutex
	orphan []string // response tanpa pendaftar (diagnostik)
	stderr *bytes.Buffer
	t      *testing.T
}

func newRPCClient(t *testing.T, bin string, args ...string) *rpcClient {
	t.Helper()
	c := &rpcClient{
		stdin:  make(chan string, 8),
		respCh: make(chan map[string]any, 16),
		pend:   map[int]chan map[string]any{},
		stderr: &bytes.Buffer{},
		t:      t,
	}
	cmd := exec.Command(bin, args...)
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = c.stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start serve: %v", err)
	}
	c.cmd = cmd
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	// Pembaca stdout: satu baris JSON per response.
	go func() {
		sc := bufio.NewScanner(stdoutPipe)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				continue // bukan JSON (seharusnya tidak pernah di stdout)
			}
			c.respCh <- m
		}
		close(c.respCh)
	}()

	// Dispatcher tunggal: distribusikan response ke pendaftar berdasar id.
	go func() {
		for resp := range c.respCh {
			idf, _ := resp["id"].(float64)
			c.mu.Lock()
			wait, ok := c.pend[int(idf)]
			if ok {
				delete(c.pend, int(idf))
			}
			c.mu.Unlock()
			if ok {
				wait <- resp
			} else {
				b, _ := json.Marshal(resp)
				c.mu.Lock()
				c.orphan = append(c.orphan, string(b))
				c.mu.Unlock()
			}
		}
	}()

	// Penulis stdin (serialize).
	go func() {
		for line := range c.stdin {
			if _, err := stdinPipe.Write([]byte(line + "\n")); err != nil {
				return
			}
		}
	}()
	return c
}

// call mengirim satu JSON-RPC request dan menunggu response dengan id sama.
func (c *rpcClient) call(id int, method string, params any, timeout time.Duration) map[string]any {
	ch := c.callAsync(id, method, params)
	select {
	case resp := <-ch:
		return resp
	case <-time.After(timeout):
		c.t.Fatalf("timeout %s menunggu response id=%d (orphan: %v, stderr: %s)", timeout, id, c.orphanSnapshot(), c.stderr.String())
		return nil
	}
}

func (c *rpcClient) orphanSnapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.orphan...)
}

// callAsync mengirim request dan mengembalikan channel response-nya —
// dipakai untuk skenario in-flight (response dibaca belakangan).
func (c *rpcClient) callAsync(id int, method string, params any) chan map[string]any {
	ch := make(chan map[string]any, 1)
	c.mu.Lock()
	c.pend[id] = ch
	c.mu.Unlock()
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		c.t.Fatal(err)
	}
	select {
	case c.stdin <- string(b):
	case <-time.After(10 * time.Second):
		c.t.Fatalf("timeout menulis ke stdin serve")
	}
	return ch
}

// callText mengambil text content pertama dari response tools/call.
func callText(t *testing.T, resp map[string]any) string {
	t.Helper()
	res, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("response tanpa result: %v", resp)
	}
	content, ok := res["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("result tanpa content: %v", res)
	}
	first, _ := content[0].(map[string]any)
	s, _ := first["text"].(string)
	return s
}

// ---------------------------------------------------------------- test utils

func runCLI(t *testing.T, bin string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("jalankan %v: %v", args, err)
	}
	return code, out.String()
}

func auditContains(t *testing.T, path, needle string) bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("baca audit %s: %v", path, err)
	}
	return strings.Contains(string(data), needle)
}

// ---------------------------------------------------------------- E2E utama

func TestKillSwitchMidExecutionE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E di-skip pada -short")
	}
	root := repoRoot(t)
	tmp := t.TempDir()
	caseID := "case-adv-e2e"
	auditFile := filepath.Join(tmp, "audit", "audit.jsonl")

	// ---- (1) Build binary control plane + proxy.
	secBin := buildBinary(t, root, "cmd/hermes-security")
	proxyBin := buildBinary(t, root, "cmd/hermes-proxy")

	// ---- (2) Target lokal: endpoint lambat (in-flight) dan cepat.
	slowStarted := make(chan struct{})
	var once sync.Once
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slow":
			once.Do(func() { close(slowStarted) })
			time.Sleep(3 * time.Second)
			fmt.Fprint(w, "SLOW-OK")
		default:
			fmt.Fprint(w, "FAST-OK")
		}
	}))
	defer target.Close()
	// Catatan: scope checker menolak IP literal loopback (deny-first, guard
	// SSRF) TETAPI mengizinkan hostname "localhost" — untuk E2E lab lokal,
	// target di-address via hostname localhost (resolusi ke 127.0.0.1).
	_, targetPort, _ := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	targetURL := fmt.Sprintf("http://localhost:%s", targetPort)

	// ---- (3) Policy bundle + jalankan hermes-proxy.
	proxyPort := freePort(t)
	bundle := map[string]any{
		"version":         1,
		"allowed_hosts":   []string{"localhost:" + targetPort},
		"max_requests":    100,
		"rate_limit_rps":  10,
		"timeout_seconds": 30,
	}
	bundleBytes, _ := json.Marshal(bundle)
	bundlePath := filepath.Join(tmp, "bundle.json")
	if err := os.WriteFile(bundlePath, bundleBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bundleBytes)
	evidenceDir := filepath.Join(tmp, "evidence")
	proxyLog := &bytes.Buffer{}
	proxyCmd := exec.Command(proxyBin,
		"--addr", fmt.Sprintf("127.0.0.1:%d", proxyPort),
		"--bundle", bundlePath,
		"--bundle-sha256", hex.EncodeToString(sum[:]),
		"--evidence-dir", evidenceDir,
	)
	proxyCmd.Stdout = proxyLog
	proxyCmd.Stderr = proxyLog
	if err := proxyCmd.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer func() {
		_ = proxyCmd.Process.Kill()
		_, _ = proxyCmd.Process.Wait()
	}()
	// Tunggu proxy siap.
	deadline := time.Now().Add(15 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), time.Second)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("proxy tidak siap: %s", proxyLog.String())
		}
		time.Sleep(100 * time.Millisecond)
	}

	// ---- (4) Approval ter-scope + scope file + serve --mcp.
	stateDir := filepath.Join(tmp, "state")
	store := approval.OpenStore(filepath.Join(stateDir, "approvals.json"))
	if err := store.Save(approval.Record{
		CaseID: caseID, Capability: "request_replay", Host: "localhost",
		Method: "GET", Path: approval.PathAny, MaxRequests: 5,
		ExpiresAt: time.Now().Add(time.Hour).UTC(), Risk: "medium",
	}); err != nil {
		t.Fatal(err)
	}
	scopeFile := filepath.Join(tmp, "scope.yaml")
	if err := os.WriteFile(scopeFile, []byte("allowed_hosts:\n  - localhost:"+targetPort+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cli := newRPCClient(t, secBin, "serve", "--mcp",
		"--proxy-url", fmt.Sprintf("http://127.0.0.1:%d", proxyPort),
		"--scope-file", scopeFile,
		"--registry", filepath.Join(root, "capabilities", "registry.yaml"),
		"--policy-dir", filepath.Join(root, "policy"),
		"--state-dir", stateDir,
		"--jobs-dir", filepath.Join(tmp, "jobs"),
		"--evidence-dir", evidenceDir,
		"--audit-file", auditFile,
	)
	initResp := cli.call(1, "initialize", map[string]any{}, 15*time.Second)
	if _, ok := initResp["result"]; !ok {
		t.Fatalf("initialize gagal: %v (stderr: %s)", initResp, cli.stderr.String())
	}

	// ---- (5) tools/call in-flight ke endpoint lambat (3s).
	slowCall := cli.callAsync(2, "tools/call", map[string]any{
		"name": "request_replay",
		"arguments": map[string]any{
			"url": targetURL + "/slow", "method": "GET", "case": caseID,
		},
	})
	select {
	case <-slowStarted:
	case <-time.After(10 * time.Second):
		// Diagnostik: kemungkinan besar request DITOLAK — tampilkan response.
		select {
		case resp := <-slowCall:
			t.Fatalf("target lambat tidak menerima request; tools/call ditolak: %s (orphan: %v, stderr: %s)",
				callText(t, resp), cli.orphanSnapshot(), cli.stderr.String())
		default:
			t.Fatalf("target lambat tidak menerima request dan tidak ada response (orphan: %v, stderr: %s)",
				cli.orphanSnapshot(), cli.stderr.String())
		}
	}
	// Beri jeda kecil agar request benar-benar in-flight di tengah eksekusi.
	time.Sleep(500 * time.Millisecond)

	// ---- (6) KILL SWITCH di tengah eksekusi.
	// Catatan portabilitas: bila docker CLI/daemon tidak tersedia, cmdAbort
	// tetap menulis marker + revoke approval (hanya kill container yang
	// gagal) dan keluar exit 1 dengan peringatan — itu tetap dapat diterima
	// untuk sub-fase berikutnya.
	abortCode, abortOut := runCLI(t, secBin, "abort",
		"--case", caseID,
		"--jobs-dir", filepath.Join(tmp, "jobs"),
		"--state-dir", stateDir,
		"--audit-file", auditFile,
	)
	if abortCode != 0 && !strings.Contains(abortOut, "docker") {
		t.Fatalf("abort exit=%d out=%s", abortCode, abortOut)
	}

	// (a) Approval revoked dengan reason kill switch.
	recs, err := store.Load()
	if err != nil {
		t.Fatalf("load approval setelah abort: %v", err)
	}
	if len(recs) != 1 || !recs[0].Revoked || recs[0].RevokeReason != approval.ReasonRevokedByAbort {
		t.Errorf("approval harus revoked-by-abort: %+v", recs)
	}
	act, err := store.Active(caseID)
	if err != nil || len(act) != 0 {
		t.Errorf("tidak boleh ada approval aktif setelah abort (act=%v err=%v)", act, err)
	}

	// (b) ABORTED marker.
	if !jobs.IsAborted(filepath.Join(tmp, "jobs"), caseID) {
		t.Error("ABORTED marker tidak terdeteksi oleh jobs.IsAborted")
	}
	if _, err := os.Stat(filepath.Join(tmp, "jobs", caseID, "ABORTED")); err != nil {
		t.Errorf("file ABORTED harus ada: %v", err)
	}

	// (d) Audit entry kill switch.
	if !auditContains(t, auditFile, `"aborted"`) {
		t.Error("audit harus memuat entry aborted")
	}

	// ---- (7) Realitas in-flight: eksekusi yang SUDAH berjalan TIDAK
	// dibatalkan di tengah (known limitation §10 — tidak ada sinyal cancel
	// dari abort ke proxy). Test MENGECEK realitas ini, bukan mengasumsikan.
	select {
	case resp := <-slowCall:
		text := callText(t, resp)
		if !strings.Contains(text, `"status":"executed"`) {
			t.Errorf("in-flight: eksekusi yang sudah berjalan diharapkan selesai (executed); dapat: %.200s", text)
		}
		t.Logf("REALITAS in-flight: request yang sudah berjalan selesai normal setelah abort (known limitation, terdokumentasi)")
	case <-time.After(30 * time.Second):
		t.Fatal("timeout menunggu response in-flight")
	}

	// ---- (8) (c) Panggilan BARU ditolak: approval sudah revoked + case
	// aborted. Dua lapis penolakan harus bekerja.
	fast := cli.call(3, "tools/call", map[string]any{
		"name": "request_replay",
		"arguments": map[string]any{
			"url": targetURL + "/fast", "method": "GET", "case": caseID,
		},
	}, 15*time.Second)
	fastText := callText(t, fast)
	if !strings.Contains(fastText, `"status":"denied"`) {
		t.Errorf("eksekusi baru pasca-abort harus denied: %.200s", fastText)
	}
	if !strings.Contains(fastText, "di-abort") && !strings.Contains(fastText, "Revoked") && !strings.Contains(fastText, "revoked") {
		t.Errorf("alasan penolakan harus menyebut abort/revocation: %.200s", fastText)
	}
	if !auditContains(t, auditFile, `"decision":"denied"`) {
		t.Error("penolakan tools/call harus ter-audit")
	}

	// (c2) Read-only juga ditolak untuk case aborted (§10).
	ro := cli.call(4, "tools/call", map[string]any{
		"name":     "list_history",
		"arguments": map[string]any{"case": caseID},
	}, 15*time.Second)
	if !strings.Contains(callText(t, ro), `"status":"denied"`) {
		t.Errorf("read-only pada case aborted harus denied: %.200s", callText(t, ro))
	}

	// Tanpa case: read-only tetap melayani (event store utuh, bukti tidak hilang).
	roAll := cli.call(5, "tools/call", map[string]any{
		"name":     "list_history",
		"arguments": map[string]any{},
	}, 15*time.Second)
	allText := callText(t, roAll)
	if !strings.Contains(allText, `"status":"observed"`) {
		t.Errorf("list_history tanpa case harus tetap observed: %.160s", allText)
	}
	if !strings.Contains(allText, "evidence-000001.json") {
		t.Errorf("evidence request in-flight harus tercatat: %.200s", allText)
	}

	// ---- (9) validate --runtime docker menolak case aborted (§10).
	if !dockerOK() {
		t.Skip("docker daemon tidak tersedia — sub-fase validate di-skip")
	}
	taskPath := filepath.Join(tmp, "validation-task.json")
	if err := os.WriteFile(taskPath, []byte(`{"task_id":"adv-task-1","validator":{"id":"validator-http"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	vCode, vOut := runCLI(t, secBin, "validate",
		"--runtime", "docker",
		"--task", taskPath,
		"--case", caseID,
		"--jobs-dir", filepath.Join(tmp, "jobs"),
		"--audit-file", auditFile,
	)
	if vCode == 0 {
		t.Errorf("validate pada case aborted harus GAGAL (kill switch §10); out=%s", vOut)
	}
	if !strings.Contains(vOut, "di-abort") {
		t.Errorf("error validate harus menyebut case aborted: %s", vOut)
	}
}

// TestAbortIdempotentAndUnknownCase: abort pada case yang sama dua kali dan
// pada case tanpa approval tidak boleh merusak state — kill switch harus
// aman dipanggil berulang.
func TestAbortIdempotentAndUnknownCase(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E di-skip pada -short")
	}
	root := repoRoot(t)
	tmp := t.TempDir()
	secBin := buildBinary(t, root, "cmd/hermes-security")
	auditFile := filepath.Join(tmp, "audit", "audit.jsonl")
	stateDir := filepath.Join(tmp, "state")

	// Case tanpa approval sama sekali.
	code, out := runCLI(t, secBin, "abort", "--case", "case-kosong",
		"--jobs-dir", filepath.Join(tmp, "jobs"),
		"--state-dir", stateDir,
		"--audit-file", auditFile)
	if code != 0 {
		t.Fatalf("abort case tanpa approval harus sukses (0 revoked): exit=%d out=%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(tmp, "jobs", "case-kosong", "ABORTED")); err != nil {
		t.Errorf("marker harus tetap ditulis: %v", err)
	}

	// Abort berulang: idempotent, tetap exit 0.
	code2, out2 := runCLI(t, secBin, "abort", "--case", "case-kosong",
		"--jobs-dir", filepath.Join(tmp, "jobs"),
		"--state-dir", stateDir,
		"--audit-file", auditFile)
	if code2 != 0 {
		t.Fatalf("abort kedua harus idempotent: exit=%d out=%s", code2, out2)
	}
	if !auditContains(t, auditFile, `"aborted"`) {
		t.Error("audit aborted harus tercatat")
	}
}
