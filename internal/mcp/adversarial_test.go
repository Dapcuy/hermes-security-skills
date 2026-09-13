package mcp

// Test adversarial level sistem: permukaan injeksi MCP (JSON-RPC over stdio).
// Arguments JSON dengan field ekstra aneh, unicode escapes, payload 1MB,
// nesting dalam, dan baris protokol yang tidak masuk akal — semuanya harus
// menghasilkan error JSON-RPC yang RAPI (atau result bersih), TIDAK PANIC,
// TIDAK hang, dan TIDAK mengeksekusi apa pun di luar jalur enforcement.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hermes-security-skills/internal/approval"
)

// fuzzParams: baris params tools/call yang ditulis mentah (bukan via
// mustRequest) agar bentuk JSON-nya bebas.
var fuzzParams = []string{
	// arguments berisi field ekstra aneh (prototype pollution style).
	`{"name":"json_diff","arguments":{"json_a":1,"json_b":2,"__proto__":{"isAdmin":true},"constructor":"x","hasOwnProperty":1}}`,
	// arguments berupa array, bukan object.
	`{"name":"json_diff","arguments":[1,2,3]}`,
	// arguments null.
	`{"name":"json_diff","arguments":null}`,
	// name bukan string.
	`{"name":123,"arguments":{}}`,
	`{"name":{"$gt":""},"arguments":{}}`,
	// name kosong / whitespace.
	`{"name":"   ","arguments":{}}`,
	// name dengan unicode escapes dan karakter kontrol.
	`{"name":"\u0000\u0001json_diff","arguments":{}}`,
	`{"name":"json_diff","arguments":{"json_a":"null\u0000byte","json_b":"null byte"}}`,
	// lone surrogate (JSON tidak valid secara Unicode).
	`{"name":"json_diff","arguments":{"json_a":"\ud800","json_b":"ok"}}`,
	// surrogate pair valid — harus diterima sebagai string biasa.
	`{"name":"json_diff","arguments":{"json_a":"\ud83d\ude00","json_b":"😀"}}`,
	// params berupa skalar, bukan object.
	`"hanya string"`,
	`42`,
	`true`,
	`null`,
	`[]`,
	// jsonrpc salah versi.
	`{"jsonrpc":"1.0","id":1,"method":"tools/list"}`,
	`{"jsonrpc":2.0,"id":1,"method":"tools/list"}`,
	// id aneh: object, array, string raksasa, float.
	`{"jsonrpc":"2.0","id":{"a":1},"method":"tools/list"}`,
	`{"jsonrpc":"2.0","id":[1,2],"method":"tools/list"}`,
	fmt.Sprintf(`{"jsonrpc":"2.0","id":"%s","method":"tools/list"}`, strings.Repeat("x", 100000)),
	`{"jsonrpc":"2.0","id":1.5,"method":"ping"}`,
	// method unicode / kontrol.
	`{"jsonrpc":"2.0","id":9,"method":"t\u0000ools/list"}`,
	`{"jsonrpc":"2.0","id":9,"method":"tools/list\u00e9"}`,
}

// callText mengambil teks content[0] dari response tools/call yang sukses.
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
	first, ok := content[0].(map[string]any)
	if !ok {
		t.Fatalf("content[0] bukan object: %v", content)
	}
	s, _ := first["text"].(string)
	return s
}

// TestToolsCallFuzzParamsNoPanic: semua params aneh menghasilkan TEPAT satu
// response JSON valid (atau tidak ada response untuk notification) — tidak
// ada panic, tidak ada hang, tidak ada traffic ke mana pun.
func TestToolsCallFuzzParamsNoPanic(t *testing.T) {
	for i, raw := range fuzzParams {
		line := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":%s}`, 1000+i, raw)
		// Beberapa kasus bukan notification, sebagian ya; runServer hanya
		// memverifikasi tiap response adalah JSON valid.
		srv, _ := newTestServer(t, nil, nil)
		resps := runServer(t, srv, line)
		for _, resp := range resps {
			if _, ok := resp["error"]; ok {
				continue // error rapi = bagus
			}
			if _, ok := resp["result"]; ok {
				continue // result bersih = bagus
			}
			t.Errorf("vektor %d: response tanpa error/result: %v", i, resp)
		}
	}
}

// TestFuzzParamsOneCleanResponseEach: vektor dengan id sah (bukan
// notification) wajib dijawab TEPAT SATU response dengan id yang dicocokkan.
func TestFuzzParamsOneCleanResponseEach(t *testing.T) {
	idx := 0
	for _, raw := range fuzzParams {
		var probe map[string]any
		if err := json.Unmarshal([]byte(raw), &probe); err != nil {
			continue // params tidak parseable — dilayani vektor lain/error parse
		}
		id := 7000 + idx
		idx++
		line := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":%s}`, id, raw)
		srv, _ := newTestServer(t, nil, nil)
		resps := runServer(t, srv, line)
		if len(resps) != 1 {
			t.Fatalf("params %s: mau 1 response, dapat %d", raw, len(resps))
		}
		if resps[0]["id"] == nil {
			t.Errorf("params %s: id response kosong", raw)
		}
	}
}

// TestToolsCallOversizedArguments: payload 1MB tidak boleh membuat server
// panic/hang — json_diff dieksekusi lokal, filter event store menerima
// string sepanjang apa pun, ref/url panjang ditolak rapi.
func TestToolsCallOversizedArguments(t *testing.T) {
	big := strings.Repeat("A", 1<<20) // 1MB

	srv, _ := newTestServer(t, nil, nil)
	// json_diff 1MB vs 1MB identik → observed, observations kosong.
	resps := runServer(t, srv, mustRequest(t, 1, "tools/call", map[string]any{
		"name": "json_diff", "arguments": map[string]any{"json_a": big, "json_b": big},
	}))
	if text := callText(t, resps[0]); !strings.Contains(text, `"status":"observed"`) {
		t.Errorf("json_diff 1MB identik harus observed, dapat: %.120s", text)
	}

	// json_diff 1MB dengan satu char beda → tetap observed (bukan error).
	resps = runServer(t, srv, mustRequest(t, 2, "tools/call", map[string]any{
		"name": "json_diff", "arguments": map[string]any{"json_a": big, "json_b": "B" + big[1:]},
	}))
	if text := callText(t, resps[0]); !strings.Contains(text, `"status":"observed"`) {
		t.Errorf("json_diff beda 1 char harus observed: %.120s", text)
	}

	// list_history dengan url_substring 1MB → tidak ada yang cocok.
	resps = runServer(t, srv, mustRequest(t, 3, "tools/call", map[string]any{
		"name": "list_history", "arguments": map[string]any{"url_substring": big},
	}))
	if text := callText(t, resps[0]); !strings.Contains(text, `"status":"observed"`) {
		t.Errorf("list_history substring 1MB harus observed: %.120s", text)
	}

	// inspect_request dengan evidence_ref 1MB → invalid params rapi.
	resps = runServer(t, srv, mustRequest(t, 4, "tools/call", map[string]any{
		"name": "inspect_request", "arguments": map[string]any{"evidence_ref": big},
	}))
	if e, ok := resps[0]["error"].(map[string]any); !ok || e["code"] != float64(codeInvalidParams) {
		t.Errorf("evidence_ref 1MB harus -32602, dapat %v", resps[0])
	}

	// request_replay url 1MB → ditolak di jalur enforcement (approval tidak
	// ada untuk host seperti itu), tanpa panic.
	resps = runServer(t, srv, mustRequest(t, 5, "tools/call", map[string]any{
		"name": "request_replay",
		"arguments": map[string]any{
			"url": "http://localhost:8901/" + big, "method": "GET", "case": "c",
		},
	}))
	if _, ok := resps[0]["error"].(map[string]any); ok {
		t.Errorf("url 1MB harus callResult denied (bukan rpcError): %v", resps[0])
	} else {
		if !strings.Contains(callText(t, resps[0]), "denied") {
			t.Errorf("url 1MB harus denied, dapat: %.120s", callText(t, resps[0]))
		}
	}
}

// TestToolsCallOversizedBodyForwarded: body 1MB dengan approval sah harus
// diteruskan utuh ke proxy — besar bukan alasan penolakan diam-diam, tapi
// juga tidak boleh merusak server.
func TestToolsCallOversizedBodyForwarded(t *testing.T) {
	var receivedLen int
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		if b, ok := req["body"].(string); ok {
			receivedLen = len(b)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "executed"})
	}))
	defer proxySrv.Close()

	srv, store := newTestServer(t, nil, func(c *Config) { c.ProxyURL = proxySrv.URL })
	if err := store.Save(approval.Record{
		CaseID: "c", Capability: "request_replay", Host: "localhost",
		Method: "GET", Path: approval.PathAny, MaxRequests: 5,
		ExpiresAt: time.Now().Add(time.Hour).UTC(), Risk: "medium",
	}); err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("B", 1<<20)
	resps := runServer(t, srv, mustRequest(t, 21, "tools/call", map[string]any{
		"name": "request_replay",
		"arguments": map[string]any{
			"url": "http://localhost:8901/orders/1", "method": "GET", "body": big, "case": "c",
		},
	}))
	if !strings.Contains(callText(t, resps[0]), "forwarded") {
		t.Errorf("body 1MB dengan approval harus forwarded: %.160s", callText(t, resps[0]))
	}
	if receivedLen != len(big) {
		t.Errorf("proxy menerima %d byte, mau %d (body tidak boleh rusak)", receivedLen, len(big))
	}
}

// TestServeFuzzProtocolLines: baris protokol tak masuk akal (bukan JSON,
// array, nesting dalam, null) tidak boleh membunuh server atau merusak
// framing output.
func TestServeFuzzProtocolLines(t *testing.T) {
	deep := strings.Repeat("[", 100000) + strings.Repeat("]", 100000) // json depth limit
	lines := []string{
		"bukan json {{{",
		"\x00\x01\x02\xff binary garbage",
		"[]",
		"{}",
		"null",
		`{"jsonrpc":"2.0","id":51,"method":"ping"}`,
		deep,
		`   `,
		`{"jsonrpc":"2.0","id":52,"method":"ping"}`,
	}
	srv, _ := newTestServer(t, nil, nil)
	// line "null" dan "{}" adalah notification (tanpa response); sisanya
	// harus error rapi atau result — yang penting TIDAK panic dan dua ping
	// di akhir tetap terjawab (server tidak "rusak" oleh baris sebelumnya).
	resps := runServer(t, srv, lines...)
	pingOK := 0
	for _, r := range resps {
		if _, ok := r["result"]; ok {
			pingOK++
		}
	}
	if pingOK < 2 {
		t.Errorf("dua ping setelah baris sampah harus tetap terjawab, dapat %d result dari %v", pingOK, resps)
	}
}

// TestServeOversizedLineFailsClosed: satu baris melebihi buffer scanner
// (4MB) menghentikan serve dengan error — fail-closed, bukan silent truncate.
func TestServeOversizedLineFailsClosed(t *testing.T) {
	huge := strings.Repeat("A", 5<<20) // 5MB
	input := `{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n" + huge + "\n"
	srv, _ := newTestServer(t, nil, nil)
	var out strings.Builder
	err := srv.Serve(strings.NewReader(input), &out)
	if err == nil {
		t.Error("baris >4MB harus mengembalikan error (fail-closed), dapat nil")
	}
	// Ping pertama (sebelum baris raksasa) tetap harus terjawab.
	first := strings.SplitN(strings.TrimSpace(out.String()), "\n", 2)[0]
	var m map[string]any
	if err := json.Unmarshal([]byte(first), &m); err != nil {
		t.Fatalf("response pertama bukan JSON valid: %v (%q)", err, first)
	}
}

// TestInspectRequestTraversalRefs: evidence_ref dengan path traversal dan
// bentuk aneh ditolak invalid params (defense in depth §24).
func TestInspectRequestTraversalRefs(t *testing.T) {
	refs := []string{
		"../../etc/passwd",
		"..\\..\\windows\\win.ini",
		"evidence-000001.json/../../secret.json",
		"/etc/passwd",
		"evidence-000001.json\x00.png",
		".hidden.json",
		"evidence-.json",
		"EVIDENCE-000001.JSON",
	}
	for i, ref := range refs {
		srv, _ := newTestServer(t, nil, nil)
		resps := runServer(t, srv, mustRequest(t, 9000+i, "tools/call", map[string]any{
			"name": "inspect_request", "arguments": map[string]any{"evidence_ref": ref},
		}))
		if e, ok := resps[0]["error"].(map[string]any); !ok || e["code"] != float64(codeInvalidParams) {
			t.Errorf("ref %q harus -32602, dapat %v", ref, resps[0])
		}
	}
	// response_comparison juga tervalidasi.
	srv, _ := newTestServer(t, nil, nil)
	resps := runServer(t, srv, mustRequest(t, 9999, "tools/call", map[string]any{
		"name": "response_comparison",
		"arguments": map[string]any{
			"evidence_ref_a": "evidence-000001.json", "evidence_ref_b": "../evidence-000002.json",
		},
	}))
	if e, ok := resps[0]["error"].(map[string]any); !ok || e["code"] != float64(codeInvalidParams) {
		t.Errorf("ref traversal di compare harus -32602, dapat %v", resps[0])
	}
}

// TestToolsCallEvidenceTamperFailsClosed: evidence di-tamper di disk → tool
// event store menolak fail-closed (§25), bukan menyajikan data basi.
func TestToolsCallEvidenceTamperFailsClosed(t *testing.T) {
	dir := writeTestEvidence(t)
	path := filepath.Join(dir, "evidence-000001.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	resp, _ := m["response"].(map[string]any)
	resp["status"] = float64(500)
	out, _ := json.Marshal(m)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}

	srv, _ := newTestServer(t, nil, func(c *Config) { c.EvidenceDir = dir })
	resps := runServer(t, srv,
		mustRequest(t, 31, "tools/call", map[string]any{
			"name": "inspect_request", "arguments": map[string]any{"evidence_ref": "evidence-000001.json"},
		}),
		mustRequest(t, 32, "tools/call", map[string]any{"name": "list_history", "arguments": map[string]any{}}),
	)
	if e, ok := resps[0]["error"].(map[string]any); !ok || !strings.Contains(fmt.Sprint(e["data"]), "integritas") {
		t.Errorf("inspect pada evidence tamper harus error integritas, dapat %v", resps[0])
	}
	if e, ok := resps[1]["error"].(map[string]any); !ok {
		t.Errorf("list_history pada dir tamper harus gagal fail-closed, dapat %v", resps[1])
	} else if !strings.Contains(fmt.Sprint(e["data"]), "integritas") && !strings.Contains(fmt.Sprint(e["data"]), "sha256") {
		t.Errorf("error list_history harus menjelaskan integritas: %v", e)
	}
}
