package dockerx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fakeExecer: fake exec helper — merekam semua invocation dan boleh
// mengembalikan error untuk invocation pertama (mis. simulasi docker run
// gagal/timeout) serta stdout canned per perintah (keyed by args[0]).
type fakeExecer struct {
	calls     [][]string
	firstErr  error             // error invocation pertama
	responses map[string]string // args[0] -> stdout
}

func (f *fakeExecer) Exec(_ context.Context, args ...string) ([]byte, error) {
	f.calls = append(f.calls, args)
	if len(f.calls) == 1 && f.firstErr != nil {
		return nil, f.firstErr
	}
	if f.responses != nil {
		if out, ok := f.responses[args[0]]; ok {
			return []byte(out), nil
		}
	}
	return nil, nil
}

// commands mengembalikan daftar subcommand docker yang dipanggil.
func (f *fakeExecer) commands() []string {
	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		if len(c) > 0 {
			out = append(out, c[0])
		}
	}
	return out
}

func validSpec(t *testing.T) RunSpec {
	t.Helper()
	base := t.TempDir()
	return RunSpec{
		Image:     "hermes-validator-http:0.1.0",
		Cmd:       []string{"--input", "/workspace/input/validation-task.json"},
		InputDir:  filepath.Join(base, "in"),
		OutputDir: filepath.Join(base, "out"),
		Env:       []string{"HERMES_TASK_ID=val-001"},
		Labels:    map[string]string{LabelCase: "demo", "hermes.run": "e2e"},
		Timeout:   30 * time.Second,
		Name:      "hermes-val-demo-001",
	}
}

// ------------------------------------------------------------- buildRunArgs

func TestBuildRunArgsBaseline(t *testing.T) {
	spec := validSpec(t)
	args, err := buildRunArgs(spec)
	if err != nil {
		t.Fatalf("buildRunArgs error: %v", err)
	}
	joined := strings.Join(args, " ")

	// Pasangan baseline wajib ada dan berurutan (§15, §16).
	wantPairs := [][2]string{
		{"run", "--rm"},
		{"--name", "hermes-val-demo-001"},
		{"--network", "none"},
		{"--read-only", ""},
		{"--cap-drop", "ALL"},
		{"--security-opt", "no-new-privileges:true"},
		{"--pids-limit", "64"},
		{"--memory", "512m"},
		{"--cpus", "1.0"},
		{"--tmpfs", "/tmp:rw,size=16m"},
		{"--label", "hermes.managed=true"},
		{"--label", "hermes.role=validator"},
		{"--label", "hermes.case=demo"},
		{"--label", "hermes.run=e2e"},
		{"-v", spec.InputDir + ":/workspace/input:ro"},
		{"-v", spec.OutputDir + ":/workspace/output"},
		{"-e", "HERMES_TASK_ID=val-001"},
	}
	for _, p := range wantPairs {
		if !containsPair(args, p[0], p[1]) {
			t.Errorf("pasangan %q->%q tidak ada di args: %s", p[0], p[1], joined)
		}
	}

	// Image dan Cmd harus di posisi akhir, berurutan.
	last := len(args) - 1
	if args[last-len(spec.Cmd)] != spec.Image {
		t.Errorf("image harus sebelum cmd: %v", args)
	}
	for i, c := range spec.Cmd {
		if args[last-len(spec.Cmd)+1+i] != c {
			t.Errorf("cmd[%d] salah: %v", i, args)
		}
	}
	// Mount output TIDAK boleh read-only.
	if strings.Contains(joined, "/workspace/output:ro") {
		t.Error("output dir tidak boleh di-mount read-only")
	}
}

// containsPair memeriksa ada arg `a` yang langsung diikuti `b`
// (b == "" berarti cukup ada `a`).
func containsPair(args []string, a, b string) bool {
	for i, v := range args {
		if v != a {
			continue
		}
		if b == "" || (i+1 < len(args) && args[i+1] == b) {
			return true
		}
	}
	return false
}

func TestBuildRunArgsFailClosed(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*RunSpec)
	}{
		{"image kosong", func(s *RunSpec) { s.Image = "" }},
		{"image berspasi", func(s *RunSpec) { s.Image = "img with space" }},
		{"name kosong", func(s *RunSpec) { s.Name = "" }},
		{"name invalid", func(s *RunSpec) { s.Name = "-bad name!" }},
		{"timeout nol", func(s *RunSpec) { s.Timeout = 0 }},
		{"timeout negatif", func(s *RunSpec) { s.Timeout = -time.Second }},
		{"input relatif", func(s *RunSpec) { s.InputDir = "jobs/x/input" }},
		{"output relatif", func(s *RunSpec) { s.OutputDir = "jobs/x/output" }},
		{"tanpa label case", func(s *RunSpec) { delete(s.Labels, LabelCase) }},
		{"label case kosong", func(s *RunSpec) { s.Labels[LabelCase] = "" }},
		{"label key invalid", func(s *RunSpec) { s.Labels["hermes ev il"] = "x" }},
		{"label value invalid", func(s *RunSpec) { s.Labels["evil"] = "a b" }},
		{"env invalid", func(s *RunSpec) { s.Env = []string{"BAD ENV=1"} }},
		{"env tanpa nilai", func(s *RunSpec) { s.Env = []string{"NOVALUE"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := validSpec(t)
			tc.mut(&spec)
			if _, err := buildRunArgs(spec); err == nil {
				t.Errorf("harus fail-closed (error), dapat nil")
			}
		})
	}
}

// Label reserved (managed/role) yang dioverride caller TIDAK boleh
// mengubah nilai adapter — versi adapter selalu menang.
func TestBuildRunArgsReservedLabelsWin(t *testing.T) {
	spec := validSpec(t)
	spec.Labels[LabelManaged] = "pwned"
	args, err := buildRunArgs(spec)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	for i, a := range args {
		if a == "--label" && i+1 < len(args) && strings.HasPrefix(args[i+1], LabelManaged+"=") {
			if args[i+1] != labelManagedValue {
				t.Errorf("label managed dioverride caller: %s", args[i+1])
			}
		}
	}
}

// -------------------------------------------------------------------- Run

func TestRunSuccessNoCleanupCall(t *testing.T) {
	fake := &fakeExecer{}
	spec := validSpec(t)
	out, err := runWith(fake, context.Background(), spec)
	if err != nil {
		t.Fatalf("run error: %v", err)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("harus 1 invocation, dapat %v", fake.commands())
	}
	if fake.calls[0][0] != "run" {
		t.Errorf("invocation pertama harus docker run: %v", fake.calls[0])
	}
	if out != nil {
		t.Logf("out=%s", out)
	}
}

func TestRunFailureAlwaysCleansUp(t *testing.T) {
	fake := &fakeExecer{firstErr: errors.New("exit status 137 (simulasi timeout)")}
	spec := validSpec(t)
	_, err := runWith(fake, context.Background(), spec)
	if err == nil {
		t.Fatal("run gagal harus error")
	}
	if !strings.Contains(err.Error(), "simulasi timeout") {
		t.Errorf("error harus memuat sebab asal: %v", err)
	}
	// Lifecycle §18: setelah gagal, wajib ada `docker rm -f <name>`.
	if len(fake.calls) != 2 {
		t.Fatalf("harus ada invocation cleanup, dapat %v", fake.commands())
	}
	rm := fake.calls[1]
	if rm[0] != "rm" || rm[1] != "-f" || rm[2] != spec.Name {
		t.Errorf("cleanup harus `rm -f %s`, dapat %v", spec.Name, rm)
	}
}

// --------------------------------------------------------------- RemoveByLabel

func TestRemoveByLabel(t *testing.T) {
	fake := &fakeExecer{responses: map[string]string{
		"ps": "abc123\ndef456\n\n",
	}}
	n, err := removeByLabel(fake, "hermes.case=demo")
	if err != nil {
		t.Fatalf("removeByLabel error: %v", err)
	}
	if n != 2 {
		t.Errorf("removed = %d, mau 2", n)
	}
	if len(fake.calls) != 3 {
		t.Fatalf("harus ps + 2 rm, dapat %v", fake.calls)
	}
	if fake.calls[0][1] != "-aq" || fake.calls[0][3] != "label=hermes.case=demo" {
		t.Errorf("filter label salah: %v", fake.calls[0])
	}
	for _, c := range fake.calls[1:] {
		if c[0] != "rm" || c[1] != "-f" {
			t.Errorf("harus rm -f per id: %v", c)
		}
	}
}

func TestRemoveByLabelEmptyAndInvalid(t *testing.T) {
	fake := &fakeExecer{responses: map[string]string{"ps": ""}}
	if n, err := removeByLabel(fake, "hermes.case=none"); err != nil || n != 0 {
		t.Errorf("kosong harus (0, nil), dapat (%d, %v)", n, err)
	}
	if len(fake.calls) != 1 {
		t.Errorf("tidak boleh rm saat tidak ada container")
	}
	if _, err := removeByLabel(&fakeExecer{}, "label-tanpa-value"); err == nil {
		t.Error("selector tanpa '=' harus error")
	}
	if _, err := removeByLabel(&fakeExecer{}, "a b=c"); err == nil {
		t.Error("selector berspasi harus error")
	}
}

// ---------------------------------------------------------------- Available

func TestAvailable(t *testing.T) {
	ok := &fakeExecer{responses: map[string]string{"version": `{"Client":{"Version":"29.7.2"},"Server":{"Version":"29.7.2"}}`}}
	if err := available(ok); err != nil {
		t.Errorf("server ada harus nil, dapat %v", err)
	}

	daemonMati := &fakeExecer{responses: map[string]string{"version": `{"Client":{"Version":"29.7.2"},"Server":null}`}}
	if err := available(daemonMati); err == nil {
		t.Error("server null harus error (fail-closed)")
	}

	cliError := &fakeExecer{firstErr: errors.New("executable not found")}
	if err := available(cliError); err == nil {
		t.Error("docker tidak ada harus error")
	}

	badJSON := &fakeExecer{responses: map[string]string{"version": "bukan json"}}
	if err := available(badJSON); err == nil {
		t.Error("json invalid harus error")
	}

	// trimJSON: noise sebelum/sesudah payload dibuang.
	if got := string(trimJSON([]byte("warning: x\n{\"a\":1}\ntrailing"))); got != `{"a":1}` {
		t.Errorf("trimJSON = %q", got)
	}
}

func TestServerVersion(t *testing.T) {
	fake := &fakeExecer{responses: map[string]string{"version": `{"Server":{"Version":"29.7.2"}}`}}
	v, err := serverVersion(fake)
	if err != nil || v != "29.7.2" {
		t.Errorf("serverVersion = %q, %v", v, err)
	}
}

func TestVerifyImageRejectsTagEvenWithExpectedDigest(t *testing.T) {
	const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fake := &fakeExecer{responses: map[string]string{"image": `["registry.example/tool@` + digest + `"]`}}
	sig := &recordingSignatureVerifier{}
	if err := VerifyImage(context.Background(), fake, sig, ImageVerificationSpec{
		Image: "registry.example/tool:release", ExpectedDigest: digest, SignatureRequired: true,
	}); err == nil || !strings.Contains(err.Error(), "digest-pinned") {
		t.Fatalf("tag reference with required signature must fail closed, got %v", err)
	}
}

func TestVerifyImageDigestAndSignature(t *testing.T) {
	const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fake := &fakeExecer{responses: map[string]string{"image": `["registry.example/tool@` + digest + `"]`}}
	sig := &recordingSignatureVerifier{}
	if err := VerifyImage(context.Background(), fake, sig, ImageVerificationSpec{
		Image: "registry.example/tool@" + digest, ExpectedDigest: digest, SignatureRequired: true,
	}); err != nil {
		t.Fatalf("valid digest and signature should pass: %v", err)
	}
	if sig.image != "registry.example/tool@"+digest {
		t.Errorf("signature provider received %q", sig.image)
	}
}

func TestVerifyImageFailsClosed(t *testing.T) {
	const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cases := []struct {
		name string
		out  string
		spec ImageVerificationSpec
	}{
		{"digest mismatch", `["registry.example/tool@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]`, ImageVerificationSpec{Image: "registry.example/tool@" + digest, ExpectedDigest: digest}},
		{"signature requires pin", `[]`, ImageVerificationSpec{Image: "registry.example/tool:latest", SignatureRequired: true}},
		{"signature provider missing", `["registry.example/tool@` + digest + `"]`, ImageVerificationSpec{Image: "registry.example/tool@" + digest, ExpectedDigest: digest, SignatureRequired: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeExecer{responses: map[string]string{"image": tc.out}}
			var sig SignatureVerifier
			if tc.name != "signature provider missing" {
				sig = &recordingSignatureVerifier{}
			}
			if err := VerifyImage(context.Background(), fake, sig, tc.spec); err == nil {
				t.Fatal("verification must fail closed")
			}
		})
	}
}

func TestCosignTrustPolicyArgs(t *testing.T) {
	tests := []struct {
		name string
		v    CosignVerifier
		want []string
		err  string
	}{
		{name: "key", v: CosignVerifier{KeyRef: "C:/keys/team.pub"}, want: []string{"--key", "C:/keys/team.pub"}},
		{name: "identity issuer", v: CosignVerifier{CertificateIdentity: "release@example.com", CertificateOIDCIssuer: "https://issuer.example"}, want: []string{"--certificate-identity", "release@example.com", "--certificate-oidc-issuer", "https://issuer.example"}},
		{name: "missing", v: CosignVerifier{}, err: "explicit trust policy"},
		{name: "identity without issuer", v: CosignVerifier{CertificateIdentity: "release@example.com"}, err: "must be configured together"},
		{name: "issuer without identity", v: CosignVerifier{CertificateOIDCIssuer: "https://issuer.example"}, err: "must be configured together"},
		{name: "mismatched policy", v: CosignVerifier{KeyRef: "team.pub", CertificateIdentity: "release@example.com", CertificateOIDCIssuer: "https://issuer.example"}, err: "cannot be combined"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.v.policyArgs()
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("policyArgs error = %v, want substring %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("policyArgs failed: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("policyArgs = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// recordingSignatureVerifier is deliberately only a test double; production
// uses CosignVerifier and never treats a boolean as cryptographic evidence.
type recordingSignatureVerifier struct{ image string }

func (v *recordingSignatureVerifier) Verify(_ context.Context, image string) error {
	v.image = image
	return nil
}

// ------------------------------------------------------------ SanitizeName

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"demo":         "demo",
		"Case ID/01":   "case-id-01",
		"UPPER":        "upper",
		"  spaced  ":   "spaced",
		"a/b\\c:d*e?f": "a-b-c-d-e-f",
		"日本語":          "x",
	}
	for in, want := range cases {
		if got := SanitizeName(in); got != want {
			t.Errorf("SanitizeName(%q) = %q, mau %q", in, got, want)
		}
	}
	long := strings.Repeat("a", 100)
	if got := SanitizeName(long); len(got) != 48 {
		t.Errorf("hasil harus dipotong 48, dapat %d", len(got))
	}
	if SanitizeName("///") != "x" {
		t.Error("hasil kosong harus fallback 'x'")
	}
	// Hasil selalu valid sebagai nama container.
	if !validContainerName.MatchString(SanitizeName("日本語")) {
		t.Error("hasil sanitize harus lolos validasi nama container")
	}
}

// ------------------------------------------------------- Integration (real)

// TestIntegrationValidatorHTTP menjalankan image validator-http sungguhan
// (build lokal: docker build -f runtimes/docker/images/http-validator/
// Dockerfile -t hermes/validator-http:dev .). Di-skip bila Docker tidak
// tersedia atau image belum di-build — tidak pernah pull otomatis.
func TestIntegrationValidatorHTTP(t *testing.T) {
	const image = "hermes/validator-http:dev"
	if err := Available(); err != nil {
		t.Skipf("docker tidak tersedia: %v", err)
	}
	ok, err := ImageExists(image)
	if err != nil {
		t.Fatalf("image inspect error: %v", err)
	}
	if !ok {
		t.Skipf("image %s belum di-build lokal", image)
	}

	base := t.TempDir()
	inDir := filepath.Join(base, "input")
	outDir := filepath.Join(base, "output")
	for _, d := range []string{inDir, outDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	task := `{
  "task_id": "it-val-001",
  "response_a": {"status": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"ok\":true}"},
  "response_b": {"status": 403, "headers": {"Content-Type": "application/json"}, "body": "{\"error\":\"forbidden\"}"}
}`
	if err := os.WriteFile(filepath.Join(inDir, "validation-task.json"), []byte(task), 0o600); err != nil {
		t.Fatal(err)
	}

	spec := RunSpec{
		Image:     image,
		Cmd:       []string{"--input", ContainerInputDir + "/validation-task.json", "--output", ContainerOutputDir + "/validation-result.json"},
		InputDir:  inDir,
		OutputDir: outDir,
		Labels:    map[string]string{LabelCase: "integration-test"},
		Timeout:   2 * time.Minute,
		Name:      "hermes-val-integration-test",
	}
	out, err := Run(context.Background(), spec)
	if err != nil {
		t.Fatalf("run error: %v (out: %s)", err, out)
	}
	result, readErr := os.ReadFile(filepath.Join(outDir, "validation-result.json"))
	if readErr != nil {
		t.Fatalf("validation-result.json tidak ada: %v (container out: %s)", readErr, out)
	}
	if !strings.Contains(string(result), `"status": "observed"`) {
		t.Errorf("result tak terduga: %s", result)
	}
	// Lifecycle: container --rm harus sudah hilang.
	alive, _ := imageExistsThroughPS("hermes-val-integration-test")
	if alive {
		t.Error("container masih ada setelah run (leak)")
	}
}

// imageExistsThroughPS cek container masih terdaftar (untuk uji leak).
func imageExistsThroughPS(name string) (bool, error) {
	out, err := defaultExecer.Exec(context.Background(), "ps", "-aq", "--filter", "name=^/"+name+"$")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) != "", nil
}
