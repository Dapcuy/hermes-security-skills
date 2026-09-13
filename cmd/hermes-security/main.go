// Command hermes-security: control plane CLI (Phase 4 skeleton + Phase 5
// Docker validator runtime, ROADMAP 35/36).
//
// Subcommands: list-skills, list-capabilities, validate-scope, check-policy,
// route, doctor, validate, abort, serve. Semua command menulis audit entry
// JSONL (flag --audit-file untuk override, default audit/audit.jsonl).
//
// Catatan enforcement (ROADMAP 4.2): command non-runtime masih advisory;
// subcommand validate SUDAH di jalur enforcement — ia satu-satunya yang
// menyentuh Docker, melalui internal/dockerx dengan baseline security
// fail-closed (§15/§16). Hermes (LLM) tidak pernah menjalankan docker
// langsung (§12/§20).
package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "list-skills":
		err = cmdListSkills(os.Args[2:])
	case "list-capabilities":
		err = cmdListCapabilities(os.Args[2:])
	case "validate-scope":
		err = cmdValidateScope(os.Args[2:])
	case "check-policy":
		err = cmdCheckPolicy(os.Args[2:])
	case "route":
		err = cmdRoute(os.Args[2:])
	case "doctor":
		err = cmdDoctor(os.Args[2:])
	case "validate":
		err = cmdValidate(os.Args[2:])
	case "abort":
		err = cmdAbort(os.Args[2:])
	case "cred":
		err = cmdCred(os.Args[2:])
	case "knowledge":
		err = cmdKnowledge(os.Args[2:])
	case "case":
		err = cmdCase(os.Args[2:])
	case "benchmark":
		err = cmdBenchmark(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "help", "-h", "--help":
		usage(os.Stdout)
		return
	default:
		fmt.Fprintf(os.Stderr, "hermes-security: subcommand tidak dikenal %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "hermes-security: error: %v\n", err)
		os.Exit(1)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `hermes-security — control plane Hermes Security Skills

Usage:
  hermes-security <command> [flags]

Commands:
  list-skills        scan skills/*/SKILL.md dan tampilkan frontmatter
  list-capabilities  tampilkan capability registry
  validate-scope     validasi URL terhadap scope rules
                     --url <url> --scope-file <file.yaml>
  check-policy       klasifikasi risk + evaluasi policy action
                     --capability <nama> --method <http-method>
  route              routing STUB query -> skill (match kata kunci;
                     routing penuh = ROUTING.md) --query <teks>
  doctor             cek kesehatan project (registry, policy, skills)
  validate           jalankan validator di container Docker ephemeral
                     (Phase 5, ROADMAP 36) — network=none, baseline §15
                     --runtime docker --task <validation-task.json>
                     --case <id> [--jobs-dir dir] [--image-overrides file]
                     [--manifest file] [--timeout 60s]
  abort              kill switch satu case (ROADMAP 10): kill container
                     berlabel hermes.case=<id>, revoke semua approval case,
                     tulis jobs/<case>/ABORTED, audit entry
                     --case <id> [--jobs-dir dir] [--state-dir dir]
  cred               credential provider v0 (ROADMAP 23): add/list/get/remove
                     pada vault terenkripsi (AES-256-GCM, PBKDF2)
                     cred add --account id --purpose p --expires RFC3339
                     (secret dari STDIN; passphrase via --passphrase-env /
                     --passphrase-file — TIDAK pernah argumen CLI)
  knowledge          knowledge & memory pipeline (ROADMAP 27, 41):
                     knowledge ingest <file> --category <c> --source <s>
                       --confidence <f> [--expires RFC3339]
                     knowledge list [--state s] [--category c]
                     knowledge search <query>
                     knowledge review <id> --state reviewed (human-in-the-loop)
                     knowledge stale (tandai entry >90 hari tanpa review)
  case               case memory (ROADMAP 25, 27):
                     case archive --case <id> (retention: arsipkan case yang
                     entry-nya sudah expired ke memory/cases/<case>.archived)
  benchmark          benchmark harness lab (ROADMAP 42, 43):
                     benchmark run --scenarios benchmarks/scenarios.json
                     [--proxy-url URL] [--scope-file f] [--out file]
  serve              MCP server mode (ROADMAP 4.3, 35) — JSON-RPC 2.0 over
                     stdio, enforcement in-line (scope + risk + approval);
                     tool read-only dilayani event store dari evidence dir
                     --mcp (wajib) [--proxy-url URL] [--scope-file file]
                     [--evidence-dir dir]

Common flags:
  --audit-file <path>   file audit JSONL (default audit/audit.jsonl)
`)
}
