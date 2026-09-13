package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"hermes-security-skills/internal/credential"
)

// cmdCred — credential provider v0 via CLI (ROADMAP 23).
//
//	hermes-security cred add    --account id --purpose p --expires RFC3339  (secret dari STDIN)
//	hermes-security cred list
//	hermes-security cred get    --account id     (print hanya untuk konsumsi tool)
//	hermes-security cred remove --account id
//
// Aturan keras:
//   - secret TIDAK PERNAH lewat argumen CLI (terlihat di process list) —
//     add membaca dari stdin;
//   - passphrase TIDAK PERNAH lewat argumen CLI — hanya --passphrase-env
//     (nama env var) atau --passphrase-file;
//   - audit mencatat operasi TANPA secret/passphrase apa pun (§23).
func cmdCred(args []string) error {
	if len(args) == 0 {
		usageCred(os.Stderr)
		return fmt.Errorf("cred: subcommand wajib (add|list|get|remove)")
	}
	switch args[0] {
	case "add":
		return credAdd(args[1:])
	case "list":
		return credList(args[1:])
	case "get":
		return credGet(args[1:])
	case "remove":
		return credRemove(args[1:])
	case "help", "-h", "--help":
		usageCred(os.Stdout)
		return nil
	default:
		usageCred(os.Stderr)
		return fmt.Errorf("cred: subcommand tidak dikenal %q", args[0])
	}
}

func usageCred(w io.Writer) {
	fmt.Fprint(w, `Usage: hermes-security cred <add|list|get|remove> [flags]

  add    --account <id> --purpose <teks> --expires <RFC3339>
         Secret dibaca dari STDIN (satu baris) — TIDAK pernah dari argumen.
  list   metadata semua kredensial — TANPA secret.
  get    --account <id>
         Print secret (HANYA untuk konsumsi tool; peringatan ke stderr).
  remove --account <id>

Flags bersama:
  --vault <path>              file vault (default ./credentials/vault.enc —
                              di .gitignore, JANGAN pernah di-commit)
  --passphrase-env <ENV>      nama env var berisi passphrase (pilih salah satu)
  --passphrase-file <path>    file berisi passphrase (pilih salah satu)
  --audit-file <path>         file audit JSONL
`)
}

// defaultVaultPath lokasi vault default — folder credentials/ sudah
// di-exclude .gitignore (ROADMAP 23: store tidak pernah masuk repo).
// Slash maju aman di semua platform untuk fungsi os/* Go.
const defaultVaultPath = "credentials/vault.enc"

// credFlags mendaftarkan flag bersama subcommand cred.
type credFlags struct {
	vault          *string
	passphraseEnv  *string
	passphraseFile *string
	audit          *string
}

func registerCredFlags(fs *flag.FlagSet) credFlags {
	return credFlags{
		vault:          fs.String("vault", defaultVaultPath, "path file vault terenkripsi"),
		passphraseEnv:  fs.String("passphrase-env", "", "NAMA env var berisi passphrase (jangan pernah nilainya di CLI)"),
		passphraseFile: fs.String("passphrase-file", "", "file berisi passphrase (alternatif --passphrase-env)"),
		audit:          auditFlag(fs),
	}
}

// resolvePassphrase mengambil passphrase HANYA dari env var atau file —
// TIDAK pernah sebagai argumen CLI (§23; secret di process list = bocor).
func resolvePassphrase(envName, filePath string) (string, error) {
	envName, filePath = strings.TrimSpace(envName), strings.TrimSpace(filePath)
	switch {
	case envName != "" && filePath != "":
		return "", fmt.Errorf("cred: pilih SALAH SATU --passphrase-env atau --passphrase-file")
	case envName != "":
		v, ok := os.LookupEnv(envName)
		if !ok || v == "" {
			return "", fmt.Errorf("cred: env var %s tidak ada / kosong (passphrase tidak pernah lewat argumen CLI)", envName)
		}
		return v, nil
	case filePath != "":
		b, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("cred: baca passphrase-file %s: %w", filePath, err)
		}
		s := strings.TrimSuffix(string(b), "\n")
		s = strings.TrimSuffix(s, "\r") // CRLF
		if s == "" {
			return "", fmt.Errorf("cred: passphrase-file %s kosong", filePath)
		}
		return s, nil
	default:
		return "", fmt.Errorf("cred: passphrase wajib via --passphrase-env atau --passphrase-file (TIDAK pernah sebagai argumen CLI)")
	}
}

// openVault resolves passphrase lalu membuka (atau membuat) vault.
func openVault(cf credFlags) (*credential.Vault, error) {
	pass, err := resolvePassphrase(*cf.passphraseEnv, *cf.passphraseFile)
	if err != nil {
		return nil, err
	}
	v, err := credential.Open(*cf.vault, pass)
	if err != nil {
		return nil, fmt.Errorf("cred: %w", err)
	}
	return v, nil
}

// credAdd membaca secret dari STDIN (satu baris, trailing newline dipangkas).
func credAdd(args []string) error {
	fs := newFlagSet("cred add")
	account := fs.String("account", "", "account id (credential reference, §23)")
	purpose := fs.String("purpose", "", "tujuan kredensial (mis. 'idor test akun A')")
	expires := fs.String("expires", "", "kadaluarsa RFC3339 (mis. 2026-12-31T23:59:59Z) — wajib")
	cf := registerCredFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*account) == "" || strings.TrimSpace(*purpose) == "" {
		return fmt.Errorf("cred add: --account dan --purpose wajib diisi")
	}
	expAt, err := time.Parse(time.RFC3339, strings.TrimSpace(*expires))
	if err != nil {
		return fmt.Errorf("cred add: --expires harus RFC3339 (contoh: 2026-12-31T23:59:59Z): %v", err)
	}
	secret, err := readSecretStdin(os.Stdin)
	if err != nil {
		return err
	}
	v, err := openVault(cf)
	if err != nil {
		return err
	}
	if err := v.Add(*account, *purpose, secret, expAt); err != nil {
		return fmt.Errorf("cred add: %w", err)
	}
	fmt.Printf("cred add: kredensial %q tersimpan di %s (expired %s) — secret TIDAK tercatat di audit\n",
		*account, filepath.ToSlash(v.Path()), expAt.Format(time.RFC3339))
	return writeAudit(*cf.audit, "cred_add", map[string]any{
		"account": *account, "purpose": *purpose,
		"expires_at": expAt.Format(time.RFC3339), "vault": filepath.ToSlash(v.Path()),
	})
}

// readSecretStdin membaca secret dari reader (satu baris). Tidak pernah
// di-echo, tidak di-log; trailing newline dipangkas agar pipa `echo s |`
// tidak mengubah nilai.
func readSecretStdin(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("cred: baca secret dari stdin: %w", err)
	}
	s := strings.TrimSuffix(line, "\n")
	s = strings.TrimSuffix(s, "\r")
	if s == "" {
		return "", fmt.Errorf("cred: secret kosong — pipakan secret ke stdin (mis. printf '%%s' \"$SECRET\" | hermes-security cred add ...)")
	}
	return s, nil
}

func credList(args []string) error {
	fs := newFlagSet("cred list")
	cf := registerCredFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	v, err := openVault(cf)
	if err != nil {
		return err
	}
	infos, err := v.List()
	if err != nil {
		return fmt.Errorf("cred list: %w", err)
	}
	fmt.Printf("Kredensial (%d) di %s — metadata saja, TANPA secret:\n", len(infos), filepath.ToSlash(v.Path()))
	for _, in := range infos {
		status := "aktif"
		if in.Expired {
			status = "EXPIRED"
		}
		fmt.Printf("  %-24s %-32s expires=%s [%s]\n",
			in.AccountID, in.Purpose, in.ExpiresAt.Format(time.RFC3339), status)
	}
	return writeAudit(*cf.audit, "cred_list", map[string]any{
		"count": len(infos), "vault": filepath.ToSlash(v.Path()),
	})
}

func credGet(args []string) error {
	fs := newFlagSet("cred get")
	account := fs.String("account", "", "account id yang diambil")
	cf := registerCredFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*account) == "" {
		return fmt.Errorf("cred get: --account wajib diisi")
	}
	v, err := openVault(cf)
	if err != nil {
		return err
	}
	e, err := v.Get(*account)
	if err != nil {
		return fmt.Errorf("cred get: %w", err)
	}
	// Peringatan ke STDERR, secret ke STDOUT (stdout bersih untuk konsumsi
	// tool; manusia yang salah jalan akan melihat peringatannya).
	fmt.Fprintln(os.Stderr, "PERINGATAN: secret ditampilkan HANYA untuk konsumsi tool (injection oleh control plane, ROADMAP 23).")
	fmt.Fprintln(os.Stderr, "  JANGAN pernah menyimpan/menyalinnya ke konteks reasoning, log, evidence, atau report.")
	fmt.Println(e.Secret)
	return writeAudit(*cf.audit, "cred_get", map[string]any{
		"account": *account, "vault": filepath.ToSlash(v.Path()),
	})
}

func credRemove(args []string) error {
	fs := newFlagSet("cred remove")
	account := fs.String("account", "", "account id yang dihapus")
	cf := registerCredFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*account) == "" {
		return fmt.Errorf("cred remove: --account wajib diisi")
	}
	v, err := openVault(cf)
	if err != nil {
		return err
	}
	if err := v.Remove(*account); err != nil {
		return fmt.Errorf("cred remove: %w", err)
	}
	fmt.Printf("cred remove: kredensial %q dihapus dari %s\n", *account, filepath.ToSlash(v.Path()))
	return writeAudit(*cf.audit, "cred_remove", map[string]any{
		"account": *account, "vault": filepath.ToSlash(v.Path()),
	})
}
