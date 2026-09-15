package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"hermes-security-skills/internal/recovery"
)

func cmdBackup(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("backup: butuh subcommand (create|verify|restore)")
	}
	switch args[0] {
	case "create":
		return backupCreate(args[1:])
	case "verify":
		return backupVerify(args[1:])
	case "restore":
		return backupRestore(args[1:])
	default:
		return fmt.Errorf("backup: subcommand tidak dikenal %q (create|verify|restore)", args[0])
	}
}

func backupCreate(args []string) error {
	fs := newFlagSet("backup create")
	out := fs.String("out", "", "path arsip backup .tar.gz (wajib)")
	auditFile := auditFlag(fs)
	jobsDir := fs.String("jobs-dir", defaultJobsDir, "root direktori jobs")
	evidenceDir := fs.String("evidence-dir", "", "opsional: root direktori evidence terpisah (kosong bila sudah di bawah jobs)")
	stateDir := fs.String("state-dir", "", "opsional: root direktori approval/state terpisah (kosong bila sudah di bawah jobs)")
	knowledgeDir := fs.String("knowledge-dir", defaultKnowledgeDir, "root direktori knowledge")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*out) == "" {
		return fmt.Errorf("backup create: --out wajib diisi")
	}
	roots := map[string]string{
		"audit.jsonl": *auditFile,
		"jobs":        *jobsDir,
		"knowledge":   *knowledgeDir,
	}
	if strings.TrimSpace(*evidenceDir) != "" {
		roots["evidence"] = *evidenceDir
	}
	if strings.TrimSpace(*stateDir) != "" {
		roots["state"] = *stateDir
	}
	if err := rejectArchiveInsideRoots(*out, roots); err != nil {
		return err
	}
	sources, err := recovery.CollectSources(roots)
	if err != nil {
		return fmt.Errorf("backup create: collect state: %w", err)
	}
	if err := recovery.Create(*out, sources); err != nil {
		return fmt.Errorf("backup create: %w", err)
	}
	if err := recovery.Verify(*out); err != nil {
		return fmt.Errorf("backup create: post-write verification: %w", err)
	}
	archiveSHA, err := recovery.ArchiveSHA256(*out)
	if err != nil {
		return fmt.Errorf("backup create: digest archive: %w", err)
	}
	if err := writeAudit(*auditFile, "backup_create", map[string]any{
		"archive": filepathToSlash(*out), "files": len(sources), "result": "ok",
	}); err != nil {
		return fmt.Errorf("backup create: audit: %w", err)
	}
	fmt.Printf("backup create: OK\n  archive: %s\n  sha256:  %s\n  files:   %d\n", filepathToSlash(*out), archiveSHA, len(sources))
	return nil
}

func backupVerify(args []string) error {
	fs := newFlagSet("backup verify")
	archive := fs.String("archive", "", "path arsip backup .tar.gz (wajib)")
	expectedSHA := fs.String("sha256", "", "trusted external archive SHA-256 (opsional untuk verify; wajib untuk restore)")
	auditFile := auditFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*archive) == "" {
		return fmt.Errorf("backup verify: --archive wajib diisi")
	}
	if err := recovery.Verify(*archive); err != nil {
		_ = writeAudit(*auditFile, "backup_verify", map[string]any{
			"archive": filepathToSlash(*archive), "result": "error",
		})
		return fmt.Errorf("backup verify: %w", err)
	}
	if strings.TrimSpace(*expectedSHA) != "" {
		if err := recovery.VerifyDigest(*archive, *expectedSHA); err != nil {
			return fmt.Errorf("backup verify: external digest: %w", err)
		}
	}
	if err := writeAudit(*auditFile, "backup_verify", map[string]any{
		"archive": filepathToSlash(*archive), "result": "ok",
	}); err != nil {
		return fmt.Errorf("backup verify: audit: %w", err)
	}
	fmt.Printf("backup verify: OK\n  archive: %s\n", filepathToSlash(*archive))
	return nil
}

func backupRestore(args []string) error {
	fs := newFlagSet("backup restore")
	archive := fs.String("archive", "", "path arsip backup .tar.gz (wajib)")
	dir := fs.String("dir", "", "destination restore baru (wajib; harus belum ada)")
	expectedSHA := fs.String("sha256", "", "trusted external archive SHA-256 (wajib)")
	auditFile := auditFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*archive) == "" || strings.TrimSpace(*dir) == "" || strings.TrimSpace(*expectedSHA) == "" {
		return fmt.Errorf("backup restore: --archive, --dir, dan trusted --sha256 wajib diisi")
	}
	if err := recovery.VerifyDigest(*archive, *expectedSHA); err != nil {
		return fmt.Errorf("backup restore: external digest: %w", err)
	}
	if err := recovery.Restore(*archive, *dir); err != nil {
		_ = writeAudit(*auditFile, "backup_restore", map[string]any{
			"archive": filepathToSlash(*archive), "result": "error",
		})
		return fmt.Errorf("backup restore: %w", err)
	}
	if err := writeAudit(*auditFile, "backup_restore", map[string]any{
		"archive": filepathToSlash(*archive), "result": "ok",
	}); err != nil {
		return fmt.Errorf("backup restore: audit: %w", err)
	}
	fmt.Printf("backup restore: OK\n  archive: %s\n  dir:     %s\n", filepathToSlash(*archive), filepathToSlash(*dir))
	return nil
}

func rejectArchiveInsideRoots(archive string, roots map[string]string) error {
	archiveAbs, err := filepath.Abs(archive)
	if err != nil {
		return err
	}
	archiveAbs = filepath.Clean(archiveAbs)
	for name, root := range roots {
		rootAbs, err := filepath.Abs(root)
		if err != nil {
			return err
		}
		rootAbs = filepath.Clean(rootAbs)
		rel, err := filepath.Rel(rootAbs, archiveAbs)
		if err != nil {
			return err
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
			return fmt.Errorf("backup create: archive %s berada di dalam root %s (%s)", archive, name, root)
		}
	}
	return nil
}
