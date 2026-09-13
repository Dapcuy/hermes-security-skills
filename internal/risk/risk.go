// Package risk mengklasifikasikan operasi ke level risiko (ROADMAP 8 — Risk)
// dan memetakan level ke default action:
//
//	LOW      -> automatic
//	MEDIUM   -> conditional
//	HIGH     -> approval_required
//	CRITICAL -> disabled
//
// Operasi ambigu diperlakukan konservatif (level lebih tinggi, fail-closed).
package risk

import (
	"fmt"
	"strings"
)

// Level kelas risiko. Nilai string sesuai policy/risk.yaml.
type Level string

const (
	LevelLow      Level = "low"
	LevelMedium   Level = "medium"
	LevelHigh     Level = "high"
	LevelCritical Level = "critical"
)

// Action tindakan yang dipersyaratkan policy sebelum operasi berjalan.
type Action string

const (
	ActionAutomatic        Action = "automatic"
	ActionConditional      Action = "conditional"
	ActionApprovalRequired Action = "approval_required"
	ActionDisabled         Action = "disabled"
)

// Operation mendeskripsikan operasi yang akan diklasifikasikan.
type Operation struct {
	Method string // HTTP method ("" untuk operasi non-HTTP)

	Replay           bool // replay request sebelumnya (termasuk replay GET)
	Upload           bool // upload file/payload besar
	Concurrency      bool // eksekusi paralel terhadap target
	CredentialAttack bool // credential stuffing / brute force
	Exfiltration     bool // mengirim data keluar
	Persistence      bool // menanam artefak di target
	LateralMovement  bool // bergerak antar host
}

var passiveMethods = map[string]bool{
	"GET":     true,
	"HEAD":    true,
	"OPTIONS": true,
}

// Classify memetakan operasi ke Level sesuai ROADMAP 8.
func Classify(op Operation) Level {
	// CRITICAL: kategori yang dilarang keras (ROADMAP 2 Non-Goals).
	if op.CredentialAttack || op.Exfiltration || op.Persistence || op.LateralMovement {
		return LevelCritical
	}
	// HIGH: mutasi, upload, concurrency, transaction testing.
	m := strings.ToUpper(strings.TrimSpace(op.Method))
	if m != "" && !passiveMethods[m] {
		// Method mutasi yang dikenal ATAU method tidak dikenal:
		// konservatif = HIGH.
		return LevelHigh
	}
	if op.Upload || op.Concurrency {
		return LevelHigh
	}
	// MEDIUM: limited replay, response comparison, safe mutation —
	// replay GET juga MEDIUM karena mengirim ulang request nyata.
	if op.Replay {
		return LevelMedium
	}
	// LOW: passive analysis, metadata GET, source review, local analysis.
	return LevelLow
}

// DefaultAction mengembalikan action default per level (fail-closed:
// level tidak dikenal = error).
func DefaultAction(l Level) (Action, error) {
	switch l {
	case LevelLow:
		return ActionAutomatic, nil
	case LevelMedium:
		return ActionConditional, nil
	case LevelHigh:
		return ActionApprovalRequired, nil
	case LevelCritical:
		return ActionDisabled, nil
	case "":
		return "", fmt.Errorf("risk: level kosong")
	default:
		return "", fmt.Errorf("risk: level tidak dikenal %q", l)
	}
}

var levelRank = map[Level]int{
	LevelLow:      1,
	LevelMedium:   2,
	LevelHigh:     3,
	LevelCritical: 4,
}

// MaxLevel mengembalikan level tertinggi dari dua level (konservatif).
// Level tidak dikenal = error fail-closed.
func MaxLevel(a, b Level) (Level, error) {
	ra, ok := levelRank[a]
	if !ok {
		return "", fmt.Errorf("risk: level tidak dikenal %q", a)
	}
	rb, ok := levelRank[b]
	if !ok {
		return "", fmt.Errorf("risk: level tidak dikenal %q", b)
	}
	if ra >= rb {
		return a, nil
	}
	return b, nil
}
