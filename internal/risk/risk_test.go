package risk

import "testing"

func TestClassifyMethods(t *testing.T) {
	cases := []struct {
		method string
		want   Level
	}{
		{"GET", LevelLow},      // pasif
		{"HEAD", LevelLow},     // pasif
		{"OPTIONS", LevelLow},  // pasif
		{"POST", LevelHigh},    // mutasi
		{"PUT", LevelHigh},     // mutasi
		{"PATCH", LevelHigh},   // mutasi
		{"DELETE", LevelHigh},  // mutasi
		{"get", LevelLow},      // case-insensitive
		{"TRACE", LevelHigh},   // method tidak dikenal -> konservatif
		{"CONNECT", LevelHigh}, // method tidak dikenal -> konservatif
	}
	for _, tc := range cases {
		if got := Classify(Operation{Method: tc.method}); got != tc.want {
			t.Errorf("Classify(%q) = %s, mau %s", tc.method, got, tc.want)
		}
	}
	if got := Classify(Operation{}); got != LevelLow {
		t.Errorf("Classify(empty) = %s, mau low (pasif)", got)
	}
}

func TestClassifyFlags(t *testing.T) {
	cases := []struct {
		name string
		op   Operation
		want Level
	}{
		{"replay GET = medium", Operation{Method: "GET", Replay: true}, LevelMedium},
		{"replay tanpa method = medium", Operation{Replay: true}, LevelMedium},
		{"upload = high", Operation{Method: "GET", Upload: true}, LevelHigh},
		{"concurrency = high", Operation{Method: "GET", Concurrency: true}, LevelHigh},
		{"credential attack = critical", Operation{CredentialAttack: true}, LevelCritical},
		{"exfiltration = critical", Operation{Exfiltration: true}, LevelCritical},
		{"persistence = critical", Operation{Persistence: true}, LevelCritical},
		{"lateral movement = critical", Operation{LateralMovement: true}, LevelCritical},
		{"critical menang atas high", Operation{Method: "POST", Upload: true, Exfiltration: true}, LevelCritical},
		{"high menang atas medium", Operation{Method: "POST", Replay: true}, LevelHigh},
	}
	for _, tc := range cases {
		if got := Classify(tc.op); got != tc.want {
			t.Errorf("%s: Classify = %s, mau %s", tc.name, got, tc.want)
		}
	}
}

func TestDefaultAction(t *testing.T) {
	cases := []struct {
		level Level
		want  Action
	}{
		{LevelLow, ActionAutomatic},
		{LevelMedium, ActionConditional},
		{LevelHigh, ActionApprovalRequired},
		{LevelCritical, ActionDisabled},
	}
	for _, tc := range cases {
		got, err := DefaultAction(tc.level)
		if err != nil {
			t.Fatalf("DefaultAction(%s) error: %v", tc.level, err)
		}
		if got != tc.want {
			t.Errorf("DefaultAction(%s) = %s, mau %s", tc.level, got, tc.want)
		}
	}
	if _, err := DefaultAction(Level("unknown")); err == nil {
		t.Error("DefaultAction(level tak dikenal) harus error (fail-closed)")
	}
	if _, err := DefaultAction(""); err == nil {
		t.Error("DefaultAction(empty) harus error (fail-closed)")
	}
}

func TestMaxLevel(t *testing.T) {
	if got, err := MaxLevel(LevelLow, LevelHigh); err != nil || got != LevelHigh {
		t.Errorf("MaxLevel(low, high) = %s, %v; mau high, nil", got, err)
	}
	if got, err := MaxLevel(LevelCritical, LevelMedium); err != nil || got != LevelCritical {
		t.Errorf("MaxLevel(critical, medium) = %s, %v; mau critical, nil", got, err)
	}
	if _, err := MaxLevel(Level("bogus"), LevelLow); err == nil {
		t.Error("MaxLevel dengan level tak dikenal harus error")
	}
}
