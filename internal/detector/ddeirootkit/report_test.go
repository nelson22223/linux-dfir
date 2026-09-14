package ddeirootkit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"
)

func TestReportBehaviorEvidencePreserved(t *testing.T) {
	rep := Report{Verdict: VerdictInfected, Complete: true, Findings: []Finding{
		{ID: "behavior", Title: "Correlated runtime behavior", Level: LevelCompromised, Detail: "preload + PAM control + daemon RWX/PTY"},
	}}
	var console bytes.Buffer
	Print(rep, &console)
	path, err := WriteLog(rep, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	log, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if console.String() != string(log) || string(log) != Text(rep) {
		t.Fatal("human outputs differ")
	}
	for _, s := range []string{rep.Findings[0].Title, rep.Findings[0].Detail} {
		if !strings.Contains(string(log), s) {
			t.Fatalf("missing evidence %q", s)
		}
	}
}

func TestReportExitCodes(t *testing.T) {
	for _, tc := range []struct {
		v    Verdict
		want int
	}{{VerdictClean, 0}, {VerdictInfected, 3}, {Verdict("REVIEW"), 2}, {Verdict("INCONCLUSIVE"), 2}, {Verdict("unknown"), 2}} {
		if got := ExitCode(tc.v); got != tc.want {
			t.Fatalf("%s: %d", tc.v, got)
		}
	}
}

func TestReportLogExclusivePrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "new")
	rep := Report{Timestamp: time.Now(), Verdict: Verdict("INCONCLUSIVE")}
	a, err := WriteLog(rep, dir)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	b, err := WriteLog(rep, dir)
	if err != nil || a == b {
		t.Fatalf("collision: %s %s %v", a, b, err)
	}
	after, err := os.ReadFile(a)
	if err != nil || string(before) != string(after) {
		t.Fatal("original log changed")
	}
	info, err := os.Stat(a)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private log: %v %v", info, err)
	}
	info, err = os.Stat(dir)
	if err != nil || info.Mode().Perm()&0027 != 0 {
		t.Fatalf("directory mode: %v %v", info, err)
	}
	if !strings.Contains(string(before), "coverage insufficient") || !strings.Contains(string(before), "INCONCLUSIVE") {
		t.Fatal(string(before))
	}
}

func TestReportLogFailure(t *testing.T) {
	p := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(p, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if path, err := WriteLog(Report{}, p); err == nil || path != "" {
		t.Fatalf("path=%s err=%v", path, err)
	}
}

func TestReportTextCompletion(t *testing.T) {
	got := Text(Report{Verdict: VerdictClean, Complete: true,
		Coverage: Coverage{Root: true, Proc: true, Processes: 123, Objects: 456}})
	if !strings.Contains(got, "checks completed") || !strings.Contains(got, "not a guarantee of overall host safety") {
		t.Fatal(got)
	}
	for _, want := range []string{"No indicators flagged", "processes=123", "objects=456"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q: %s", want, got)
		}
	}
	if strings.Contains(got, "No checks recorded") {
		t.Fatal(got)
	}
	got = Text(Report{Verdict: Verdict("unexpected")})
	if !strings.Contains(got, "Verdict: unexpected") || strings.Contains(got, "Verdict: CLEAN") {
		t.Fatal(got)
	}
}

func TestReportEnglishVerdicts(t *testing.T) {
	for _, verdict := range []Verdict{VerdictClean, VerdictInfected, VerdictInconclusive} {
		rep := Report{Verdict: verdict, Complete: verdict != VerdictInconclusive}
		text := Text(rep)
		if !strings.Contains(text, "Verdict: "+string(verdict)) {
			t.Fatalf("missing verdict: %s", text)
		}
		if strings.ContainsFunc(text, func(r rune) bool { return unicode.Is(unicode.Han, r) }) {
			t.Fatalf("non-English generated report: %s", text)
		}
	}
}
