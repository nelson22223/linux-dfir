package ddeirootkit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	if !strings.Contains(string(before), "覆盖不足") || !strings.Contains(string(before), "INCONCLUSIVE") {
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
	if !strings.Contains(got, "已完成") || !strings.Contains(got, "不代表主机整体安全") {
		t.Fatal(got)
	}
	for _, want := range []string{"未发现需标记的指标", "进程=123", "对象=456"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q: %s", want, got)
		}
	}
	if strings.Contains(got, "无检查记录") {
		t.Fatal(got)
	}
	got = Text(Report{Verdict: Verdict("unexpected")})
	if !strings.Contains(got, "判定：unexpected") || strings.Contains(got, "判定：CLEAN") {
		t.Fatal(got)
	}
}
