package app

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"linux-dfir/internal/detector/ddeirootkit"
)

func fakeDetection(t *testing.T, fn func(context.Context, ddeirootkit.Options) ddeirootkit.Report) {
	t.Helper()
	old := runDetector
	runDetector = fn
	t.Cleanup(func() { runDetector = old })
}

func TestDDEIConflictingFlags(t *testing.T) {
	fakeDetection(t, func(context.Context, ddeirootkit.Options) ddeirootkit.Report {
		t.Fatal("detector called")
		return ddeirootkit.Report{}
	})
	if err := Run(context.Background(), []string{"--detect-only", "--no-detect"}); err == nil || ExitCode() != 1 {
		t.Fatalf("err=%v code=%d", err, ExitCode())
	}
}

func TestDDEIErrorExitCodeContract(t *testing.T) {
	fakeDetection(t, func(context.Context, ddeirootkit.Options) ddeirootkit.Report {
		t.Fatal("unexpected detector call")
		return ddeirootkit.Report{}
	})
	missing := filepath.Join(t.TempDir(), "missing")
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"legacy profile failure", []string{"--no-detect", "--profile-dir", missing}, 1},
		{"legacy validation failure", []string{"--no-detect", "--timeout", "bad"}, 1},
		{"legacy parsed before error", []string{"--no-detect", "--unknown"}, 1},
		{"default parse failure resets code", []string{"--unknown"}, 2},
		{"unparsed no-detect", []string{"--unknown", "--no-detect"}, 2},
		{"explicit false", []string{"--no-detect=false", "--timeout", "bad"}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Run(context.Background(), tc.args)
			if err == nil || ErrorExitCode() != tc.want || ExitCode() != tc.want {
				t.Fatalf("err=%v errorCode=%d code=%d want=%d", err, ErrorExitCode(), ExitCode(), tc.want)
			}
		})
	}
}

func TestDDEIInvalidTimeoutBeforeDetection(t *testing.T) {
	fakeDetection(t, func(context.Context, ddeirootkit.Options) ddeirootkit.Report {
		t.Fatal("detector called for invalid timeout")
		return ddeirootkit.Report{}
	})
	for _, value := range []string{"bad", "0", "-1s"} {
		if err := Run(context.Background(), []string{"--detect-only", "--timeout", value}); err == nil || ExitCode() != 2 {
			t.Fatalf("timeout=%s err=%v code=%d", value, err, ExitCode())
		}
	}
}

func TestDDEINoDetectResetsExitCode(t *testing.T) {
	fakeDetection(t, func(context.Context, ddeirootkit.Options) ddeirootkit.Report {
		t.Fatal("detector called with no-detect")
		return ddeirootkit.Report{}
	})
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fixture.yaml"), []byte("collectors: [session]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	detectorExitCode = 3
	err := Run(context.Background(), []string{"--no-detect", "--profile-dir", dir, "--profile", "fixture", "--output", filepath.Join(dir, "out")})
	if err != nil || ExitCode() != 0 || lastRun.Detection != "未执行" {
		t.Fatalf("err=%v code=%d status=%+v", err, ExitCode(), lastRun)
	}
}

func TestDDEIDetectionOutcomes(t *testing.T) {
	for _, tc := range []struct {
		verdict  string
		complete bool
		code     int
	}{
		{"CLEAN", true, 0}, {"INFECTED", true, 3}, {"INCONCLUSIVE", false, 2}, {"REVIEW", true, 2}, {"CLEAN", false, 2}, {"INFECTED", false, 3},
	} {
		t.Run(tc.verdict+string(rune('0'+tc.code)), func(t *testing.T) {
			fakeDetection(t, func(context.Context, ddeirootkit.Options) ddeirootkit.Report {
				return ddeirootkit.Report{Verdict: ddeirootkit.Verdict(tc.verdict), Complete: tc.complete}
			})
			err := Run(context.Background(), []string{"--detect-only", "--detector-log-dir", t.TempDir()})
			if err != nil || ExitCode() != tc.code {
				t.Fatalf("err=%v code=%d", err, ExitCode())
			}
		})
	}
}

func TestDDEILogFailure(t *testing.T) {
	fakeDetection(t, func(context.Context, ddeirootkit.Options) ddeirootkit.Report {
		return ddeirootkit.Report{Verdict: ddeirootkit.VerdictClean, Complete: true}
	})
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), []string{"--detect-only", "--detector-log-dir", path})
	if err == nil || !strings.Contains(err.Error(), "日志") || ExitCode() != 2 {
		t.Fatalf("err=%v code=%d", err, ExitCode())
	}
}

func TestDDEIIncompleteInfectedExecutionErrors(t *testing.T) {
	fakeDetection(t, func(context.Context, ddeirootkit.Options) ddeirootkit.Report {
		return ddeirootkit.Report{Verdict: ddeirootkit.VerdictInfected, Complete: false}
	})
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), []string{"--detect-only", "--detector-log-dir", path})
	if err == nil || ExitCode() != 2 || !strings.HasPrefix(lastRun.Detection, "INFECTED") {
		t.Fatalf("log failure: err=%v code=%d status=%+v", err, ExitCode(), lastRun)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = Run(ctx, []string{"--detect-only", "--detector-log-dir", t.TempDir()})
	if !errors.Is(err, context.Canceled) || ExitCode() != 2 || !strings.HasPrefix(lastRun.Detection, "INFECTED") {
		t.Fatalf("context failure: err=%v code=%d status=%+v", err, ExitCode(), lastRun)
	}
}

func TestDDEIContext(t *testing.T) {
	fakeDetection(t, func(ctx context.Context, _ ddeirootkit.Options) ddeirootkit.Report {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > time.Second {
			t.Fatal("missing detector deadline")
		}
		<-ctx.Done()
		return ddeirootkit.Report{Verdict: ddeirootkit.Verdict("INCONCLUSIVE")}
	})
	err := Run(context.Background(), []string{"--detect-only", "--timeout", "1ms", "--detector-log-dir", t.TempDir()})
	if !errors.Is(err, context.DeadlineExceeded) || ExitCode() != 2 {
		t.Fatalf("err=%v code=%d", err, ExitCode())
	}
}

func TestDDEIParentCancellation(t *testing.T) {
	fakeDetection(t, func(ctx context.Context, _ ddeirootkit.Options) ddeirootkit.Report {
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatal("parent cancellation lost")
		}
		return ddeirootkit.Report{Verdict: ddeirootkit.Verdict("INCONCLUSIVE")}
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, []string{"--detect-only", "--detector-log-dir", t.TempDir()}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestDDEIDefaultFallback(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	cfg, err := parseArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadProfileOrDefault(cfg); err != nil {
		t.Fatal(err)
	}
	explicit, _ := parseArgs([]string{"--profile-dir", "profiles"})
	if _, err := loadProfileOrDefault(explicit); err == nil {
		t.Fatal("explicit missing directory fell back")
	}
	if err := os.Mkdir("profiles", 0750); err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{"[broken", "name: ddei\ncollectors: []\n"} {
		if err := os.WriteFile("profiles/ddei.yaml", []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadProfileOrDefault(cfg); err == nil {
			t.Fatal("invalid profile fell back")
		}
	}
	if err := os.Chmod("profiles/ddei.yaml", 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod("profiles/ddei.yaml", 0600) })
	if os.Geteuid() != 0 {
		if _, err := loadProfileOrDefault(cfg); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("permission error swallowed: %v", err)
		}
	}
}

func TestDDEICollectionFailurePreservesVerdict(t *testing.T) {
	fakeDetection(t, func(context.Context, ddeirootkit.Options) ddeirootkit.Report {
		return ddeirootkit.Report{Verdict: ddeirootkit.VerdictInfected, Complete: true}
	})
	err := Run(context.Background(), []string{"--profile-dir", filepath.Join(t.TempDir(), "missing"), "--detector-log-dir", t.TempDir()})
	if err == nil || ExitCode() != 2 || lastRun.Detection != "INFECTED" {
		t.Fatalf("err=%v code=%d status=%+v", err, ExitCode(), lastRun)
	}
}

func TestDDEIArchiveHumanReportAndFactsOnlyAI(t *testing.T) {
	fakeDetection(t, func(context.Context, ddeirootkit.Options) ddeirootkit.Report {
		return ddeirootkit.Report{Verdict: ddeirootkit.VerdictInfected, Complete: true, Summary: "unique-detector-verdict-summary",
			Findings: []ddeirootkit.Finding{{Title: "Runtime behavioral correlation", Detail: "preload + PAM control + daemon RWX/PTY"}}}
	})
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fixture.yaml"), []byte("name: fixture\ncollectors: [session]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "output")
	err := Run(context.Background(), []string{"--profile-dir", dir, "--profile", "fixture", "--output", out, "--detector-log-dir", dir})
	if err != nil {
		t.Fatal(err)
	}
	if ExitCode() != 3 || lastRun.Collection != "已完成" {
		t.Fatalf("code=%d status=%+v", ExitCode(), lastRun)
	}
	for _, p := range []string{"legacy/ddei_rootkit/report.json", "legacy/ddei_rootkit/report.txt"} {
		b, err := os.ReadFile(filepath.Join(out, p))
		if err != nil || !strings.Contains(string(b), "INFECTED") || !strings.Contains(string(b), "preload + PAM control + daemon RWX/PTY") {
			t.Fatalf("%s: %s %v", p, b, err)
		}
	}
	if _, err := os.Stat(out + ".tar.gz"); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(out + ".tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	found := false
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(h.Name, "/legacy/ddei_rootkit/report.txt") {
			found = true
		}
	}
	if !found {
		t.Fatal("human report missing from archive")
	}
	err = filepath.WalkDir(filepath.Join(out, "ai"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), "unique-detector-verdict-summary") || strings.Contains(string(b), "INFECTED") {
			t.Errorf("detector verdict leaked to AI: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
