package app

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
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

func isolatedWorkingDir(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(cwd); err != nil {
			t.Error(err)
		}
	})
	return dir
}

func TestDDEIDefaultConsoleOnly(t *testing.T) {
	dir := isolatedWorkingDir(t)
	calls := 0
	fakeDetection(t, func(context.Context, ddeirootkit.Options) ddeirootkit.Report {
		calls++
		return ddeirootkit.Report{Verdict: ddeirootkit.VerdictClean, Complete: true}
	})
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
	for _, args := range [][]string{
		nil, nil,
		{"--profile-dir", "missing", "--profile", "missing", "--output", "missing/output"},
		{"--profile-dir", dir, "--output", dir, "--detector-log-dir="},
		{"--detect-only", "--output", ""},
	} {
		if err := Run(context.Background(), args); err != nil || ExitCode() != 0 || lastRun.Collection != "not_started" {
			t.Fatalf("args=%v err=%v code=%d status=%+v", args, err, ExitCode(), lastRun)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("unexpected files: %v err=%v", entries, err)
		}
	}
	if calls != 5 {
		t.Fatalf("detector calls=%d", calls)
	}
}

func TestDDEIExplicitLogOnly(t *testing.T) {
	dir := isolatedWorkingDir(t)
	fakeDetection(t, func(context.Context, ddeirootkit.Options) ddeirootkit.Report {
		return ddeirootkit.Report{Verdict: ddeirootkit.VerdictClean, Complete: true}
	})
	if err := Run(context.Background(), []string{"--detector-log-dir", dir}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].IsDir() || !strings.HasSuffix(entries[0].Name(), ".log") {
		t.Fatalf("expected exactly one log: %v err=%v", entries, err)
	}
	if lastRun.Collection != "not_started" {
		t.Fatalf("unexpected collection: %+v", lastRun)
	}
}

func TestDDEICollectionIntentValidation(t *testing.T) {
	fakeDetection(t, func(context.Context, ddeirootkit.Options) ddeirootkit.Report {
		t.Fatal("detector called for conflicting intent")
		return ddeirootkit.Report{}
	})
	for _, args := range [][]string{
		{"--detect-only", "--collect"},
		{"--scan", "yara"}, {"--scan", "tmbrfix"}, {"--scan", "osquery"},
		{"--clean", "confirm"}, {"--clean", "force"},
		{"--detect-only", "--scan", "yara"},
		{"--collect=false", "--clean", "force"},
	} {
		if err := Run(context.Background(), args); err == nil || ExitCode() != 2 {
			t.Fatalf("args=%v err=%v code=%d", args, err, ExitCode())
		}
	}
	for _, args := range [][]string{
		{"--collect", "--scan", "yara", "--clean", "confirm"},
		{"--no-detect", "--scan", "tmbrfix", "--clean", "force"},
		{"--scan", "NONE", "--clean", "DISABLED"},
	} {
		cfg, err := parseArgs(args)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateConfig(cfg); err != nil {
			t.Fatalf("args=%v err=%v", args, err)
		}
	}
}

func TestDDEIDefaultCancellationNoFiles(t *testing.T) {
	dir := isolatedWorkingDir(t)
	for _, during := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "during"}[during], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if !during {
				cancel()
			}
			fakeDetection(t, func(got context.Context, _ ddeirootkit.Options) ddeirootkit.Report {
				cancel()
				if !errors.Is(got.Err(), context.Canceled) {
					t.Fatal("parent cancellation lost")
				}
				return ddeirootkit.Report{Verdict: ddeirootkit.VerdictInfected, Complete: false}
			})
			if err := Run(ctx, nil); !errors.Is(err, context.Canceled) || ExitCode() != 2 || lastRun.Collection != "not_started" {
				t.Fatalf("err=%v code=%d status=%+v", err, ExitCode(), lastRun)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("unexpected files: %v err=%v", entries, err)
			}
		})
	}
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
	if err != nil || ExitCode() != 0 || lastRun.Detection != "not_started" {
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
			var err error
			stdout := captureCLIOutput(t, func() {
				err = Run(context.Background(), nil)
			})
			if err != nil || ExitCode() != tc.code {
				t.Fatalf("err=%v code=%d", err, ExitCode())
			}
			detection := tc.verdict
			if !tc.complete {
				detection += " (incomplete coverage)"
			}
			want := fmt.Sprintf("Execution: completed; detection=%s; collection=not_started; exit_code=%d\n", detection, tc.code)
			if !strings.HasSuffix(stdout, want) {
				t.Fatalf("stdout=%q, want suffix %q", stdout, want)
			}
		})
	}
}

func captureCLIOutput(t *testing.T, run func()) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	old := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = old }()
	run()
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCLICollectionFailureStatus(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fixture.yaml"), []byte("collectors: [session]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(dir, "file")
	if err := os.WriteFile(blocked, nil, 0600); err != nil {
		t.Fatal(err)
	}
	stdout := captureCLIOutput(t, func() {
		err := Run(context.Background(), []string{"--no-detect", "--profile-dir", dir, "--profile", "fixture", "--output", filepath.Join(blocked, "out")})
		if err == nil {
			t.Fatal("expected collection failure")
		}
	})
	if want := "Execution: failed; detection=not_started; collection=failed; exit_code=1\n"; !strings.HasSuffix(stdout, want) {
		t.Fatalf("stdout=%q, want suffix %q", stdout, want)
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
	if err == nil || !strings.Contains(err.Error(), "detector log write failed") || ExitCode() != 2 {
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
	err := Run(context.Background(), []string{"--collect", "--profile-dir", filepath.Join(t.TempDir(), "missing"), "--detector-log-dir", t.TempDir()})
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
	err := Run(context.Background(), []string{"--collect", "--profile-dir", dir, "--profile", "fixture", "--output", out})
	if err != nil {
		t.Fatal(err)
	}
	if ExitCode() != 3 || lastRun.Collection != "completed" {
		t.Fatalf("code=%d status=%+v", ExitCode(), lastRun)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 3 {
		t.Fatalf("expected only profile, output and archive; entries=%v err=%v", entries, err)
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
