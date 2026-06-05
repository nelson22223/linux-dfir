package scanners

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"linux-dfir/internal/archive"
	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
)

func TestRunNoneWritesAbsentRecords(t *testing.T) {
	out, outDir := newOutput(t)
	if err := Run(context.Background(), out, Options{Mode: "none", CleanMode: "disabled"}); err != nil {
		t.Fatal(err)
	}
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"scanner":"none"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"stream":"facts/scanner_runs"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"stream":"facts/scanner_findings"`)
	assertFileNotContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"stream":"parsed/`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"status":"skipped"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exists":false`)
	assertFileNotContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `0001-01-01T00:00:00Z`)
	assertFileContains(t, filepath.Join(outDir, "legacy/filescan/scanner_status.out"), "scanner: none")
}

func TestTmbrfixUnsupportedOnNonLinuxDoesNotExecute(t *testing.T) {
	oldCompatibility := compatibilityFunc
	compatibilityFunc = func(scanner, exeType string) (string, string) {
		return "unsupported", "test runtime does not support tmbrfix"
	}
	defer func() { compatibilityFunc = oldCompatibility }()

	root := t.TempDir()
	payload := filepath.Join(root, "payload")
	writeELF386(t, filepath.Join(payload, "tmbrfix"))
	out, outDir := newOutput(t)
	runner := &fakeRunner{}
	if err := Run(context.Background(), out, Options{Mode: "tmbrfix", CleanMode: "disabled", PayloadRoot: payload, Runner: runner}); err != nil {
		t.Fatal(err)
	}
	if runner.called {
		t.Fatal("runner should not execute unsupported tmbrfix")
	}
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"scanner":"tmbrfix"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"status":"skipped"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"executable_sha256"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exists":false`)
	assertFileContains(t, filepath.Join(outDir, "legacy/filescan/scanner_status.out"), "scanner: tmbrfix")
}

func TestBuildArgsCleanGating(t *testing.T) {
	if got := strings.Join(buildArgs("tmbrfix", "disabled", "/tmp"), " "); strings.Contains(got, "-clean") {
		t.Fatalf("disabled clean should not include clean arg: %s", got)
	}
	if got := strings.Join(buildArgs("tmbrfix", "confirm", "/tmp"), " "); !strings.Contains(got, "-clean") {
		t.Fatalf("confirm clean should include clean arg: %s", got)
	}
}

func TestScanOnlySemantics(t *testing.T) {
	if scanOnly("tmbrfix", "confirm") {
		t.Fatal("tmbrfix confirm clean should not be marked scan-only")
	}
	if !scanOnly("yara", "confirm") {
		t.Fatal("yara should remain scan-only even when clean flag is set globally")
	}
}

func TestScannerPathUsesPathForNativeTools(t *testing.T) {
	path := scannerPath("payload", Plugin{Name: "yara", ExeName: "sh"})
	if path == "sh" {
		t.Fatal("expected PATH lookup for native scanner tools")
	}
}

func TestParseFindings(t *testing.T) {
	findings := parseFindings("fake", []byte("OK\nMALWARE.Found virus /tmp/bad\n"))
	if len(findings) != 1 || findings[0].Path != "/tmp/bad" || !findings[0].Exists {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func TestParseYARAStandardFindings(t *testing.T) {
	findings := parseFindings("yara", []byte("SuspiciousWebshell /tmp/a.php\nNamespace.Rule [meta] /var/www/shell.php\n"))
	if len(findings) != 2 {
		t.Fatalf("expected yara findings, got %#v", findings)
	}
	if findings[0].Signature != "SuspiciousWebshell" || findings[0].Path != "/tmp/a.php" {
		t.Fatalf("unexpected first yara finding: %#v", findings[0])
	}
	if findings[1].Path != "/var/www/shell.php" {
		t.Fatalf("unexpected second yara finding: %#v", findings[1])
	}
}

func TestRunWithFakeSupportedPlugin(t *testing.T) {
	oldCompatibility := compatibilityFunc
	compatibilityFunc = func(scanner, exeType string) (string, string) { return "supported", "" }
	defer func() { compatibilityFunc = oldCompatibility }()

	root := t.TempDir()
	payload := filepath.Join(root, "payload")
	writeELF386(t, filepath.Join(payload, "tmbrfix"))
	out, outDir := newOutput(t)
	runner := &fakeRunner{result: ExecResult{Stdout: []byte("MALWARE Found /tmp/bad\n"), Stderr: []byte("warn\n"), ExitCode: 0, Started: time.Now().UTC(), Ended: time.Now().UTC()}}
	if err := Run(context.Background(), out, Options{Mode: "tmbrfix", CleanMode: "disabled", PayloadRoot: payload, Target: "/tmp", Runner: runner}); err != nil {
		t.Fatal(err)
	}
	if !runner.called {
		t.Fatal("runner was not called")
	}
	assertFileContains(t, filepath.Join(outDir, "ai/raw/scanners/tmbrfix/stdout.txt"), "MALWARE")
	assertFileContains(t, filepath.Join(outDir, "legacy/filescan/tmbrfix_stdout.log"), "MALWARE")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"status":"completed"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"finding_count":1`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"/tmp/bad"`)
	assertFileNotContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"severity"`)
}

func TestRunWithTimeoutResult(t *testing.T) {
	oldCompatibility := compatibilityFunc
	compatibilityFunc = func(scanner, exeType string) (string, string) { return "supported", "" }
	defer func() { compatibilityFunc = oldCompatibility }()

	root := t.TempDir()
	payload := filepath.Join(root, "payload")
	writeELF386(t, filepath.Join(payload, "tmbrfix"))
	out, outDir := newOutput(t)
	runner := &fakeRunner{result: ExecResult{TimedOut: true, Error: "context deadline exceeded", ExitCode: -1, Started: time.Now().UTC(), Ended: time.Now().UTC()}}
	if err := Run(context.Background(), out, Options{Mode: "tmbrfix", CleanMode: "disabled", PayloadRoot: payload, Runner: runner}); err != nil {
		t.Fatal(err)
	}
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"status":"timeout"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"timed_out":true`)
}

func TestScannerArtifactsEnterFinalizedArchive(t *testing.T) {
	oldCompatibility := compatibilityFunc
	compatibilityFunc = func(scanner, exeType string) (string, string) { return "supported", "" }
	defer func() { compatibilityFunc = oldCompatibility }()

	root := t.TempDir()
	payload := filepath.Join(root, "payload")
	writeELF386(t, filepath.Join(payload, "tmbrfix"))
	out, outDir := newOutput(t)
	runner := &fakeRunner{result: ExecResult{Stdout: []byte("MALWARE Found /tmp/bad\n"), Stderr: []byte("warn\n"), ExitCode: 0, Started: time.Now().UTC(), Ended: time.Now().UTC()}}
	if err := Run(context.Background(), out, Options{Mode: "tmbrfix", CleanMode: "disabled", PayloadRoot: payload, Target: "/tmp", Runner: runner}); err != nil {
		t.Fatal(err)
	}
	if err := out.Finalize("dual", "scanner-archive-test", []string{"scanner"}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(root, "scanner.tar.gz")
	if _, err := archive.CreateTarGz(outDir, archivePath, archive.Options{Prefix: "bundle"}); err != nil {
		t.Fatal(err)
	}
	names := tarNames(t, archivePath)
	assertSliceContains(t, names, "bundle/ai/raw/scanners/tmbrfix/stdout.txt")
	assertSliceContains(t, names, "bundle/ai/raw/scanners/tmbrfix/stderr.txt")
	assertSliceContains(t, names, "bundle/ai/evidence.jsonl")
	assertSliceContains(t, names, "bundle/ai/evidence.jsonl")
	assertSliceContains(t, names, "bundle/legacy/filescan/tmbrfix_stdout.log")
}

type fakeRunner struct {
	called bool
	result ExecResult
}

func (f *fakeRunner) Run(ctx context.Context, executable string, args []string) ExecResult {
	f.called = true
	return f.result
}

func writeELF386(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 64)
	data[0] = 0x7f
	data[1] = 'E'
	data[2] = 'L'
	data[3] = 'F'
	data[4] = 1
	data[18] = 3
	if err := os.WriteFile(path, data, 0o750); err != nil {
		t.Fatal(err)
	}
}

func newOutput(t *testing.T) (*output.Manager, string) {
	t.Helper()
	outDir := filepath.Join(t.TempDir(), "out")
	out, err := output.New(outDir, "dual", evidence.Session{
		CaseID:    "case-test",
		HostID:    "host-test",
		SessionID: "session-test",
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return out, outDir
}

func assertFileContains(t *testing.T, path, fragment string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), fragment) {
		t.Fatalf("%s does not contain %q: %s", path, fragment, string(data))
	}
}

func assertFileNotContains(t *testing.T, path, fragment string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), fragment) {
		t.Fatalf("%s unexpectedly contains %q: %s", path, fragment, string(data))
	}
}

func tarNames(t *testing.T, path string) []string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	var names []string
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, header.Name)
	}
	return names
}

func assertSliceContains(t *testing.T, values []string, want string) {
	t.Helper()
	for _, value := range values {
		if value == want {
			return
		}
	}
	t.Fatalf("missing %q in %v", want, values)
}
