package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBinaryConsoleContract(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "dfir-collector")
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(dir, "fixture.yaml"), []byte("name: fixture\ncollectors: [session]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(dir, "blocked")
	if err := os.WriteFile(blocked, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		args    []string
		failure bool
	}{
		{"default", nil, false},
		{"detect-only", []string{"--detect-only"}, false},
		{"log-only", []string{"--detector-log-dir", filepath.Join(dir, "logs")}, false},
		{"collect", []string{"--collect", "--profile-dir", dir, "--profile", "fixture", "--output", filepath.Join(dir, "out")}, false},
		{"log failure", []string{"--detector-log-dir", blocked}, true},
		{"collection failure", []string{"--collect", "--profile-dir", blocked}, true},
		{"parse failure", []string{"--unknown"}, true},
		{"validation failure", []string{"--timeout", "bad"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(binary, tc.args...)
			cmd.Dir = dir
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			_ = cmd.Run()
			code := cmd.ProcessState.ExitCode()
			lines := strings.Split(stdout.String(), "\n")
			if stderr.Len() != 0 || len(lines) != 3 || lines[2] != "" {
				t.Fatalf("stdout=%q stderr=%q exit=%d", stdout.String(), stderr.String(), code)
			}
			if lines[0] != "Execution: SUCCESS" && lines[0] != "Execution: FAILED" {
				t.Fatalf("invalid execution: %q", lines[0])
			}
			wantCode := 2
			switch lines[1] {
			case "Verdict: CLEAN":
				if lines[0] != "Execution: SUCCESS" {
					t.Fatal("false clean")
				}
				wantCode = 0
			case "Verdict: INFECTED":
				if !tc.failure {
					wantCode = 3
				}
			case "Verdict: INCONCLUSIVE":
			default:
				t.Fatalf("invalid verdict: %q", lines[1])
			}
			if code != wantCode || (tc.failure && lines[0] != "Execution: FAILED") {
				t.Fatalf("stdout=%q code=%d want=%d", stdout.String(), code, wantCode)
			}
		})
	}
	for _, args := range [][]string{{"--help"}, {"--no-detect", "--timeout", "bad"}} {
		cmd := exec.Command(binary, args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		if args[0] == "--help" {
			if err != nil || stderr.Len() != 0 || !strings.Contains(stdout.String(), "-detect-only") || strings.Contains(stdout.String(), "Execution:") {
				t.Fatalf("help: stdout=%q stderr=%q err=%v", stdout.String(), stderr.String(), err)
			}
		} else if cmd.ProcessState.ExitCode() != 1 || !strings.Contains(stderr.String(), "Execution failed:") || strings.Contains(stdout.String(), "CLEAN") {
			t.Fatalf("legacy: stdout=%q stderr=%q err=%v", stdout.String(), stderr.String(), err)
		}
	}
}
