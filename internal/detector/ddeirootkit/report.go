package ddeirootkit

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Text renders the same human report for console, log, and archive.
func Text(rep Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "DDEI Rootkit Detection\nHost: %s\nTime: %s\nFamily: %s\n", rep.Hostname, rep.Timestamp.Format(time.RFC3339), FamilyName)
	coverage := "Requested checks completed (detector scope only; not a guarantee of overall host safety)"
	if !rep.Complete {
		coverage = "Checks incomplete or coverage insufficient; infection cannot be ruled out"
	}
	fmt.Fprintf(&b, "Completion/coverage: %s\nVerdict: %s\nSummary: %s\n", coverage, rep.Verdict, rep.Summary)
	fmt.Fprintf(&b, "Coverage: root=%t proc=%t processes=%d objects=%d errors=%d skipped=%d\n",
		rep.Coverage.Root, rep.Coverage.Proc, rep.Coverage.Processes, rep.Coverage.Objects, rep.Coverage.Errors, rep.Coverage.Skipped)
	if len(rep.Findings) == 0 {
		b.WriteString("No indicators flagged\n")
	}
	for _, f := range rep.Findings {
		fmt.Fprintf(&b, "[%s] %s\n", f.Level, f.Title)
		if f.Detail != "" {
			fmt.Fprintf(&b, "  %s\n", f.Detail)
		}
	}
	for _, h := range rep.ProcHits {
		fmt.Fprintf(&b, "Process: pid=%d comm=%s exe=%s %s\n", h.PID, h.Comm, h.Exe, h.Note)
	}
	switch rep.Verdict {
	case VerdictInfected:
		b.WriteString("Evidence of infection found. Isolate the host and preserve evidence.\n")
	case VerdictClean:
		if rep.Complete {
			b.WriteString("No family indicators found within the checked scope.\n")
		}
	default:
		b.WriteString("Insufficient evidence for a conclusive result; further investigation required. Not CLEAN.\n")
	}
	return b.String()
}

func Print(rep Report, w io.Writer) { fmt.Fprint(w, Text(rep)) }

// WriteLog exclusively creates a private log, never truncating existing files.
func WriteLog(rep Report, dir string) (string, error) {
	if dir == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("locate executable directory: %w", err)
		}
		dir = filepath.Dir(exe)
	} else if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	base := "ddei_rootkit_check_" + rep.Timestamp.UTC().Format("20060102T150405Z")
	for n := 0; n < 10000; n++ {
		name := base + ".log"
		if n > 0 {
			name = fmt.Sprintf("%s_%d.log", base, n)
		}
		path := filepath.Join(dir, name)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		_, writeErr := io.WriteString(f, Text(rep))
		if writeErr == nil {
			writeErr = f.Sync()
		}
		closeErr := f.Close()
		if writeErr != nil {
			return "", writeErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		return path, nil
	}
	return "", fmt.Errorf("too many detector log filename collisions: %s", dir)
}

// ExitCode maps unknown and legacy REVIEW outcomes conservatively to 2.
func ExitCode(v Verdict) int {
	switch v {
	case VerdictInfected:
		return 3
	case VerdictClean:
		return 0
	default:
		return 2
	}
}
