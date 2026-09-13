package ddeirootkit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Print renders the report to the terminal in a responder-friendly layout.
func Print(rep Report, w *os.File) {
	fmt.Fprintln(w, "====== DDEI Rootkit Detector (linux-dfir/ddei-rootkit-detector) ======")
	fmt.Fprintf(w, "host=%s time=%s family=%s\n", rep.Hostname, rep.Timestamp.Format(time.RFC3339), FamilyName)
	fmt.Fprintln(w, "----------------------------------------------------------------------")
	if len(rep.Checks) == 0 {
		fmt.Fprintln(w, "no checks produced results")
	}
	for _, c := range rep.Checks {
		fmt.Fprintf(w, "[%s] %s\n", c.Severity, c.Title)
		if c.Detail != "" {
			fmt.Fprintf(w, "        %s\n", c.Detail)
		}
	}
	if len(rep.ProcHits) > 0 {
		fmt.Fprintln(w, "----------------------------------------------------------------------")
		fmt.Fprintln(w, "processes with family artifacts mapped:")
		for _, h := range rep.ProcHits {
			fmt.Fprintf(w, "  pid=%-7d comm=%-12s exe=%s %s\n", h.PID, h.Comm, h.Exe, h.Note)
		}
	}
	fmt.Fprintln(w, "======================================================================")
	switch rep.Verdict {
	case VerdictInfected:
		fmt.Fprintf(w, "VERDICT: *** INFECTED *** — %s (%s)\n", FamilyName, rep.Summary)
		fmt.Fprintln(w, "Recommended: isolate the host, image the disk, rebuild; treat all local tool output as untrusted.")
	case VerdictLikelyInfected:
		fmt.Fprintf(w, "VERDICT: *** LIKELY INFECTED *** — %s\n", rep.Summary)
		fmt.Fprintln(w, "Recommended: isolate the host and escalate to full DFIR collection (-profile deep).")
	case VerdictSuspicious:
		fmt.Fprintf(w, "VERDICT: SUSPICIOUS — %s\n", rep.Summary)
	default:
		fmt.Fprintf(w, "VERDICT: CLEAN — %s\n", rep.Summary)
	}
}

// WriteLog persists a plain-text report next to the given directory (dir may
// be the directory of the running executable). It returns the log path.
func WriteLog(rep Report, dir string) (string, error) {
	if dir == "" {
		if exe, err := os.Executable(); err == nil {
			dir = filepath.Dir(exe)
		} else {
			dir, _ = os.Getwd()
		}
	}
	name := fmt.Sprintf("ddei_rootkit_check_%s.log", rep.Timestamp.Format("20060102T150405Z"))
	path := filepath.Join(dir, name)
	var b strings.Builder
	b.WriteString("# DDEI rootkit detector report\n")
	fmt.Fprintf(&b, "timestamp=%s\nhost=%s\nfamily=%s\nverdict=%s\nsummary=%s\n\n",
		rep.Timestamp.Format(time.RFC3339), rep.Hostname, FamilyName, rep.Verdict, rep.Summary)
	for _, c := range rep.Checks {
		fmt.Fprintf(&b, "[%s] %s\n", c.Severity, c.Title)
		if c.Detail != "" {
			fmt.Fprintf(&b, "        %s\n", c.Detail)
		}
	}
	if len(rep.ProcHits) > 0 {
		b.WriteString("\nprocess_hits:\n")
		for _, h := range rep.ProcHits {
			fmt.Fprintf(&b, "  pid=%d comm=%s exe=%s %s\n", h.PID, h.Comm, h.Exe, h.Note)
		}
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// ExitCode maps a verdict onto a scriptable process exit code.
func ExitCode(v Verdict) int {
	switch v {
	case VerdictInfected:
		return 3
	case VerdictLikelyInfected:
		return 2
	case VerdictSuspicious:
		return 1
	default:
		return 0
	}
}
