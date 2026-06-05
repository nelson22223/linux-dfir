package scanners

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"linux-dfir/internal/evidence"
	"linux-dfir/internal/integrity"
	"linux-dfir/internal/output"
)

const (
	collector   = "scanner"
	runsRel     = "facts/scanner_runs.jsonl"
	findingsRel = "facts/scanner_findings.jsonl"
)

type Options struct {
	Mode        string
	CleanMode   string
	PayloadRoot string
	Timeout     time.Duration
	Target      string
	Runner      Runner
}

type Runner interface {
	Run(ctx context.Context, executable string, args []string) ExecResult
}

type ExecResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Error    string
	TimedOut bool
	Started  time.Time
	Ended    time.Time
}

type RunRecord struct {
	evidence.RecordMeta
	Exists              bool       `json:"exists"`
	AbsentReason        string     `json:"absent_reason,omitempty"`
	Scanner             string     `json:"scanner"`
	Status              string     `json:"status"`
	Compatibility       string     `json:"compatibility"`
	CompatibilityReason string     `json:"compatibility_reason,omitempty"`
	CleanMode           string     `json:"clean_mode"`
	ScanOnly            bool       `json:"scan_only"`
	ExecutablePath      string     `json:"executable_path,omitempty"`
	ExecutableSHA256    string     `json:"executable_sha256,omitempty"`
	ExecutableMD5       string     `json:"executable_md5,omitempty"`
	ExecutableSize      int64      `json:"executable_size,omitempty"`
	ExecutableType      string     `json:"executable_type,omitempty"`
	Args                []string   `json:"args,omitempty"`
	Target              string     `json:"target,omitempty"`
	ExitCode            int        `json:"exit_code,omitempty"`
	Error               string     `json:"error,omitempty"`
	TimedOut            bool       `json:"timed_out,omitempty"`
	StdoutRef           string     `json:"stdout_ref,omitempty"`
	StderrRef           string     `json:"stderr_ref,omitempty"`
	FindingCount        int        `json:"finding_count"`
	StartedAt           *time.Time `json:"started_at,omitempty"`
	CompletedAt         *time.Time `json:"completed_at,omitempty"`
}

type FindingRecord struct {
	evidence.RecordMeta
	Exists       bool   `json:"exists"`
	AbsentReason string `json:"absent_reason,omitempty"`
	Scanner      string `json:"scanner"`
	Signature    string `json:"signature,omitempty"`
	Path         string `json:"path,omitempty"`
	RawLine      string `json:"raw_line,omitempty"`
}

type Plugin struct {
	Name       string
	ExeName    string
	OutputType string
}

var plugins = map[string]Plugin{
	"tmbrfix": {Name: "tmbrfix", ExeName: "tmbrfix", OutputType: "tmbrfix_stdout"},
	"yara":    {Name: "yara", ExeName: "yara", OutputType: "yara_stdout"},
	"osquery": {Name: "osquery", ExeName: "osqueryi", OutputType: "osquery_stdout"},
}

var compatibilityFunc = compatibility

func Run(ctx context.Context, out *output.Manager, opts Options) error {
	mode := strings.ToLower(opts.Mode)
	cleanMode := strings.ToLower(opts.CleanMode)
	if mode == "" || mode == "none" {
		return writeScannerDisabled(out)
	}
	plugin, ok := plugins[mode]
	if !ok {
		return writeRunWithAbsentFinding(out, runAbsent(mode, cleanMode, "unsupported scanner mode"), "scanner", "unsupported scanner mode")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.Target == "" {
		opts.Target = "/"
	}
	if opts.PayloadRoot == "" {
		opts.PayloadRoot = "payload"
	}
	path := scannerPath(opts.PayloadRoot, plugin)
	run := RunRecord{
		RecordMeta: out.Meta(collector, runsRel, path, "scanner", "medium"),
		Exists:     true,
		Scanner:    plugin.Name,
		CleanMode:  cleanMode,
		ScanOnly:   true,
		Target:     opts.Target,
	}
	if cleanMode == "" {
		run.CleanMode = "disabled"
	}
	run.ScanOnly = scanOnly(plugin.Name, run.CleanMode)
	if err := enrichExecutable(&run, path); err != nil {
		run.Exists = false
		run.Status = "absent"
		run.AbsentReason = err.Error()
		run.Compatibility = "not_applicable"
		run.CompatibilityReason = err.Error()
		return writeRunWithAbsentFinding(out, run, path, err.Error())
	}
	run.Compatibility, run.CompatibilityReason = compatibilityFunc(plugin.Name, run.ExecutableType)
	if run.Compatibility != "supported" {
		run.Status = "skipped"
		return writeRunWithAbsentFinding(out, run, path, run.CompatibilityReason)
	}
	args := buildArgs(plugin.Name, run.CleanMode, opts.Target)
	run.Args = args
	if opts.Runner == nil {
		opts.Runner = osExecRunner{}
	}
	ctxRun, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	result := opts.Runner.Run(ctxRun, path, args)
	if !result.Started.IsZero() {
		startedAt := result.Started.UTC()
		run.StartedAt = &startedAt
	}
	if !result.Ended.IsZero() {
		completedAt := result.Ended.UTC()
		run.CompletedAt = &completedAt
	}
	run.ExitCode = result.ExitCode
	run.Error = result.Error
	run.TimedOut = result.TimedOut
	if result.TimedOut {
		run.Status = "timeout"
	} else if result.Error != "" || result.ExitCode != 0 {
		run.Status = "failed"
	} else {
		run.Status = "completed"
	}
	stdoutRel := filepath.ToSlash(filepath.Join("raw", "scanners", plugin.Name, "stdout.txt"))
	stderrRel := filepath.ToSlash(filepath.Join("raw", "scanners", plugin.Name, "stderr.txt"))
	if err := out.WriteAIFromSource(stdoutRel, result.Stdout, collector, path, "scanner", "medium"); err != nil {
		return err
	}
	if err := out.WriteAIFromSource(stderrRel, result.Stderr, collector, path, "scanner", "medium"); err != nil {
		return err
	}
	if err := out.WriteLegacyFromSource(filepath.ToSlash(filepath.Join("filescan", plugin.Name+"_stdout.log")), result.Stdout, collector, path, "scanner", "medium"); err != nil {
		return err
	}
	if err := out.WriteLegacyFromSource(filepath.ToSlash(filepath.Join("filescan", plugin.Name+"_stderr.log")), result.Stderr, collector, path, "scanner", "medium"); err != nil {
		return err
	}
	run.StdoutRef = filepath.ToSlash(filepath.Join("ai", stdoutRel))
	run.StderrRef = filepath.ToSlash(filepath.Join("ai", stderrRel))
	findings := parseFindings(plugin.Name, result.Stdout)
	run.FindingCount = len(findings)
	if err := writeRun(out, run); err != nil {
		return err
	}
	for _, finding := range findings {
		finding.RecordMeta = out.Meta(collector, findingsRel, path, "scanner", "medium")
		if err := out.AppendAIJSONL(findingsRel, finding, collector, path, "scanner", "medium"); err != nil {
			return err
		}
	}
	if len(findings) == 0 {
		return writeFindingAbsent(out, plugin.Name, path, "no scanner findings parsed")
	}
	return nil
}

func writeScannerDisabled(out *output.Manager) error {
	run := runAbsent("none", "disabled", "scanner disabled")
	run.RecordMeta = out.Meta(collector, runsRel, "scanner", "generated", "medium")
	run.Status = "skipped"
	if err := writeRun(out, run); err != nil {
		return err
	}
	return writeFindingAbsent(out, "none", "scanner", "scanner disabled")
}

func runAbsent(scanner, cleanMode, reason string) RunRecord {
	if cleanMode == "" {
		cleanMode = "disabled"
	}
	return RunRecord{Exists: false, AbsentReason: reason, Scanner: scanner, Status: "skipped", CleanMode: cleanMode, ScanOnly: cleanMode == "disabled", Compatibility: "not_applicable", CompatibilityReason: reason}
}

func writeRun(out *output.Manager, run RunRecord) error {
	if run.RecordMeta.SchemaVersion == "" {
		run.RecordMeta = out.Meta(collector, runsRel, defaultString(run.ExecutablePath, "scanner"), defaultSourceType(run), "medium")
	}
	if err := out.AppendAIJSONL(runsRel, run, collector, run.SourcePath, run.SourceType, run.SourceTrust); err != nil {
		return err
	}
	return out.WriteLegacyFromSource("filescan/scanner_status.out", []byte(legacyStatus(run)), collector, defaultString(run.ExecutablePath, "scanner"), defaultSourceType(run), "medium")
}

func writeRunWithAbsentFinding(out *output.Manager, run RunRecord, source, reason string) error {
	if err := writeRun(out, run); err != nil {
		return err
	}
	return writeFindingAbsent(out, run.Scanner, source, reason)
}

func writeFindingAbsent(out *output.Manager, scanner, source, reason string) error {
	record := FindingRecord{RecordMeta: out.Meta(collector, findingsRel, source, "scanner", "medium"), Exists: false, AbsentReason: reason, Scanner: scanner}
	return out.AppendAIJSONL(findingsRel, record, collector, source, "scanner", "medium")
}

func legacyStatus(run RunRecord) string {
	var b strings.Builder
	b.WriteString("Linux DFIR scanner status\n")
	b.WriteString("=========================\n")
	b.WriteString("scanner: " + run.Scanner + "\n")
	b.WriteString("status: " + run.Status + "\n")
	b.WriteString("compatibility: " + run.Compatibility + "\n")
	if run.CompatibilityReason != "" {
		b.WriteString("compatibility_reason: " + run.CompatibilityReason + "\n")
	}
	if run.AbsentReason != "" {
		b.WriteString("absent_reason: " + run.AbsentReason + "\n")
	}
	if run.ExecutablePath != "" {
		b.WriteString("executable: " + run.ExecutablePath + "\n")
		b.WriteString("sha256: " + run.ExecutableSHA256 + "\n")
	}
	b.WriteString("clean_mode: " + run.CleanMode + "\n")
	b.WriteString(fmt.Sprintf("scan_only: %t\n", run.ScanOnly))
	b.WriteString(fmt.Sprintf("finding_count: %d\n", run.FindingCount))
	return b.String()
}

func scannerPath(payloadRoot string, plugin Plugin) string {
	if plugin.Name == "tmbrfix" {
		return filepath.Join(payloadRoot, plugin.ExeName)
	}
	if path, err := exec.LookPath(plugin.ExeName); err == nil {
		return path
	}
	return plugin.ExeName
}

func enrichExecutable(run *RunRecord, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("scanner executable is a directory: %s", path)
	}
	hash, err := integrity.HashFile(path)
	if err != nil {
		return err
	}
	run.ExecutablePath = path
	run.ExecutableSHA256 = hash.SHA256
	run.ExecutableMD5 = hash.MD5
	run.ExecutableSize = hash.Size
	run.ExecutableType = executableType(path)
	return nil
}

func executableType(path string) string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 20 {
		return "unknown"
	}
	if data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		class := "unknown"
		if data[4] == 1 {
			class = "elf32"
		} else if data[4] == 2 {
			class = "elf64"
		}
		machine := uint16(data[18]) | uint16(data[19])<<8
		switch machine {
		case 3:
			return class + "-386-linux"
		case 62:
			return class + "-amd64-linux"
		case 183:
			return class + "-arm64-linux"
		default:
			return class + "-linux-machine-" + fmt.Sprint(machine)
		}
	}
	return "unknown"
}

func compatibility(scanner, exeType string) (string, string) {
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	if scanner == "tmbrfix" {
		if !strings.Contains(exeType, "386-linux") {
			return "unsupported", "tmbrfix payload is not Linux i386 ELF"
		}
		if goos != "linux" {
			return "unsupported", "tmbrfix requires Linux runtime"
		}
		if goarch != "386" && goarch != "amd64" {
			return "unsupported", "tmbrfix requires linux/386 or linux/amd64 with 32-bit compatibility"
		}
		return "supported", ""
	}
	if goos != "linux" {
		return "unsupported", scanner + " scanner execution is Linux-only in this phase"
	}
	return "supported", ""
}

func buildArgs(scanner, cleanMode, target string) []string {
	switch scanner {
	case "tmbrfix":
		args := []string{"-scan", target}
		if cleanMode == "confirm" || cleanMode == "force" {
			args = append(args, "-clean")
		}
		return args
	case "yara":
		return []string{"-r", "rules.yar", target}
	case "osquery":
		return []string{"--json", "select * from processes limit 1;"}
	default:
		return nil
	}
}

func scanOnly(scanner, cleanMode string) bool {
	return !(scanner == "tmbrfix" && (cleanMode == "confirm" || cleanMode == "force"))
}

func parseFindings(scanner string, stdout []byte) []FindingRecord {
	var findings []FindingRecord
	for _, line := range strings.Split(string(stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if scanner == "yara" {
			if finding, ok := parseYARAFinding(scanner, line); ok {
				findings = append(findings, finding)
			}
			continue
		}
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "found") && !strings.Contains(lower, "virus") && !strings.Contains(lower, "malware") && !strings.Contains(lower, "infected") && !strings.Contains(line, "MATCH") {
			continue
		}
		finding := FindingRecord{Exists: true, Scanner: scanner, RawLine: line}
		parts := strings.Fields(line)
		if len(parts) > 0 {
			finding.Signature = strings.Trim(parts[0], "[]:")
		}
		for _, part := range parts {
			if strings.HasPrefix(part, "/") {
				finding.Path = part
				break
			}
		}
		findings = append(findings, finding)
	}
	return findings
}

func parseYARAFinding(scanner, line string) (FindingRecord, bool) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return FindingRecord{}, false
	}
	path := ""
	for i := len(parts) - 1; i >= 1; i-- {
		if strings.HasPrefix(parts[i], "/") {
			path = parts[i]
			break
		}
	}
	if path == "" {
		return FindingRecord{}, false
	}
	return FindingRecord{Exists: true, Scanner: scanner, Signature: strings.Trim(parts[0], "[]:"), Path: path, RawLine: line}, true
}

type osExecRunner struct{}

func (osExecRunner) Run(ctx context.Context, executable string, args []string) ExecResult {
	started := time.Now().UTC()
	cmd := exec.CommandContext(ctx, executable, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	ended := time.Now().UTC()
	result := ExecResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Started: started, Ended: ended}
	if ctx.Err() != nil {
		result.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
		result.Error = ctx.Err().Error()
	}
	if err != nil {
		result.Error = err.Error()
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else if result.ExitCode == 0 {
			result.ExitCode = -1
		}
	}
	return result
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func defaultSourceType(run RunRecord) string {
	if run.ExecutablePath == "" {
		return "generated"
	}
	return "scanner"
}
