package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"linux-dfir/internal/archive"
	"linux-dfir/internal/collectors"
	"linux-dfir/internal/collectors/logs"
	"linux-dfir/internal/detector/ddeirootkit"
	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
	"linux-dfir/internal/profile"
	"linux-dfir/internal/scanners"
	"linux-dfir/internal/session"
	"linux-dfir/internal/timeline"
)

const (
	defaultProfile = "ddei"
	defaultMode    = string(output.ModeDual)
)

// Execution failures override the verdict's exit code, not the report itself.
var detectorExitCode int

var errorExitCode = 2

// ErrorExitCode preserves the legacy failure contract when detection is disabled.
func ErrorExitCode() int { return errorExitCode }

var runDetector = ddeirootkit.RunContext

type runStatus struct {
	Detection  string
	Collection string
}

var lastRun runStatus

// ExitCode returns the detector-driven exit code (0 when detection was
// skipped or the host is clean).
func ExitCode() int { return detectorExitCode }

type Config struct {
	CleanMode          string
	OutputDir          string
	Profile            string
	ProfileDir         string
	Scan               string
	Timeout            string
	DetectOnly         bool
	Collect            bool
	NoDetect           bool
	DetectorLog        string
	ProfileDirExplicit bool
}

func Run(ctx context.Context, args []string) (runErr error) {
	detectorExitCode = 0
	errorExitCode = 2
	lastRun = runStatus{Detection: "not_started", Collection: "not_started"}
	defer func() {
		execution := "completed"
		if errors.Is(runErr, flag.ErrHelp) {
			return
		}
		if runErr != nil {
			execution = "failed"
			detectorExitCode = ErrorExitCode()
			if lastRun.Collection == "running" {
				lastRun.Collection = "failed"
			}
		}
		fmt.Printf("Execution: %s; detection=%s; collection=%s; exit_code=%d\n", execution, lastRun.Detection, lastRun.Collection, detectorExitCode)
	}()

	cfg, err := parseArgs(args)
	if cfg.NoDetect {
		errorExitCode = 1
	}
	if err != nil {
		return err
	}

	if err := validateConfig(cfg); err != nil {
		return err
	}
	cfg.Scan = strings.ToLower(cfg.Scan)
	cfg.CleanMode = strings.ToLower(cfg.CleanMode)
	runCtx, cancel, scannerTimeout := optionalTimeoutContext(ctx, cfg.Timeout)
	defer cancel()

	// The detector runs before anything that touches the profile system so a
	// standalone binary on a victim host always produces a verdict even when
	// no profiles/ directory ships next to the executable.
	var detectorReport *ddeirootkit.Report
	if !cfg.NoDetect {
		rep := runDetector(runCtx, ddeirootkit.Options{
			ScanProcMaps: true,
		})
		detectorReport = &rep
		lastRun.Detection = string(rep.Verdict)
		detectorExitCode = ddeirootkit.ExitCode(rep.Verdict)
		if !rep.Complete {
			if rep.Verdict != ddeirootkit.VerdictInfected {
				detectorExitCode = 2
			}
			lastRun.Detection += " (incomplete coverage)"
		}
		ddeirootkit.Print(rep, os.Stdout)
		if cfg.DetectorLog != "" {
			logPath, logErr := ddeirootkit.WriteLog(rep, cfg.DetectorLog)
			if logErr != nil {
				return fmt.Errorf("detector log write failed: %w", logErr)
			}
			fmt.Printf("Detector log saved: %s\n", logPath)
		}
		if err := runCtx.Err(); err != nil {
			return fmt.Errorf("detector execution interrupted: %w", err)
		}
		if !cfg.Collect {
			return nil
		}
	}

	profileDef, err := loadProfileOrDefault(cfg)
	if err != nil {
		return err
	}
	logs.Configure(logs.Options{JournalMaxLines: profileDef.Limits.JournalMaxLines})
	lastRun.Collection = "running"

	sess, err := session.New("", time.Now().UTC())
	if err != nil {
		return err
	}
	out, err := output.New(cfg.OutputDir, defaultMode, sess)
	if err != nil {
		return err
	}

	started := time.Now().UTC()
	if err := out.LogEvent(evidence.CollectionEvent{
		Collector: "session",
		Event:     "session_start",
		Status:    "ok",
		Message:   "collector session started",
	}); err != nil {
		return err
	}
	if err := out.Timeline(timeline.SessionEvent("session_start", "collector session started", started)); err != nil {
		return err
	}
	if err := out.WriteLegacy("command_not_found.out", []byte("# Commands unavailable during Go-native phase 1 initialization\n"), "session"); err != nil {
		return err
	}
	summary := fmt.Sprintf("Linux DFIR Collector\nSession: %s\nCase: %s\nProfile: %s\nCollectors: %s\n",
		sess.SessionID, sess.CaseID, profileDef.Name, strings.Join(profileDef.Collectors, ","))
	if err := out.WriteLegacy("SUMMARY", []byte(summary), "session"); err != nil {
		return err
	}

	finalCollectors := append([]string{}, profileDef.Collectors...)
	if detectorReport != nil {
		// The AI stream deliberately carries no verdicts; the detector report
		// belongs in the human-readable legacy tree (legacy/ddei_rootkit/).
		if blob, err := json.MarshalIndent(detectorReport, "", "  "); err == nil {
			if err := out.WriteLegacy("ddei_rootkit/report.json", append(blob, '\n'), "detector"); err != nil {
				return err
			}
		} else {
			return err
		}
		finalCollectors = appendIfMissing(finalCollectors, "detector")
		if err := out.WriteLegacy("ddei_rootkit/report.txt", []byte(ddeirootkit.Text(*detectorReport)), "detector"); err != nil {
			return err
		}
	}
	registry := collectors.Registry()
	for _, collectorName := range profileDef.Collectors {
		if collectorName == "session" || collectorName == "scanner" {
			continue
		}
		collector, ok := registry[collectorName]
		if ok {
			if err := out.LogEvent(evidence.CollectionEvent{
				Collector: collectorName,
				Event:     "collector_start",
				Status:    "ok",
				Message:   "collector started",
			}); err != nil {
				return err
			}
			if err := runCtx.Err(); err != nil {
				_ = out.Error(evidence.ErrorEvent{Collector: collectorName, Error: err.Error(), SourcePath: "timeout", SourceType: "generated", SourceTrust: "medium"})
				return err
			}
			if err := collector(runCtx, out); err != nil {
				_ = out.Error(evidence.ErrorEvent{Collector: collectorName, Error: err.Error(), SourcePath: "collector", SourceType: "generated", SourceTrust: "high"})
				_ = writeCollectorStatus(out, collectorName, "error", err.Error())
				return err
			}
			if err := out.LogEvent(evidence.CollectionEvent{
				Collector: collectorName,
				Event:     "collector_end",
				Status:    "ok",
				Message:   "collector completed",
			}); err != nil {
				return err
			}
			if err := writeCollectorStatus(out, collectorName, "ok", "collector completed"); err != nil {
				return err
			}
			continue
		}
		if err := out.LogEvent(evidence.CollectionEvent{
			Collector: collectorName,
			Event:     "collector_skipped",
			Status:    "skipped",
			Message:   "collector not implemented in current phase",
		}); err != nil {
			return err
		}
		if err := writeCollectorStatus(out, collectorName, "skipped", "collector not implemented in current phase"); err != nil {
			return err
		}
	}
	if shouldRunScanner(cfg) {
		finalCollectors = appendIfMissing(finalCollectors, "scanner")
		if err := out.LogEvent(evidence.CollectionEvent{
			Collector: "scanner",
			Event:     "scanner_start",
			Status:    "ok",
			Message:   "scanner phase started",
		}); err != nil {
			return err
		}
		if err := scanners.Run(runCtx, out, scanners.Options{Mode: cfg.Scan, CleanMode: cfg.CleanMode, PayloadRoot: "payload", Timeout: scannerTimeout}); err != nil {
			_ = out.Error(evidence.ErrorEvent{Collector: "scanner", Error: err.Error(), SourcePath: "scanner", SourceType: "scanner", SourceTrust: "medium"})
			_ = writeCollectorStatus(out, "scanner", "error", err.Error())
			return err
		}
		if err := out.LogEvent(evidence.CollectionEvent{
			Collector: "scanner",
			Event:     "scanner_end",
			Status:    "ok",
			Message:   "scanner phase completed",
		}); err != nil {
			return err
		}
		if err := writeCollectorStatus(out, "scanner", "ok", "scanner phase completed"); err != nil {
			return err
		}
	}
	if err := out.LogEvent(evidence.CollectionEvent{
		Collector: "session",
		Event:     "session_end",
		Status:    "ok",
		Message:   "collector session finalized",
	}); err != nil {
		return err
	}
	if err := out.Timeline(timeline.SessionEvent("session_end", "collector session finalized", time.Now().UTC())); err != nil {
		return err
	}
	if err := out.Finalize(defaultMode, profileDef.Name, finalCollectors, time.Now().UTC()); err != nil {
		return err
	}
	if err := writeArchive(cfg.OutputDir, sess.SessionID); err != nil {
		return err
	}

	lastRun.Collection = "completed"
	fmt.Printf("Collection and archive completed\n")
	fmt.Printf("session=%s profile=%s collectors=%s output_mode=%s output=%s scan=%s clean=%s\n",
		sess.SessionID, profileDef.Name, strings.Join(finalCollectors, ","), defaultMode, cfg.OutputDir, cfg.Scan, cfg.CleanMode)
	return nil
}

func writeCollectorStatus(out *output.Manager, collectorName, status, message string) error {
	body := fmt.Sprintf("collector: %s\nstatus: %s\nmessage: %s\n", collectorName, status, message)
	return out.WriteLegacy(filepath.Join("collector_status", collectorName+".out"), []byte(body), collectorName)
}

func parseArgs(args []string) (Config, error) {
	cfg := Config{
		CleanMode:  "disabled",
		OutputDir:  defaultOutputDir(time.Now()),
		Profile:    defaultProfile,
		ProfileDir: "profiles",
		Scan:       "none",
	}

	fs := flag.NewFlagSet("dfir-collector", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.CleanMode, "clean", cfg.CleanMode, "clean mode: disabled, confirm, force")
	fs.StringVar(&cfg.OutputDir, "output", cfg.OutputDir, "output directory")
	fs.StringVar(&cfg.Profile, "profile", cfg.Profile, "collection profile name under --profile-dir")
	fs.StringVar(&cfg.ProfileDir, "profile-dir", cfg.ProfileDir, "directory containing collection profiles")
	fs.StringVar(&cfg.Scan, "scan", cfg.Scan, "scanner: none, tmbrfix, yara, osquery")
	fs.StringVar(&cfg.Timeout, "timeout", cfg.Timeout, "optional overall collection timeout, disabled when omitted")
	fs.BoolVar(&cfg.DetectOnly, "detect-only", false, "run only the DDEI rootkit detector (no collection/archive)")
	fs.BoolVar(&cfg.Collect, "collect", false, "enable collection and archive after detection")
	fs.BoolVar(&cfg.NoDetect, "no-detect", false, "skip the DDEI rootkit detector (original collection behaviour)")
	fs.StringVar(&cfg.DetectorLog, "detector-log-dir", "", "directory for an optional detector log file (empty: no log file)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(os.Stdout)
			fs.PrintDefaults()
		}
		return cfg, err
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "profile-dir" {
			cfg.ProfileDirExplicit = true
		}
	})
	return cfg, nil
}

func defaultOutputDir(now time.Time) string {
	return "dfir_" + now.Format("20060102150405")
}

// loadProfileOrDefault loads the requested profile, falling back to a
// built-in definition of the branch default when the binary runs standalone
// (no profiles/ directory next to the executable).
func loadProfileOrDefault(cfg Config) (profile.Definition, error) {
	def, err := profile.Load(cfg.ProfileDir, cfg.Profile)
	if err == nil {
		return def, nil
	}
	if cfg.Profile != defaultProfile || cfg.ProfileDirExplicit || cfg.ProfileDir != "profiles" || !errors.Is(err, os.ErrNotExist) {
		return profile.Definition{}, err
	}
	if _, statErr := os.Lstat(filepath.Join(cfg.ProfileDir, cfg.Profile+".yaml")); !errors.Is(statErr, os.ErrNotExist) {
		return profile.Definition{}, err
	}
	fmt.Fprintf(os.Stderr, "Default profile missing; using built-in %s profile\n", defaultProfile)
	return profile.Definition{
		Name:        defaultProfile,
		Description: "built-in DDEI triage profile (detector output plus supporting artifacts)",
		Collectors:  []string{"host", "system", "process", "network", "persistence", "logs"},
		Limits: profile.Limits{
			MaxFileSize:     104857600,
			Timeout:         "10m",
			JournalMaxLines: 5000,
		},
	}, nil
}

func validateConfig(cfg Config) error {
	if cfg.DetectOnly && cfg.NoDetect {
		return errors.New("--detect-only and --no-detect cannot be used together")
	}
	if cfg.DetectOnly && cfg.Collect {
		return errors.New("--detect-only and --collect cannot be used together")
	}
	if (cfg.Collect || cfg.NoDetect) && cfg.OutputDir == "" {
		return errors.New("output directory is required")
	}

	if !oneOf(cfg.Scan, "none", "tmbrfix", "yara", "osquery") {
		return fmt.Errorf("unsupported scanner: %s", cfg.Scan)
	}
	if !oneOf(cfg.CleanMode, "disabled", "confirm", "force") {
		return fmt.Errorf("unsupported clean mode: %s", cfg.CleanMode)
	}
	if !cfg.Collect && !cfg.NoDetect && (!oneOf(cfg.Scan, "none") || !oneOf(cfg.CleanMode, "disabled")) {
		return errors.New("--scan and --clean require --collect or --no-detect")
	}
	if cfg.Timeout != "" {
		if timeout, err := time.ParseDuration(cfg.Timeout); err != nil || timeout <= 0 {
			return fmt.Errorf("unsupported timeout: %s", cfg.Timeout)
		}
	}
	return nil
}

func shouldRunScanner(cfg Config) bool {
	return strings.ToLower(cfg.Scan) != "none"
}

func appendIfMissing(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}

func optionalTimeoutContext(ctx context.Context, value string) (context.Context, context.CancelFunc, time.Duration) {
	if value == "" {
		return ctx, func() {}, 0
	}
	timeout, _ := time.ParseDuration(value)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	return runCtx, cancel, timeout
}

func writeArchive(outputDir, sessionID string) error {
	outputAbs, err := filepath.Abs(outputDir)
	if err != nil {
		return err
	}
	archivePath := outputAbs + ".tar.gz"
	summary, err := archive.CreateTarGz(outputAbs, archivePath, archive.Options{Prefix: filepath.Base(outputAbs)})
	if err != nil {
		return err
	}
	summaryPath := filepath.Join(outputAbs, "ai", "archive_summary.json")
	if err := archive.WriteSummary(summaryPath, summary); err != nil {
		return err
	}
	fmt.Printf("archive=%s sha256=%s session=%s\n", archivePath, summary.Archive.SHA256, sessionID)
	return nil
}

func oneOf(value string, allowed ...string) bool {
	value = strings.ToLower(value)
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}
