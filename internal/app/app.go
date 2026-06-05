package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"linux-dfir/internal/archive"
	"linux-dfir/internal/collectors"
	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
	"linux-dfir/internal/profile"
	"linux-dfir/internal/scanners"
	"linux-dfir/internal/session"
	"linux-dfir/internal/timeline"
)

const (
	defaultProfile = "standard"
	defaultMode    = "dual"
)

type Config struct {
	Archive    bool
	CaseID     string
	CleanMode  string
	Encrypt    bool
	KeepWork   bool
	OutputDir  string
	OutputMode string
	Profile    string
	ProfileDir string
	Redact     bool
	Scan       string
	Timeout    string
}

func Run(ctx context.Context, args []string) error {
	_ = ctx

	cfg, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}

	if err := validateConfig(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	cfg.OutputMode = strings.ToLower(cfg.OutputMode)
	cfg.Scan = strings.ToLower(cfg.Scan)
	cfg.CleanMode = strings.ToLower(cfg.CleanMode)

	profileDef, err := profile.Load(cfg.ProfileDir, cfg.Profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	effectiveTimeout := effectiveTimeout(cfg.Timeout, profileDef.Limits.Timeout)
	runCtx, cancel := context.WithTimeout(ctx, effectiveTimeout)
	defer cancel()

	sess, err := session.New(cfg.CaseID, time.Now().UTC())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	out, err := output.New(cfg.OutputDir, cfg.OutputMode, sess)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
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
	}
	if shouldRunScanner(cfg, profileDef.Collectors) {
		if err := out.LogEvent(evidence.CollectionEvent{
			Collector: "scanner",
			Event:     "scanner_start",
			Status:    "ok",
			Message:   "scanner phase started",
		}); err != nil {
			return err
		}
		if err := scanners.Run(runCtx, out, scanners.Options{Mode: cfg.Scan, CleanMode: cfg.CleanMode, PayloadRoot: "payload", Timeout: effectiveTimeout}); err != nil {
			_ = out.Error(evidence.ErrorEvent{Collector: "scanner", Error: err.Error(), SourcePath: "scanner", SourceType: "scanner", SourceTrust: "medium"})
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
	if err := out.Finalize(cfg.OutputMode, profileDef.Name, profileDef.Collectors, time.Now().UTC()); err != nil {
		return err
	}
	if shouldArchive(cfg, profileDef.Name) {
		if err := writeArchive(cfg.OutputDir, sess.SessionID); err != nil {
			return err
		}
	}

	fmt.Printf("linux-dfir collector initialized\n")
	fmt.Printf("session=%s profile=%s collectors=%s output_mode=%s output=%s scan=%s clean=%s\n",
		sess.SessionID, profileDef.Name, strings.Join(profileDef.Collectors, ","), cfg.OutputMode, cfg.OutputDir, cfg.Scan, cfg.CleanMode)
	return nil
}

func parseArgs(args []string) (Config, error) {
	cfg := Config{
		CleanMode:  "disabled",
		OutputDir:  filepath.Join("attk_log", "go-dev-session"),
		OutputMode: defaultMode,
		Profile:    defaultProfile,
		ProfileDir: "profiles",
		Scan:       "none",
	}

	fs := flag.NewFlagSet("dfir-collector", flag.ContinueOnError)
	fs.BoolVar(&cfg.Archive, "archive", false, "create finalized tar.gz archive next to output directory")
	fs.StringVar(&cfg.CaseID, "case-id", "", "case identifier")
	fs.StringVar(&cfg.CleanMode, "clean", cfg.CleanMode, "clean mode: disabled, confirm, force")
	fs.BoolVar(&cfg.Encrypt, "encrypt", false, "encrypt output archive")
	fs.BoolVar(&cfg.KeepWork, "keep-workdir", false, "keep working directory")
	fs.StringVar(&cfg.OutputDir, "output", cfg.OutputDir, "output directory")
	fs.StringVar(&cfg.OutputMode, "output-mode", cfg.OutputMode, "output mode: legacy, ai, dual")
	fs.StringVar(&cfg.Profile, "profile", cfg.Profile, "collection profile name under --profile-dir")
	fs.StringVar(&cfg.ProfileDir, "profile-dir", cfg.ProfileDir, "directory containing collection profiles")
	fs.BoolVar(&cfg.Redact, "redact", false, "redact sensitive fields where supported")
	fs.StringVar(&cfg.Scan, "scan", cfg.Scan, "scanner: none, tmbrfix, yara, osquery")
	fs.StringVar(&cfg.Timeout, "timeout", cfg.Timeout, "overall collection timeout")

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func validateConfig(cfg Config) error {
	if cfg.OutputDir == "" {
		return errors.New("output directory is required")
	}

	if !oneOf(cfg.OutputMode, "legacy", "ai", "dual") {
		return fmt.Errorf("unsupported output mode: %s", cfg.OutputMode)
	}
	if !oneOf(cfg.Scan, "none", "tmbrfix", "yara", "osquery") {
		return fmt.Errorf("unsupported scanner: %s", cfg.Scan)
	}
	if !oneOf(cfg.CleanMode, "disabled", "confirm", "force") {
		return fmt.Errorf("unsupported clean mode: %s", cfg.CleanMode)
	}
	if cfg.Timeout != "" {
		if timeout, err := time.ParseDuration(cfg.Timeout); err != nil || timeout <= 0 {
			return fmt.Errorf("unsupported timeout: %s", cfg.Timeout)
		}
	}
	if cfg.Encrypt {
		return errors.New("archive encryption is not implemented yet")
	}
	return nil
}

func shouldArchive(cfg Config, profileName string) bool {
	return cfg.Archive || profileName == "phase12-archive"
}

func shouldRunScanner(cfg Config, collectors []string) bool {
	if strings.ToLower(cfg.Scan) != "none" {
		return true
	}
	for _, collector := range collectors {
		if collector == "scanner" {
			return true
		}
	}
	return false
}

func effectiveTimeout(flagValue, profileValue string) time.Duration {
	value := flagValue
	if value == "" {
		value = profileValue
	}
	timeout, err := time.ParseDuration(value)
	if err != nil || timeout <= 0 {
		return 10 * time.Minute
	}
	return timeout
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
