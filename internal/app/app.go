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
	"linux-dfir/internal/collectors/logs"
	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
	"linux-dfir/internal/profile"
	"linux-dfir/internal/scanners"
	"linux-dfir/internal/session"
	"linux-dfir/internal/timeline"
)

const (
	defaultProfile = "deep"
	defaultMode    = string(output.ModeDual)
)

type Config struct {
	CleanMode  string
	OutputDir  string
	Profile    string
	ProfileDir string
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
	cfg.Scan = strings.ToLower(cfg.Scan)
	cfg.CleanMode = strings.ToLower(cfg.CleanMode)

	profileDef, err := profile.Load(cfg.ProfileDir, cfg.Profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	logs.Configure(logs.Options{JournalMaxLines: profileDef.Limits.JournalMaxLines})
	runCtx, cancel, scannerTimeout := optionalTimeoutContext(ctx, cfg.Timeout)
	defer cancel()

	sess, err := session.New("", time.Now().UTC())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	out, err := output.New(cfg.OutputDir, defaultMode, sess)
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

	finalCollectors := append([]string{}, profileDef.Collectors...)
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

	fmt.Printf("linux-dfir collector initialized\n")
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
	fs.StringVar(&cfg.CleanMode, "clean", cfg.CleanMode, "clean mode: disabled, confirm, force")
	fs.StringVar(&cfg.OutputDir, "output", cfg.OutputDir, "output directory")
	fs.StringVar(&cfg.Profile, "profile", cfg.Profile, "collection profile name under --profile-dir")
	fs.StringVar(&cfg.ProfileDir, "profile-dir", cfg.ProfileDir, "directory containing collection profiles")
	fs.StringVar(&cfg.Scan, "scan", cfg.Scan, "scanner: none, tmbrfix, yara, osquery")
	fs.StringVar(&cfg.Timeout, "timeout", cfg.Timeout, "optional overall collection timeout, disabled when omitted")

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func defaultOutputDir(now time.Time) string {
	return "dfir_" + now.Format("20060102150405")
}

func validateConfig(cfg Config) error {
	if cfg.OutputDir == "" {
		return errors.New("output directory is required")
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
