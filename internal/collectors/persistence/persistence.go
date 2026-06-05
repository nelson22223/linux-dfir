package persistence

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
	"linux-dfir/internal/redact"
)

const (
	collector         = "persistence"
	fileRecordsRel    = "entities/persistence_file.jsonl"
	itemRecordsRel    = "facts/persistence_items.jsonl"
	cronRecordsRel    = "facts/cron_entries.jsonl"
	systemdRecordsRel = "entities/systemd_unit.jsonl"
	pamRecordsRel     = "facts/pam_persistence.jsonl"
)

var filesystemRoot = "/"

type FileRecord struct {
	evidence.RecordMeta
	EntityType      string               `json:"entity_type,omitempty"`
	EntityID        string               `json:"entity_id,omitempty"`
	Exists          bool                 `json:"exists"`
	AbsentReason    string               `json:"absent_reason,omitempty"`
	Category        string               `json:"category"`
	Kind            string               `json:"kind"`
	Path            string               `json:"path"`
	Name            string               `json:"name,omitempty"`
	Mode            string               `json:"mode,omitempty"`
	UID             int                  `json:"uid,omitempty"`
	GID             int                  `json:"gid,omitempty"`
	Size            int64                `json:"size,omitempty"`
	ModTime         *time.Time           `json:"mod_time,omitempty"`
	SHA256          string               `json:"sha256,omitempty"`
	SymlinkTarget   string               `json:"symlink_target,omitempty"`
	ContentSource   string               `json:"content_source,omitempty"`
	LegacyPath      string               `json:"legacy_path,omitempty"`
	ContentCopied   bool                 `json:"content_copied"`
	ContentRedacted bool                 `json:"content_redacted"`
	Sensitive       bool                 `json:"sensitive"`
	Sources         []evidence.SourceRef `json:"sources,omitempty"`
}

type ItemRecord struct {
	evidence.RecordMeta
	EntityType          string               `json:"entity_type,omitempty"`
	EntityID            string               `json:"entity_id,omitempty"`
	Exists              bool                 `json:"exists"`
	AbsentReason        string               `json:"absent_reason,omitempty"`
	Category            string               `json:"category"`
	ItemType            string               `json:"item_type"`
	Path                string               `json:"path,omitempty"`
	LineNumber          int                  `json:"line_number,omitempty"`
	User                string               `json:"user,omitempty"`
	Name                string               `json:"name,omitempty"`
	Schedule            string               `json:"schedule,omitempty"`
	Command             string               `json:"command,omitempty"`
	Commands            []string             `json:"commands,omitempty"`
	Directives          []DirectiveRecord    `json:"directives,omitempty"`
	DirectiveValues     map[string][]string  `json:"directive_values,omitempty"`
	Section             string               `json:"section,omitempty"`
	Unit                string               `json:"unit,omitempty"`
	UnitType            string               `json:"unit_type,omitempty"`
	EnabledHint         string               `json:"enabled_hint,omitempty"`
	Environment         map[string]string    `json:"environment,omitempty"`
	EnvironmentFiles    []string             `json:"environment_files,omitempty"`
	ExecDirectives      map[string][]string  `json:"exec_directives,omitempty"`
	InstallTargets      map[string][]string  `json:"install_targets,omitempty"`
	DependencyTargets   map[string][]string  `json:"dependency_targets,omitempty"`
	TriggerDirectives   map[string][]string  `json:"trigger_directives,omitempty"`
	SymlinkTarget       string               `json:"symlink_target,omitempty"`
	LinkState           string               `json:"link_state,omitempty"`
	LinkedUnit          string               `json:"linked_unit,omitempty"`
	KeyType             string               `json:"key_type,omitempty"`
	KeyFingerprint      string               `json:"key_fingerprint,omitempty"`
	KeyOptions          []string             `json:"key_options,omitempty"`
	KeyOptionCommand    string               `json:"key_option_command,omitempty"`
	KeyOptionFrom       []string             `json:"key_option_from,omitempty"`
	KeyOptionEnv        []string             `json:"key_option_environment,omitempty"`
	KeyOptionPermitOpen []string             `json:"key_option_permitopen,omitempty"`
	KeyOptionNoPTY      bool                 `json:"key_option_no_pty,omitempty"`
	KeyComment          string               `json:"key_comment,omitempty"`
	ConfigKeyword       string               `json:"config_keyword,omitempty"`
	ConfigValues        []string             `json:"config_values,omitempty"`
	ProfileAction       string               `json:"profile_action,omitempty"`
	Variable            string               `json:"variable,omitempty"`
	Value               string               `json:"value,omitempty"`
	AliasName           string               `json:"alias_name,omitempty"`
	TargetPath          string               `json:"target_path,omitempty"`
	TargetPaths         []string             `json:"target_paths,omitempty"`
	TargetExists        *bool                `json:"target_exists,omitempty"`
	TargetMode          string               `json:"target_mode,omitempty"`
	TargetUID           int                  `json:"target_uid,omitempty"`
	TargetGID           int                  `json:"target_gid,omitempty"`
	TargetSize          int64                `json:"target_size,omitempty"`
	TargetSHA256        string               `json:"target_sha256,omitempty"`
	Subject             string               `json:"subject,omitempty"`
	Hosts               []string             `json:"hosts,omitempty"`
	RunAs               string               `json:"run_as,omitempty"`
	SudoTags            []string             `json:"sudo_tags,omitempty"`
	SudoCommands        []string             `json:"sudo_commands,omitempty"`
	IncludedPath        string               `json:"included_path,omitempty"`
	SourceFileSHA256    string               `json:"source_file_sha256,omitempty"`
	SourceFileRedacted  bool                 `json:"source_file_redacted,omitempty"`
	Sources             []evidence.SourceRef `json:"sources,omitempty"`
}

type DirectiveRecord struct {
	Name       string `json:"name"`
	Value      string `json:"value"`
	LineNumber int    `json:"line_number,omitempty"`
}

type PAMRecord struct {
	evidence.RecordMeta
	Exists             bool     `json:"exists"`
	AbsentReason       string   `json:"absent_reason,omitempty"`
	SourceFile         string   `json:"source_file,omitempty"`
	LineNumber         int      `json:"line_number,omitempty"`
	Service            string   `json:"service,omitempty"`
	PAMType            string   `json:"pam_type,omitempty"`
	Control            string   `json:"control,omitempty"`
	Module             string   `json:"module,omitempty"`
	ModulePath         string   `json:"module_path,omitempty"`
	ModulePathResolved string   `json:"module_path_resolved,omitempty"`
	ModuleFileExists   bool     `json:"module_file_exists"`
	ModuleFileSHA256   string   `json:"module_file_sha256,omitempty"`
	ModuleFileSize     int64    `json:"module_file_size,omitempty"`
	ModuleFileMode     string   `json:"module_file_mode,omitempty"`
	ModuleFileError    string   `json:"module_file_error,omitempty"`
	ModuleArgs         []string `json:"module_args,omitempty"`
	RawLine            string   `json:"raw_line,omitempty"`
	RedactedLine       string   `json:"redacted_line,omitempty"`
	SourceFileSHA256   string   `json:"source_file_sha256,omitempty"`
	Sensitive          bool     `json:"sensitive"`
}

type userHome struct {
	Name  string
	UID   int
	Home  string
	Shell string
}

type sourceFile struct {
	SourcePath string
	ActualPath string
	Category   string
	Kind       string
	CopyLegacy bool
	Optional   bool
}

func Collect(ctx context.Context, out *output.Manager) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	users := discoverUsers(out)
	if err := scanCron(out); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := scanRcInit(out); err != nil {
		return err
	}
	if err := scanSystemd(out); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := scanSSH(out, users); err != nil {
		return err
	}
	if err := scanProfiles(out, users); err != nil {
		return err
	}
	if err := scanLoader(out); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := scanSudoers(out); err != nil {
		return err
	}
	if err := scanPAM(out); err != nil {
		return err
	}
	if err := scanAt(out); err != nil {
		return err
	}
	if err := scanCronLog(out); err != nil {
		return err
	}
	return scanXDG(out, users)
}

func scanCron(out *output.Manager) error {
	files := []sourceFile{
		file("/etc/crontab", "cron", "crontab", true),
		file("/etc/cron.allow", "cron", "cron_access", true),
		file("/etc/cron.deny", "cron", "cron_access", true),
	}
	for _, src := range files {
		src.Optional = true
		parse := parseCronFile
		if src.Kind == "cron_access" {
			parse = nil
		}
		if err := processTextFile(out, src, parse); err != nil {
			return err
		}
	}
	cronDirs := []string{"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron", "/var/spool/cron/crontabs", "/var/cron/tabs"}
	for _, dir := range cronDirs {
		scan := scanDirectoryOptional
		excludedDirs := []string(nil)
		if dir == "/var/spool/cron" {
			excludedDirs = []string{"/var/spool/cron/crontabs", "/var/spool/cron/atjobs"}
			scan = func(out *output.Manager, sourceDir, category, kind string, copyLegacy bool, parse func(sourceFile, string) []ItemRecord) error {
				return scanDirectoryOptionalSkipping(out, sourceDir, category, kind, copyLegacy, excludedDirs, parse)
			}
		}
		if err := scan(out, dir, "cron", "cron_file", true, func(sf sourceFile, text string) []ItemRecord {
			if strings.Contains(dir, "cron.") && dir != "/etc/cron.d" {
				item := ItemRecord{Exists: true, Category: "cron", ItemType: "cron_periodic_script", Path: sf.SourcePath, Command: sf.SourcePath, TargetPath: sf.SourcePath}
				enrichTargetFileMetadata(&item, sf.SourcePath)
				return []ItemRecord{item}
			}
			userHint := ""
			if strings.Contains(dir, "spool") || dir == "/var/cron/tabs" {
				userHint = filepath.Base(sf.SourcePath)
			}
			return parseCronText(sf.SourcePath, text, dir == "/etc/cron.d", userHint)
		}); err != nil {
			return err
		}
	}
	skip := sourcePathSet(append([]string{"/etc/crontab", "/etc/cron.allow", "/etc/cron.deny"}, cronDirs...)...)
	return scanGlobExtras(out, "/etc/cron*", "cron", "cron_file", true, skip, func(sf sourceFile, text string) []ItemRecord {
		if strings.Contains(filepath.Base(sf.SourcePath), "allow") || strings.Contains(filepath.Base(sf.SourcePath), "deny") {
			return nil
		}
		if isPeriodicCronPath(sf.SourcePath) {
			item := ItemRecord{Exists: true, Category: "cron", ItemType: "cron_periodic_script", Path: sf.SourcePath, Command: sf.SourcePath, TargetPath: sf.SourcePath}
			enrichTargetFileMetadata(&item, sf.SourcePath)
			return []ItemRecord{item}
		}
		return parseCronText(sf.SourcePath, text, strings.HasPrefix(sf.SourcePath, "/etc/cron.d/"), "")
	})
}

func scanRcInit(out *output.Manager) error {
	for _, src := range []sourceFile{
		file("/etc/rc.local", "rc_init", "rc_local", true),
		file("/etc/inittab", "rc_init", "inittab", true),
	} {
		src.Optional = true
		if err := processTextFile(out, src, parseRcText); err != nil {
			return err
		}
	}
	rcDirs := []string{"/etc/init", "/etc/init.d", "/etc/rc0.d", "/etc/rc1.d", "/etc/rc2.d", "/etc/rc3.d", "/etc/rc4.d", "/etc/rc5.d", "/etc/rc6.d"}
	for _, dir := range rcDirs {
		if err := scanDirectoryOptional(out, dir, "rc_init", "init_script", true, func(sf sourceFile, text string) []ItemRecord {
			enabled := "script"
			if strings.HasPrefix(filepath.Base(sf.SourcePath), "S") {
				enabled = "start_symlink"
			} else if strings.HasPrefix(sf.SourcePath, "/etc/init/") {
				enabled = "upstart_conf"
			}
			return []ItemRecord{{Exists: true, Category: "rc_init", ItemType: "init_script", Path: sf.SourcePath, Name: filepath.Base(sf.SourcePath), Command: sf.SourcePath, EnabledHint: enabled}}
		}); err != nil {
			return err
		}
	}
	skip := sourcePathSet(append([]string{"/etc/rc.local"}, rcDirs...)...)
	return scanGlobExtras(out, "/etc/rc*", "rc_init", "rc_file", true, skip, func(sf sourceFile, text string) []ItemRecord {
		return parseRcText(sf.SourcePath, text)
	})
}

func scanSystemd(out *output.Manager) error {
	for _, dir := range []string{"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system", "/run/systemd/system", "/etc/systemd/user", "/lib/systemd/user", "/usr/lib/systemd/user", "/run/systemd/user"} {
		if err := scanDirectoryOptional(out, dir, "systemd", "unit_file", true, func(sf sourceFile, text string) []ItemRecord {
			return parseSystemdUnit(sf.SourcePath, text)
		}); err != nil {
			return err
		}
	}
	for _, user := range discoverUsers(out) {
		dir := filepath.Join(user.Home, ".config/systemd/user")
		if err := scanDirectoryOptional(out, dir, "systemd", "user_unit_file", true, func(sf sourceFile, text string) []ItemRecord {
			items := parseSystemdUnit(sf.SourcePath, text)
			for i := range items {
				items[i].User = user.Name
			}
			return items
		}); err != nil {
			return err
		}
	}
	return nil
}

func scanSSH(out *output.Manager, users []userHome) error {
	if err := scanDirectoryOptional(out, "/etc/ssh", "ssh", "ssh_file", true, func(sf sourceFile, text string) []ItemRecord {
		base := filepath.Base(sf.SourcePath)
		if base == "sshd_config" || base == "ssh_config" {
			return parseSSHConfig(sf.SourcePath, text)
		}
		if isPrivateKeyPath(sf.SourcePath) || looksLikePrivateKey(text) {
			return []ItemRecord{{Exists: true, Category: "ssh", ItemType: "private_key_metadata", Path: sf.SourcePath, Name: filepath.Base(sf.SourcePath), SourceFileRedacted: true}}
		}
		return nil
	}); err != nil {
		return err
	}
	for _, user := range users {
		if user.Home == "" || user.Home == "/" {
			continue
		}
		sshDir := filepath.Join(user.Home, ".ssh")
		if err := scanDirectoryOptional(out, sshDir, "ssh", "user_ssh_file", true, func(sf sourceFile, text string) []ItemRecord {
			base := filepath.Base(sf.SourcePath)
			if base == "authorized_keys" || strings.HasPrefix(base, "authorized_keys") {
				return parseAuthorizedKeys(sf.SourcePath, text, user.Name)
			}
			if isPrivateKeyPath(sf.SourcePath) || looksLikePrivateKey(text) {
				return []ItemRecord{{Exists: true, Category: "ssh", ItemType: "private_key_metadata", Path: sf.SourcePath, User: user.Name, Name: base, SourceFileRedacted: true}}
			}
			if base == "config" {
				return parseSSHConfig(sf.SourcePath, text)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func scanProfiles(out *output.Manager, users []userHome) error {
	for _, src := range []sourceFile{
		file("/etc/profile", "shell_profile", "profile", true),
		file("/etc/bash.bashrc", "shell_profile", "bashrc", true),
		file("/etc/zsh/zshenv", "shell_profile", "zshenv", true),
		file("/etc/zsh/zprofile", "shell_profile", "zprofile", true),
	} {
		src.Optional = true
		if err := processTextFile(out, src, parseProfileText); err != nil {
			return err
		}
	}
	if err := scanDirectoryOptional(out, "/etc/profile.d", "shell_profile", "profile_fragment", true, func(sf sourceFile, text string) []ItemRecord {
		return parseProfileText(sf.SourcePath, text)
	}); err != nil {
		return err
	}
	names := []string{".profile", ".bashrc", ".bash_profile", ".bash_login", ".zshrc", ".zprofile", ".zshenv", ".config/fish/config.fish"}
	for _, user := range users {
		for _, name := range names {
			src := file(filepath.Join(user.Home, name), "shell_profile", "user_profile", true)
			src.Optional = true
			if err := processTextFile(out, src, func(path, text string) []ItemRecord {
				items := parseProfileText(path, text)
				for i := range items {
					items[i].User = user.Name
				}
				return items
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func scanLoader(out *output.Manager) error {
	for _, src := range []sourceFile{
		file("/etc/ld.so.preload", "loader", "ld_so_preload", true),
		file("/etc/ld.so.conf", "loader", "ld_so_conf", true),
	} {
		src.Optional = true
		if err := processTextFile(out, src, parseLoaderText); err != nil {
			return err
		}
	}
	return scanDirectoryOptional(out, "/etc/ld.so.conf.d", "loader", "ld_so_conf_fragment", true, func(sf sourceFile, text string) []ItemRecord {
		return parseLoaderText(sf.SourcePath, text)
	})
}

func scanSudoers(out *output.Manager) error {
	for _, src := range []sourceFile{
		file("/etc/sudoers", "sudoers", "sudoers", true),
	} {
		src.Optional = true
		if err := processTextFile(out, src, parseSudoersText); err != nil {
			return err
		}
	}
	return scanDirectoryOptional(out, "/etc/sudoers.d", "sudoers", "sudoers_fragment", true, func(sf sourceFile, text string) []ItemRecord {
		return parseSudoersText(sf.SourcePath, text)
	})
}

func scanPAM(out *output.Manager) error {
	sourceDir := "/etc/pam.d"
	actualDir := actualPath(sourceDir)
	info, err := os.Lstat(actualDir)
	if err != nil {
		src := sourceFile{SourcePath: sourceDir, ActualPath: actualDir, Category: "pam", Kind: "pam_config", Optional: true}
		if err := writeAbsentFile(out, src, err.Error()); err != nil {
			return err
		}
		return writeAbsentPAM(out, sourceDir, err.Error())
	}
	if !info.IsDir() {
		record, text, err := recordFile(out, sourceFile{SourcePath: sourceDir, ActualPath: actualDir, Category: "pam", Kind: "pam_config", CopyLegacy: true, Optional: true})
		if err != nil {
			return err
		}
		return writePAMRecords(out, sourceDir, parsePAMText(sourceDir, text, record.SHA256))
	}
	return filepath.WalkDir(actualDir, func(path string, d os.DirEntry, walkErr error) error {
		sourcePath := sourcePathFromActual(path)
		if walkErr != nil {
			_ = out.Error(evidence.ErrorEvent{Collector: collector, Error: walkErr.Error(), SourcePath: sourcePath, SourceType: "file", SourceTrust: "high", RawArtifactRef: "ai/" + pamRecordsRel})
			return nil
		}
		if path == actualDir || d.IsDir() {
			_, _, err := recordFile(out, sourceFile{SourcePath: sourcePath, ActualPath: path, Category: "pam", Kind: "directory", CopyLegacy: false, Optional: true})
			return err
		}
		record, text, err := recordFile(out, sourceFile{SourcePath: sourcePath, ActualPath: path, Category: "pam", Kind: "pam_config", CopyLegacy: true, Optional: true})
		if err != nil {
			return err
		}
		return writePAMRecords(out, sourcePath, parsePAMText(sourcePath, text, record.SHA256))
	})
}

func writePAMRecords(out *output.Manager, sourcePath string, records []PAMRecord) error {
	for _, record := range records {
		record.RecordMeta = out.Meta(collector, pamRecordsRel, sourcePath, "file", "high")
		if err := out.AppendAIJSONL(pamRecordsRel, record, collector, sourcePath, "file", "high"); err != nil {
			return err
		}
	}
	return nil
}

func writeAbsentPAM(out *output.Manager, sourcePath, reason string) error {
	record := PAMRecord{
		RecordMeta:   out.Meta(collector, pamRecordsRel, sourcePath, "file", "high"),
		Exists:       false,
		AbsentReason: reason,
		SourceFile:   sourcePath,
	}
	return out.AppendAIJSONL(pamRecordsRel, record, collector, sourcePath, "file", "high")
}

func scanAt(out *output.Manager) error {
	for _, src := range []sourceFile{
		file("/etc/at.allow", "at", "at_access", true),
		file("/etc/at.deny", "at", "at_access", true),
	} {
		src.Optional = true
		if err := processTextFile(out, src, nil); err != nil {
			return err
		}
	}
	for _, dir := range []string{"/var/spool/at", "/var/spool/atjobs", "/var/spool/cron/atjobs", "/var/at/jobs"} {
		if err := scanDirectoryOptional(out, dir, "at", "at_job", true, func(sf sourceFile, text string) []ItemRecord {
			return []ItemRecord{{Exists: true, Category: "at", ItemType: "at_job", Path: sf.SourcePath, Name: filepath.Base(sf.SourcePath), Command: firstInterestingLine(text)}}
		}); err != nil {
			return err
		}
	}
	return nil
}

func scanCronLog(out *output.Manager) error {
	src := file("/var/log/cron", "cron_log", "cron_log", true)
	src.Optional = true
	return processTextFile(out, src, nil)
}

func scanXDG(out *output.Manager, users []userHome) error {
	if err := scanDirectoryOptional(out, "/etc/xdg/autostart", "xdg_autostart", "desktop_file", true, func(sf sourceFile, text string) []ItemRecord {
		return parseDesktopFile(sf.SourcePath, text, "")
	}); err != nil {
		return err
	}
	for _, user := range users {
		dir := filepath.Join(user.Home, ".config/autostart")
		if err := scanDirectoryOptional(out, dir, "xdg_autostart", "desktop_file", true, func(sf sourceFile, text string) []ItemRecord {
			return parseDesktopFile(sf.SourcePath, text, user.Name)
		}); err != nil {
			return err
		}
	}
	return nil
}

func processTextFile(out *output.Manager, src sourceFile, parse func(string, string) []ItemRecord) error {
	record, text, err := recordFile(out, src)
	if err != nil {
		return err
	}
	if !record.Exists {
		return writeAbsentItem(out, src, record.AbsentReason)
	}
	if src.Category == "systemd" && record.SymlinkTarget != "" {
		item := systemdSymlinkItem(record)
		item.SourceFileSHA256 = record.SHA256
		if err := writeItem(out, item, src.SourcePath); err != nil {
			return err
		}
	}
	if parse == nil {
		return nil
	}
	items := parse(src.SourcePath, text)
	for _, item := range items {
		item.SourceFileSHA256 = record.SHA256
		if record.ContentRedacted {
			item.SourceFileRedacted = true
		}
		if err := writeItem(out, item, src.SourcePath); err != nil {
			return err
		}
	}
	return nil
}

func scanDirectory(out *output.Manager, sourceDir, category, kind string, copyLegacy bool, parse func(sourceFile, string) []ItemRecord) error {
	return scanDirectoryEx(out, sourceDir, category, kind, copyLegacy, false, nil, parse)
}

func scanDirectoryOptional(out *output.Manager, sourceDir, category, kind string, copyLegacy bool, parse func(sourceFile, string) []ItemRecord) error {
	return scanDirectoryEx(out, sourceDir, category, kind, copyLegacy, true, nil, parse)
}

func scanDirectoryOptionalSkipping(out *output.Manager, sourceDir, category, kind string, copyLegacy bool, excludedDirs []string, parse func(sourceFile, string) []ItemRecord) error {
	return scanDirectoryEx(out, sourceDir, category, kind, copyLegacy, true, sourcePathSet(excludedDirs...), parse)
}

func scanGlobExtras(out *output.Manager, pattern, category, kind string, copyLegacy bool, skip map[string]bool, parse func(sourceFile, string) []ItemRecord) error {
	matches, err := filepath.Glob(actualPath(pattern))
	if err != nil {
		return err
	}
	sort.Strings(matches)
	for _, actual := range matches {
		sourcePath := sourcePathFromActual(actual)
		if skip[filepath.Clean(sourcePath)] {
			continue
		}
		info, err := os.Lstat(actual)
		if err != nil {
			_ = out.Error(evidence.ErrorEvent{Collector: collector, Error: err.Error(), SourcePath: sourcePath, SourceType: "file", SourceTrust: "high", RawArtifactRef: "ai/" + fileRecordsRel})
			continue
		}
		if info.IsDir() {
			if err := scanDirectoryOptional(out, sourcePath, category, kind, copyLegacy, parse); err != nil {
				return err
			}
			continue
		}
		sf := sourceFile{SourcePath: sourcePath, ActualPath: actual, Category: category, Kind: kind, CopyLegacy: copyLegacy, Optional: true}
		if err := processTextFile(out, sf, func(path, text string) []ItemRecord {
			if parse == nil {
				return nil
			}
			return parse(sf, text)
		}); err != nil {
			return err
		}
	}
	return nil
}

func scanDirectoryEx(out *output.Manager, sourceDir, category, kind string, copyLegacy, optional bool, excludedDirs map[string]bool, parse func(sourceFile, string) []ItemRecord) error {
	actualDir := actualPath(sourceDir)
	info, err := os.Lstat(actualDir)
	if err != nil {
		if !optional {
			_ = out.Error(evidence.ErrorEvent{Collector: collector, Error: err.Error(), SourcePath: sourceDir, SourceType: "file", SourceTrust: "high", RawArtifactRef: "ai/" + fileRecordsRel})
		}
		if err := writeAbsentFile(out, sourceFile{SourcePath: sourceDir, ActualPath: actualDir, Category: category, Kind: kind, CopyLegacy: false, Optional: optional}, err.Error()); err != nil {
			return err
		}
		return writeAbsentItem(out, sourceFile{SourcePath: sourceDir, ActualPath: actualDir, Category: category, Kind: kind, Optional: optional}, err.Error())
	}
	if !info.IsDir() {
		return processTextFile(out, sourceFile{SourcePath: sourceDir, ActualPath: actualDir, Category: category, Kind: kind, CopyLegacy: copyLegacy, Optional: optional}, func(path, text string) []ItemRecord {
			if parse == nil {
				return nil
			}
			return parse(sourceFile{SourcePath: path, ActualPath: actualDir, Category: category, Kind: kind, CopyLegacy: copyLegacy, Optional: optional}, text)
		})
	}
	return filepath.WalkDir(actualDir, func(path string, d os.DirEntry, walkErr error) error {
		sourcePath := sourcePathFromActual(path)
		if walkErr != nil {
			_ = out.Error(evidence.ErrorEvent{Collector: collector, Error: walkErr.Error(), SourcePath: sourcePath, SourceType: "file", SourceTrust: "high", RawArtifactRef: "ai/" + fileRecordsRel})
			return nil
		}
		if path == actualDir {
			_, _, err := recordFile(out, sourceFile{SourcePath: sourcePath, ActualPath: path, Category: category, Kind: "directory", CopyLegacy: false})
			return err
		}
		if d.IsDir() && excludedDirs[filepath.Clean(sourcePath)] {
			return filepath.SkipDir
		}
		if d.IsDir() {
			_, _, err := recordFile(out, sourceFile{SourcePath: sourcePath, ActualPath: path, Category: category, Kind: "directory", CopyLegacy: false})
			return err
		}
		sf := sourceFile{SourcePath: sourcePath, ActualPath: path, Category: category, Kind: kind, CopyLegacy: copyLegacy, Optional: optional}
		return processTextFile(out, sf, func(path, text string) []ItemRecord {
			if parse == nil {
				return nil
			}
			return parse(sf, text)
		})
	})
}

func recordFile(out *output.Manager, src sourceFile) (FileRecord, string, error) {
	if src.ActualPath == "" {
		src.ActualPath = actualPath(src.SourcePath)
	}
	info, err := os.Lstat(src.ActualPath)
	if err != nil {
		if !src.Optional {
			_ = out.Error(evidence.ErrorEvent{Collector: collector, Error: err.Error(), SourcePath: src.SourcePath, SourceType: "file", SourceTrust: "high", RawArtifactRef: "ai/" + fileRecordsRel})
		}
		record := FileRecord{
			RecordMeta:   out.Meta(collector, fileRecordsRel, src.SourcePath, "file", "high"),
			EntityType:   "persistence_file",
			EntityID:     "persistence_file:" + src.SourcePath,
			Exists:       false,
			AbsentReason: err.Error(),
			Category:     src.Category,
			Kind:         src.Kind,
			Path:         src.SourcePath,
			Name:         filepath.Base(src.SourcePath),
			Sources:      []evidence.SourceRef{sourceRef(src.SourcePath, "file", "high", "ai/evidence.jsonl")},
		}
		return record, "", out.AppendAIJSONL(fileRecordsRel, record, collector, src.SourcePath, "file", "high")
	}
	modTime := info.ModTime().UTC()
	record := FileRecord{
		RecordMeta: out.Meta(collector, fileRecordsRel, src.SourcePath, "file", "high"),
		EntityType: "persistence_file",
		EntityID:   "persistence_file:" + src.SourcePath,
		Exists:     true,
		Category:   src.Category,
		Kind:       src.Kind,
		Path:       src.SourcePath,
		Name:       filepath.Base(src.SourcePath),
		Mode:       info.Mode().String(),
		Size:       info.Size(),
		ModTime:    &modTime,
		Sources:    []evidence.SourceRef{sourceRef(src.SourcePath, "file", "high", "ai/evidence.jsonl")},
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		record.UID = int(st.Uid)
		record.GID = int(st.Gid)
	}
	contentInfo := info
	if info.Mode()&os.ModeSymlink != 0 {
		if target, err := os.Readlink(src.ActualPath); err == nil {
			record.SymlinkTarget = target
		}
		if targetInfo, err := os.Stat(src.ActualPath); err == nil {
			contentInfo = targetInfo
			record.ContentSource = "symlink_target"
		}
	} else {
		record.ContentSource = "file"
	}
	text := ""
	if contentInfo.Mode().IsRegular() {
		sensitive := isPrivateKeyPath(src.SourcePath)
		data, readErr := os.ReadFile(src.ActualPath)
		if readErr != nil {
			_ = out.Error(evidence.ErrorEvent{Collector: collector, Error: readErr.Error(), SourcePath: src.SourcePath, SourceType: "file", SourceTrust: "high", RawArtifactRef: "ai/" + fileRecordsRel})
		} else {
			sum := sha256.Sum256(data)
			record.SHA256 = hex.EncodeToString(sum[:])
			text = string(data)
			if looksLikePrivateKey(text) {
				sensitive = true
			}
			record.Sensitive = sensitive
			if src.CopyLegacy && !sensitive {
				legacyRel := legacyRel(src.Category, src.SourcePath)
				if err := out.WriteLegacyFromSource(legacyRel, data, collector, src.SourcePath, "file", "high"); err != nil {
					return record, text, err
				}
				record.LegacyPath = filepath.ToSlash(filepath.Join("legacy", legacyRel))
				record.ContentCopied = true
			}
			if sensitive {
				record.ContentRedacted = true
			}
		}
	}
	if err := out.AppendAIJSONL(fileRecordsRel, record, collector, src.SourcePath, "file", "high"); err != nil {
		return record, text, err
	}
	_ = out.Timeline(evidence.TimelineEvent{
		Collector:      collector,
		EventType:      "file_metadata",
		Timestamp:      modTime,
		SourcePath:     src.SourcePath,
		SourceType:     "file",
		SourceTrust:    "high",
		RawArtifactRef: "ai/" + fileRecordsRel,
		Summary:        src.SourcePath,
	})
	return record, text, nil
}

func writeAbsentFile(out *output.Manager, src sourceFile, reason string) error {
	record := FileRecord{
		RecordMeta:   out.Meta(collector, fileRecordsRel, src.SourcePath, "file", "high"),
		EntityType:   "persistence_file",
		EntityID:     "persistence_file:" + src.SourcePath,
		Exists:       false,
		AbsentReason: reason,
		Category:     src.Category,
		Kind:         src.Kind,
		Path:         src.SourcePath,
		Name:         filepath.Base(src.SourcePath),
		Sources:      []evidence.SourceRef{sourceRef(src.SourcePath, "file", "high", "ai/evidence.jsonl")},
	}
	return out.AppendAIJSONL(fileRecordsRel, record, collector, src.SourcePath, "file", "high")
}

func writeAbsentItem(out *output.Manager, src sourceFile, reason string) error {
	return writeItem(out, ItemRecord{
		Exists:       false,
		AbsentReason: reason,
		Category:     src.Category,
		ItemType:     src.Kind,
		Path:         src.SourcePath,
	}, src.SourcePath)
}

func writeItem(out *output.Manager, item ItemRecord, sourcePath string) error {
	if item.Category == "" {
		item.Category = "persistence"
	}
	if item.ItemType == "" {
		item.ItemType = "unknown"
	}
	if len(item.Sources) == 0 {
		item.Sources = []evidence.SourceRef{sourceRef(sourcePath, "file", "high", "ai/evidence.jsonl")}
	}
	item = sanitizeItemRecord(item)
	switch item.Category {
	case "cron":
		item.RecordMeta = out.Meta(collector, cronRecordsRel, sourcePath, "file", "high")
		item.EntityType = "cron_entry"
		item.EntityID = cronEntryID(item)
		if item.SourceFileSHA256 == "" {
			item.SourceFileSHA256 = ""
		}
		return out.AppendAIJSONL(cronRecordsRel, item, collector, sourcePath, "file", "high")
	case "systemd":
		item.RecordMeta = out.Meta(collector, systemdRecordsRel, sourcePath, "file", "high")
		item.EntityType = "systemd_unit"
		item.EntityID = systemdUnitID(item)
		return out.AppendAIJSONL(systemdRecordsRel, item, collector, sourcePath, "file", "high")
	default:
		item.RecordMeta = out.Meta(collector, itemRecordsRel, sourcePath, "file", "high")
		item.EntityType = "persistence_item"
		item.EntityID = persistenceItemID(item)
		return out.AppendAIJSONL(itemRecordsRel, item, collector, sourcePath, "file", "high")
	}
}

func sanitizeItemRecord(item ItemRecord) ItemRecord {
	item.Command = redact.Text(item.Command)
	item.Commands = redact.Texts(item.Commands)
	for i := range item.Directives {
		item.Directives[i].Value = redact.Value(item.Directives[i].Name, item.Directives[i].Value)
	}
	item.DirectiveValues = redact.MapValues(item.DirectiveValues)
	item.EnabledHint = redact.Text(item.EnabledHint)
	item.Environment = redact.StringMapValues(item.Environment)
	item.ExecDirectives = redact.MapValues(item.ExecDirectives)
	item.InstallTargets = redact.MapValues(item.InstallTargets)
	item.DependencyTargets = redact.MapValues(item.DependencyTargets)
	item.TriggerDirectives = redact.MapValues(item.TriggerDirectives)
	item.KeyOptions = redact.Texts(item.KeyOptions)
	item.KeyOptionCommand = redact.Text(item.KeyOptionCommand)
	item.KeyOptionEnv = redact.Texts(item.KeyOptionEnv)
	if redact.SensitiveKey(item.ConfigKeyword) {
		item.ConfigValues = redact.Values(item.ConfigKeyword, item.ConfigValues)
	} else {
		item.ConfigValues = redact.Args(item.ConfigValues)
	}
	if item.Variable != "" {
		item.Value = redact.Value(item.Variable, item.Value)
	} else {
		item.Value = redact.Text(item.Value)
	}
	item.SudoCommands = redact.Texts(item.SudoCommands)
	return item
}

func parseCronFile(path, text string) []ItemRecord {
	return parseCronText(path, text, true, "")
}

func isPeriodicCronPath(path string) bool {
	for _, dir := range []string{"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"} {
		if path == dir || strings.HasPrefix(path, dir+"/") {
			return true
		}
	}
	return false
}

func parseCronText(path, text string, systemCron bool, userHint string) []ItemRecord {
	var records []ItemRecord
	scanner := bufio.NewScanner(strings.NewReader(text))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.Contains(line, "=") && !strings.Contains(line, " ") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		rec := ItemRecord{Exists: true, Category: "cron", ItemType: "cron_entry", Path: path, LineNumber: lineNo, User: userHint}
		if strings.HasPrefix(parts[0], "@") {
			rec.Schedule = parts[0]
			start := 1
			if systemCron && len(parts) > 2 {
				rec.User = parts[1]
				start = 2
			}
			rec.Command = strings.Join(parts[start:], " ")
		} else if len(parts) >= 6 {
			rec.Schedule = strings.Join(parts[0:5], " ")
			start := 5
			if systemCron && len(parts) >= 7 {
				rec.User = parts[5]
				start = 6
			}
			rec.Command = strings.Join(parts[start:], " ")
		}
		if rec.Command != "" || rec.Schedule != "" {
			enrichCronCommandTarget(&rec)
			records = append(records, rec)
		}
	}
	return records
}

func enrichCronCommandTarget(item *ItemRecord) {
	primary, paths := cronCommandTargets(item.Command)
	if primary == "" {
		return
	}
	item.TargetPath = primary
	item.TargetPaths = paths
	enrichTargetFileMetadata(item, primary)
}

func cronCommandTargets(command string) (string, []string) {
	var paths []string
	for _, field := range shellFields(command) {
		field = strings.TrimSpace(field)
		if field == "" || strings.ContainsAny(field, "*?[") {
			continue
		}
		field = strings.Trim(field, `"'`)
		if !strings.HasPrefix(field, "/") {
			continue
		}
		if strings.ContainsAny(field, "|&;<>(){}") {
			continue
		}
		paths = append(paths, field)
	}
	paths = uniqueStrings(paths)
	if len(paths) == 0 {
		return "", nil
	}
	return paths[0], paths
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func parseRcText(path, text string) []ItemRecord {
	return interestingLineItems("rc_init", "rc_command", path, text)
}

func parseProfileText(path, text string) []ItemRecord {
	var records []ItemRecord
	for _, line := range effectiveLines(text) {
		rec := ItemRecord{
			Exists:     true,
			Category:   "shell_profile",
			ItemType:   "profile_command",
			Path:       path,
			LineNumber: line.number,
			Command:    line.text,
		}
		lower := strings.ToLower(line.text)
		if name, value, ok := parseShellAssignment(line.text); ok {
			rec.ItemType = "profile_export"
			rec.ProfileAction = "set_variable"
			rec.Variable = name
			rec.Value = value
			if isLoaderEnvVar(name) {
				rec.ItemType = "loader_environment"
				rec.Category = "loader"
				rec.TargetPaths = splitPathList(value)
			}
		} else if name, value, ok := parseShellAlias(line.text); ok {
			rec.ItemType = "profile_alias"
			rec.ProfileAction = "alias"
			rec.AliasName = name
			rec.Value = value
		} else if target, ok := parseShellSource(line.text); ok {
			rec.ItemType = "profile_source"
			rec.ProfileAction = "source"
			rec.TargetPath = target
		} else if isExecLikeShellLine(lower) {
			rec.ItemType = "profile_exec"
			rec.ProfileAction = "exec"
		}
		records = append(records, rec)
	}
	return records
}

func parseSudoersText(path, text string) []ItemRecord {
	var records []ItemRecord
	for _, line := range effectiveSudoersLines(text) {
		rec := parseSudoersLine(path, line.number, line.text)
		if rec.Exists {
			records = append(records, rec)
		}
	}
	return records
}

func parsePAMText(path, text, sourceSHA256 string) []PAMRecord {
	var records []PAMRecord
	for _, line := range effectiveLines(text) {
		record, ok := parsePAMLine(path, line.number, line.text, sourceSHA256)
		if ok {
			records = append(records, record)
		}
	}
	return records
}

func parsePAMLine(path string, lineNumber int, text, sourceSHA256 string) (PAMRecord, bool) {
	fields := strings.Fields(text)
	if len(fields) < 3 {
		return PAMRecord{}, false
	}
	pamType := strings.TrimPrefix(fields[0], "-")
	if strings.HasPrefix(pamType, "@") {
		return PAMRecord{}, false
	}
	controlStart := 1
	controlEnd := 1
	if strings.HasPrefix(fields[controlStart], "[") {
		for controlEnd < len(fields) && !strings.HasSuffix(fields[controlEnd], "]") {
			controlEnd++
		}
	}
	if controlEnd >= len(fields)-1 {
		return PAMRecord{}, false
	}
	control := strings.Join(fields[controlStart:controlEnd+1], " ")
	moduleIndex := controlEnd + 1
	module := fields[moduleIndex]
	args := redact.Args(fields[moduleIndex+1:])
	record := PAMRecord{
		Exists:           true,
		SourceFile:       path,
		LineNumber:       lineNumber,
		Service:          filepath.Base(path),
		PAMType:          pamType,
		Control:          control,
		Module:           module,
		ModulePath:       module,
		ModuleArgs:       args,
		RedactedLine:     redact.Text(text),
		SourceFileSHA256: sourceSHA256,
		Sensitive:        true,
	}
	resolvePAMModule(&record)
	return record, true
}

func resolvePAMModule(record *PAMRecord) {
	candidates := pamModuleCandidates(record.Module)
	for _, candidate := range candidates {
		actual := actualPath(candidate)
		info, err := os.Lstat(actual)
		if err != nil {
			continue
		}
		record.ModulePathResolved = candidate
		record.ModuleFileExists = true
		record.ModuleFileSize = info.Size()
		record.ModuleFileMode = info.Mode().String()
		if info.Mode().IsRegular() {
			if data, err := os.ReadFile(actual); err == nil {
				sum := sha256.Sum256(data)
				record.ModuleFileSHA256 = hex.EncodeToString(sum[:])
			} else {
				record.ModuleFileError = err.Error()
			}
		}
		return
	}
	if filepath.IsAbs(record.Module) {
		record.ModuleFileError = "module file not found"
		return
	}
	if len(candidates) > 0 {
		record.ModuleFileError = "module file not found in pam module directories"
	}
}

func pamModuleCandidates(module string) []string {
	if module == "" {
		return nil
	}
	if filepath.IsAbs(module) {
		return []string{filepath.Clean(module)}
	}
	var dirs []string
	for _, dir := range []string{"/lib/security", "/lib64/security", "/usr/lib/security", "/usr/lib64/security"} {
		dirs = append(dirs, dir)
	}
	for _, actual := range pamGlobActual("/usr/lib/*/security") {
		source := sourcePathFromActual(actual)
		if source != "" {
			dirs = append(dirs, source)
		}
	}
	seen := map[string]bool{}
	var candidates []string
	for _, dir := range dirs {
		candidate := filepath.Clean(filepath.Join(dir, module))
		if !seen[candidate] {
			seen[candidate] = true
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

func pamGlobActual(pattern string) []string {
	matches, err := filepath.Glob(actualPath(pattern))
	if err != nil {
		return nil
	}
	sort.Strings(matches)
	return matches
}

func parseSSHConfig(path, text string) []ItemRecord {
	var records []ItemRecord
	for _, line := range effectiveLines(text) {
		keyword, values := parseConfigDirective(line.text)
		if keyword == "" {
			continue
		}
		records = append(records, ItemRecord{
			Exists:        true,
			Category:      "ssh",
			ItemType:      "ssh_config_directive",
			Path:          path,
			LineNumber:    line.number,
			Command:       line.text,
			Name:          keyword,
			ConfigKeyword: keyword,
			ConfigValues:  values,
		})
	}
	return records
}

func interestingLineItems(category, itemType, path, text string) []ItemRecord {
	var records []ItemRecord
	scanner := bufio.NewScanner(strings.NewReader(text))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		records = append(records, ItemRecord{Exists: true, Category: category, ItemType: itemType, Path: path, LineNumber: lineNo, Command: line})
	}
	return records
}

type effectiveLine struct {
	number int
	text   string
}

func effectiveLines(text string) []effectiveLine {
	var lines []effectiveLine
	scanner := bufio.NewScanner(strings.NewReader(text))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, effectiveLine{number: lineNo, text: line})
	}
	return lines
}

func effectiveSudoersLines(text string) []effectiveLine {
	var lines []effectiveLine
	scanner := bufio.NewScanner(strings.NewReader(text))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#include") || strings.HasPrefix(line, "@include") {
			lines = append(lines, effectiveLine{number: lineNo, text: line})
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, effectiveLine{number: lineNo, text: stripInlineComment(line)})
	}
	return lines
}

func parseLoaderText(path, text string) []ItemRecord {
	var records []ItemRecord
	for _, line := range effectiveLines(text) {
		fields := strings.Fields(line.text)
		if len(fields) == 0 {
			continue
		}
		if strings.EqualFold(fields[0], "include") && len(fields) > 1 {
			rec := ItemRecord{Exists: true, Category: "loader", ItemType: "ld_so_conf_include", Path: path, LineNumber: line.number, Command: line.text, TargetPath: fields[1], TargetPaths: fields[1:]}
			records = append(records, rec)
			continue
		}
		for _, target := range fields {
			rec := ItemRecord{Exists: true, Category: "loader", ItemType: loaderItemType(path), Path: path, LineNumber: line.number, Command: line.text, TargetPath: target}
			enrichTargetFileMetadata(&rec, target)
			records = append(records, rec)
		}
	}
	return records
}

func loaderItemType(path string) string {
	if filepath.Base(path) == "ld.so.preload" {
		return "ld_so_preload_entry"
	}
	return "ld_so_conf_path"
}

func parseSudoersLine(path string, lineNo int, line string) ItemRecord {
	rec := ItemRecord{Exists: true, Category: "sudoers", ItemType: "sudo_rule", Path: path, LineNumber: lineNo, Command: line}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ItemRecord{}
	}
	if isSudoInclude(fields[0]) {
		rec.ItemType = "sudo_include"
		if len(fields) > 1 {
			rec.IncludedPath = fields[1]
			rec.TargetPath = fields[1]
		}
		return rec
	}
	if strings.Contains(fields[0], "_Alias") && strings.Contains(line, "=") {
		rec.ItemType = "sudo_alias"
		rec.Name = fields[0]
		return rec
	}
	rec.Subject = fields[0]
	rest := strings.TrimSpace(strings.TrimPrefix(line, fields[0]))
	hostPart, afterHost, _ := strings.Cut(rest, "=")
	rec.Hosts = splitCommaFields(strings.TrimSpace(hostPart))
	afterHost = strings.TrimSpace(afterHost)
	if strings.HasPrefix(afterHost, "(") {
		if end := strings.Index(afterHost, ")"); end >= 0 {
			rec.RunAs = strings.TrimSpace(afterHost[:end+1])
			afterHost = strings.TrimSpace(afterHost[end+1:])
		}
	}
	tagsPart := ""
	commandsPart := afterHost
	if idx := strings.Index(afterHost, ":"); idx >= 0 {
		tagsPart = strings.TrimSpace(afterHost[:idx])
		commandsPart = strings.TrimSpace(afterHost[idx+1:])
	}
	if tagsPart != "" {
		rec.SudoTags = splitSudoTags(tagsPart)
	}
	rec.SudoCommands = splitCommaRespectingQuotes(commandsPart)
	if len(rec.SudoCommands) == 1 {
		rec.Value = rec.SudoCommands[0]
	}
	return rec
}

func isSudoInclude(word string) bool {
	return word == "#include" || word == "#includedir" || word == "@include" || word == "@includedir"
}

func splitSudoTags(text string) []string {
	var tags []string
	for _, field := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		field = strings.TrimSpace(strings.TrimSuffix(field, ":"))
		if field != "" {
			tags = append(tags, field)
		}
	}
	return tags
}

func parseConfigDirective(line string) (string, []string) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", nil
	}
	return parts[0], parts[1:]
}

func parseShellAssignment(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "export ")
	line = strings.TrimPrefix(line, "setenv ")
	idx := strings.Index(line, "=")
	if idx <= 0 {
		return "", "", false
	}
	name := strings.TrimSpace(line[:idx])
	if !isShellName(name) {
		return "", "", false
	}
	value := strings.TrimSpace(line[idx+1:])
	value = strings.Trim(value, `"'`)
	return name, value, true
}

func parseShellAlias(line string) (string, string, bool) {
	if !strings.HasPrefix(strings.TrimSpace(line), "alias ") {
		return "", "", false
	}
	body := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "alias "))
	name, value, ok := strings.Cut(body, "=")
	if !ok || strings.TrimSpace(name) == "" {
		return "", "", false
	}
	return strings.TrimSpace(name), strings.Trim(strings.TrimSpace(value), `"'`), true
}

func parseShellSource(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", false
	}
	if fields[0] == "source" || fields[0] == "." {
		return strings.Trim(fields[1], `"'`), true
	}
	return "", false
}

func isExecLikeShellLine(lower string) bool {
	for _, marker := range []string{"exec ", "bash ", "sh ", "zsh ", "python ", "perl ", "ruby ", "curl ", "wget ", "nc ", "ncat ", "socat "} {
		if strings.HasPrefix(lower, marker) || strings.Contains(lower, "; "+marker) || strings.Contains(lower, "&& "+marker) || strings.Contains(lower, "| "+marker) {
			return true
		}
	}
	return false
}

func isShellName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		if r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

func isLoaderEnvVar(name string) bool {
	switch name {
	case "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PATH":
		return true
	default:
		return false
	}
}

func splitPathList(value string) []string {
	var paths []string
	for _, part := range strings.Split(value, ":") {
		part = strings.TrimSpace(part)
		if part != "" {
			paths = append(paths, part)
		}
	}
	return paths
}

func parseSystemdUnit(path, text string) []ItemRecord {
	ext := filepath.Ext(path)
	if isSystemdDropInPath(path) {
		record := systemdBaseRecord(path, "dropin", "dropin")
		fillSystemdDirectives(&record, text)
		return []ItemRecord{record}
	}
	if ext == "" || !strings.Contains(".service.timer.socket.path.mount.automount.target", ext) {
		return nil
	}
	record := systemdBaseRecord(path, strings.TrimPrefix(ext, "."), strings.TrimPrefix(ext, ".")+"_unit")
	fillSystemdDirectives(&record, text)
	return []ItemRecord{record}
}

func systemdBaseRecord(path, unitType, itemType string) ItemRecord {
	unit := filepath.Base(path)
	if strings.HasSuffix(unit, ".d") {
		unit = strings.TrimSuffix(unit, ".d")
	} else if strings.HasSuffix(filepath.Base(filepath.Dir(path)), ".d") {
		unit = strings.TrimSuffix(filepath.Base(filepath.Dir(path)), ".d")
	}
	return ItemRecord{
		Exists:     true,
		Category:   "systemd",
		ItemType:   itemType,
		Path:       path,
		Unit:       unit,
		UnitType:   unitType,
		LineNumber: 0,
	}
}

func fillSystemdDirectives(record *ItemRecord, text string) {
	record.DirectiveValues = map[string][]string{}
	record.ExecDirectives = map[string][]string{}
	record.InstallTargets = map[string][]string{}
	record.DependencyTargets = map[string][]string{}
	record.TriggerDirectives = map[string][]string{}
	record.Environment = map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(text))
	lineNo := 0
	section := ""
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if name == "" {
			continue
		}
		if record.Section == "" && section != "" {
			record.Section = section
		}
		record.Directives = append(record.Directives, DirectiveRecord{Name: name, Value: value, LineNumber: lineNo})
		appendMapValue(record.DirectiveValues, name, value)
		lowerName := strings.ToLower(name)
		switch lowerName {
		case "execstart", "execstartpre", "execstartpost", "execreload", "execstop", "execcondition":
			appendMapValue(record.ExecDirectives, name, value)
			record.Commands = append(record.Commands, value)
			if record.Command == "" {
				record.Command = value
				record.LineNumber = lineNo
			}
		case "environment":
			for key, envValue := range parseEnvironmentAssignments(value) {
				record.Environment[key] = envValue
			}
		case "environmentfile":
			record.EnvironmentFiles = append(record.EnvironmentFiles, strings.Fields(value)...)
		case "wantedby", "requiredby":
			appendMapValue(record.InstallTargets, name, value)
			if record.EnabledHint == "" {
				record.EnabledHint = name + "=" + value
			}
		case "wants", "requires", "before", "after":
			appendMapValue(record.DependencyTargets, name, value)
		case "oncalendar", "onbootsec", "onunitactivesec", "onunitinactivesec", "pathchanged", "pathmodified", "listenstream", "listendatagram", "listenfifo":
			appendMapValue(record.TriggerDirectives, name, value)
			record.Commands = append(record.Commands, value)
			if record.Command == "" {
				record.Command = value
				record.LineNumber = lineNo
			}
		case "user":
			record.User = value
		}
	}
	if len(record.DirectiveValues) == 0 {
		record.DirectiveValues = nil
	}
	if len(record.ExecDirectives) == 0 {
		record.ExecDirectives = nil
	}
	if len(record.InstallTargets) == 0 {
		record.InstallTargets = nil
	}
	if len(record.DependencyTargets) == 0 {
		record.DependencyTargets = nil
	}
	if len(record.TriggerDirectives) == 0 {
		record.TriggerDirectives = nil
	}
	if len(record.Environment) == 0 {
		record.Environment = nil
	}
}

func systemdSymlinkItem(record FileRecord) ItemRecord {
	item := ItemRecord{
		Exists:        true,
		Category:      "systemd",
		ItemType:      "unit_symlink",
		Path:          record.Path,
		Name:          record.Name,
		Unit:          filepath.Base(record.Path),
		SymlinkTarget: record.SymlinkTarget,
		LinkedUnit:    filepath.Base(record.SymlinkTarget),
	}
	if strings.HasSuffix(record.Path, ".wants/"+record.Name) || strings.Contains(record.Path, ".wants/") {
		item.LinkState = "enabled_wants"
	} else if strings.HasSuffix(record.Path, ".requires/"+record.Name) || strings.Contains(record.Path, ".requires/") {
		item.LinkState = "enabled_requires"
	} else if record.SymlinkTarget == "/dev/null" {
		item.LinkState = "masked"
	} else {
		item.LinkState = "symlink"
	}
	item.EnabledHint = item.LinkState
	return item
}

func isSystemdDropInPath(path string) bool {
	dir := filepath.Base(filepath.Dir(path))
	return strings.HasSuffix(dir, ".d") && strings.HasSuffix(path, ".conf")
}

func appendMapValue(values map[string][]string, name, value string) {
	if values == nil {
		return
	}
	values[name] = append(values[name], value)
}

func parseEnvironmentAssignments(value string) map[string]string {
	result := map[string]string{}
	for _, field := range shellFields(value) {
		name, envValue, ok := strings.Cut(field, "=")
		if !ok || name == "" {
			continue
		}
		result[name] = strings.Trim(envValue, `"'`)
	}
	return result
}

func parseAuthorizedKeys(path, text, user string) []ItemRecord {
	var records []ItemRecord
	scanner := bufio.NewScanner(strings.NewReader(text))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keyType, blob, opts, comment := splitAuthorizedKey(line)
		if keyType == "" || blob == "" {
			continue
		}
		optionFields := parseAuthorizedKeyOptions(opts)
		records = append(records, ItemRecord{
			Exists:              true,
			Category:            "ssh",
			ItemType:            "authorized_key",
			Path:                path,
			LineNumber:          lineNo,
			User:                user,
			KeyType:             keyType,
			KeyFingerprint:      publicKeyFingerprint(blob),
			KeyOptions:          opts,
			KeyOptionCommand:    optionFields.command,
			KeyOptionFrom:       optionFields.from,
			KeyOptionEnv:        optionFields.environment,
			KeyOptionPermitOpen: optionFields.permitOpen,
			KeyOptionNoPTY:      optionFields.noPTY,
			KeyComment:          comment,
		})
	}
	return records
}

func parseDesktopFile(path, text, user string) []ItemRecord {
	fields := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(text))
	lineNo := 0
	execLine := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		fields[strings.ToLower(parts[0])] = parts[1]
		if strings.EqualFold(parts[0], "Exec") {
			execLine = lineNo
		}
	}
	if fields["exec"] == "" {
		return nil
	}
	return []ItemRecord{{Exists: true, Category: "xdg_autostart", ItemType: "desktop_autostart", Path: path, LineNumber: execLine, User: user, Name: fields["name"], Command: fields["exec"], EnabledHint: hiddenDisabled(fields)}}
}

func discoverUsers(out *output.Manager) []userHome {
	path := "/etc/passwd"
	data, err := os.ReadFile(actualPath(path))
	if err != nil {
		return nil
	}
	var users []userHome
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(parts[2])
		if parts[5] == "" || parts[5] == "/" {
			continue
		}
		home := parts[5]
		shell := parts[6]
		if uid != 0 && uid < 500 {
			continue
		}
		if uid != 0 && (strings.Contains(shell, "nologin") || strings.HasSuffix(shell, "/false")) {
			continue
		}
		if uid != 0 && !strings.HasPrefix(home, "/home/") && !strings.HasPrefix(home, "/Users/") {
			continue
		}
		users = append(users, userHome{Name: parts[0], UID: uid, Home: home, Shell: shell})
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })
	return users
}

func file(path, category, kind string, copyLegacy bool) sourceFile {
	return sourceFile{SourcePath: filepath.Clean(path), ActualPath: actualPath(path), Category: category, Kind: kind, CopyLegacy: copyLegacy}
}

func actualPath(sourcePath string) string {
	if filesystemRoot == "" || filesystemRoot == "/" {
		return sourcePath
	}
	clean := filepath.Clean(sourcePath)
	return filepath.Join(filesystemRoot, strings.TrimPrefix(clean, string(filepath.Separator)))
}

func sourcePathFromActual(actual string) string {
	if filesystemRoot == "" || filesystemRoot == "/" {
		return actual
	}
	rel, err := filepath.Rel(filesystemRoot, actual)
	if err != nil {
		return actual
	}
	return filepath.Clean("/" + filepath.ToSlash(rel))
}

func legacyRel(category, sourcePath string) string {
	_ = category
	clean := strings.TrimPrefix(filepath.Clean(sourcePath), string(filepath.Separator))
	return filepath.ToSlash(filepath.Join("autorun", clean))
}

func splitAuthorizedKey(line string) (string, string, []string, string) {
	parts := strings.Fields(line)
	for i, part := range parts {
		if isPublicKeyType(part) && i+1 < len(parts) {
			comment := ""
			if i+2 < len(parts) {
				comment = strings.Join(parts[i+2:], " ")
			}
			var opts []string
			if i > 0 {
				opts = splitCommaRespectingQuotes(strings.Join(parts[:i], " "))
			}
			return part, parts[i+1], opts, comment
		}
	}
	return "", "", nil, ""
}

type authorizedKeyOptionFields struct {
	command     string
	from        []string
	environment []string
	permitOpen  []string
	noPTY       bool
}

func parseAuthorizedKeyOptions(options []string) authorizedKeyOptionFields {
	var fields authorizedKeyOptionFields
	for _, option := range options {
		name, value, hasValue := strings.Cut(strings.TrimSpace(option), "=")
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch name {
		case "command":
			if hasValue {
				fields.command = value
			}
		case "from":
			if hasValue {
				fields.from = splitCommaFields(value)
			}
		case "environment":
			if hasValue {
				fields.environment = append(fields.environment, value)
			}
		case "permitopen":
			if hasValue {
				fields.permitOpen = append(fields.permitOpen, value)
			}
		case "no-pty":
			fields.noPTY = true
		}
	}
	return fields
}

func publicKeyFingerprint(blob string) string {
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func isPublicKeyType(s string) bool {
	return s == "ssh-rsa" || s == "ssh-ed25519" || strings.HasPrefix(s, "ecdsa-sha2-") || strings.HasPrefix(s, "sk-")
}

func isPrivateKeyPath(path string) bool {
	base := filepath.Base(path)
	if strings.HasSuffix(base, ".pub") || base == "authorized_keys" || base == "known_hosts" || base == "config" {
		return false
	}
	return base == "id_rsa" || base == "id_dsa" || base == "id_ecdsa" || base == "id_ed25519" || strings.HasPrefix(base, "ssh_host_") && strings.HasSuffix(base, "_key")
}

func looksLikePrivateKey(text string) bool {
	return strings.Contains(text, "-----BEGIN OPENSSH PRIVATE KEY-----") ||
		strings.Contains(text, "-----BEGIN RSA PRIVATE KEY-----") ||
		strings.Contains(text, "-----BEGIN DSA PRIVATE KEY-----") ||
		strings.Contains(text, "-----BEGIN EC PRIVATE KEY-----") ||
		strings.Contains(text, "-----BEGIN PRIVATE KEY-----")
}

func hiddenDisabled(fields map[string]string) string {
	if strings.EqualFold(fields["hidden"], "true") || strings.EqualFold(fields["x-gnome-autostart-enabled"], "false") {
		return "disabled"
	}
	return "enabled"
}

func firstInterestingLine(text string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			return line
		}
	}
	return ""
}

func firstWord(text string) string {
	parts := strings.Fields(text)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func shellFields(text string) []string {
	var fields []string
	var b strings.Builder
	inQuote := rune(0)
	escaped := false
	for _, r := range text {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if inQuote != 0 {
			if r == inQuote {
				inQuote = 0
			} else {
				b.WriteRune(r)
			}
			continue
		}
		if r == '\'' || r == '"' {
			inQuote = r
			continue
		}
		if r == ' ' || r == '\t' {
			if b.Len() > 0 {
				fields = append(fields, b.String())
				b.Reset()
			}
			continue
		}
		b.WriteRune(r)
	}
	if b.Len() > 0 {
		fields = append(fields, b.String())
	}
	return fields
}

func splitCommaRespectingQuotes(text string) []string {
	var parts []string
	var b strings.Builder
	inQuote := rune(0)
	escaped := false
	for _, r := range text {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			b.WriteRune(r)
			continue
		}
		if inQuote != 0 {
			if r == inQuote {
				inQuote = 0
			}
			b.WriteRune(r)
			continue
		}
		if r == '\'' || r == '"' {
			inQuote = r
			b.WriteRune(r)
			continue
		}
		if r == ',' {
			part := strings.TrimSpace(b.String())
			if part != "" {
				parts = append(parts, part)
			}
			b.Reset()
			continue
		}
		b.WriteRune(r)
	}
	part := strings.TrimSpace(b.String())
	if part != "" {
		parts = append(parts, part)
	}
	return parts
}

func splitCommaFields(text string) []string {
	var values []string
	for _, value := range strings.Split(text, ",") {
		value = strings.TrimSpace(strings.Trim(value, `"'`))
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}

func stripInlineComment(line string) string {
	inQuote := rune(0)
	escaped := false
	for i, r := range line {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if inQuote != 0 {
			if r == inQuote {
				inQuote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			inQuote = r
			continue
		}
		if r == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			return strings.TrimSpace(line[:i])
		}
	}
	return strings.TrimSpace(line)
}

func enrichTargetFileMetadata(item *ItemRecord, sourcePath string) {
	if sourcePath == "" || strings.ContainsAny(sourcePath, "*?[") {
		return
	}
	item.TargetExists = boolPtr(false)
	actual := actualPath(sourcePath)
	info, err := os.Lstat(actual)
	if err != nil {
		return
	}
	item.TargetExists = boolPtr(true)
	item.TargetMode = info.Mode().String()
	item.TargetSize = info.Size()
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		item.TargetUID = int(st.Uid)
		item.TargetGID = int(st.Gid)
	}
	if info.Mode().IsRegular() {
		data, err := os.ReadFile(actual)
		if err == nil {
			sum := sha256.Sum256(data)
			item.TargetSHA256 = hex.EncodeToString(sum[:])
		}
	}
}

func boolPtr(value bool) *bool {
	return &value
}

func sourceRef(path, sourceType, sourceTrust, rawArtifactRef string) evidence.SourceRef {
	return evidence.SourceRef{
		SourcePath:     path,
		SourceType:     sourceType,
		SourceTrust:    sourceTrust,
		RawArtifactRef: rawArtifactRef,
	}
}

func cronEntryID(item ItemRecord) string {
	return "cron:" + item.Path + ":" + strconv.Itoa(item.LineNumber) + ":" + shortHash(item.Schedule+"\x00"+item.User+"\x00"+item.Command)
}

func systemdUnitID(item ItemRecord) string {
	if item.Path != "" {
		if item.ItemType == "unit_symlink" {
			return "systemd_unit_symlink:" + item.Path
		}
		return "systemd_unit:" + item.Path
	}
	return "systemd_unit:" + item.Unit
}

func persistenceItemID(item ItemRecord) string {
	return "persistence_item:" + item.Category + ":" + item.ItemType + ":" + item.Path + ":" + strconv.Itoa(item.LineNumber) + ":" + shortHash(item.Command)
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:16]
}

func sourcePathSet(paths ...string) map[string]bool {
	result := map[string]bool{}
	for _, path := range paths {
		result[filepath.Clean(path)] = true
	}
	return result
}
