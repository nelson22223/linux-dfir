package files

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
	"linux-dfir/internal/procfs"
)

const (
	collector       = "files"
	filesRel        = "entities/file.jsonl"
	hashesRel       = "facts/file_hashes.jsonl"
	attributesRel   = "facts/file_attributes.jsonl"
	suidFilesRel    = "facts/suid_files.jsonl"
	openFilesRel    = "facts/open_files.jsonl"
	recentFilesRel  = "facts/recent_files.jsonl"
	fileFlagsRel    = "facts/file_flags.jsonl"
	maxHashBytes    = 32 * 1024 * 1024
	maxScanFiles    = 5000
	maxRecentFiles  = 500
	recentWindow    = 14 * 24 * time.Hour
	legacyEnumRel   = "enum/enum_file.out"
	legacyInfoRel   = "enum/file_info.out"
	legacyHashesRel = "enum/file_hashes.out"
)

var (
	filesystemRoot  = "/"
	procRoot        = "/proc"
	hashSizeLimit   = int64(maxHashBytes)
	scanFileLimit   = maxScanFiles
	recentFileLimit = maxRecentFiles
)

type FileRecord struct {
	evidence.RecordMeta
	Exists        bool       `json:"exists"`
	AbsentReason  string     `json:"absent_reason,omitempty"`
	Path          string     `json:"path"`
	Category      string     `json:"category"`
	FileType      string     `json:"file_type,omitempty"`
	Mode          string     `json:"mode,omitempty"`
	UID           int        `json:"uid,omitempty"`
	GID           int        `json:"gid,omitempty"`
	Size          int64      `json:"size,omitempty"`
	ModTime       *time.Time `json:"mtime,omitempty"`
	AccessTime    *time.Time `json:"atime,omitempty"`
	ChangeTime    *time.Time `json:"ctime,omitempty"`
	LinkTarget    string     `json:"link_target,omitempty"`
	ProcessPID    int        `json:"process_pid,omitempty"`
	ProcessFD     string     `json:"process_fd,omitempty"`
	Source        string     `json:"source,omitempty"`
	SUID          bool       `json:"suid,omitempty"`
	SGID          bool       `json:"sgid,omitempty"`
	WorldWritable bool       `json:"world_writable,omitempty"`
}

type HashRecord struct {
	evidence.RecordMeta
	Exists       bool   `json:"exists"`
	AbsentReason string `json:"absent_reason,omitempty"`
	Path         string `json:"path"`
	Size         int64  `json:"size,omitempty"`
	MD5          string `json:"md5,omitempty"`
	SHA1         string `json:"sha1,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	Skipped      bool   `json:"skipped,omitempty"`
	SkipReason   string `json:"skip_reason,omitempty"`
}

type FileAttributeRecord struct {
	evidence.RecordMeta
	Exists                bool                 `json:"exists"`
	AbsentReason          string               `json:"absent_reason,omitempty"`
	Path                  string               `json:"path"`
	Category              string               `json:"category,omitempty"`
	Source                string               `json:"source,omitempty"`
	FileType              string               `json:"file_type,omitempty"`
	Mode                  string               `json:"mode,omitempty"`
	UID                   *int                 `json:"uid,omitempty"`
	GID                   *int                 `json:"gid,omitempty"`
	Size                  *int64               `json:"size,omitempty"`
	MTime                 *time.Time           `json:"mtime,omitempty"`
	CTime                 *time.Time           `json:"ctime,omitempty"`
	BirthTime             *time.Time           `json:"birth_time,omitempty"`
	BirthTimeStatus       string               `json:"birth_time_status,omitempty"`
	SHA256                string               `json:"sha256,omitempty"`
	HashStatus            string               `json:"hash_status,omitempty"`
	XattrCount            *int                 `json:"xattr_count,omitempty"`
	XattrNames            []string             `json:"xattr_names,omitempty"`
	LinuxCapabilityRawHex string               `json:"linux_capability_raw_hex,omitempty"`
	LinuxCapabilitySize   *int                 `json:"linux_capability_size,omitempty"`
	LinuxCapabilitySHA256 string               `json:"linux_capability_sha256,omitempty"`
	FSFlagsHex            string               `json:"fs_flags_hex,omitempty"`
	FSFlagsStatus         string               `json:"fs_flags_status,omitempty"`
	Immutable             *bool                `json:"immutable,omitempty"`
	AppendOnly            *bool                `json:"append_only,omitempty"`
	PackageOwner          string               `json:"package_owner,omitempty"`
	Status                string               `json:"status"`
	Issues                []FileAttributeIssue `json:"issues,omitempty"`
}

type FileAttributeIssue struct {
	Field  string `json:"field"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type FileFlagRecord struct {
	evidence.RecordMeta
	Exists       bool     `json:"exists"`
	AbsentReason string   `json:"absent_reason,omitempty"`
	Path         string   `json:"path"`
	Reasons      []string `json:"reasons,omitempty"`
	Category     string   `json:"category,omitempty"`
	Mode         string   `json:"mode,omitempty"`
	Size         int64    `json:"size,omitempty"`
	ModTime      string   `json:"mtime,omitempty"`
}

type discoveredFile struct {
	DisplayPath string
	ActualPath  string
	Category    string
	Source      string
	ProcessPID  int
	ProcessFD   string
}

type scanStats struct {
	Visited  int
	LimitHit bool
}

func Collect(ctx context.Context, out *output.Manager) error {
	discovered := map[string]discoveredFile{}
	add := func(item discoveredFile) {
		if item.DisplayPath == "" {
			return
		}
		if shouldExcludeCollectorArtifactPath(item.DisplayPath, item.ActualPath, out.Root()) {
			return
		}
		if _, ok := discovered[item.DisplayPath]; !ok {
			discovered[item.DisplayPath] = item
		}
	}
	if err := collectKernelModuleFiles(out, add); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := collectOpenFiles(out, add); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	collectPersistenceFiles(add)
	for _, spec := range scanSpecs() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := scanPath(out, spec.path, spec.category, spec.depth, add); err != nil {
			return err
		}
	}

	records := make([]FileRecord, 0, len(discovered))
	for _, item := range discovered {
		record, err := writeFile(out, item)
		if err != nil {
			return err
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Path < records[j].Path })
	if err := writeRecentRecords(out, records); err != nil {
		return err
	}
	return writeLegacy(out, records)
}

func collectKernelModuleFiles(out *output.Manager, add func(discoveredFile)) error {
	releasePaths := []string{"/proc/sys/kernel/osrelease"}
	release := ""
	for _, path := range releasePaths {
		data, err := os.ReadFile(actualPath(path))
		if err == nil {
			release = strings.TrimSpace(string(data))
			break
		}
	}
	if release == "" {
		return nil
	}
	for _, rel := range []string{"/lib/modules/" + release, "/usr/lib/modules/" + release} {
		if err := scanPath(out, rel, "kernel_module", 4, add); err != nil {
			return err
		}
	}
	return nil
}

func collectOpenFiles(out *output.Manager, add func(discoveredFile)) error {
	pids, err := procfs.ListPIDs(actualProcRoot())
	if err != nil {
		_ = out.Error(evidence.ErrorEvent{Collector: collector, Error: err.Error(), SourcePath: procRoot, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/" + filesRel})
		return writeAbsent(out, "/proc/[pid]/fd", "open_file", err.Error())
	}
	for _, pid := range pids {
		base := filepath.Join(actualProcRoot(), strconv.Itoa(pid))
		for _, linkName := range []string{"exe", "cwd"} {
			linkPath := filepath.Join(base, linkName)
			target, err := os.Readlink(linkPath)
			if err != nil {
				if !os.IsNotExist(err) {
					recordProcReadlinkError(out, linkPath, filesRel, err)
				}
				continue
			}
			if shouldTrackTarget(target) {
				add(discoveredFile{DisplayPath: target, ActualPath: actualPath(target), Category: "open_file", Source: "/proc", ProcessPID: pid, ProcessFD: linkName})
			}
		}
		fdDir := filepath.Join(base, "fd")
		entries, err := os.ReadDir(fdDir)
		if err != nil {
			if !os.IsNotExist(err) {
				_ = out.Error(evidence.ErrorEvent{Collector: collector, Error: err.Error(), SourcePath: displayProcPath(fdDir), SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/" + filesRel})
			}
			continue
		}
		for _, entry := range entries {
			fdPath := filepath.Join(fdDir, entry.Name())
			target, err := os.Readlink(fdPath)
			if err != nil {
				if !os.IsNotExist(err) {
					recordProcReadlinkError(out, fdPath, filesRel, err)
				}
				continue
			}
			if !shouldTrackTarget(target) {
				continue
			}
			add(discoveredFile{DisplayPath: target, ActualPath: actualPath(target), Category: "open_file", Source: "/proc", ProcessPID: pid, ProcessFD: entry.Name()})
		}
	}
	return nil
}

func collectPersistenceFiles(add func(discoveredFile)) {
	for _, path := range []string{"/etc/crontab", "/etc/rc.local", "/etc/inittab", "/etc/ld.so.preload", "/etc/sudoers", "/etc/ssh/sshd_config"} {
		add(discoveredFile{DisplayPath: path, ActualPath: actualPath(path), Category: "autorun_file", Source: "persistence"})
	}
	for _, dir := range []string{"/etc/cron.d", "/etc/init", "/etc/init.d", "/etc/systemd/system", "/etc/systemd/user", "/etc/profile.d", "/etc/sudoers.d", "/etc/xdg/autostart"} {
		_ = scanPath(nil, dir, "autorun_file", 3, add)
	}
}

func scanPath(out *output.Manager, displayRoot, category string, maxDepth int, add func(discoveredFile)) error {
	actualRoot := actualPath(displayRoot)
	info, err := os.Lstat(actualRoot)
	if err != nil {
		if out != nil {
			if !os.IsNotExist(err) {
				_ = out.Error(evidence.ErrorEvent{Collector: collector, Error: err.Error(), SourcePath: displayRoot, SourceType: "file", SourceTrust: "high", RawArtifactRef: "ai/" + filesRel})
			}
			return writeAbsent(out, displayRoot, category, err.Error())
		}
		return nil
	}
	if !info.IsDir() {
		add(discoveredFile{DisplayPath: displayRoot, ActualPath: actualRoot, Category: category, Source: "scan"})
		return nil
	}
	stats := scanStats{}
	err = filepath.WalkDir(actualRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if out != nil {
				_ = out.Error(evidence.ErrorEvent{Collector: collector, Error: walkErr.Error(), SourcePath: displayPath(path), SourceType: "file", SourceTrust: "high", RawArtifactRef: "ai/" + filesRel})
			}
			return nil
		}
		if stats.Visited >= scanFileLimit {
			stats.LimitHit = true
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(actualRoot, path)
		depth := 0
		if rel != "." {
			depth = len(strings.Split(rel, string(filepath.Separator)))
		}
		if depth > maxDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			add(discoveredFile{DisplayPath: displayPath(path), ActualPath: path, Category: category, Source: "scan"})
			stats.Visited++
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			if shouldSkipCollectorArtifactDir(displayPath(path), path, out) {
				return filepath.SkipDir
			}
			return nil
		}
		add(discoveredFile{DisplayPath: displayPath(path), ActualPath: path, Category: category, Source: "scan"})
		stats.Visited++
		return nil
	})
	if out != nil && stats.LimitHit {
		_ = out.Error(evidence.ErrorEvent{Collector: collector, Error: "scan file limit reached", SourcePath: displayRoot, SourceType: "file", SourceTrust: "high", RawArtifactRef: "ai/" + filesRel})
	}
	return err
}

func writeFile(out *output.Manager, item discoveredFile) (FileRecord, error) {
	info, err := os.Lstat(item.ActualPath)
	if err != nil {
		if !os.IsNotExist(err) {
			_ = out.Error(evidence.ErrorEvent{Collector: collector, Error: err.Error(), SourcePath: item.DisplayPath, SourceType: sourceType(item), SourceTrust: "high", RawArtifactRef: "ai/" + filesRel})
		}
		record := FileRecord{RecordMeta: out.Meta(collector, filesRel, item.DisplayPath, sourceType(item), "high"), Exists: false, AbsentReason: err.Error(), Path: item.DisplayPath, Category: item.Category, Source: item.Source, ProcessPID: item.ProcessPID, ProcessFD: item.ProcessFD}
		if err := out.AppendAIJSONL(filesRel, record, collector, item.DisplayPath, sourceType(item), "high"); err != nil {
			return record, err
		}
		if err := writeFileAttributes(out, item, record, nil, nil); err != nil {
			return record, err
		}
		if record.Category == "open_file" {
			if err := appendFileRecord(out, openFilesRel, record); err != nil {
				return record, err
			}
		}
		reasons := []string{"missing_after_discovery"}
		if strings.Contains(record.Path, " (deleted)") {
			reasons = append(reasons, "deleted_open_file")
		}
		return record, writeFileFlags(out, record, reasons)
	}
	modTime := info.ModTime().UTC()
	record := FileRecord{
		RecordMeta:    out.Meta(collector, filesRel, item.DisplayPath, sourceType(item), "high"),
		Exists:        true,
		Path:          item.DisplayPath,
		Category:      item.Category,
		FileType:      fileType(info),
		Mode:          info.Mode().String(),
		Size:          info.Size(),
		ModTime:       &modTime,
		ProcessPID:    item.ProcessPID,
		ProcessFD:     item.ProcessFD,
		Source:        item.Source,
		SUID:          info.Mode()&os.ModeSetuid != 0,
		SGID:          info.Mode()&os.ModeSetgid != 0,
		WorldWritable: info.Mode().Perm()&0o002 != 0,
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		record.UID = int(st.Uid)
		record.GID = int(st.Gid)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if target, err := os.Readlink(item.ActualPath); err == nil {
			record.LinkTarget = target
		}
	}
	if err := out.AppendAIJSONL(filesRel, record, collector, item.DisplayPath, sourceType(item), "high"); err != nil {
		return record, err
	}
	if err := writeClassifiedRecords(out, record); err != nil {
		return record, err
	}
	var hashRecord *HashRecord
	if info.Mode().IsRegular() {
		hash, err := writeHash(out, item, info)
		if err != nil {
			return record, err
		}
		hashRecord = &hash
	}
	if err := writeFileAttributes(out, item, record, info, hashRecord); err != nil {
		return record, err
	}
	reasons := fileFlagReasons(record)
	if len(reasons) > 0 {
		if err := writeFileFlags(out, record, reasons); err != nil {
			return record, err
		}
	}
	_ = out.Timeline(evidence.TimelineEvent{
		Collector:      collector,
		EventType:      "file_metadata",
		Timestamp:      modTime,
		SourcePath:     item.DisplayPath,
		SourceType:     sourceType(item),
		SourceTrust:    "high",
		RawArtifactRef: "ai/" + filesRel,
		Summary:        item.DisplayPath,
	})
	return record, nil
}

func writeHash(out *output.Manager, item discoveredFile, info os.FileInfo) (HashRecord, error) {
	record := HashRecord{RecordMeta: out.Meta(collector, hashesRel, item.DisplayPath, sourceType(item), "high"), Exists: true, Path: item.DisplayPath, Size: info.Size()}
	if shouldSkipContentHash(item.DisplayPath) {
		record.Skipped = true
		record.SkipReason = "pseudo filesystem path is metadata-only"
		return record, out.AppendAIJSONL(hashesRel, record, collector, item.DisplayPath, sourceType(item), "high")
	}
	if info.Size() > hashSizeLimit {
		record.Skipped = true
		record.SkipReason = "file exceeds hash size limit"
		return record, out.AppendAIJSONL(hashesRel, record, collector, item.DisplayPath, sourceType(item), "high")
	}
	hashes, err := hashFile(item.ActualPath)
	if err != nil {
		record.Exists = false
		record.AbsentReason = err.Error()
		_ = out.Error(evidence.ErrorEvent{Collector: collector, Error: err.Error(), SourcePath: item.DisplayPath, SourceType: sourceType(item), SourceTrust: "high", RawArtifactRef: "ai/" + hashesRel})
	} else {
		record.MD5 = hashes.md5
		record.SHA1 = hashes.sha1
		record.SHA256 = hashes.sha256
	}
	return record, out.AppendAIJSONL(hashesRel, record, collector, item.DisplayPath, sourceType(item), "high")
}

func writeFileAttributes(out *output.Manager, item discoveredFile, file FileRecord, info os.FileInfo, hash *HashRecord) error {
	record := FileAttributeRecord{
		RecordMeta:   out.Meta(collector, attributesRel, file.Path, recordSourceType(file), "high"),
		Exists:       file.Exists,
		AbsentReason: file.AbsentReason,
		Path:         file.Path,
		Category:     file.Category,
		Source:       file.Source,
		FileType:     file.FileType,
		Mode:         file.Mode,
		MTime:        file.ModTime,
	}
	var issues []FileAttributeIssue
	if !file.Exists {
		record.Status = "absent"
		return out.AppendAIJSONL(attributesRel, record, collector, file.Path, recordSourceType(file), "high")
	}
	record.UID = intPtr(file.UID)
	record.GID = intPtr(file.GID)
	record.Size = int64Ptr(file.Size)
	if hash == nil {
		if file.FileType == "regular" {
			issues = append(issues, FileAttributeIssue{Field: "sha256", Status: "not_collected"})
		}
	} else {
		switch {
		case hash.SHA256 != "":
			record.SHA256 = hash.SHA256
			record.HashStatus = "ok"
		case hash.Skipped:
			record.HashStatus = "skipped"
			issues = append(issues, FileAttributeIssue{Field: "sha256", Status: "skipped", Error: hash.SkipReason})
		case hash.AbsentReason != "":
			record.HashStatus = "error"
			issues = append(issues, FileAttributeIssue{Field: "sha256", Status: "error", Error: hash.AbsentReason})
		default:
			record.HashStatus = "absent"
			issues = append(issues, FileAttributeIssue{Field: "sha256", Status: "absent"})
		}
	}
	if info != nil {
		issues = append(issues, enrichPlatformFileAttributes(item.ActualPath, info, &record)...)
	}
	record.Issues = issues
	record.Status = fileAttributeStatus(record.Exists, issues)
	return out.AppendAIJSONL(attributesRel, record, collector, file.Path, recordSourceType(file), "high")
}

func writeClassifiedRecords(out *output.Manager, record FileRecord) error {
	if record.Category == "open_file" {
		if err := appendFileRecord(out, openFilesRel, record); err != nil {
			return err
		}
	}
	if record.SUID || record.SGID {
		if err := appendFileRecord(out, suidFilesRel, record); err != nil {
			return err
		}
	}
	return nil
}

func writeRecentRecords(out *output.Manager, records []FileRecord) error {
	recent := make([]FileRecord, 0, len(records))
	now := time.Now()
	for _, record := range records {
		if !record.Exists || record.ModTime == nil || record.ModTime.IsZero() {
			continue
		}
		if now.Sub(*record.ModTime) <= recentWindow {
			recent = append(recent, record)
		}
	}
	sort.Slice(recent, func(i, j int) bool {
		return recent[i].ModTime.After(*recent[j].ModTime)
	})
	if len(recent) > recentFileLimit {
		recent = recent[:recentFileLimit]
	}
	for _, record := range recent {
		if err := appendFileRecord(out, recentFilesRel, record); err != nil {
			return err
		}
	}
	return nil
}

func appendFileRecord(out *output.Manager, rel string, record FileRecord) error {
	record.RecordMeta = out.Meta(collector, rel, record.Path, recordSourceType(record), "high")
	return out.AppendAIJSONL(rel, record, collector, record.Path, recordSourceType(record), "high")
}

func writeFileFlags(out *output.Manager, file FileRecord, reasons []string) error {
	record := FileFlagRecord{
		RecordMeta: out.Meta(collector, fileFlagsRel, file.Path, "file", "high"),
		Exists:     file.Exists,
		Path:       file.Path,
		Reasons:    reasons,
		Category:   file.Category,
		Mode:       file.Mode,
		Size:       file.Size,
		ModTime:    formatTimePtr(file.ModTime),
	}
	return out.AppendAIJSONL(fileFlagsRel, record, collector, file.Path, "file", "high")
}

func writeAbsent(out *output.Manager, path, category, reason string) error {
	source := "scan"
	if category == "open_file" {
		source = "/proc"
	}
	record := FileRecord{RecordMeta: out.Meta(collector, filesRel, path, recordSourceType(FileRecord{Source: source}), "high"), Exists: false, AbsentReason: reason, Path: path, Category: category, Source: source}
	if err := out.AppendAIJSONL(filesRel, record, collector, path, recordSourceType(record), "high"); err != nil {
		return err
	}
	if err := writeFileAttributes(out, discoveredFile{DisplayPath: path, ActualPath: actualPath(path), Category: category, Source: source}, record, nil, nil); err != nil {
		return err
	}
	if category == "open_file" {
		if err := appendFileRecord(out, openFilesRel, record); err != nil {
			return err
		}
	}
	return writeFileFlags(out, record, []string{"absent"})
}

func writeLegacy(out *output.Manager, records []FileRecord) error {
	var enum strings.Builder
	var info strings.Builder
	var hashes strings.Builder
	info.WriteString("path\tcategory\tmode\tuid\tgid\tsize\tmtime\ttype\n")
	hashes.WriteString("path\tmd5\tsha1\tsha256\n")
	sort.Slice(records, func(i, j int) bool { return records[i].Path < records[j].Path })
	for _, record := range records {
		if !record.Exists {
			continue
		}
		enum.WriteString(record.Path)
		enum.WriteByte('\n')
		info.WriteString(fmt.Sprintf("%s\t%s\t%s\t%d\t%d\t%d\t%s\t%s\n", record.Path, record.Category, record.Mode, record.UID, record.GID, record.Size, formatTimePtr(record.ModTime), record.FileType))
		if record.FileType == "regular" && record.Size <= hashSizeLimit && !shouldSkipContentHash(record.Path) {
			if result, err := hashFile(actualPath(record.Path)); err == nil {
				hashes.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\n", record.Path, result.md5, result.sha1, result.sha256))
			}
		}
	}
	if err := out.WriteLegacyFromSource(legacyEnumRel, []byte(enum.String()), collector, "generated:file-enum", "generated", "high"); err != nil {
		return err
	}
	if err := out.WriteLegacyFromSource(legacyInfoRel, []byte(info.String()), collector, "generated:file-info", "generated", "high"); err != nil {
		return err
	}
	return out.WriteLegacyFromSource(legacyHashesRel, []byte(hashes.String()), collector, "generated:file-hashes", "generated", "high")
}

type hashResult struct {
	md5    string
	sha1   string
	sha256 string
}

func hashFile(path string) (hashResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return hashResult{}, err
	}
	defer f.Close()
	hMD5 := md5.New()
	hSHA1 := sha1.New()
	hSHA256 := sha256.New()
	limited := &io.LimitedReader{R: f, N: hashSizeLimit + 1}
	if _, err := io.Copy(io.MultiWriter(hMD5, hSHA1, hSHA256), limited); err != nil {
		return hashResult{}, err
	}
	if limited.N == 0 {
		return hashResult{}, errors.New("file exceeds hash size limit while hashing")
	}
	return hashResult{md5: hex.EncodeToString(hMD5.Sum(nil)), sha1: hex.EncodeToString(hSHA1.Sum(nil)), sha256: hex.EncodeToString(hSHA256.Sum(nil))}, nil
}

func recordProcReadlinkError(out *output.Manager, actualLinkPath, rawRef string, err error) {
	_ = out.Error(evidence.ErrorEvent{
		Collector:      collector,
		Error:          err.Error(),
		SourcePath:     displayProcPath(actualLinkPath),
		SourceType:     "procfs",
		SourceTrust:    "high",
		RawArtifactRef: "ai/" + rawRef,
	})
}

func scanSpecs() []struct {
	path     string
	category string
	depth    int
} {
	return []struct {
		path     string
		category string
		depth    int
	}{
		{"/tmp", "tmp_file", 3},
		{"/var/tmp", "tmp_file", 3},
		{"/dev/shm", "tmp_file", 2},
		{"/usr/bin", "suid_scan", 1},
		{"/usr/sbin", "suid_scan", 1},
		{"/bin", "suid_scan", 1},
		{"/sbin", "suid_scan", 1},
		{"/var/www", "webroot", 4},
		{"/srv/www", "webroot", 4},
	}
}

func fileFlagReasons(record FileRecord) []string {
	var reasons []string
	if record.SUID {
		reasons = append(reasons, "suid")
	}
	if record.SGID {
		reasons = append(reasons, "sgid")
	}
	if record.WorldWritable {
		reasons = append(reasons, "world_writable")
	}
	if record.Category == "tmp_file" {
		reasons = append(reasons, "tmp_location")
	}
	if record.Category == "tmp_file" && record.ModTime != nil && time.Since(*record.ModTime) <= recentWindow {
		reasons = append(reasons, "recently_modified")
	}
	if strings.Contains(record.Path, " (deleted)") {
		reasons = append(reasons, "deleted_open_file")
	}
	return reasons
}

func shouldTrackTarget(target string) bool {
	if target == "" || strings.HasPrefix(target, "socket:") || strings.HasPrefix(target, "pipe:") || strings.HasPrefix(target, "anon_inode:") {
		return false
	}
	if strings.Contains(target, " (deleted)") {
		return true
	}
	return filepath.IsAbs(target)
}

func shouldSkipContentHash(path string) bool {
	clean := filepath.Clean(strings.TrimSuffix(path, " (deleted)"))
	return clean == "/proc" || strings.HasPrefix(clean, "/proc/") ||
		clean == "/sys" || strings.HasPrefix(clean, "/sys/") ||
		clean == "/dev" || strings.HasPrefix(clean, "/dev/")
}

func shouldSkipCollectorArtifactDir(display, actual string, out *output.Manager) bool {
	if out != nil && pathWithin(actual, out.Root()) {
		return true
	}
	return isCollectorArtifactDir(display, actual)
}

func shouldExcludeCollectorArtifactPath(display, actual, outRoot string) bool {
	if outRoot != "" && pathWithin(actual, outRoot) {
		return true
	}
	return isCollectorArtifactPath(display, actual)
}

func pathWithin(path, root string) bool {
	if path == "" || root == "" {
		return false
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(rootAbs, pathAbs)
	return err == nil && (rel == "." || !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}

func hasCollectorOutputMarker(dir string) bool {
	for _, marker := range []string{
		filepath.Join("ai", "evidence.jsonl"),
		filepath.Join("ai", "manifest.json"),
		filepath.Join("out", "ai", "evidence.jsonl"),
		filepath.Join("out", "ai", "manifest.json"),
		filepath.Join("attk_log"),
		filepath.Join("legacy", "SUMMARY"),
		filepath.Join("legacy", "enum", "enum_file.out"),
		filepath.Join("profiles", "standard.yaml"),
		"standard.yaml",
		"deep.yaml",
		"dfir-collector",
	} {
		if _, err := os.Lstat(filepath.Join(dir, marker)); err == nil {
			return true
		}
	}
	return false
}

func isCollectorArtifactPath(display, actual string) bool {
	cleanDisplay := filepath.Clean(display)
	cleanActual := filepath.Clean(actual)
	if isCollectorArtifactDir(cleanDisplay, cleanActual) {
		return true
	}
	displayDir := filepath.Dir(cleanDisplay)
	actualDir := filepath.Dir(cleanActual)
	for {
		if isCollectorArtifactDir(displayDir, actualDir) {
			return true
		}
		if displayDir == "." || displayDir == "/" || displayDir == "/tmp" || displayDir == "/var/tmp" {
			return false
		}
		nextDisplay := filepath.Dir(displayDir)
		nextActual := filepath.Dir(actualDir)
		if nextDisplay == displayDir || nextActual == actualDir {
			return false
		}
		displayDir = nextDisplay
		actualDir = nextActual
	}
}

func isCollectorArtifactDir(display, actual string) bool {
	clean := filepath.Clean(display)
	if !strings.HasPrefix(clean, "/tmp/") && !strings.HasPrefix(clean, "/var/tmp/") {
		return false
	}
	base := filepath.Base(clean)
	if !(strings.HasPrefix(base, "dfir-") ||
		strings.HasPrefix(base, "linux-dfir-") ||
		strings.HasPrefix(base, "attk-original-") ||
		strings.HasPrefix(base, "attk-original-run")) {
		return false
	}
	return hasCollectorOutputMarker(actual)
}

func formatTimePtr(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func fileAttributeStatus(exists bool, issues []FileAttributeIssue) string {
	if !exists {
		return "absent"
	}
	if len(issues) > 0 {
		return "partial"
	}
	return "ok"
}

func parseNullSeparatedNames(data []byte) []string {
	var names []string
	for _, part := range strings.Split(string(data), "\x00") {
		if part == "" {
			continue
		}
		names = append(names, part)
	}
	sort.Strings(names)
	return names
}

func hasName(names []string, want string) bool {
	i := sort.SearchStrings(names, want)
	return i < len(names) && names[i] == want
}

func intPtr(value int) *int {
	return &value
}

func int64Ptr(value int64) *int64 {
	return &value
}

func boolPtr(value bool) *bool {
	return &value
}

func actualPath(display string) string {
	cleanDisplay := strings.TrimSuffix(display, " (deleted)")
	if filesystemRoot == "" || filesystemRoot == "/" {
		return cleanDisplay
	}
	clean := strings.TrimPrefix(filepath.Clean(cleanDisplay), string(filepath.Separator))
	return filepath.Join(filesystemRoot, clean)
}

func displayPath(actual string) string {
	if filesystemRoot == "" || filesystemRoot == "/" {
		return actual
	}
	rel, err := filepath.Rel(filesystemRoot, actual)
	if err != nil {
		return actual
	}
	return filepath.Clean(string(filepath.Separator) + filepath.ToSlash(rel))
}

func actualProcRoot() string {
	if procRoot == "/proc" {
		return actualPath("/proc")
	}
	return procRoot
}

func displayProcPath(actual string) string {
	if procRoot != "/proc" {
		rel, err := filepath.Rel(procRoot, actual)
		if err == nil {
			return filepath.Join("/proc", rel)
		}
	}
	return displayPath(actual)
}

func sourceType(item discoveredFile) string {
	if item.Source == "/proc" {
		return "procfs"
	}
	return "file"
}

func recordSourceType(record FileRecord) string {
	if record.Source == "/proc" {
		return "procfs"
	}
	return "file"
}

func fileType(info os.FileInfo) string {
	mode := info.Mode()
	switch {
	case mode.IsRegular():
		return "regular"
	case mode.IsDir():
		return "directory"
	case mode&os.ModeSymlink != 0:
		return "symlink"
	default:
		return mode.Type().String()
	}
}
