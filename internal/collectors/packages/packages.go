package packages

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
)

const (
	collector       = "packages"
	packagesRel     = "entities/package.jsonl"
	ownersRel       = "facts/file_package_owners.jsonl"
	integrityRel    = "facts/package_integrity.jsonl"
	maxNativeOutput = 32 * 1024 * 1024
)

var (
	filesystemRoot  = "/"
	commandLookPath = exec.LookPath
	nativeRunner    = runNative
)

type PackageRecord struct {
	evidence.RecordMeta
	Exists        bool       `json:"exists"`
	AbsentReason  string     `json:"absent_reason,omitempty"`
	Manager       string     `json:"manager"`
	Name          string     `json:"name,omitempty"`
	Version       string     `json:"version,omitempty"`
	Architecture  string     `json:"architecture,omitempty"`
	Status        string     `json:"status,omitempty"`
	Source        string     `json:"source,omitempty"`
	SourcePackage string     `json:"source_package,omitempty"`
	Maintainer    string     `json:"maintainer,omitempty"`
	Description   string     `json:"description,omitempty"`
	InstalledSize int64      `json:"installed_size_kb,omitempty"`
	CollectedHint string     `json:"collected_hint,omitempty"`
	ObservedAt    *time.Time `json:"observed_at,omitempty"`
}

type OwnerRecord struct {
	evidence.RecordMeta
	Exists       bool   `json:"exists"`
	AbsentReason string `json:"absent_reason,omitempty"`
	Manager      string `json:"manager"`
	Path         string `json:"path,omitempty"`
	PackageName  string `json:"package_name,omitempty"`
	PackageKey   string `json:"package_key,omitempty"`
	Version      string `json:"version,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	MD5Sum       string `json:"md5sum,omitempty"`
	Source       string `json:"source,omitempty"`
}

type PackageIntegrityRecord struct {
	evidence.RecordMeta
	Exists          bool       `json:"exists"`
	AbsentReason    string     `json:"absent_reason,omitempty"`
	Manager         string     `json:"manager"`
	PackageName     string     `json:"package_name,omitempty"`
	PackageKey      string     `json:"package_key,omitempty"`
	Version         string     `json:"version,omitempty"`
	Architecture    string     `json:"architecture,omitempty"`
	Path            string     `json:"path,omitempty"`
	ExpectedMD5     string     `json:"expected_md5,omitempty"`
	ActualMD5       string     `json:"actual_md5,omitempty"`
	HashAvailable   bool       `json:"hash_available"`
	FileExists      bool       `json:"file_exists"`
	Size            *int64     `json:"size,omitempty"`
	Mode            string     `json:"mode,omitempty"`
	UID             *int       `json:"uid,omitempty"`
	GID             *int       `json:"gid,omitempty"`
	MTime           *time.Time `json:"mtime,omitempty"`
	PackageConffile bool       `json:"package_conffile"`
	Source          string     `json:"source,omitempty"`
	Sensitive       bool       `json:"sensitive"`
}

func Collect(ctx context.Context, out *output.Manager) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	pkgIndex := map[string]PackageRecord{}
	if err := collectDPKG(out, pkgIndex); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return collectRPM(out)
}

func collectDPKG(out *output.Manager, pkgIndex map[string]PackageRecord) error {
	statusPath := "/var/lib/dpkg/status"
	actualStatus := actualPath(statusPath)
	data, err := os.ReadFile(actualStatus)
	if err != nil {
		if !os.IsNotExist(err) {
			recordError(out, statusPath, "file", packagesRel, err)
		}
		if legacyErr := out.WriteLegacyFromSource("enum/dpkg/status.out", unavailableLegacy("dpkg status", err), collector, statusPath, "file", "high"); legacyErr != nil {
			return legacyErr
		}
		if err := writeAbsentPackage(out, "dpkg", statusPath, "file", err.Error()); err != nil {
			return err
		}
	} else {
		if err := out.WriteLegacyFromSource("enum/dpkg/status.out", data, collector, statusPath, "file", "high"); err != nil {
			return err
		}
		for _, pkg := range ParseDPKGStatus(string(data)) {
			pkg.RecordMeta = out.Meta(collector, packagesRel, statusPath, "file", "high")
			pkg.Exists = true
			pkg.Manager = "dpkg"
			pkg.Source = statusPath
			pkg.ObservedAt = nowPtr()
			if err := out.AppendAIJSONL(packagesRel, pkg, collector, statusPath, "file", "high"); err != nil {
				return err
			}
			indexDPKGPackage(pkgIndex, pkg)
		}
	}
	return collectDPKGOwners(out, pkgIndex)
}

func collectDPKGOwners(out *output.Manager, pkgIndex map[string]PackageRecord) error {
	infoDir := "/var/lib/dpkg/info"
	actualInfo := actualPath(infoDir)
	entries, err := os.ReadDir(actualInfo)
	if err != nil {
		if !os.IsNotExist(err) {
			recordError(out, infoDir, "file", ownersRel, err)
		}
		if legacyErr := out.WriteLegacyFromSource("enum/dpkg/package_files.out", unavailableLegacy("dpkg package files", err), collector, infoDir, "file", "high"); legacyErr != nil {
			return legacyErr
		}
		if err := writeAbsentOwner(out, "dpkg", infoDir, "file", err.Error()); err != nil {
			return err
		}
		return writeAbsentIntegrity(out, "dpkg", infoDir, "file", err.Error())
	}
	var legacy strings.Builder
	legacy.WriteString("package\tpath\tmd5sum\n")
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".list") {
			continue
		}
		pkgKey := strings.TrimSuffix(entry.Name(), ".list")
		pkgName, pkgArch := splitDPKGPackageKey(pkgKey)
		sourcePath := filepath.Join(infoDir, entry.Name())
		text, err := os.ReadFile(filepath.Join(actualInfo, entry.Name()))
		if err != nil {
			recordError(out, sourcePath, "file", ownersRel, err)
			continue
		}
		md5sums, err := readDPKGMD5Sums(actualInfo, pkgKey)
		if err != nil && !os.IsNotExist(err) {
			recordError(out, filepath.Join(infoDir, pkgKey+".md5sums"), "file", ownersRel, err)
		}
		conffiles, err := readDPKGConffiles(actualInfo, pkgKey)
		if err != nil && !os.IsNotExist(err) {
			recordError(out, filepath.Join(infoDir, pkgKey+".conffiles"), "file", integrityRel, err)
		}
		paths := ParseDPKGList(string(text))
		for _, path := range paths {
			owner := OwnerRecord{
				RecordMeta:   out.Meta(collector, ownersRel, sourcePath, "file", "high"),
				Exists:       true,
				Manager:      "dpkg",
				Path:         path,
				PackageName:  pkgName,
				PackageKey:   pkgKey,
				Architecture: pkgArch,
				Source:       sourcePath,
			}
			if sum := md5sums[path]; sum != "" {
				owner.MD5Sum = sum
			}
			if pkg, ok := lookupDPKGPackage(pkgIndex, pkgKey, pkgName); ok {
				owner.PackageName = normalizedDPKGPackageName(pkg.Name)
				owner.Version = pkg.Version
				owner.Architecture = pkg.Architecture
			}
			if err := out.AppendAIJSONL(ownersRel, owner, collector, sourcePath, "file", "high"); err != nil {
				return err
			}
			legacy.WriteString(pkgName)
			legacy.WriteByte('\t')
			legacy.WriteString(path)
			legacy.WriteByte('\t')
			legacy.WriteString(owner.MD5Sum)
			legacy.WriteByte('\n')
		}
		if err := writeDPKGIntegrityRecords(out, pkgIndex, pkgKey, sourcePath, paths, md5sums, conffiles); err != nil {
			return err
		}
	}
	return out.WriteLegacyFromSource("enum/dpkg/package_files.out", []byte(legacy.String()), collector, infoDir, "file", "high")
}

func collectRPM(out *output.Manager) error {
	rpmPath, err := commandLookPath("rpm")
	if err != nil {
		if legacyErr := out.WriteLegacyFromSource("enum/rpm/rpm_-qa.out", unavailableLegacy("rpm -qa", err), collector, "rpm -qa", "native_command", "medium"); legacyErr != nil {
			return legacyErr
		}
		if legacyErr := out.WriteLegacyFromSource("enum/rpm/rpm_-q_filesbypkg_-a.out", unavailableLegacy("rpm -q --filesbypkg -a", err), collector, "rpm -q --filesbypkg -a", "native_command", "medium"); legacyErr != nil {
			return legacyErr
		}
		if err := writeAbsentPackage(out, "rpm", "rpm -qa", "native_command", err.Error()); err != nil {
			return err
		}
		return writeAbsentOwner(out, "rpm", "rpm -q --filesbypkg -a", "native_command", err.Error())
	}
	rpmIndex := map[string]PackageRecord{}
	pkgOutput, err := nativeRunner(rpmPath, "-qa", "--qf", "%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n")
	if err != nil {
		recordError(out, "rpm -qa", "native_command", packagesRel, err)
		if legacyErr := out.WriteLegacyFromSource("enum/rpm/rpm_-qa.out", append(pkgOutput, unavailableLegacy("rpm -qa", err)...), collector, "rpm -qa", "native_command", "medium"); legacyErr != nil {
			return legacyErr
		}
		if err := writeAbsentPackage(out, "rpm", "rpm -qa", "native_command", err.Error()); err != nil {
			return err
		}
	} else {
		if err := out.WriteLegacyFromSource("enum/rpm/rpm_-qa.out", pkgOutput, collector, "rpm -qa", "native_command", "medium"); err != nil {
			return err
		}
		for _, pkg := range ParseRPMQA(string(pkgOutput)) {
			pkg.RecordMeta = out.Meta(collector, packagesRel, "rpm -qa", "native_command", "medium")
			pkg.ObservedAt = nowPtr()
			if err := out.AppendAIJSONL(packagesRel, pkg, collector, "rpm -qa", "native_command", "medium"); err != nil {
				return err
			}
			rpmIndex[pkg.Name] = pkg
		}
	}
	fileOutput, err := nativeRunner(rpmPath, "-q", "--filesbypkg", "-a")
	if err != nil {
		recordError(out, "rpm -q --filesbypkg -a", "native_command", ownersRel, err)
		if legacyErr := out.WriteLegacyFromSource("enum/rpm/rpm_-q_filesbypkg_-a.out", append(fileOutput, unavailableLegacy("rpm -q --filesbypkg -a", err)...), collector, "rpm -q --filesbypkg -a", "native_command", "medium"); legacyErr != nil {
			return legacyErr
		}
		return writeAbsentOwner(out, "rpm", "rpm -q --filesbypkg -a", "native_command", err.Error())
	}
	if err := out.WriteLegacyFromSource("enum/rpm/rpm_-q_filesbypkg_-a.out", fileOutput, collector, "rpm -q --filesbypkg -a", "native_command", "medium"); err != nil {
		return err
	}
	for _, owner := range ParseRPMFilesByPackage(string(fileOutput)) {
		owner.RecordMeta = out.Meta(collector, ownersRel, "rpm -q --filesbypkg -a", "native_command", "medium")
		if pkg, ok := rpmIndex[owner.PackageName]; ok {
			owner.Version = pkg.Version
			owner.Architecture = pkg.Architecture
		}
		if err := out.AppendAIJSONL(ownersRel, owner, collector, "rpm -q --filesbypkg -a", "native_command", "medium"); err != nil {
			return err
		}
	}
	return nil
}

func ParseDPKGStatus(text string) []PackageRecord {
	var packages []PackageRecord
	for _, stanza := range splitStanzas(text) {
		fields := parseDebianFields(stanza)
		name := fields["Package"]
		if name == "" {
			continue
		}
		size, _ := strconv.ParseInt(fields["Installed-Size"], 10, 64)
		packages = append(packages, PackageRecord{
			Exists:        true,
			Manager:       "dpkg",
			Name:          normalizedDPKGPackageName(name),
			Version:       fields["Version"],
			Architecture:  fields["Architecture"],
			Status:        fields["Status"],
			SourcePackage: fields["Source"],
			Maintainer:    fields["Maintainer"],
			Description:   fields["Description"],
			InstalledSize: size,
		})
	}
	sort.Slice(packages, func(i, j int) bool { return packages[i].Name < packages[j].Name })
	return packages
}

func ParseDPKGList(text string) []string {
	var paths []string
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "/") || seen[line] {
			continue
		}
		seen[line] = true
		paths = append(paths, line)
	}
	sort.Strings(paths)
	return paths
}

func ParseDPKGMD5Sums(text string) map[string]string {
	sums := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 || len(parts[0]) != 32 {
			continue
		}
		path := parts[1]
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		sums[path] = strings.ToLower(parts[0])
	}
	return sums
}

func ParseDPKGConffiles(text string) map[string]bool {
	conffiles := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "/") {
			continue
		}
		path := strings.Fields(line)[0]
		if strings.HasPrefix(path, "/") {
			conffiles[path] = true
		}
	}
	return conffiles
}

func ParseRPMQA(text string) []PackageRecord {
	var packages []PackageRecord
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 4 {
			continue
		}
		packages = append(packages, PackageRecord{Exists: true, Manager: "rpm", Name: parts[0], Version: parts[1] + "-" + parts[2], Architecture: parts[3], Source: "rpm -qa", CollectedHint: "native_command"})
	}
	sort.Slice(packages, func(i, j int) bool { return packages[i].Name < packages[j].Name })
	return packages
}

func ParseRPMFilesByPackage(text string) []OwnerRecord {
	var owners []OwnerRecord
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "/") {
			continue
		}
		pkgName, path := splitRPMFilesByPackageLine(line)
		if pkgName == "" || !strings.HasPrefix(path, "/") {
			continue
		}
		owners = append(owners, OwnerRecord{Exists: true, Manager: "rpm", PackageName: pkgName, Path: path, Source: "rpm -q --filesbypkg -a"})
	}
	return owners
}

func splitRPMFilesByPackageLine(line string) (string, string) {
	for i, r := range line {
		if r == ' ' || r == '\t' {
			return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i:])
		}
	}
	return "", ""
}

func splitStanzas(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	raw := strings.Split(text, "\n\n")
	var stanzas []string
	for _, stanza := range raw {
		stanza = strings.TrimSpace(stanza)
		if stanza != "" {
			stanzas = append(stanzas, stanza)
		}
	}
	return stanzas
}

func parseDebianFields(stanza string) map[string]string {
	fields := map[string]string{}
	current := ""
	scanner := bufio.NewScanner(strings.NewReader(stanza))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if current != "" {
				fields[current] += "\n" + strings.TrimSpace(line)
			}
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		current = strings.TrimSpace(parts[0])
		fields[current] = strings.TrimSpace(parts[1])
	}
	return fields
}

func readDPKGMD5Sums(actualInfoDir, pkgName string) (map[string]string, error) {
	path := filepath.Join(actualInfoDir, pkgName+".md5sums")
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]string{}, err
	}
	return ParseDPKGMD5Sums(string(data)), nil
}

func readDPKGConffiles(actualInfoDir, pkgName string) (map[string]bool, error) {
	path := filepath.Join(actualInfoDir, pkgName+".conffiles")
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]bool{}, err
	}
	return ParseDPKGConffiles(string(data)), nil
}

func writeDPKGIntegrityRecords(out *output.Manager, pkgIndex map[string]PackageRecord, pkgKey, sourcePath string, listPaths []string, md5sums map[string]string, conffiles map[string]bool) error {
	pkgName, pkgArch := splitDPKGPackageKey(pkgKey)
	recordPackageName := pkgName
	recordArchitecture := pkgArch
	version := ""
	if pkg, ok := lookupDPKGPackage(pkgIndex, pkgKey, pkgName); ok {
		recordPackageName = normalizedDPKGPackageName(pkg.Name)
		recordArchitecture = pkg.Architecture
		version = pkg.Version
	}
	for _, path := range packageIntegrityPaths(listPaths, md5sums, conffiles) {
		recordSource := packageIntegritySource(sourcePath, pkgKey, path, md5sums, conffiles)
		record := PackageIntegrityRecord{
			RecordMeta:      out.Meta(collector, integrityRel, recordSource, "file", "high"),
			Exists:          true,
			Manager:         "dpkg",
			PackageName:     recordPackageName,
			PackageKey:      pkgKey,
			Version:         version,
			Architecture:    recordArchitecture,
			Path:            path,
			ExpectedMD5:     md5sums[path],
			HashAvailable:   md5sums[path] != "",
			PackageConffile: conffiles[path],
			Source:          recordSource,
			Sensitive:       sensitivePackageIntegrityPath(path),
		}
		fillPackageIntegrityFileFacts(&record)
		if err := out.AppendAIJSONL(integrityRel, record, collector, recordSource, "file", "high"); err != nil {
			return err
		}
	}
	return nil
}

func packageIntegrityPaths(listPaths []string, md5sums map[string]string, conffiles map[string]bool) []string {
	seen := map[string]bool{}
	for _, path := range listPaths {
		if path != "" {
			seen[path] = true
		}
	}
	for path := range md5sums {
		if path != "" {
			seen[path] = true
		}
	}
	for path := range conffiles {
		if path != "" {
			seen[path] = true
		}
	}
	paths := make([]string, 0, len(seen))
	for path := range seen {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func packageIntegritySource(listSourcePath, pkgKey, path string, md5sums map[string]string, conffiles map[string]bool) string {
	switch {
	case strings.HasSuffix(listSourcePath, ".list"):
		if _, ok := md5sums[path]; ok {
			return strings.TrimSuffix(listSourcePath, ".list") + ".md5sums"
		}
		if conffiles[path] {
			return strings.TrimSuffix(listSourcePath, ".list") + ".conffiles"
		}
	}
	if _, ok := md5sums[path]; ok {
		return filepath.Join("/var/lib/dpkg/info", pkgKey+".md5sums")
	}
	if conffiles[path] {
		return filepath.Join("/var/lib/dpkg/info", pkgKey+".conffiles")
	}
	return listSourcePath
}

func fillPackageIntegrityFileFacts(record *PackageIntegrityRecord) {
	info, err := os.Lstat(actualPath(record.Path))
	if err != nil {
		if !os.IsNotExist(err) {
			record.AbsentReason = err.Error()
		}
		return
	}
	record.FileExists = true
	record.Mode = info.Mode().String()
	size := info.Size()
	record.Size = &size
	modTime := info.ModTime().UTC()
	record.MTime = &modTime
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		uid := int(st.Uid)
		gid := int(st.Gid)
		record.UID = &uid
		record.GID = &gid
	}
	if record.ExpectedMD5 == "" {
		return
	}
	actualMD5, err := fileMD5(actualPath(record.Path))
	if err != nil {
		record.AbsentReason = err.Error()
		return
	}
	record.ActualMD5 = actualMD5
}

func fileMD5(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func sensitivePackageIntegrityPath(path string) bool {
	clean := filepath.ToSlash(filepath.Clean(path))
	return clean == "/etc/shadow" ||
		clean == "/etc/gshadow" ||
		clean == "/etc/sudoers" ||
		strings.HasPrefix(clean, "/etc/ssh/ssh_host_")
}

func indexDPKGPackage(index map[string]PackageRecord, pkg PackageRecord) {
	keys := []string{pkg.Name}
	if pkg.Architecture != "" {
		keys = append(keys, pkg.Name+":"+pkg.Architecture)
	}
	for _, key := range keys {
		if key != "" {
			index[key] = pkg
		}
	}
}

func lookupDPKGPackage(index map[string]PackageRecord, pkgKey, pkgName string) (PackageRecord, bool) {
	if pkg, ok := index[pkgKey]; ok {
		return pkg, true
	}
	pkg, ok := index[pkgName]
	return pkg, ok
}

func splitDPKGPackageKey(key string) (string, string) {
	name, arch, ok := strings.Cut(key, ":")
	if !ok || name == "" || arch == "" {
		return key, ""
	}
	return name, arch
}

func normalizedDPKGPackageName(name string) string {
	base, _ := splitDPKGPackageKey(name)
	return base
}

func runNative(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stdout
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), err
	}
	if stdout.Len() > maxNativeOutput {
		return stdout.Bytes()[:maxNativeOutput], errors.New("native command output truncated")
	}
	return stdout.Bytes(), nil
}

func actualPath(path string) string {
	if filesystemRoot == "" || filesystemRoot == "/" {
		return path
	}
	return filepath.Join(filesystemRoot, strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)))
}

func writeAbsentPackage(out *output.Manager, manager, sourcePath, sourceType, reason string) error {
	record := PackageRecord{RecordMeta: out.Meta(collector, packagesRel, sourcePath, sourceType, sourceTrust(sourceType)), Exists: false, AbsentReason: reason, Manager: manager, Source: sourcePath}
	return out.AppendAIJSONL(packagesRel, record, collector, sourcePath, sourceType, sourceTrust(sourceType))
}

func writeAbsentOwner(out *output.Manager, manager, sourcePath, sourceType, reason string) error {
	record := OwnerRecord{RecordMeta: out.Meta(collector, ownersRel, sourcePath, sourceType, sourceTrust(sourceType)), Exists: false, AbsentReason: reason, Manager: manager, Source: sourcePath}
	return out.AppendAIJSONL(ownersRel, record, collector, sourcePath, sourceType, sourceTrust(sourceType))
}

func writeAbsentIntegrity(out *output.Manager, manager, sourcePath, sourceType, reason string) error {
	record := PackageIntegrityRecord{RecordMeta: out.Meta(collector, integrityRel, sourcePath, sourceType, sourceTrust(sourceType)), Exists: false, AbsentReason: reason, Manager: manager, Source: sourcePath}
	return out.AppendAIJSONL(integrityRel, record, collector, sourcePath, sourceType, sourceTrust(sourceType))
}

func recordError(out *output.Manager, sourcePath, sourceType, rawRel string, err error) {
	_ = out.Error(evidence.ErrorEvent{Collector: collector, Error: err.Error(), SourcePath: sourcePath, SourceType: sourceType, SourceTrust: sourceTrust(sourceType), RawArtifactRef: "ai/" + rawRel})
}

func sourceTrust(sourceType string) string {
	if sourceType == "native_command" {
		return "medium"
	}
	return "high"
}

func unavailableLegacy(label string, err error) []byte {
	return []byte("# unavailable: " + label + "\n# error: " + err.Error() + "\n")
}

func nowPtr() *time.Time {
	now := time.Now().UTC()
	return &now
}
