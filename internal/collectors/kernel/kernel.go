package kernel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"linux-dfir/internal/collectors/common"
	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
)

var (
	procModulesPath     = "/proc/modules"
	procCmdlinePath     = "/proc/cmdline"
	procTaintedPath     = "/proc/sys/kernel/tainted"
	kernelReleasePath   = "/proc/sys/kernel/osrelease"
	sysModuleRoot       = "/sys/module"
	libModulesRoot      = "/lib/modules"
	lockdownPath        = "/sys/kernel/security/lockdown"
	lsmPath             = "/sys/kernel/security/lsm"
	apparmorPath        = "/sys/module/apparmor/parameters/enabled"
	selinuxPath         = "/sys/fs/selinux/enforce"
	kptrRestrictPath    = "/proc/sys/kernel/kptr_restrict"
	dmesgRestrictPath   = "/proc/sys/kernel/dmesg_restrict"
	modulesDisabledPath = "/proc/sys/kernel/modules_disabled"
)

const modulesRel = "entities/kernel_module.jsonl"

const (
	kernelSecurityRel    = "facts/kernel_security.jsonl"
	kernelConsistencyRel = "facts/kernel_consistency.jsonl"
)

type Module struct {
	evidence.RecordMeta
	EntityType   string   `json:"entity_type,omitempty"`
	EntityID     string   `json:"entity_id,omitempty"`
	Exists       bool     `json:"exists"`
	Name         string   `json:"name"`
	Size         int64    `json:"size"`
	RefCount     int      `json:"ref_count"`
	UsedBy       []string `json:"used_by"`
	State        string   `json:"state,omitempty"`
	Address      string   `json:"address,omitempty"`
	SysfsPath    string   `json:"sysfs_path,omitempty"`
	ModulePath   string   `json:"module_path,omitempty"`
	Version      string   `json:"version,omitempty"`
	SrcVersion   string   `json:"src_version,omitempty"`
	Holders      []string `json:"holders,omitempty"`
	AbsentReason string   `json:"absent_reason,omitempty"`
}

type SecurityFact struct {
	evidence.RecordMeta
	Exists       bool   `json:"exists"`
	FactType     string `json:"fact_type"`
	Key          string `json:"key"`
	Value        string `json:"value,omitempty"`
	SourceFile   string `json:"source_file,omitempty"`
	Sensitive    bool   `json:"sensitive"`
	AbsentReason string `json:"absent_reason,omitempty"`
}

type ConsistencyFact struct {
	evidence.RecordMeta
	Exists             bool     `json:"exists"`
	ModuleName         string   `json:"module_name"`
	Loaded             bool     `json:"loaded"`
	ProcModulesPresent bool     `json:"proc_modules_present"`
	SysfsPresent       bool     `json:"sysfs_present"`
	SysfsPath          string   `json:"sysfs_path,omitempty"`
	ModulePath         string   `json:"module_path,omitempty"`
	ModuleFileExists   bool     `json:"module_file_exists"`
	ModuleFileSize     int64    `json:"module_file_size,omitempty"`
	ModuleFileSHA256   string   `json:"module_file_sha256,omitempty"`
	ModuleFileError    string   `json:"module_file_error,omitempty"`
	Holders            []string `json:"holders,omitempty"`
	RefCount           int      `json:"refcount"`
	UsedBy             []string `json:"used_by,omitempty"`
	SourceFacts        []string `json:"source_facts,omitempty"`
	SourceProcModules  string   `json:"source_proc_modules,omitempty"`
	SourceSysfsPath    string   `json:"source_sysfs_path,omitempty"`
	SourceModulesDep   string   `json:"source_modules_dep,omitempty"`
	SourceModuleFile   string   `json:"source_module_file,omitempty"`
}

func Collect(ctx context.Context, out *output.Manager) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	loaded, err := collectProcModules(ctx, out)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := collectSysModules(out, loaded); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := collectModprobeLegacy(ctx, out); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := collectCmdline(out); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := collectTainted(out); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return collectKernelSecurity(out)
}

func collectProcModules(ctx context.Context, out *output.Manager) (map[string]bool, error) {
	loaded := map[string]bool{}
	path, text, err := common.ReadFirstExisting(procModulesPath)
	if err != nil {
		_ = out.Error(evidence.ErrorEvent{Collector: "kernel", Error: err.Error(), SourcePath: procModulesPath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/" + modulesRel})
		return loaded, writeAbsentModule(out, procModulesPath, "procfs", err.Error())
	}
	if err := out.WriteLegacyFromSource("system/kernel/modules.out", []byte(text), "kernel", path, "procfs", "high"); err != nil {
		return loaded, err
	}
	common.TimelineFileStat(out, "kernel", path, "legacy/system/kernel/modules.out")
	modulePaths := modulePathIndex(out)
	modules := ParseProcModules(text)
	if err := collectModinfoLegacy(ctx, out, modules); err != nil {
		return loaded, err
	}
	for _, module := range modules {
		module.Exists = true
		enrichModule(&module, modulePaths)
		if module.SysfsPath != "" {
			common.TimelineFileStat(out, "kernel", module.SysfsPath, "ai/"+modulesRel)
		}
		module.RecordMeta = out.Meta("kernel", modulesRel, path, "procfs", "high")
		fillModuleEntity(&module)
		if err := out.AppendAIJSONL(modulesRel, module, "kernel", path, "procfs", "high"); err != nil {
			return loaded, err
		}
		if err := appendKernelConsistency(out, module, path); err != nil {
			return loaded, err
		}
		loaded[module.Name] = true
	}
	return loaded, nil
}

func collectModinfoLegacy(ctx context.Context, out *output.Manager, modules []Module) error {
	if len(modules) == 0 {
		return nil
	}
	for _, module := range modules {
		if err := ctx.Err(); err != nil {
			return err
		}
		if module.Name == "" {
			continue
		}
		result := common.RunCommand(ctx, "modinfo", module.Name)
		if result.Missing() {
			return nil
		}
		rel := filepath.ToSlash(filepath.Join("system/kernel/module", module.Name+".out"))
		source := result.CommandLine()
		if result.Path != "" {
			source = result.Path + " " + strings.Join(result.Args, " ")
		}
		if err := out.WriteLegacyFromSource(rel, result.Output, "kernel", source, "native_command", "medium"); err != nil {
			return err
		}
	}
	return nil
}

func collectModprobeLegacy(ctx context.Context, out *output.Manager) error {
	result := common.RunCommand(ctx, "modprobe", "-n", "-l", "-v")
	if result.Missing() {
		return nil
	}
	source := result.CommandLine()
	if result.Path != "" {
		source = result.Path + " " + strings.Join(result.Args, " ")
	}
	return out.WriteLegacyFromSource("system/kernel/modprobe_-n-l-v.out", result.Output, "kernel", source, "native_command", "medium")
}

func collectSysModules(out *output.Manager, loaded map[string]bool) error {
	stat, err := os.Lstat(sysModuleRoot)
	if err != nil {
		_ = out.Error(evidence.ErrorEvent{Collector: "kernel", Error: err.Error(), SourcePath: sysModuleRoot, SourceType: "sysfs", SourceTrust: "high", RawArtifactRef: "ai/" + modulesRel})
		return writeAbsentModule(out, sysModuleRoot, "sysfs", err.Error())
	}
	if !stat.IsDir() {
		errText := "sys module path is not a directory"
		_ = out.Error(evidence.ErrorEvent{Collector: "kernel", Error: errText, SourcePath: sysModuleRoot, SourceType: "sysfs", SourceTrust: "high", RawArtifactRef: "ai/" + modulesRel})
		return writeAbsentModule(out, sysModuleRoot, "sysfs", errText)
	}
	common.TimelineFileStat(out, "kernel", sysModuleRoot, "ai/"+modulesRel)

	entries, err := os.ReadDir(sysModuleRoot)
	if err != nil {
		_ = out.Error(evidence.ErrorEvent{Collector: "kernel", Error: err.Error(), SourcePath: sysModuleRoot, SourceType: "sysfs", SourceTrust: "high", RawArtifactRef: "ai/" + modulesRel})
		return nil
	}
	modulePaths := modulePathIndex(out)
	for _, entry := range entries {
		if !entry.IsDir() || loaded[entry.Name()] {
			continue
		}
		module := Module{
			Exists:    true,
			Name:      entry.Name(),
			SysfsPath: filepath.Join(sysModuleRoot, entry.Name()),
		}
		enrichModule(&module, modulePaths)
		common.TimelineFileStat(out, "kernel", module.SysfsPath, "ai/"+modulesRel)
		module.RecordMeta = out.Meta("kernel", modulesRel, module.SysfsPath, "sysfs", "high")
		fillModuleEntity(&module)
		if err := out.AppendAIJSONL(modulesRel, module, "kernel", module.SysfsPath, "sysfs", "high"); err != nil {
			return err
		}
		if err := appendKernelConsistency(out, module, module.SysfsPath); err != nil {
			return err
		}
	}
	return nil
}

func collectCmdline(out *output.Manager) error {
	path, text, err := common.ReadFirstExisting(procCmdlinePath)
	if err != nil {
		_ = out.Error(evidence.ErrorEvent{Collector: "kernel", Error: err.Error(), SourcePath: procCmdlinePath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "legacy/system/kernel/cmdline"})
		return nil
	}
	if err := out.WriteLegacyFromSource("system/kernel/cmdline", []byte(text), "kernel", path, "procfs", "high"); err != nil {
		return err
	}
	common.TimelineFileStat(out, "kernel", path, "legacy/system/kernel/cmdline")
	return nil
}

func collectTainted(out *output.Manager) error {
	path, text, err := common.ReadFirstExisting(procTaintedPath)
	if err != nil {
		_ = out.Error(evidence.ErrorEvent{Collector: "kernel", Error: err.Error(), SourcePath: procTaintedPath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "legacy/system/kernel/tainted"})
		return nil
	}
	if err := out.WriteLegacyFromSource("system/kernel/tainted", []byte(text), "kernel", path, "procfs", "high"); err != nil {
		return err
	}
	common.TimelineFileStat(out, "kernel", path, "legacy/system/kernel/tainted")
	return nil
}

func collectKernelSecurity(out *output.Manager) error {
	for _, item := range []struct {
		path     string
		factType string
		key      string
	}{
		{procCmdlinePath, "cmdline", "cmdline"},
		{procTaintedPath, "tainted", "tainted"},
		{lockdownPath, "lockdown", "lockdown"},
		{lsmPath, "lsm", "lsm"},
		{apparmorPath, "apparmor", "apparmor_enabled"},
		{selinuxPath, "selinux", "selinux_enforce"},
		{kptrRestrictPath, "sysctl", "kernel.kptr_restrict"},
		{dmesgRestrictPath, "sysctl", "kernel.dmesg_restrict"},
		{modulesDisabledPath, "sysctl", "kernel.modules_disabled"},
	} {
		if err := appendKernelSecurityFact(out, item.path, item.factType, item.key); err != nil {
			return err
		}
	}
	return nil
}

func appendKernelSecurityFact(out *output.Manager, path, factType, key string) error {
	text, err := common.ReadText(path)
	record := SecurityFact{
		RecordMeta: out.Meta("kernel", kernelSecurityRel, path, kernelSourceType(path), "high"),
		Exists:     err == nil,
		FactType:   factType,
		Key:        key,
		SourceFile: path,
		Sensitive:  false,
	}
	if err != nil {
		record.AbsentReason = err.Error()
	} else {
		record.Value = strings.TrimSpace(text)
		common.TimelineFileStat(out, "kernel", path, "ai/"+kernelSecurityRel)
	}
	return out.AppendAIJSONL(kernelSecurityRel, record, "kernel", path, kernelSourceType(path), "high")
}

func appendKernelConsistency(out *output.Manager, module Module, sourcePath string) error {
	record := ConsistencyFact{
		RecordMeta:         out.Meta("kernel", kernelConsistencyRel, sourcePath, "generated", "high"),
		Exists:             true,
		ModuleName:         module.Name,
		Loaded:             true,
		ProcModulesPresent: sourcePath != module.SysfsPath,
		SysfsPresent:       module.SysfsPath != "",
		SysfsPath:          module.SysfsPath,
		ModulePath:         module.ModulePath,
		Holders:            module.Holders,
		RefCount:           module.RefCount,
		UsedBy:             module.UsedBy,
		SourceProcModules:  procModulesPath,
		SourceSysfsPath:    module.SysfsPath,
	}
	if sourcePath == module.SysfsPath {
		record.SourceProcModules = ""
	}
	if module.ModulePath != "" {
		record.SourceModulesDep = filepath.Join(libModulesRoot, strings.TrimSpace(readTrimmed(kernelReleasePath)), "modules.dep")
		record.SourceModuleFile = module.ModulePath
		fillModuleFileFacts(&record, module.ModulePath)
	} else {
		record.ModuleFileError = "module path unavailable"
	}
	record.SourceFacts = kernelConsistencySourceFacts(record)
	return out.AppendAIJSONL(kernelConsistencyRel, record, "kernel", sourcePath, "generated", "high")
}

func kernelSourceType(path string) string {
	switch {
	case strings.Contains(path, "/proc/") || strings.HasPrefix(path, "/proc/"):
		return "procfs"
	case strings.Contains(path, "/sys/") || strings.HasPrefix(path, "/sys/"):
		return "sysfs"
	default:
		return "file"
	}
}

func fillModuleFileFacts(record *ConsistencyFact, path string) {
	info, err := os.Lstat(path)
	if err != nil {
		record.ModuleFileExists = false
		record.ModuleFileError = err.Error()
		return
	}
	record.ModuleFileExists = true
	record.ModuleFileSize = info.Size()
	sum, err := fileSHA256(path)
	if err != nil {
		record.ModuleFileError = err.Error()
		return
	}
	record.ModuleFileSHA256 = sum
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func kernelConsistencySourceFacts(record ConsistencyFact) []string {
	var facts []string
	if record.SourceProcModules != "" {
		facts = append(facts, "proc_modules")
	}
	if record.SourceSysfsPath != "" {
		facts = append(facts, "sysfs_module")
	}
	if record.SourceModulesDep != "" {
		facts = append(facts, "modules_dep")
	}
	if record.SourceModuleFile != "" {
		facts = append(facts, "module_file")
	}
	return facts
}

func writeAbsentModule(out *output.Manager, sourcePath, sourceType, reason string) error {
	module := Module{
		RecordMeta:   out.Meta("kernel", modulesRel, sourcePath, sourceType, "high"),
		Exists:       false,
		AbsentReason: reason,
	}
	return out.AppendAIJSONL(modulesRel, module, "kernel", sourcePath, sourceType, "high")
}

func fillModuleEntity(module *Module) {
	if module.Name == "" {
		return
	}
	module.EntityType = "kernel_module"
	module.EntityID = "kernel_module:" + module.Name
}

func ParseProcModules(text string) []Module {
	var modules []Module
	for _, line := range common.Lines(text) {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		size, errSize := strconv.ParseInt(fields[1], 10, 64)
		refCount, errRef := strconv.Atoi(fields[2])
		if errSize != nil || errRef != nil {
			continue
		}
		module := Module{
			Name:     fields[0],
			Size:     size,
			RefCount: refCount,
		}
		if len(fields) > 3 && fields[3] != "-" {
			module.UsedBy = splitCommaList(strings.TrimSuffix(fields[3], ","))
		}
		if len(fields) > 4 {
			module.State = fields[4]
		}
		if len(fields) > 5 {
			module.Address = fields[5]
		}
		modules = append(modules, module)
	}
	return modules
}

func enrichModule(module *Module, modulePaths map[string]string) {
	sysfsPath := filepath.Join(sysModuleRoot, module.Name)
	if stat, err := os.Stat(sysfsPath); err == nil && stat.IsDir() {
		module.SysfsPath = sysfsPath
		module.Version = readTrimmed(filepath.Join(sysfsPath, "version"))
		module.SrcVersion = readTrimmed(filepath.Join(sysfsPath, "srcversion"))
		module.Holders = readDirNames(filepath.Join(sysfsPath, "holders"))
	}
	if modulePaths != nil {
		module.ModulePath = modulePaths[normalizeModuleName(module.Name)]
	}
}

func splitCommaList(value string) []string {
	if value == "" {
		return nil
	}
	raw := strings.Split(value, ",")
	items := make([]string, 0, len(raw))
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item != "" && item != "-" {
			items = append(items, item)
		}
	}
	return items
}

func readTrimmed(path string) string {
	text, err := common.ReadText(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(text)
}

func readDirNames(path string) []string {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func modulePathIndex(out *output.Manager) map[string]string {
	release := readTrimmed(kernelReleasePath)
	if release == "" {
		_ = out.Error(evidence.ErrorEvent{Collector: "kernel", Error: "kernel release unavailable for module path mapping", SourcePath: kernelReleasePath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/" + modulesRel})
		return nil
	}
	base := filepath.Join(libModulesRoot, release)
	depPath := filepath.Join(base, "modules.dep")
	text, err := common.ReadText(depPath)
	if err != nil {
		_ = out.Error(evidence.ErrorEvent{Collector: "kernel", Error: err.Error(), SourcePath: depPath, SourceType: "file", SourceTrust: "high", RawArtifactRef: "ai/" + modulesRel})
		return nil
	}
	index := map[string]string{}
	for _, line := range common.Lines(text) {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 0 || parts[0] == "" {
			continue
		}
		rel := parts[0]
		name := moduleNameFromPath(rel)
		if name != "" {
			index[name] = filepath.Join(base, rel)
		}
	}
	return index
}

func moduleNameFromPath(path string) string {
	base := filepath.Base(path)
	for _, suffix := range []string{".ko.xz", ".ko.zst", ".ko.gz", ".ko"} {
		if strings.HasSuffix(base, suffix) {
			base = strings.TrimSuffix(base, suffix)
			break
		}
	}
	return normalizeModuleName(base)
}

func normalizeModuleName(name string) string {
	return strings.ReplaceAll(name, "-", "_")
}
