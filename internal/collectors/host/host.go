package host

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"linux-dfir/internal/collectors/common"
	systemcollector "linux-dfir/internal/collectors/system"
	"linux-dfir/internal/evidence"
	"linux-dfir/internal/integrity"
	"linux-dfir/internal/output"
)

type Profile struct {
	evidence.RecordMeta
	Hostname      string            `json:"hostname"`
	OS            string            `json:"os"`
	OSName        string            `json:"os_name"`
	OSVersion     string            `json:"os_version"`
	Kernel        string            `json:"kernel"`
	Arch          string            `json:"arch"`
	CPUCount      int               `json:"cpu_count"`
	MemoryKB      int64             `json:"memory_kb,omitempty"`
	UptimeSeconds float64           `json:"uptime_seconds,omitempty"`
	OSRelease     map[string]string `json:"os_release,omitempty"`
}

type HostEntity struct {
	evidence.RecordMeta
	EntityType    string               `json:"entity_type"`
	EntityID      string               `json:"entity_id"`
	Hostname      string               `json:"hostname"`
	OS            string               `json:"os"`
	OSName        string               `json:"os_name"`
	OSVersion     string               `json:"os_version"`
	Kernel        string               `json:"kernel"`
	Arch          string               `json:"arch"`
	CPUCount      int                  `json:"cpu_count"`
	MemoryKB      int64                `json:"memory_kb,omitempty"`
	UptimeSeconds float64              `json:"uptime_seconds,omitempty"`
	OSRelease     map[string]string    `json:"os_release,omitempty"`
	Resources     HostResources        `json:"resources,omitempty"`
	SSHHostKeys   []SSHHostKeyFact     `json:"ssh_host_keys,omitempty"`
	Sources       []evidence.SourceRef `json:"sources,omitempty"`
}

type HostResources struct {
	MemInfo map[string]MemInfoValue `json:"meminfo,omitempty"`
	CPUInfo []CPUInfoFact           `json:"cpuinfo,omitempty"`
}

type MemInfoValue struct {
	Value int64  `json:"value"`
	Unit  string `json:"unit,omitempty"`
}

type CPUInfoFact struct {
	Processor string            `json:"processor,omitempty"`
	Fields    map[string]string `json:"fields"`
}

type SSHHostKeyFact struct {
	Path       string `json:"path"`
	Exists     bool   `json:"exists"`
	Size       int64  `json:"size,omitempty"`
	Mode       string `json:"mode,omitempty"`
	ModifiedAt string `json:"modified_at,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	HashError  string `json:"hash_error,omitempty"`
}

func Collect(ctx context.Context, out *output.Manager) error {
	_ = ctx
	profile := BuildProfile(out)

	summary := fmt.Sprintf("Linux DFIR Collector\nHost: %s\nOS: %s %s\nKernel: %s\nArch: %s\nCPU: %d\nMemoryKB: %d\n",
		profile.Hostname, profile.OSName, profile.OSVersion, profile.Kernel, profile.Arch, profile.CPUCount, profile.MemoryKB)
	if err := out.WriteLegacy("SUMMARY", []byte(summary), "host"); err != nil {
		return err
	}
	uname := fmt.Sprintf("%s %s %s %s\n", profile.OS, profile.Hostname, profile.Kernel, profile.Arch)
	if err := out.WriteLegacy("system/uname_-a.out", []byte(uname), "host"); err != nil {
		return err
	}
	resources, resourceSources := buildHostResources(out)
	keys, err := collectSSHHostKeys(out)
	if err != nil {
		return err
	}
	sources := []evidence.SourceRef{
		{SourcePath: "/etc/os-release", SourceType: "file", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"},
		{SourcePath: "/proc/sys/kernel/osrelease", SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"},
		{SourcePath: "/proc/uptime", SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"},
		{SourcePath: "/etc/ssh/ssh_host_*_key*", SourceType: "file", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"},
	}
	sources = append(sources, resourceSources...)
	entity := HostEntity{
		RecordMeta:    out.Meta("host", "entities/host.jsonl", "/etc/os-release", "file", "high"),
		EntityType:    "host",
		EntityID:      "host:" + profile.Hostname,
		Hostname:      profile.Hostname,
		OS:            profile.OS,
		OSName:        profile.OSName,
		OSVersion:     profile.OSVersion,
		Kernel:        profile.Kernel,
		Arch:          profile.Arch,
		CPUCount:      profile.CPUCount,
		MemoryKB:      profile.MemoryKB,
		UptimeSeconds: profile.UptimeSeconds,
		OSRelease:     profile.OSRelease,
		Resources:     resources,
		SSHHostKeys:   keys,
		Sources:       uniqueSources(sources),
	}
	if err := out.AppendAIJSONL("entities/host.jsonl", entity, "host", "/etc/os-release", "file", "high"); err != nil {
		return err
	}
	return nil
}

func buildHostResources(out *output.Manager) (HostResources, []evidence.SourceRef) {
	resources := HostResources{MemInfo: map[string]MemInfoValue{}}
	sources := []evidence.SourceRef{}
	if path, text, err := common.ReadFirstExisting("/proc/meminfo"); err == nil {
		for _, item := range systemcollector.ParseMemInfo(text) {
			resources.MemInfo[item.Key] = MemInfoValue{Value: item.Value, Unit: item.Unit}
		}
		sources = append(sources, evidence.SourceRef{SourcePath: path, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"})
	}
	if path, text, err := common.ReadFirstExisting("/proc/cpuinfo"); err == nil {
		for _, item := range systemcollector.ParseCPUInfo(text) {
			resources.CPUInfo = append(resources.CPUInfo, CPUInfoFact{Processor: item.Processor, Fields: item.Fields})
		}
		sources = append(sources, evidence.SourceRef{SourcePath: path, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"})
	}
	if len(resources.MemInfo) == 0 {
		resources.MemInfo = nil
	}
	return resources, sources
}

func BuildProfile(out *output.Manager) Profile {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown-host"
	}
	osRelease := map[string]string{}
	if path, text, err := common.ReadFirstExisting("/etc/os-release", "/usr/lib/os-release"); err == nil {
		osRelease = ParseOSRelease(text)
		common.TimelineFileStat(out, "host", path, "ai/host_profile.jsonl")
	} else {
		_ = out.Error(evidence.ErrorEvent{Collector: "host", Error: err.Error(), SourcePath: "/etc/os-release", SourceType: "file", SourceTrust: "high", RawArtifactRef: "ai/host_profile.jsonl"})
	}
	kernel := firstTrimmed(out, "host", "/proc/sys/kernel/osrelease", runtime.GOOS, "ai/host_profile.jsonl")
	memoryKB := parseFirstInt(firstTrimmed(out, "host", "/proc/meminfo", "", "ai/host_profile.jsonl"))
	uptimeSeconds := parseUptime(firstTrimmed(out, "host", "/proc/uptime", "", "ai/host_profile.jsonl"))

	return Profile{
		RecordMeta:    out.Meta("host", "host_profile.jsonl", "/etc/os-release", "file", "high"),
		Hostname:      hostname,
		OS:            runtime.GOOS,
		OSName:        firstNonEmpty(osRelease["PRETTY_NAME"], osRelease["NAME"], runtime.GOOS),
		OSVersion:     firstNonEmpty(osRelease["VERSION_ID"], osRelease["VERSION"]),
		Kernel:        kernel,
		Arch:          runtime.GOARCH,
		CPUCount:      runtime.NumCPU(),
		MemoryKB:      memoryKB,
		UptimeSeconds: uptimeSeconds,
		OSRelease:     osRelease,
	}
}

func ParseOSRelease(text string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		values[key] = value
	}
	return values
}

func firstTrimmed(out *output.Manager, collector, path, fallback, rawArtifactRef string) string {
	text, err := common.ReadText(path)
	if err != nil {
		_ = out.Error(evidence.ErrorEvent{Collector: collector, Error: err.Error(), SourcePath: path, SourceType: sourceType(path), SourceTrust: "high", RawArtifactRef: rawArtifactRef})
		return fallback
	}
	common.TimelineFileStat(out, collector, path, rawArtifactRef)
	return strings.TrimSpace(text)
}

func parseFirstInt(text string) int64 {
	fields := strings.Fields(text)
	for _, field := range fields {
		if value, err := strconv.ParseInt(field, 10, 64); err == nil {
			return value
		}
	}
	return 0
}

func parseUptime(text string) float64 {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return 0
	}
	value, _ := strconv.ParseFloat(fields[0], 64)
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func collectSSHHostKeys(out *output.Manager) ([]SSHHostKeyFact, error) {
	paths, err := filepath.Glob("/etc/ssh/ssh_host_*_key*")
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return []SSHHostKeyFact{{
			Path:   "/etc/ssh/ssh_host_*_key*",
			Exists: false,
		}}, nil
	}
	items := make([]SSHHostKeyFact, 0, len(paths))
	for _, path := range paths {
		stat, err := os.Lstat(path)
		item := SSHHostKeyFact{
			Path:   path,
			Exists: err == nil,
		}
		if err == nil {
			item.Size = stat.Size()
			item.Mode = stat.Mode().String()
			item.ModifiedAt = stat.ModTime().UTC().Format(time.RFC3339Nano)
			if hash, hashErr := integrity.HashFile(path); hashErr == nil {
				item.SHA256 = hash.SHA256
			} else {
				item.HashError = hashErr.Error()
			}
			common.TimelineFileStat(out, "host", path, "ai/evidence.jsonl")
		} else {
			_ = out.Error(evidence.ErrorEvent{Collector: "host", Error: err.Error(), SourcePath: path, SourceType: "file", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"})
		}
		items = append(items, item)
	}
	return items, nil
}

func sourceType(path string) string {
	if strings.HasPrefix(path, "/proc/") {
		return "procfs"
	}
	return "file"
}

func uniqueSources(sources []evidence.SourceRef) []evidence.SourceRef {
	seen := map[string]bool{}
	result := []evidence.SourceRef{}
	for _, source := range sources {
		key := source.SourcePath + "\x00" + source.SourceType + "\x00" + source.SourceTrust + "\x00" + source.RawArtifactRef
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, source)
	}
	return result
}
