package system

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"linux-dfir/internal/collectors/common"
	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
)

type MemInfo struct {
	evidence.RecordMeta
	Key   string `json:"key"`
	Value int64  `json:"value"`
	Unit  string `json:"unit,omitempty"`
}

type CPUInfo struct {
	evidence.RecordMeta
	Processor string            `json:"processor,omitempty"`
	Fields    map[string]string `json:"fields"`
}

func Collect(ctx context.Context, out *output.Manager) error {
	if err := writeNativeVMStat(ctx, out); err != nil {
		return err
	}
	if path, text, err := common.ReadFirstExisting("/proc/meminfo"); err == nil {
		if err := out.WriteLegacyFromSource("system/proc_meminfo.out", []byte(text), "system", path, "procfs", "high"); err != nil {
			return err
		}
		common.TimelineFileStat(out, "system", path, "legacy/system/proc_meminfo.out")
	} else {
		_ = out.Error(evidence.ErrorEvent{Collector: "system", Error: err.Error(), SourcePath: "/proc/meminfo", SourceType: "procfs", SourceTrust: "high"})
	}

	if path, text, err := common.ReadFirstExisting("/proc/cpuinfo"); err == nil {
		if err := out.WriteLegacyFromSource("system/cpuinfo.out", []byte(text), "system", path, "procfs", "high"); err != nil {
			return err
		}
		common.TimelineFileStat(out, "system", path, "legacy/system/cpuinfo.out")
	} else {
		_ = out.Error(evidence.ErrorEvent{Collector: "system", Error: err.Error(), SourcePath: "/proc/cpuinfo", SourceType: "procfs", SourceTrust: "high"})
	}
	return nil
}

func writeNativeVMStat(ctx context.Context, out *output.Manager) error {
	result := common.RunCommand(ctx, "vmstat", "-s")
	if result.Missing() {
		_ = out.Error(evidence.ErrorEvent{Collector: "system", Error: result.Err.Error(), SourcePath: "vmstat -s", SourceType: "native_command", SourceTrust: "medium", RawArtifactRef: "legacy/system/vmstat_-s.out"})
		return nil
	}
	if result.Err != nil {
		_ = out.Error(evidence.ErrorEvent{Collector: "system", Error: result.Err.Error(), SourcePath: result.CommandLine(), SourceType: "native_command", SourceTrust: "medium", RawArtifactRef: "legacy/system/vmstat_-s.out"})
	}
	if len(result.Output) == 0 {
		return nil
	}
	return out.WriteLegacyFromSource("system/vmstat_-s.out", result.Output, "system", result.CommandLine(), "native_command", "medium")
}

func ParseMemInfo(text string) []MemInfo {
	var result []MemInfo
	for _, line := range common.Lines(text) {
		parts := strings.Fields(strings.TrimSuffix(line, ":"))
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSuffix(parts[0], ":")
		value, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			continue
		}
		item := MemInfo{Key: key, Value: value}
		if len(parts) > 2 {
			item.Unit = parts[2]
		}
		result = append(result, item)
	}
	return result
}

func ParseCPUInfo(text string) []CPUInfo {
	blocks := strings.Split(strings.TrimSpace(text), "\n\n")
	result := make([]CPUInfo, 0, len(blocks))
	for _, block := range blocks {
		fields := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if !strings.Contains(line, ":") {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			fields[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
		if len(fields) == 0 {
			continue
		}
		result = append(result, CPUInfo{Processor: fmt.Sprint(fields["processor"]), Fields: fields})
	}
	return result
}
