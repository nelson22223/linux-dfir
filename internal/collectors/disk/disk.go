package disk

import (
	"context"
	"path/filepath"
	"strings"

	"linux-dfir/internal/collectors/common"
	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
)

const (
	mountsRel    = "facts/mounts.jsonl"
	mountinfoRel = "facts/mountinfo.jsonl"
)

type Mount struct {
	evidence.RecordMeta
	Source     string   `json:"source"`
	Target     string   `json:"target"`
	FSType     string   `json:"fs_type"`
	Options    []string `json:"options"`
	Dump       string   `json:"dump,omitempty"`
	Pass       string   `json:"pass,omitempty"`
	MountID    string   `json:"mount_id,omitempty"`
	ParentID   string   `json:"parent_id,omitempty"`
	MajorMinor string   `json:"major_minor,omitempty"`
}

func Collect(ctx context.Context, out *output.Manager) error {
	_ = ctx
	if path, text, err := common.ReadFirstExisting("/proc/mounts", "/etc/mtab"); err == nil {
		if err := out.WriteLegacyFromSource("system/disks/mounts.out", []byte(text), "disk", path, sourceType(path), "high"); err != nil {
			return err
		}
		common.TimelineFileStat(out, "disk", path, "legacy/system/disks/mounts.out")
		for _, item := range ParseMounts(text) {
			item.RecordMeta = out.Meta("disk", mountsRel, path, sourceType(path), "high")
			if err := out.AppendAIJSONL(mountsRel, item, "disk", path, sourceType(path), "high"); err != nil {
				return err
			}
		}
	} else {
		_ = out.Error(evidence.ErrorEvent{Collector: "disk", Error: err.Error(), SourcePath: "/proc/mounts", SourceType: "procfs", SourceTrust: "high"})
	}

	if path, text, err := common.ReadFirstExisting("/proc/self/mountinfo"); err == nil {
		if err := out.WriteLegacyFromSource("system/disks/mountinfo.out", []byte(text), "disk", path, "procfs", "high"); err != nil {
			return err
		}
		common.TimelineFileStat(out, "disk", path, "legacy/system/disks/mountinfo.out")
		for _, item := range ParseMountInfo(text) {
			item.RecordMeta = out.Meta("disk", mountinfoRel, path, "procfs", "high")
			if err := out.AppendAIJSONL(mountinfoRel, item, "disk", path, "procfs", "high"); err != nil {
				return err
			}
		}
	} else {
		_ = out.Error(evidence.ErrorEvent{Collector: "disk", Error: err.Error(), SourcePath: "/proc/self/mountinfo", SourceType: "procfs", SourceTrust: "high"})
	}
	return nil
}

func ParseMounts(text string) []Mount {
	var result []Mount
	for _, line := range common.Lines(text) {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		item := Mount{
			Source:  unescape(fields[0]),
			Target:  unescape(fields[1]),
			FSType:  fields[2],
			Options: strings.Split(fields[3], ","),
		}
		if len(fields) > 4 {
			item.Dump = fields[4]
		}
		if len(fields) > 5 {
			item.Pass = fields[5]
		}
		result = append(result, item)
	}
	return result
}

func ParseMountInfo(text string) []Mount {
	var result []Mount
	for _, line := range common.Lines(text) {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		sep := -1
		for i, field := range fields {
			if field == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || len(fields) <= sep+3 {
			continue
		}
		result = append(result, Mount{
			MountID:    fields[0],
			ParentID:   fields[1],
			MajorMinor: fields[2],
			Target:     unescape(fields[4]),
			Options:    strings.Split(fields[5], ","),
			FSType:     fields[sep+1],
			Source:     unescape(fields[sep+2]),
		})
	}
	return result
}

func unescape(value string) string {
	return strings.ReplaceAll(value, `\040`, " ")
}

func sourceType(path string) string {
	path = filepath.ToSlash(path)
	if strings.HasPrefix(path, "/proc/") {
		return "procfs"
	}
	return "file"
}
