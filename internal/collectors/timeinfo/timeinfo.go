package timeinfo

import (
	"context"
	"os"
	"time"

	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
)

const timeRel = "facts/time.jsonl"

type TimeInfo struct {
	evidence.RecordMeta
	NowUTC              time.Time `json:"now_utc"`
	NowLocal            time.Time `json:"now_local"`
	LocalTimezone       string    `json:"local_timezone"`
	LocaltimeExists     bool      `json:"localtime_exists"`
	LocaltimeSize       int64     `json:"localtime_size,omitempty"`
	LocaltimeMode       string    `json:"localtime_mode,omitempty"`
	LocaltimeModifiedAt time.Time `json:"localtime_modified_at,omitempty"`
}

func Collect(ctx context.Context, out *output.Manager) error {
	_ = ctx
	info := Build(out)
	if err := out.AppendAIJSONL(timeRel, info, "time", "/etc/localtime", "file", "high"); err != nil {
		return err
	}
	return out.WriteLegacyFromSource("system/time/localtime.json", []byte(legacyTime(info)), "time", "/etc/localtime", "file", "high")
}

func Build(out *output.Manager) TimeInfo {
	now := time.Now()
	name, _ := now.Zone()
	info := TimeInfo{
		RecordMeta:          out.Meta("time", timeRel, "/etc/localtime", "file", "high"),
		NowUTC:              now.UTC(),
		NowLocal:            now,
		LocalTimezone:       name,
		LocaltimeExists:     false,
		LocaltimeMode:       "",
		LocaltimeSize:       0,
		LocaltimeModifiedAt: time.Time{},
	}
	if stat, err := os.Lstat("/etc/localtime"); err == nil {
		info.LocaltimeExists = true
		info.LocaltimeSize = stat.Size()
		info.LocaltimeMode = stat.Mode().String()
		info.LocaltimeModifiedAt = stat.ModTime().UTC()
		_ = out.Timeline(evidence.TimelineEvent{
			Collector:      "time",
			EventType:      "file_metadata",
			Timestamp:      stat.ModTime().UTC(),
			SourcePath:     "/etc/localtime",
			SourceType:     "file",
			SourceTrust:    "high",
			RawArtifactRef: "ai/" + timeRel,
			Summary:        "/etc/localtime",
		})
	} else {
		_ = out.Error(evidence.ErrorEvent{Collector: "time", Error: err.Error(), SourcePath: "/etc/localtime", SourceType: "file", SourceTrust: "high"})
	}
	return info
}

func legacyTime(info TimeInfo) string {
	return "{\n  \"now_utc\": \"" + info.NowUTC.Format(time.RFC3339Nano) + "\",\n  \"local_timezone\": \"" + info.LocalTimezone + "\"\n}\n"
}
