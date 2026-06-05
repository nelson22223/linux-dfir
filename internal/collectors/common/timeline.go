package common

import (
	"os"

	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
)

func TimelineFileStat(out *output.Manager, collector, sourcePath, rawArtifactRef string) {
	stat, err := os.Lstat(sourcePath)
	if err != nil {
		_ = out.Error(evidence.ErrorEvent{
			Collector:      collector,
			Error:          err.Error(),
			SourcePath:     sourcePath,
			SourceType:     sourceTypeForPath(sourcePath),
			SourceTrust:    "high",
			RawArtifactRef: rawArtifactRef,
		})
		return
	}
	_ = out.Timeline(evidence.TimelineEvent{
		Collector:      collector,
		EventType:      "file_metadata",
		Timestamp:      stat.ModTime().UTC(),
		SourcePath:     sourcePath,
		SourceType:     sourceTypeForPath(sourcePath),
		SourceTrust:    "high",
		RawArtifactRef: rawArtifactRef,
		Summary:        sourcePath,
	})
}

func sourceTypeForPath(path string) string {
	if len(path) >= 6 && path[:6] == "/proc/" {
		return "procfs"
	}
	if len(path) >= 5 && path[:5] == "/sys/" {
		return "sysfs"
	}
	return "file"
}
