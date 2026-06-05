package timeline

import (
	"time"

	"linux-dfir/internal/evidence"
)

func SessionEvent(eventType, summary string, at time.Time) evidence.TimelineEvent {
	return evidence.TimelineEvent{
		Collector:      "session",
		EventType:      eventType,
		Timestamp:      at,
		SourcePath:     "generated",
		SourceType:     "generated",
		SourceTrust:    "high",
		RawArtifactRef: "ai/timeline.jsonl",
		Summary:        summary,
	}
}
