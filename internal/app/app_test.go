package app

import (
	"testing"
	"time"
)

func TestDefaultOutputDirUsesTimestamp(t *testing.T) {
	now := time.Date(2026, 6, 9, 10, 11, 12, 0, time.UTC)
	if got := defaultOutputDir(now); got != "dfir_20260609101112" {
		t.Fatalf("default output dir mismatch: %s", got)
	}
}
