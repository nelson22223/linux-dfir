package output

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"linux-dfir/internal/evidence"
	"linux-dfir/internal/session"
)

func TestSafeJoinRejectsEscape(t *testing.T) {
	root := t.TempDir()
	if _, err := SafeJoin(root, "../escape"); err == nil {
		t.Fatal("expected parent escape to be rejected")
	}
	if _, err := SafeJoin(root, "/tmp/escape"); err == nil {
		t.Fatal("expected absolute path to be rejected")
	}
	if got, err := SafeJoin(root, "ai/manifest.json"); err != nil || got != filepath.Join(root, "ai/manifest.json") {
		t.Fatalf("safe path mismatch got=%s err=%v", got, err)
	}
}

func TestManagerRejectsSymlinkOutputComponents(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "legacy")); err != nil {
		t.Fatal(err)
	}
	sess, err := session.New("case-1", time.Date(2026, 6, 2, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(root, "dual", sess); err == nil {
		t.Fatal("expected symlinked output component to be rejected")
	}
	if _, err := os.Stat(filepath.Join(outside, "SUMMARY")); !os.IsNotExist(err) {
		t.Fatalf("unexpected write outside output root, stat err=%v", err)
	}
}

func TestManagerWritesJSONLAndManifest(t *testing.T) {
	sess, err := session.New("case-1", time.Date(2026, 6, 2, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	manager, err := New(root, "dual", sess)
	if err != nil {
		t.Fatal(err)
	}

	if err := manager.LogEvent(evidence.CollectionEvent{Event: "session_start"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.LogEvent(evidence.CollectionEvent{Event: "session_end"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Timeline(evidence.TimelineEvent{EventType: "session_start"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Error(evidence.ErrorEvent{Collector: "test", Error: "sample error", SourcePath: "/missing", SourceType: "file", SourceTrust: "high"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.WriteLegacy("SUMMARY", []byte("summary\n"), "session"); err != nil {
		t.Fatal(err)
	}
	if err := manager.WriteLegacy("SUMMARY", []byte("summary updated\n"), "session"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Finalize("dual", "phase1", []string{"session"}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	assertEvidenceJSONL(t, filepath.Join(root, "ai/evidence.jsonl"), 4)

	data, err := os.ReadFile(filepath.Join(root, "ai/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest evidence.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.ArtifactCount == 0 {
		t.Fatal("manifest has no artifacts")
	}
	if manifest.ArtifactCount != len(manifest.Artifacts) {
		t.Fatalf("manifest artifact count mismatch: %d vs %d", manifest.ArtifactCount, len(manifest.Artifacts))
	}

	seenSummary := 0
	seenIndex := 0
	seenManifest := 0
	for _, artifact := range manifest.Artifacts {
		if artifact.Path == "legacy/SUMMARY" {
			seenSummary++
		}
		if artifact.Path == "ai/artifact_index.json" {
			seenIndex++
		}
		if artifact.Path == "ai/manifest.json" {
			seenManifest++
		}
		if artifact.ArtifactID == "" || artifact.SHA256 == "" || artifact.Collector == "" || artifact.SourceType == "" {
			t.Fatalf("artifact missing required field: %+v", artifact)
		}
	}
	if seenSummary != 1 {
		t.Fatalf("duplicate artifact handling failed, saw legacy/SUMMARY %d times", seenSummary)
	}
	if seenIndex != 1 {
		t.Fatalf("manifest must index artifact_index.json once, saw %d", seenIndex)
	}
	if seenManifest != 0 {
		t.Fatalf("manifest must not self-index, saw %d", seenManifest)
	}

	data, err = os.ReadFile(filepath.Join(root, "ai/artifact_index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var index evidence.ArtifactIndex
	if err := json.Unmarshal(data, &index); err != nil {
		t.Fatal(err)
	}
	for _, artifact := range index.Artifacts {
		if artifact.Path == "ai/artifact_index.json" || artifact.Path == "ai/manifest.json" {
			t.Fatalf("artifact index should not include control file %s", artifact.Path)
		}
	}
}

func TestManagerMirrorsAIRecordsToSingleEvidenceStream(t *testing.T) {
	sess, err := session.New("case-1", time.Date(2026, 6, 2, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	manager, err := New(root, "dual", sess)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.AppendAIJSONL("parsed/processes.jsonl", map[string]any{"pid": 123, "name": "sshd"}, "process", "/proc/123", "procfs", "high"); err != nil {
		t.Fatal(err)
	}
	if err := manager.AppendAIJSONL("host_profile.jsonl", map[string]string{"hostname": "test-host"}, "host", "/etc/os-release", "file", "high"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Finalize("dual", "phase-test", []string{"host", "process"}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	records := readEvidenceRecords(t, filepath.Join(root, "ai/evidence.jsonl"))
	if len(records) != 2 {
		t.Fatalf("evidence stream record count mismatch: got %d want 2", len(records))
	}
	if records[0]["record_type"] != "processes" || records[0]["stream"] != "parsed/processes" {
		t.Fatalf("parsed jsonl was not mirrored correctly: %+v", records[0])
	}
	firstData, ok := records[0]["data"].(map[string]any)
	if !ok {
		t.Fatalf("evidence data is not an object: %+v", records[0]["data"])
	}
	for _, key := range []string{"schema_version", "artifact_id", "case_id", "host_id", "session_id", "collector", "source_path", "source_type", "source_trust", "collected_at", "raw_artifact_ref"} {
		if _, ok := firstData[key]; ok {
			t.Fatalf("evidence data should not duplicate envelope key %s: %+v", key, firstData)
		}
	}
	if records[1]["record_type"] != "host_profile" || records[1]["collector"] != "host" {
		t.Fatalf("host profile evidence was not mirrored correctly: %+v", records[1])
	}
	if _, err := os.Stat(filepath.Join(root, "ai/parsed/processes.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("module jsonl sidecar should not exist: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(root, "ai/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest evidence.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	seenEvidence := false
	for _, artifact := range manifest.Artifacts {
		if artifact.Path == "ai/evidence.jsonl" {
			seenEvidence = true
		}
		if artifact.Path == "ai/manifest.json" {
			t.Fatal("manifest should not self-index")
		}
	}
	if !seenEvidence {
		t.Fatal("manifest did not index ai/evidence.jsonl")
	}
}

func TestWriteAIJSONRejectsNonControlFiles(t *testing.T) {
	sess, err := session.New("case-1", time.Date(2026, 6, 2, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	manager, err := New(root, "dual", sess)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.WriteAIJSON("parsed/sample.json", map[string]string{"hostname": "test-host"}, "host"); err == nil {
		t.Fatal("expected non-control AI JSON file to be rejected")
	}
	if _, err := os.Stat(filepath.Join(root, "ai/parsed/sample.json")); !os.IsNotExist(err) {
		t.Fatalf("non-control AI JSON sidecar should not exist: %v", err)
	}
}

func TestAppendAIJSONLMarksMultipleSources(t *testing.T) {
	sess, err := session.New("case-1", time.Date(2026, 6, 2, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	manager, err := New(root, "dual", sess)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.AppendAIJSONL("parsed/multi.jsonl", map[string]string{"a": "1"}, "test", "/source/a", "file", "high"); err != nil {
		t.Fatal(err)
	}
	if err := manager.AppendAIJSONL("parsed/multi.jsonl", map[string]string{"b": "2"}, "test", "/source/b", "procfs", "high"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Finalize("dual", "phase-test", []string{"test"}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	records := readEvidenceRecords(t, filepath.Join(root, "ai/evidence.jsonl"))
	if len(records) != 2 {
		t.Fatalf("evidence stream record count mismatch: got %d want 2", len(records))
	}
	if records[0]["stream"] != "parsed/multi" || records[0]["source_path"] != "/source/a" || records[0]["source_type"] != "file" {
		t.Fatalf("first multi source evidence record mismatch: %+v", records[0])
	}
	if records[1]["stream"] != "parsed/multi" || records[1]["source_path"] != "/source/b" || records[1]["source_type"] != "procfs" {
		t.Fatalf("second multi source evidence record mismatch: %+v", records[1])
	}
	data, err := os.ReadFile(filepath.Join(root, "ai/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest evidence.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, artifact := range manifest.Artifacts {
		if artifact.Path == "ai/parsed/multi.jsonl" {
			t.Fatalf("module jsonl sidecar should not be indexed: %+v", artifact)
		}
	}
}

func assertJSONL(t *testing.T, path string, wantLines int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	lines := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines++
		var obj map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &obj); err != nil {
			t.Fatalf("invalid jsonl line: %v", err)
		}
		for _, key := range []string{"schema_version", "artifact_id", "case_id", "host_id", "session_id", "collector", "source_path", "source_type", "source_trust", "raw_artifact_ref"} {
			if obj[key] == nil || obj[key] == "" {
				t.Fatalf("jsonl missing required key %s in %s", key, path)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if lines != wantLines {
		t.Fatalf("line count mismatch for %s: got %d want %d", path, lines, wantLines)
	}
}

func assertEvidenceJSONL(t *testing.T, path string, wantLines int) {
	t.Helper()
	records := readEvidenceRecords(t, path)
	if len(records) != wantLines {
		t.Fatalf("line count mismatch for %s: got %d want %d", path, len(records), wantLines)
	}
	for _, obj := range records {
		for _, key := range []string{"schema_version", "artifact_id", "case_id", "host_id", "session_id", "collector", "record_type", "stream", "source_path", "source_type", "source_trust", "raw_artifact_ref", "data"} {
			if obj[key] == nil || obj[key] == "" {
				t.Fatalf("evidence jsonl missing required key %s in %s", key, path)
			}
		}
	}
}

func readEvidenceRecords(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var records []map[string]any
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var obj map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &obj); err != nil {
			t.Fatalf("invalid evidence jsonl line: %v", err)
		}
		records = append(records, obj)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return records
}
