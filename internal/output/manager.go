package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"linux-dfir/internal/artifact"
	"linux-dfir/internal/evidence"
	"linux-dfir/internal/integrity"
)

type Mode string

const (
	ModeLegacy Mode = "legacy"
	ModeAI     Mode = "ai"
	ModeDual   Mode = "dual"
)

type Manager struct {
	root      string
	mode      Mode
	session   evidence.Session
	artifacts map[string]evidence.Artifact
}

const evidenceStreamRel = "ai/evidence.jsonl"

func New(root string, mode string, sess evidence.Session) (*Manager, error) {
	rootAbs, err := prepareRoot(root)
	if err != nil {
		return nil, err
	}
	m := &Manager{
		root:      rootAbs,
		mode:      Mode(mode),
		session:   sess,
		artifacts: make(map[string]evidence.Artifact),
	}
	if err := m.ensureLayout(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) Root() string {
	return m.root
}

func (m *Manager) ensureLayout() error {
	dirs := []string{
		"legacy",
		"legacy/system",
		"legacy/process",
		"legacy/autorun",
		"legacy/network",
		"legacy/browser",
		"legacy/enum",
		"legacy/filescan",
		"legacy/filerestore",
		"legacy/container",
		"ai",
		"ai/raw",
	}
	for _, rel := range dirs {
		if err := m.safeMkdirAll(rel); err != nil {
			return err
		}
	}
	return nil
}

func prepareRoot(root string) (string, error) {
	if root == "" {
		return "", errors.New("output root is required")
	}
	if info, err := os.Lstat(root); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("output root must not be a symlink: %s", root)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("output root exists and is not a directory: %s", root)
		}
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(root, 0o750); err != nil {
			return "", err
		}
	} else {
		return "", err
	}
	return filepath.Abs(root)
}

func SafeJoin(root, rel string) (string, error) {
	if rel == "" {
		return "", errors.New("relative path is required")
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("absolute output path is not allowed: %s", rel)
	}
	clean := filepath.Clean(rel)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("output path escapes root: %s", rel)
	}
	path := filepath.Join(root, clean)
	rootClean, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	pathClean, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if pathClean != rootClean && !strings.HasPrefix(pathClean, rootClean+string(filepath.Separator)) {
		return "", fmt.Errorf("output path escapes root: %s", rel)
	}
	return path, nil
}

func (m *Manager) WriteLegacy(rel string, data []byte, collector string) error {
	if m.mode == ModeAI {
		return nil
	}
	return m.writeArtifact(filepath.Join("legacy", rel), data, collector, rel, "generated", "high")
}

func (m *Manager) WriteLegacyFromSource(rel string, data []byte, collector, sourcePath, sourceType, sourceTrust string) error {
	if m.mode == ModeAI {
		return nil
	}
	return m.writeArtifact(filepath.Join("legacy", rel), data, collector, sourcePath, sourceType, sourceTrust)
}

func (m *Manager) WriteAIJSON(rel string, value any, collector string) error {
	if m.mode == ModeLegacy {
		return nil
	}
	if !isControlAIJSON(rel) {
		return fmt.Errorf("non-control AI JSON files are not allowed; write structured records to %s: %s", evidenceStreamRel, rel)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := m.writeArtifact(filepath.Join("ai", rel), data, collector, rel, "generated", "high"); err != nil {
		return err
	}
	return nil
}

func (m *Manager) WriteAIFromSource(rel string, data []byte, collector, sourcePath, sourceType, sourceTrust string) error {
	if m.mode == ModeLegacy {
		return nil
	}
	return m.writeArtifact(filepath.Join("ai", rel), data, collector, sourcePath, sourceType, sourceTrust)
}

func (m *Manager) AppendAIJSONL(rel string, value any, collector, sourcePath, sourceType, sourceTrust string) error {
	if m.mode == ModeLegacy {
		return nil
	}
	return m.appendEvidenceRecord(rel, value, collector, sourcePath, sourceType, sourceTrust)
}

func (m *Manager) Meta(collector, rel, sourcePath, sourceType, sourceTrust string) evidence.RecordMeta {
	aiRel := filepath.Join("ai", rel)
	rawArtifactRef := normalizeRawArtifactRef(aiRel)
	now := time.Now().UTC()
	return evidence.RecordMeta{
		SchemaVersion:  evidence.SchemaVersion,
		ArtifactID:     artifact.ID(m.session.SessionID, rawArtifactRef),
		CaseID:         m.session.CaseID,
		HostID:         m.session.HostID,
		SessionID:      m.session.SessionID,
		Collector:      defaultString(collector, "session"),
		SourcePath:     defaultString(sourcePath, rel),
		SourceType:     defaultString(sourceType, "generated"),
		SourceTrust:    defaultString(sourceTrust, "high"),
		CollectedAt:    now,
		RawArtifactRef: rawArtifactRef,
	}
}

func (m *Manager) LogEvent(event evidence.CollectionEvent) error {
	if m.mode == ModeLegacy {
		return nil
	}
	event = m.fillCollectionEvent(event)
	return m.appendEvidenceRecord("collection_log.jsonl", event, event.Collector, event.SourcePath, event.SourceType, event.SourceTrust)
}

func (m *Manager) Timeline(event evidence.TimelineEvent) error {
	if m.mode == ModeLegacy {
		return nil
	}
	now := time.Now().UTC()
	if event.Timestamp.IsZero() {
		event.Timestamp = now
	}
	event.SchemaVersion = evidence.SchemaVersion
	event.ArtifactID = defaultString(event.ArtifactID, artifact.ID(m.session.SessionID, evidenceStreamRel))
	event.CaseID = m.session.CaseID
	event.HostID = m.session.HostID
	event.SessionID = m.session.SessionID
	event.CollectedAt = defaultTime(event.CollectedAt, now)
	if event.Collector == "" {
		event.Collector = "session"
	}
	if event.SourcePath == "" {
		event.SourcePath = "generated"
	}
	if event.SourceType == "" {
		event.SourceType = "generated"
	}
	if event.SourceTrust == "" {
		event.SourceTrust = "high"
	}
	if event.RawArtifactRef == "" {
		event.RawArtifactRef = evidenceStreamRel
	}
	event.RawArtifactRef = normalizeRawArtifactRef(event.RawArtifactRef)
	return m.appendEvidenceRecord("timeline.jsonl", event, event.Collector, event.SourcePath, event.SourceType, event.SourceTrust)
}

func (m *Manager) Error(event evidence.ErrorEvent) error {
	if m.mode == ModeLegacy {
		return nil
	}
	now := time.Now().UTC()
	event.SchemaVersion = evidence.SchemaVersion
	event.ArtifactID = defaultString(event.ArtifactID, artifact.ID(m.session.SessionID, evidenceStreamRel))
	event.CaseID = m.session.CaseID
	event.HostID = m.session.HostID
	event.SessionID = m.session.SessionID
	event.CollectedAt = defaultTime(event.CollectedAt, now)
	if event.Collector == "" {
		event.Collector = "session"
	}
	if event.SourcePath == "" {
		event.SourcePath = "generated"
	}
	if event.SourceType == "" {
		event.SourceType = "generated"
	}
	if event.SourceTrust == "" {
		event.SourceTrust = "high"
	}
	if event.RawArtifactRef == "" {
		event.RawArtifactRef = evidenceStreamRel
	}
	event.RawArtifactRef = normalizeRawArtifactRef(event.RawArtifactRef)
	return m.appendEvidenceRecord("errors.jsonl", event, event.Collector, event.SourcePath, event.SourceType, event.SourceTrust)
}

func (m *Manager) Finalize(outputMode, profileName string, collectors []string, completedAt time.Time) error {
	if completedAt.IsZero() {
		completedAt = time.Now().UTC()
	}

	if err := m.touch(evidenceStreamRel); err != nil {
		return err
	}

	if err := m.registerIfExists(evidenceStreamRel, "session", "generated", "generated", "high"); err != nil {
		return err
	}
	if err := m.refreshArtifactHashes(); err != nil {
		return err
	}

	index := evidence.ArtifactIndex{
		SchemaVersion: evidence.SchemaVersion,
		CaseID:        m.session.CaseID,
		HostID:        m.session.HostID,
		SessionID:     m.session.SessionID,
		Artifacts:     m.sortedArtifacts(),
	}
	if err := m.WriteAIJSON("artifact_index.json", index, "session"); err != nil {
		return err
	}
	if err := m.refreshArtifactHashes(); err != nil {
		return err
	}

	manifestArtifacts := m.sortedArtifacts()
	manifest := evidence.Manifest{
		SchemaVersion: evidence.SchemaVersion,
		CaseID:        m.session.CaseID,
		HostID:        m.session.HostID,
		SessionID:     m.session.SessionID,
		CreatedAt:     m.session.CreatedAt,
		CompletedAt:   completedAt,
		OutputMode:    outputMode,
		Profile:       profileName,
		Collectors:    collectors,
		ArtifactCount: len(manifestArtifacts),
		Artifacts:     manifestArtifacts,
	}
	return m.WriteAIJSON("manifest.json", manifest, "session")
}

func (m *Manager) writeArtifact(rel string, data []byte, collector, sourcePath, sourceType, sourceTrust string) error {
	path, err := SafeJoin(m.root, rel)
	if err != nil {
		return err
	}
	if err := m.safeMkdirAll(filepath.Dir(rel)); err != nil {
		return err
	}
	if err := rejectSymlink(path); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return m.register(rel, collector, sourcePath, sourceType, sourceTrust)
}

func (m *Manager) registerIfExists(rel, collector, sourcePath, sourceType, sourceTrust string) error {
	path, err := SafeJoin(m.root, rel)
	if err != nil {
		return err
	}
	if err := rejectSymlink(path); err != nil {
		return err
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return m.register(rel, collector, sourcePath, sourceType, sourceTrust)
}

func (m *Manager) register(rel, collector, sourcePath, sourceType, sourceTrust string) error {
	path, err := SafeJoin(m.root, rel)
	if err != nil {
		return err
	}
	if err := rejectSymlink(path); err != nil {
		return err
	}
	hash, err := integrity.HashFile(path)
	if err != nil {
		return err
	}
	return m.registerArtifact(rel, collector, sourcePath, sourceType, sourceTrust, hash.Size, hash.SHA256, hash.MD5)
}

func (m *Manager) registerMetadata(rel, collector, sourcePath, sourceType, sourceTrust string) error {
	path, err := SafeJoin(m.root, rel)
	if err != nil {
		return err
	}
	if err := rejectSymlink(path); err != nil {
		return err
	}
	return m.registerArtifact(rel, collector, sourcePath, sourceType, sourceTrust, 0, "", "")
}

func (m *Manager) registerArtifact(rel, collector, sourcePath, sourceType, sourceTrust string, size int64, sha256sum, md5sum string) error {
	if collector == "" {
		collector = "session"
	}
	if sourcePath == "" {
		sourcePath = rel
	}
	if sourceType == "" {
		sourceType = "generated"
	}
	if sourceTrust == "" {
		sourceTrust = "high"
	}
	if existing, ok := m.artifacts[rel]; ok {
		if existing.SourcePath != sourcePath {
			sourcePath = "multiple"
		}
		if existing.SourceType != sourceType {
			sourceType = "generated"
		}
		if existing.SourceTrust != sourceTrust {
			sourceTrust = "medium"
		}
	}
	m.artifacts[rel] = evidence.Artifact{
		ArtifactID:     artifact.ID(m.session.SessionID, rel),
		CaseID:         m.session.CaseID,
		HostID:         m.session.HostID,
		SessionID:      m.session.SessionID,
		Collector:      collector,
		Path:           rel,
		Size:           size,
		SHA256:         sha256sum,
		MD5:            md5sum,
		SourcePath:     sourcePath,
		SourceType:     sourceType,
		SourceTrust:    sourceTrust,
		CollectedAt:    time.Now().UTC(),
		RawArtifactRef: rel,
	}
	return nil
}

func (m *Manager) refreshArtifactHashes() error {
	for rel, item := range m.artifacts {
		path, err := SafeJoin(m.root, rel)
		if err != nil {
			return err
		}
		if err := rejectSymlink(path); err != nil {
			return err
		}
		hash, err := integrity.HashFile(path)
		if err != nil {
			return err
		}
		item.Size = hash.Size
		item.SHA256 = hash.SHA256
		item.MD5 = hash.MD5
		item.CollectedAt = time.Now().UTC()
		m.artifacts[rel] = item
	}
	return nil
}

func (m *Manager) sortedArtifacts() []evidence.Artifact {
	artifacts := make([]evidence.Artifact, 0, len(m.artifacts))
	for _, item := range m.artifacts {
		artifacts = append(artifacts, item)
	}
	sort.Slice(artifacts, func(i, j int) bool {
		return artifacts[i].Path < artifacts[j].Path
	})
	return artifacts
}

func (m *Manager) fillCollectionEvent(event evidence.CollectionEvent) evidence.CollectionEvent {
	now := time.Now().UTC()
	event.SchemaVersion = evidence.SchemaVersion
	event.ArtifactID = defaultString(event.ArtifactID, artifact.ID(m.session.SessionID, evidenceStreamRel))
	event.CaseID = m.session.CaseID
	event.HostID = m.session.HostID
	event.SessionID = m.session.SessionID
	event.CollectedAt = defaultTime(event.CollectedAt, now)
	if event.Collector == "" {
		event.Collector = "session"
	}
	if event.Event == "" {
		event.Event = "event"
	}
	if event.Status == "" {
		event.Status = "ok"
	}
	if event.SourcePath == "" {
		event.SourcePath = "generated"
	}
	if event.SourceType == "" {
		event.SourceType = "generated"
	}
	if event.SourceTrust == "" {
		event.SourceTrust = "high"
	}
	if event.RawArtifactRef == "" {
		event.RawArtifactRef = evidenceStreamRel
	}
	event.RawArtifactRef = normalizeRawArtifactRef(event.RawArtifactRef)
	return event
}

func (m *Manager) appendEvidenceRecord(rel string, value any, collector, sourcePath, sourceType, sourceTrust string) error {
	if m.mode == ModeLegacy {
		return nil
	}
	record := evidence.EvidenceRecord{
		SchemaVersion:  evidence.SchemaVersion,
		ArtifactID:     artifact.ID(m.session.SessionID, evidenceStreamRel),
		CaseID:         m.session.CaseID,
		HostID:         m.session.HostID,
		SessionID:      m.session.SessionID,
		Collector:      defaultString(collector, "session"),
		RecordType:     recordTypeFromRel(rel),
		Stream:         streamFromRel(rel),
		SourcePath:     defaultString(sourcePath, rel),
		SourceType:     defaultString(sourceType, "generated"),
		SourceTrust:    defaultString(sourceTrust, "high"),
		CollectedAt:    time.Now().UTC(),
		RawArtifactRef: evidenceStreamRel,
		Data:           evidenceData(value),
	}
	if err := m.ensureWritableFile(evidenceStreamRel); err != nil {
		return err
	}
	path, err := SafeJoin(m.root, evidenceStreamRel)
	if err != nil {
		return err
	}
	return appendJSONL(path, record)
}

func evidenceData(value any) any {
	data, err := json.Marshal(value)
	if err != nil {
		return value
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		return value
	}
	for _, key := range evidenceMetadataKeys {
		delete(object, key)
	}
	return object
}

var evidenceMetadataKeys = []string{
	"schema_version",
	"artifact_id",
	"case_id",
	"host_id",
	"session_id",
	"collector",
	"source_path",
	"source_type",
	"source_trust",
	"collected_at",
	"raw_artifact_ref",
}

func isControlAIJSON(rel string) bool {
	switch filepath.Clean(rel) {
	case "manifest.json", "artifact_index.json", "archive_summary.json":
		return true
	default:
		return false
	}
}

func recordTypeFromRel(rel string) string {
	clean := filepath.ToSlash(filepath.Clean(rel))
	base := filepath.Base(clean)
	for _, ext := range []string{".jsonl", ".json"} {
		base = strings.TrimSuffix(base, ext)
	}
	switch base {
	case "collection_log":
		return "collection_event"
	case "timeline":
		return "timeline_event"
	case "errors":
		return "error_event"
	default:
		return base
	}
}

func streamFromRel(rel string) string {
	clean := filepath.ToSlash(filepath.Clean(rel))
	clean = strings.TrimSuffix(clean, ".jsonl")
	clean = strings.TrimSuffix(clean, ".json")
	return clean
}

func normalizeRawArtifactRef(ref string) string {
	clean := filepath.ToSlash(filepath.Clean(ref))
	if clean != "." && strings.HasPrefix(clean, "ai/") && strings.HasSuffix(clean, ".jsonl") {
		return evidenceStreamRel
	}
	return ref
}

func defaultTime(value, fallback time.Time) time.Time {
	if value.IsZero() {
		return fallback
	}
	return value
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func (m *Manager) safeMkdirAll(rel string) error {
	if rel == "." || rel == "" {
		return nil
	}
	clean := filepath.Clean(rel)
	if _, err := SafeJoin(m.root, clean); err != nil {
		return err
	}
	current := m.root
	for _, part := range strings.Split(clean, string(filepath.Separator)) {
		if part == "." || part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("output path component must not be a symlink: %s", current)
			}
			if !info.IsDir() {
				return fmt.Errorf("output path component is not a directory: %s", current)
			}
			continue
		}
		if !os.IsNotExist(err) {
			return err
		}
		if err := os.Mkdir(current, 0o750); err != nil && !os.IsExist(err) {
			return err
		}
	}
	return nil
}

func (m *Manager) ensureWritableFile(rel string) error {
	if err := m.safeMkdirAll(filepath.Dir(rel)); err != nil {
		return err
	}
	path, err := SafeJoin(m.root, rel)
	if err != nil {
		return err
	}
	return rejectSymlink(path)
}

func (m *Manager) touch(rel string) error {
	if err := m.ensureWritableFile(rel); err != nil {
		return err
	}
	path, err := SafeJoin(m.root, rel)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	return f.Close()
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("output file must not be a symlink: %s", path)
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
