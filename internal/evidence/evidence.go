package evidence

import "time"

const SchemaVersion = "linux-dfir/v1"

type Session struct {
	CaseID    string    `json:"case_id"`
	HostID    string    `json:"host_id"`
	SessionID string    `json:"session_id"`
	CreatedAt time.Time `json:"created_at"`
}

type Artifact struct {
	ArtifactID     string    `json:"artifact_id"`
	CaseID         string    `json:"case_id"`
	HostID         string    `json:"host_id"`
	SessionID      string    `json:"session_id"`
	Collector      string    `json:"collector"`
	Path           string    `json:"path"`
	Size           int64     `json:"size"`
	SHA256         string    `json:"sha256"`
	MD5            string    `json:"md5,omitempty"`
	SourcePath     string    `json:"source_path"`
	SourceType     string    `json:"source_type"`
	SourceTrust    string    `json:"source_trust"`
	CollectedAt    time.Time `json:"collected_at"`
	RawArtifactRef string    `json:"raw_artifact_ref"`
}

type RecordMeta struct {
	SchemaVersion  string    `json:"schema_version"`
	ArtifactID     string    `json:"artifact_id"`
	CaseID         string    `json:"case_id"`
	HostID         string    `json:"host_id"`
	SessionID      string    `json:"session_id"`
	Collector      string    `json:"collector"`
	SourcePath     string    `json:"source_path"`
	SourceType     string    `json:"source_type"`
	SourceTrust    string    `json:"source_trust"`
	CollectedAt    time.Time `json:"collected_at"`
	RawArtifactRef string    `json:"raw_artifact_ref"`
}

type SourceRef struct {
	SourcePath     string `json:"source_path"`
	SourceType     string `json:"source_type"`
	SourceTrust    string `json:"source_trust"`
	RawArtifactRef string `json:"raw_artifact_ref,omitempty"`
}

type EvidenceRecord struct {
	SchemaVersion  string    `json:"schema_version"`
	ArtifactID     string    `json:"artifact_id"`
	CaseID         string    `json:"case_id"`
	HostID         string    `json:"host_id"`
	SessionID      string    `json:"session_id"`
	Collector      string    `json:"collector"`
	RecordType     string    `json:"record_type"`
	Stream         string    `json:"stream"`
	SourcePath     string    `json:"source_path"`
	SourceType     string    `json:"source_type"`
	SourceTrust    string    `json:"source_trust"`
	CollectedAt    time.Time `json:"collected_at"`
	RawArtifactRef string    `json:"raw_artifact_ref"`
	Data           any       `json:"data"`
}

type Manifest struct {
	SchemaVersion string     `json:"schema_version"`
	CaseID        string     `json:"case_id"`
	HostID        string     `json:"host_id"`
	SessionID     string     `json:"session_id"`
	CreatedAt     time.Time  `json:"created_at"`
	CompletedAt   time.Time  `json:"completed_at"`
	OutputMode    string     `json:"output_mode"`
	Profile       string     `json:"profile"`
	Collectors    []string   `json:"collectors"`
	ArtifactCount int        `json:"artifact_count"`
	Artifacts     []Artifact `json:"artifacts"`
}

type ArtifactIndex struct {
	SchemaVersion string     `json:"schema_version"`
	CaseID        string     `json:"case_id"`
	HostID        string     `json:"host_id"`
	SessionID     string     `json:"session_id"`
	Artifacts     []Artifact `json:"artifacts"`
}

type CollectionEvent struct {
	SchemaVersion  string    `json:"schema_version"`
	ArtifactID     string    `json:"artifact_id"`
	CaseID         string    `json:"case_id"`
	HostID         string    `json:"host_id"`
	SessionID      string    `json:"session_id"`
	Collector      string    `json:"collector"`
	Event          string    `json:"event"`
	Status         string    `json:"status"`
	Message        string    `json:"message,omitempty"`
	SourcePath     string    `json:"source_path"`
	SourceType     string    `json:"source_type"`
	SourceTrust    string    `json:"source_trust"`
	CollectedAt    time.Time `json:"collected_at"`
	RawArtifactRef string    `json:"raw_artifact_ref"`
}

type TimelineEvent struct {
	SchemaVersion  string    `json:"schema_version"`
	ArtifactID     string    `json:"artifact_id"`
	CaseID         string    `json:"case_id"`
	HostID         string    `json:"host_id"`
	SessionID      string    `json:"session_id"`
	Collector      string    `json:"collector"`
	EventType      string    `json:"event_type"`
	Timestamp      time.Time `json:"timestamp"`
	CollectedAt    time.Time `json:"collected_at"`
	SourcePath     string    `json:"source_path"`
	SourceType     string    `json:"source_type"`
	SourceTrust    string    `json:"source_trust"`
	RawArtifactRef string    `json:"raw_artifact_ref"`
	Summary        string    `json:"summary,omitempty"`
}

type ErrorEvent struct {
	SchemaVersion  string    `json:"schema_version"`
	ArtifactID     string    `json:"artifact_id"`
	CaseID         string    `json:"case_id"`
	HostID         string    `json:"host_id"`
	SessionID      string    `json:"session_id"`
	Collector      string    `json:"collector"`
	Error          string    `json:"error"`
	SourcePath     string    `json:"source_path"`
	SourceType     string    `json:"source_type"`
	SourceTrust    string    `json:"source_trust"`
	CollectedAt    time.Time `json:"collected_at"`
	RawArtifactRef string    `json:"raw_artifact_ref"`
}
