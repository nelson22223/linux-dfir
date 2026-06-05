package container

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
	"linux-dfir/internal/procfs"
)

const (
	collector               = "container"
	containersRel           = "entities/container.jsonl"
	processesRel            = "facts/process_containers.jsonl"
	namespacesRel           = "facts/namespaces.jsonl"
	cgroupsRel              = "facts/cgroups.jsonl"
	runtimeMetaRel          = "artifacts/runtime_metadata.jsonl"
	containerIDMinLen       = 64
	containerIDFullLen      = 64
	maxRuntimeMetadataBytes = 4 * 1024 * 1024
)

var (
	procRoot       = "/proc"
	filesystemRoot = "/"
	hexIDPattern   = regexp.MustCompile(`[a-f0-9]{64}`)
)

type ContainerRecord struct {
	evidence.RecordMeta
	Exists       bool     `json:"exists"`
	AbsentReason string   `json:"absent_reason,omitempty"`
	EntityType   string   `json:"entity_type,omitempty"`
	EntityID     string   `json:"entity_id,omitempty"`
	ContainerID  string   `json:"container_id,omitempty"`
	ShortID      string   `json:"short_id,omitempty"`
	Runtime      string   `json:"runtime,omitempty"`
	PodUID       string   `json:"pod_uid,omitempty"`
	Namespace    string   `json:"namespace,omitempty"`
	Name         string   `json:"name,omitempty"`
	Image        string   `json:"image,omitempty"`
	Confidence   string   `json:"confidence,omitempty"`
	Hints        []string `json:"hints,omitempty"`
	Source       string   `json:"source,omitempty"`
	MetadataPath string   `json:"metadata_path,omitempty"`
}

type ProcessContainerRecord struct {
	evidence.RecordMeta
	Exists       bool     `json:"exists"`
	AbsentReason string   `json:"absent_reason,omitempty"`
	PID          int      `json:"pid,omitempty"`
	PPID         int      `json:"ppid,omitempty"`
	Name         string   `json:"name,omitempty"`
	Cmdline      []string `json:"cmdline,omitempty"`
	UID          int      `json:"uid,omitempty"`
	ContainerID  string   `json:"container_id,omitempty"`
	Runtime      string   `json:"runtime,omitempty"`
	PodUID       string   `json:"pod_uid,omitempty"`
	Confidence   string   `json:"confidence,omitempty"`
	CgroupPaths  []string `json:"cgroup_paths,omitempty"`
	MountHints   []string `json:"mount_hints,omitempty"`
}

type CgroupRecord struct {
	evidence.RecordMeta
	Exists       bool     `json:"exists"`
	AbsentReason string   `json:"absent_reason,omitempty"`
	PID          int      `json:"pid,omitempty"`
	HierarchyID  string   `json:"hierarchy_id,omitempty"`
	Controllers  []string `json:"controllers,omitempty"`
	Path         string   `json:"path,omitempty"`
	ContainerID  string   `json:"container_id,omitempty"`
	Runtime      string   `json:"runtime,omitempty"`
	PodUID       string   `json:"pod_uid,omitempty"`
}

type NamespaceRecord struct {
	evidence.RecordMeta
	Exists       bool   `json:"exists"`
	AbsentReason string `json:"absent_reason,omitempty"`
	PID          int    `json:"pid,omitempty"`
	Type         string `json:"type,omitempty"`
	Target       string `json:"target,omitempty"`
	Inode        string `json:"inode,omitempty"`
	ContainerID  string `json:"container_id,omitempty"`
}

type RuntimeMetadataRecord struct {
	evidence.RecordMeta
	Exists        bool     `json:"exists"`
	AbsentReason  string   `json:"absent_reason,omitempty"`
	Runtime       string   `json:"runtime,omitempty"`
	ContainerID   string   `json:"container_id,omitempty"`
	ShortID       string   `json:"short_id,omitempty"`
	Name          string   `json:"name,omitempty"`
	Image         string   `json:"image,omitempty"`
	PodUID        string   `json:"pod_uid,omitempty"`
	PodName       string   `json:"pod_name,omitempty"`
	PodNamespace  string   `json:"pod_namespace,omitempty"`
	SourcePath    string   `json:"source_path,omitempty"`
	SourcePattern string   `json:"source_pattern,omitempty"`
	RawCopyRef    string   `json:"raw_copy_ref,omitempty"`
	Size          int64    `json:"size,omitempty"`
	MetadataKeys  []string `json:"metadata_keys,omitempty"`
	ParseError    string   `json:"parse_error,omitempty"`
	ReadError     string   `json:"read_error,omitempty"`
	Hints         []string `json:"hints,omitempty"`
}

type metadataSource struct {
	Runtime string
	Glob    string
}

var runtimeMetadataSources = []metadataSource{
	{Runtime: "docker", Glob: "/var/lib/docker/containers/*/config.v2.json"},
	{Runtime: "docker", Glob: "/var/lib/docker/containers/*/hostconfig.json"},
	{Runtime: "containerd", Glob: "/var/lib/containerd/io.containerd.runtime.v2.task/*/*/config.json"},
	{Runtime: "containerd", Glob: "/run/containerd/io.containerd.runtime.v2.task/*/*/config.json"},
	{Runtime: "podman", Glob: "/var/lib/containers/storage/overlay-containers/*/userdata/config.json"},
	{Runtime: "podman", Glob: "/run/containers/storage/overlay-containers/*/userdata/config.json"},
	{Runtime: "podman", Glob: "/root/.local/share/containers/storage/overlay-containers/*/userdata/config.json"},
	{Runtime: "podman", Glob: "/home/*/.local/share/containers/storage/overlay-containers/*/userdata/config.json"},
}

type cgroupEntry struct {
	HierarchyID string
	Controllers []string
	Path        string
}

type containerHint struct {
	ID         string
	Runtime    string
	PodUID     string
	Confidence string
	Hints      []string
}

func Collect(ctx context.Context, out *output.Manager) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	pids, err := procfs.ListPIDs(procRoot)
	if err != nil {
		recordError(out, procRoot, "procfs", processesRel, err)
		if writeErr := writeAbsent(out, err.Error()); writeErr != nil {
			return writeErr
		}
		return writeLegacy(out, nil, nil)
	}
	containerIndex := map[string]ContainerRecord{}
	if err := collectRuntimeMetadata(out, containerIndex); err != nil {
		return err
	}
	var processRecords []ProcessContainerRecord
	var namespaceRecords []NamespaceRecord
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return err
		}
		proc, err := procfs.ReadProcess(procRoot, pid)
		if err != nil {
			recordError(out, filepath.Join(procRoot, strconv.Itoa(pid), "status"), "procfs", processesRel, err)
			continue
		}
		entries, err := ReadCgroupFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
		if err != nil {
			recordError(out, filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"), "procfs", cgroupsRel, err)
		}
		hint := BestContainerHint(entries)
		mountHints, err := readMountHints(filepath.Join(procRoot, strconv.Itoa(pid), "mountinfo"))
		if err != nil {
			recordError(out, filepath.Join(procRoot, strconv.Itoa(pid), "mountinfo"), "procfs", processesRel, err)
		}
		for _, entry := range entries {
			record := CgroupRecord{
				RecordMeta:  out.Meta(collector, cgroupsRel, filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"), "procfs", "high"),
				Exists:      true,
				PID:         pid,
				HierarchyID: entry.HierarchyID,
				Controllers: entry.Controllers,
				Path:        entry.Path,
				ContainerID: hint.ID,
				Runtime:     hint.Runtime,
				PodUID:      hint.PodUID,
			}
			if err := out.AppendAIJSONL(cgroupsRel, record, collector, filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"), "procfs", "high"); err != nil {
				return err
			}
		}
		if hint.ID != "" {
			process := ProcessContainerRecord{
				RecordMeta:  out.Meta(collector, processesRel, filepath.Join(procRoot, strconv.Itoa(pid)), "procfs", "high"),
				Exists:      true,
				PID:         pid,
				PPID:        proc.PPID,
				Name:        proc.Name,
				Cmdline:     proc.Cmdline,
				UID:         proc.UID,
				ContainerID: hint.ID,
				Runtime:     hint.Runtime,
				PodUID:      hint.PodUID,
				Confidence:  hint.Confidence,
				CgroupPaths: cgroupPaths(entries),
				MountHints:  mountHints,
			}
			if err := writeProcessContainer(out, process); err != nil {
				return err
			}
			processRecords = append(processRecords, process)
			if _, ok := containerIndex[hint.ID]; !ok {
				record := ContainerRecord{
					RecordMeta:  out.Meta(collector, containersRel, filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"), "procfs", "high"),
					Exists:      true,
					ContainerID: hint.ID,
					ShortID:     shortID(hint.ID),
					Runtime:     hint.Runtime,
					PodUID:      hint.PodUID,
					Confidence:  hint.Confidence,
					Hints:       hint.Hints,
					Source:      filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"),
				}
				if err := writeContainer(out, record); err != nil {
					return err
				}
				containerIndex[hint.ID] = record
			}
		}
		ns, err := readNamespaces(pid, hint.ID)
		if err != nil {
			recordError(out, filepath.Join(procRoot, strconv.Itoa(pid), "ns"), "procfs", namespacesRel, err)
		}
		for _, record := range ns {
			record.RecordMeta = out.Meta(collector, namespacesRel, filepath.Join(procRoot, strconv.Itoa(pid), "ns", record.Type), "procfs", "high")
			if err := out.AppendAIJSONL(namespacesRel, record, collector, filepath.Join(procRoot, strconv.Itoa(pid), "ns", record.Type), "procfs", "high"); err != nil {
				return err
			}
			namespaceRecords = append(namespaceRecords, record)
		}
	}
	if len(processRecords) == 0 && len(containerIndex) == 0 {
		if err := writeAbsent(out, "no container cgroup hints found"); err != nil {
			return err
		}
	}
	return writeLegacy(out, processRecords, namespaceRecords)
}

func ReadCgroupFile(path string) ([]cgroupEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries []cgroupEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		controllers := []string{}
		if parts[1] != "" {
			controllers = strings.Split(parts[1], ",")
		}
		entries = append(entries, cgroupEntry{HierarchyID: parts[0], Controllers: controllers, Path: parts[2]})
	}
	return entries, nil
}

func BestContainerHint(entries []cgroupEntry) containerHint {
	var best containerHint
	for _, entry := range entries {
		hint := ContainerHintFromPath(entry.Path)
		if hint.ID == "" {
			continue
		}
		if best.ID == "" || confidenceRank(hint.Confidence) > confidenceRank(best.Confidence) {
			best = hint
		}
	}
	return best
}

func ContainerHintFromPath(path string) containerHint {
	lower := strings.ToLower(path)
	id := ""
	for _, raw := range hexIDPattern.FindAllString(lower, -1) {
		if len(raw) >= containerIDMinLen {
			id = raw
		}
	}
	if id == "" {
		return containerHint{}
	}
	runtime := "unknown"
	hints := []string{path}
	switch {
	case strings.Contains(lower, "docker"):
		runtime = "docker"
	case strings.Contains(lower, "containerd"):
		runtime = "containerd"
	case strings.Contains(lower, "crio") || strings.Contains(lower, "cri-o"):
		runtime = "crio"
	case strings.Contains(lower, "libpod") || strings.Contains(lower, "podman"):
		runtime = "podman"
	case strings.Contains(lower, "kubepods"):
		runtime = "kubernetes"
	}
	if runtime == "unknown" {
		return containerHint{}
	}
	podUID := extractPodUID(lower)
	confidence := "high"
	return containerHint{ID: id, Runtime: runtime, PodUID: podUID, Confidence: confidence, Hints: hints}
}

func collectRuntimeMetadata(out *output.Manager, index map[string]ContainerRecord) error {
	matched := map[string]bool{}
	patterns := map[string][]string{}
	for _, metaSource := range runtimeMetadataSources {
		patterns[metaSource.Runtime] = append(patterns[metaSource.Runtime], metaSource.Glob)
		for _, actual := range globActual(metaSource.Glob) {
			source := displayPath(actual)
			matched[metaSource.Runtime] = true
			record, err := parseRuntimeConfig(out, actual, source, metaSource)
			if err != nil {
				recordError(out, source, "file", runtimeMetaRel, err)
				continue
			}
			record.RecordMeta = out.Meta(collector, runtimeMetaRel, source, "file", "high")
			if err := out.AppendAIJSONL(runtimeMetaRel, record, collector, source, "file", "high"); err != nil {
				return err
			}
			if record.ContainerID == "" {
				continue
			}
			container := ContainerRecord{
				RecordMeta:   out.Meta(collector, containersRel, source, "file", "high"),
				Exists:       true,
				ContainerID:  record.ContainerID,
				ShortID:      shortID(record.ContainerID),
				Runtime:      record.Runtime,
				PodUID:       record.PodUID,
				Namespace:    record.PodNamespace,
				Name:         record.Name,
				Image:        record.Image,
				Confidence:   "high",
				Hints:        record.Hints,
				Source:       source,
				MetadataPath: source,
			}
			if err := writeContainer(out, container); err != nil {
				return err
			}
			index[container.ContainerID] = container
		}
	}
	for runtimeName, runtimePatterns := range patterns {
		if matched[runtimeName] {
			continue
		}
		source := strings.Join(runtimePatterns, ",")
		record := RuntimeMetadataRecord{
			RecordMeta:    out.Meta(collector, runtimeMetaRel, source, "file", "high"),
			Exists:        false,
			AbsentReason:  "no runtime metadata files found under configured paths",
			Runtime:       runtimeName,
			SourcePattern: source,
			SourcePath:    source,
		}
		if err := out.AppendAIJSONL(runtimeMetaRel, record, collector, source, "file", "high"); err != nil {
			return err
		}
	}
	return nil
}

func parseRuntimeConfig(out *output.Manager, actual, source string, metaSource metadataSource) (RuntimeMetadataRecord, error) {
	stat, err := os.Stat(actual)
	if err != nil {
		return RuntimeMetadataRecord{}, err
	}
	record := RuntimeMetadataRecord{
		Exists:        true,
		Runtime:       metaSource.Runtime,
		ContainerID:   containerIDFromPath(source),
		SourcePath:    source,
		SourcePattern: metaSource.Glob,
		Size:          stat.Size(),
		Hints:         []string{source},
	}
	record.ShortID = shortID(record.ContainerID)
	if stat.Size() > maxRuntimeMetadataBytes {
		record.ReadError = fmt.Sprintf("runtime metadata file too large: %d bytes", stat.Size())
		return record, nil
	}
	data, err := os.ReadFile(actual)
	if err != nil {
		return RuntimeMetadataRecord{}, err
	}
	rawRel := filepath.ToSlash(filepath.Join("raw/container/runtime_metadata", metaSource.Runtime, safeMetadataName(source)))
	record.RawCopyRef = filepath.ToSlash(filepath.Join("ai", rawRel))
	if err := out.WriteAIFromSource(rawRel, data, collector, source, "file", "high"); err != nil {
		return RuntimeMetadataRecord{}, err
	}
	enrichRuntimeMetadata(&record, actual, data)
	return record, nil
}

func parseDockerConfig(actual, source string) (RuntimeMetadataRecord, error) {
	return oldParseDockerConfig(actual, source)
}

func enrichRuntimeMetadata(record *RuntimeMetadataRecord, actual string, data []byte) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		record.ParseError = err.Error()
		return
	}
	record.MetadataKeys = sortedAnyKeys(raw)
	id := firstString(raw, "ID", "Id", "id")
	if id == "" {
		id = filepath.Base(filepath.Dir(actual))
	}
	if record.ContainerID == "" {
		record.ContainerID = id
		record.ShortID = shortID(id)
	}
	record.Image = firstString(raw, "Image", "image")
	record.Name = strings.TrimPrefix(firstString(raw, "Name", "name"), "/")
	if config, ok := raw["Config"].(map[string]any); ok {
		if record.Image == "" {
			record.Image = firstString(config, "Image", "image")
		}
		if labels, ok := config["Labels"].(map[string]any); ok {
			enrichKubeLabels(record, labels)
		}
	}
	if labels, ok := raw["Labels"].(map[string]any); ok {
		enrichKubeLabels(record, labels)
	}
	if annotations, ok := raw["annotations"].(map[string]any); ok {
		enrichKubeLabels(record, annotations)
	}
	if spec, ok := raw["Spec"].(map[string]any); ok {
		if annotations, ok := spec["annotations"].(map[string]any); ok {
			enrichKubeLabels(record, annotations)
		}
	}
}

func enrichKubeLabels(record *RuntimeMetadataRecord, labels map[string]any) {
	asString := func(key string) string {
		if value, ok := labels[key].(string); ok {
			return value
		}
		return ""
	}
	if record.PodUID == "" {
		record.PodUID = firstNonEmpty(asString("io.kubernetes.pod.uid"), asString("io.kubernetes.cri.sandbox-id"))
	}
	if record.PodName == "" {
		record.PodName = asString("io.kubernetes.pod.name")
	}
	if record.PodNamespace == "" {
		record.PodNamespace = asString("io.kubernetes.pod.namespace")
	}
	if record.Name == "" {
		record.Name = firstNonEmpty(asString("io.kubernetes.container.name"), asString("io.kubernetes.cri.container-name"))
	}
	if record.Image == "" {
		record.Image = firstNonEmpty(asString("io.kubernetes.cri.image-name"), asString("org.opencontainers.image.ref.name"))
	}
}

func oldParseDockerConfig(actual, source string) (RuntimeMetadataRecord, error) {
	data, err := os.ReadFile(actual)
	if err != nil {
		return RuntimeMetadataRecord{}, err
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return RuntimeMetadataRecord{}, err
	}
	id := stringValue(raw["ID"])
	if id == "" {
		id = filepath.Base(filepath.Dir(actual))
	}
	image := stringValue(raw["Image"])
	name := strings.TrimPrefix(stringValue(raw["Name"]), "/")
	return RuntimeMetadataRecord{
		Exists:      true,
		Runtime:     "docker",
		ContainerID: id,
		Name:        name,
		Image:       image,
		SourcePath:  source,
		Hints:       []string{source},
	}, nil
}

func writeContainer(out *output.Manager, record ContainerRecord) error {
	if record.ShortID == "" {
		record.ShortID = shortID(record.ContainerID)
	}
	if record.EntityType == "" {
		record.EntityType = "container"
	}
	if record.EntityID == "" && record.ContainerID != "" {
		record.EntityID = "container:" + record.ContainerID
	}
	if err := out.AppendAIJSONL(containersRel, record, collector, record.Source, record.SourceType, record.SourceTrust); err != nil {
		return err
	}
	return nil
}

func writeProcessContainer(out *output.Manager, record ProcessContainerRecord) error {
	source := filepath.Join(procRoot, strconv.Itoa(record.PID))
	record.RecordMeta = out.Meta(collector, processesRel, source, "procfs", "high")
	return out.AppendAIJSONL(processesRel, record, collector, source, "procfs", "high")
}

func readNamespaces(pid int, containerID string) ([]NamespaceRecord, error) {
	nsDir := filepath.Join(procRoot, strconv.Itoa(pid), "ns")
	entries, err := os.ReadDir(nsDir)
	if err != nil {
		return nil, err
	}
	var records []NamespaceRecord
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(nsDir, entry.Name()))
		if err != nil {
			continue
		}
		records = append(records, NamespaceRecord{
			Exists:      true,
			PID:         pid,
			Type:        entry.Name(),
			Target:      target,
			Inode:       namespaceInode(target),
			ContainerID: containerID,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Type < records[j].Type })
	return records, nil
}

func readMountHints(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	hints := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.Contains(line, "/var/lib/docker/overlay2/"):
			hints["docker overlay mount present"] = true
		case strings.Contains(line, "/var/lib/docker/containers/"):
			hints["docker container metadata path present"] = true
		case strings.Contains(line, "/var/lib/containerd/"):
			hints["containerd path present"] = true
		case strings.Contains(line, "/var/lib/containers/storage/"):
			hints["containers-storage path present"] = true
		case strings.Contains(line, "/var/lib/kubelet/pods/"):
			hints["kubelet pod path present"] = true
		}
	}
	return sortedBoolKeys(hints), nil
}

func writeAbsent(out *output.Manager, reason string) error {
	container := ContainerRecord{RecordMeta: out.Meta(collector, containersRel, "containers", "generated", "medium"), Exists: false, AbsentReason: reason, EntityType: "container"}
	if err := out.AppendAIJSONL(containersRel, container, collector, "containers", "generated", "medium"); err != nil {
		return err
	}
	process := ProcessContainerRecord{RecordMeta: out.Meta(collector, processesRel, "container processes", "generated", "medium"), Exists: false, AbsentReason: reason}
	if err := out.AppendAIJSONL(processesRel, process, collector, "container processes", "generated", "medium"); err != nil {
		return err
	}
	namespace := NamespaceRecord{RecordMeta: out.Meta(collector, namespacesRel, "namespaces", "generated", "medium"), Exists: false, AbsentReason: reason}
	if err := out.AppendAIJSONL(namespacesRel, namespace, collector, "namespaces", "generated", "medium"); err != nil {
		return err
	}
	cgroup := CgroupRecord{RecordMeta: out.Meta(collector, cgroupsRel, "cgroups", "generated", "medium"), Exists: false, AbsentReason: reason}
	if err := out.AppendAIJSONL(cgroupsRel, cgroup, collector, "cgroups", "generated", "medium"); err != nil {
		return err
	}
	runtime := RuntimeMetadataRecord{RecordMeta: out.Meta(collector, runtimeMetaRel, "runtime metadata", "generated", "medium"), Exists: false, AbsentReason: reason}
	if err := out.AppendAIJSONL(runtimeMetaRel, runtime, collector, "runtime metadata", "generated", "medium"); err != nil {
		return err
	}
	return nil
}

func writeLegacy(out *output.Manager, processes []ProcessContainerRecord, namespaces []NamespaceRecord) error {
	var procText strings.Builder
	procText.WriteString("pid\tcontainer_id\truntime\tpod_uid\tname\tcmdline\n")
	for _, proc := range processes {
		procText.WriteString(fmt.Sprintf("%d\t%s\t%s\t%s\t%s\t%s\n", proc.PID, proc.ContainerID, proc.Runtime, proc.PodUID, proc.Name, strings.Join(proc.Cmdline, " ")))
	}
	if err := out.WriteLegacyFromSource("container/container_processes.out", []byte(procText.String()), collector, procRoot, "procfs", "high"); err != nil {
		return err
	}
	var nsText strings.Builder
	nsText.WriteString("pid\ttype\tinode\ttarget\tcontainer_id\n")
	for _, ns := range namespaces {
		nsText.WriteString(fmt.Sprintf("%d\t%s\t%s\t%s\t%s\n", ns.PID, ns.Type, ns.Inode, ns.Target, ns.ContainerID))
	}
	if err := out.WriteLegacyFromSource("container/namespaces.out", []byte(nsText.String()), collector, procRoot, "procfs", "high"); err != nil {
		return err
	}
	var cgText strings.Builder
	cgText.WriteString("collector\tsee stream facts/cgroups in ai/evidence.jsonl for per-pid cgroups\n")
	if err := out.WriteLegacyFromSource("container/cgroups.out", []byte(cgText.String()), collector, procRoot, "procfs", "high"); err != nil {
		return err
	}
	var contextText strings.Builder
	contextText.WriteString("Linux DFIR container context\n")
	contextText.WriteString("============================\n\n")
	contextText.WriteString("Process container associations\n")
	contextText.WriteString(procText.String())
	contextText.WriteString("\nNamespaces\n")
	contextText.WriteString(nsText.String())
	contextText.WriteString("\nCgroups\n")
	contextText.WriteString(cgText.String())
	return out.WriteLegacyFromSource("container/container_context.out", []byte(contextText.String()), collector, procRoot, "procfs", "high")
}

func cgroupPaths(entries []cgroupEntry) []string {
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		paths = append(paths, entry.Path)
	}
	return paths
}

func containerIDFromPath(path string) string {
	for _, raw := range hexIDPattern.FindAllString(strings.ToLower(path), -1) {
		if len(raw) >= containerIDMinLen {
			return raw
		}
	}
	return ""
}

func safeMetadataName(sourcePath string) string {
	sum := sha256.Sum256([]byte(sourcePath))
	clean := strings.Trim(sourcePath, "/")
	clean = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, clean)
	if len(clean) > 120 {
		clean = clean[len(clean)-120:]
	}
	return clean + "-" + hex.EncodeToString(sum[:])[:12]
}

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key].(string); ok {
			return value
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func sortedAnyKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedBoolKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if key != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func confidenceRank(value string) int {
	switch value {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func extractPodUID(path string) string {
	idx := strings.LastIndex(path, "pod")
	if idx < 0 {
		return ""
	}
	rest := path[idx+3:]
	for _, sep := range []string{".slice", "/", ":"} {
		if end := strings.Index(rest, sep); end >= 0 {
			rest = rest[:end]
		}
	}
	rest = strings.Trim(rest, "_-")
	rest = strings.ReplaceAll(rest, "_", "-")
	if strings.Contains(rest, "_") || strings.Contains(rest, "-") {
		return rest
	}
	return ""
}

func namespaceInode(target string) string {
	start := strings.IndexByte(target, '[')
	end := strings.IndexByte(target, ']')
	if start >= 0 && end > start {
		return target[start+1 : end]
	}
	return ""
}

func globActual(pattern string) []string {
	matches, _ := filepath.Glob(actualPath(pattern))
	return matches
}

func recordError(out *output.Manager, sourcePath, sourceType, rawRel string, err error) {
	_ = out.Error(evidence.ErrorEvent{Collector: collector, Error: err.Error(), SourcePath: sourcePath, SourceType: sourceType, SourceTrust: sourceTrust(sourceType), RawArtifactRef: "ai/" + rawRel})
}

func sourceTrust(sourceType string) string {
	if sourceType == "generated" {
		return "medium"
	}
	return "high"
}

func actualPath(path string) string {
	if filesystemRoot == "" || filesystemRoot == "/" {
		return path
	}
	return filepath.Join(filesystemRoot, strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)))
}

func displayPath(actual string) string {
	if filesystemRoot == "" || filesystemRoot == "/" {
		return actual
	}
	rel, err := filepath.Rel(filesystemRoot, actual)
	if err != nil || strings.HasPrefix(rel, "..") {
		return actual
	}
	return "/" + filepath.ToSlash(rel)
}

func stringValue(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}
