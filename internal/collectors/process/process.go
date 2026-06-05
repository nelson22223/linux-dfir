package process

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"linux-dfir/internal/collectors/common"
	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
	"linux-dfir/internal/procfs"
	"linux-dfir/internal/redact"
)

var procRoot = "/proc"

type ProcessRecord struct {
	evidence.RecordMeta
	EntityType   string                `json:"entity_type"`
	EntityID     string                `json:"entity_id"`
	Exists       bool                  `json:"exists"`
	AbsentReason string                `json:"absent_reason,omitempty"`
	PID          int                   `json:"pid"`
	PPID         int                   `json:"ppid"`
	UID          int                   `json:"uid"`
	GID          int                   `json:"gid"`
	Name         string                `json:"name"`
	State        string                `json:"state"`
	Cmdline      []string              `json:"cmdline"`
	Environ      procfs.EnvironSummary `json:"environ"`
	Exe          string                `json:"exe,omitempty"`
	Cwd          string                `json:"cwd,omitempty"`
	Root         string                `json:"root,omitempty"`
	Path         string                `json:"path,omitempty"`
	MapCount     int                   `json:"map_count"`
	MapBytes     int64                 `json:"map_bytes"`
	Maps         procfs.MapsSummary    `json:"maps"`
	FDCount      int                   `json:"fd_count"`
	FDs          []FDObservation       `json:"fds,omitempty"`
	Issues       []procfs.ReadIssue    `json:"issues,omitempty"`
	Sources      []evidence.SourceRef  `json:"sources,omitempty"`
}

type FDObservation struct {
	Exists       bool   `json:"exists"`
	AbsentReason string `json:"absent_reason,omitempty"`
	FD           string `json:"fd,omitempty"`
	Target       string `json:"target,omitempty"`
	Type         string `json:"type,omitempty"`
}

type FDRecord struct {
	evidence.RecordMeta
	Exists       bool   `json:"exists"`
	AbsentReason string `json:"absent_reason,omitempty"`
	PID          int    `json:"pid"`
	FD           string `json:"fd,omitempty"`
	Target       string `json:"target,omitempty"`
	Type         string `json:"type,omitempty"`
}

type MapsRecord struct {
	evidence.RecordMeta
	Exists                  bool     `json:"exists"`
	AbsentReason            string   `json:"absent_reason,omitempty"`
	PID                     int      `json:"pid"`
	MapCount                int      `json:"map_count"`
	MapBytes                int64    `json:"map_bytes"`
	ExecutableCount         int      `json:"executable_count"`
	WritableExecutableCount int      `json:"writable_executable_count"`
	DeletedCount            int      `json:"deleted_count"`
	SamplePaths             []string `json:"sample_paths,omitempty"`
}

type Entity struct {
	evidence.RecordMeta
	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
	PID        int    `json:"pid"`
	Name       string `json:"name"`
	Path       string `json:"path,omitempty"`
}

func Collect(ctx context.Context, out *output.Manager) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := writeNativeCommandOutputs(ctx, out); err != nil {
		return err
	}
	pids, err := procfs.ListPIDs(procRoot)
	if err != nil {
		_ = out.Error(evidence.ErrorEvent{Collector: "process", Error: err.Error(), SourcePath: procRoot, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"})
		if writeErr := writeAbsent(out, err.Error()); writeErr != nil {
			return writeErr
		}
		return writeLegacy(out, nil)
	}

	processes := make([]procfs.Process, 0, len(pids))
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return err
		}
		proc, err := procfs.ReadProcess(procRoot, pid)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			sourcePath := filepath.Join(procRoot, fmt.Sprint(pid), "status")
			_ = out.Error(evidence.ErrorEvent{Collector: "process", Error: err.Error(), SourcePath: sourcePath, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"})
			continue
		}
		processes = append(processes, proc)
		if err := writeProcess(out, proc); err != nil {
			return err
		}
		for _, issue := range proc.Issues {
			if issue.IsRace {
				continue
			}
			_ = out.Error(evidence.ErrorEvent{
				Collector:      "process",
				Error:          issue.Error,
				SourcePath:     issue.Path,
				SourceType:     "procfs",
				SourceTrust:    "high",
				RawArtifactRef: rawArtifactRefForIssue(issue),
			})
		}
	}

	if err := writeLegacy(out, processes); err != nil {
		return err
	}
	return nil
}

func writeAbsent(out *output.Manager, reason string) error {
	record := ProcessRecord{
		RecordMeta:   out.Meta("process", "entities/process.jsonl", procRoot, "procfs", "high"),
		EntityType:   "process_collection",
		EntityID:     "process:absent",
		Exists:       false,
		AbsentReason: reason,
		Name:         "absent",
		State:        "absent",
		Sources:      []evidence.SourceRef{{SourcePath: procRoot, SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"}},
	}
	return out.AppendAIJSONL("entities/process.jsonl", record, "process", procRoot, "procfs", "high")
}

func writeProcess(out *output.Manager, proc procfs.Process) error {
	sourcePath := filepath.Join(procRoot, fmt.Sprint(proc.PID))
	fds := make([]FDObservation, 0, len(proc.FDs)+len(proc.Issues))
	for _, fd := range proc.FDs {
		fds = append(fds, FDObservation{
			Exists: true,
			FD:     fd.FD,
			Target: fd.Target,
			Type:   fd.Type,
		})
	}
	if len(proc.FDs) == 0 && hasIssue(proc.Issues, "fd") {
		fds = append(fds, FDObservation{
			Exists:       false,
			AbsentReason: issueReason(proc.Issues, "fd"),
		})
	}
	for _, issue := range proc.Issues {
		if issue.Kind != "fd_entry" {
			continue
		}
		fds = append(fds, FDObservation{
			Exists:       false,
			AbsentReason: issue.Error,
			FD:           issue.FD,
		})
	}
	record := ProcessRecord{
		RecordMeta: out.Meta("process", "entities/process.jsonl", sourcePath, "procfs", "high"),
		EntityType: "process",
		EntityID:   fmt.Sprintf("process:%d", proc.PID),
		Exists:     true,
		PID:        proc.PID,
		PPID:       proc.PPID,
		UID:        proc.UID,
		GID:        proc.GID,
		Name:       proc.Name,
		State:      proc.State,
		Cmdline:    redact.Args(proc.Cmdline),
		Environ:    procfs.SummarizeEnviron(proc.Environ),
		Exe:        proc.Exe,
		Cwd:        proc.Cwd,
		Root:       proc.Root,
		Path:       proc.Exe,
		MapCount:   proc.Maps.Count,
		MapBytes:   proc.Maps.Bytes,
		Maps:       proc.Maps,
		FDCount:    len(proc.FDs),
		FDs:        fds,
		Issues:     proc.Issues,
		Sources: []evidence.SourceRef{
			{SourcePath: filepath.Join(sourcePath, "status"), SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"},
			{SourcePath: filepath.Join(sourcePath, "cmdline"), SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"},
			{SourcePath: filepath.Join(sourcePath, "environ"), SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"},
			{SourcePath: filepath.Join(sourcePath, "exe"), SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"},
			{SourcePath: filepath.Join(sourcePath, "cwd"), SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"},
			{SourcePath: filepath.Join(sourcePath, "root"), SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"},
			{SourcePath: filepath.Join(sourcePath, "maps"), SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"},
			{SourcePath: filepath.Join(sourcePath, "fd"), SourceType: "procfs", SourceTrust: "high", RawArtifactRef: "ai/evidence.jsonl"},
		},
	}
	return out.AppendAIJSONL("entities/process.jsonl", record, "process", sourcePath, "procfs", "high")
}

func writeLegacy(out *output.Manager, processes []procfs.Process) error {
	sort.Slice(processes, func(i, j int) bool { return processes[i].PID < processes[j].PID })
	if err := out.WriteLegacyFromSource("process/procfs_ps_auxw.out", []byte(renderPSAux(processes)), "process", procRoot, "procfs", "high"); err != nil {
		return err
	}
	if err := out.WriteLegacyFromSource("process/procfs_ps_-elf.out", []byte(renderPSElf(processes)), "process", procRoot, "procfs", "high"); err != nil {
		return err
	}
	return out.WriteLegacyFromSource("process/procfs_lsof.out", []byte(renderLSOF(processes)), "process", procRoot, "procfs", "high")
}

func writeNativeCommandOutputs(ctx context.Context, out *output.Manager) error {
	specs := []struct {
		command string
		args    []string
		legacy  string
	}{
		{command: "ps", args: []string{"auxw"}, legacy: "process/ps_auxw.out"},
		{command: "ps", args: []string{"-elf"}, legacy: "process/ps_-elf.out"},
		{command: "lsof", legacy: "process/lsof.out"},
	}
	for _, spec := range specs {
		result := common.RunCommand(ctx, spec.command, spec.args...)
		if result.Missing() {
			_ = out.Error(evidence.ErrorEvent{Collector: "process", Error: result.Err.Error(), SourcePath: result.CommandLine(), SourceType: "native_command", SourceTrust: "medium", RawArtifactRef: filepath.Join("legacy", spec.legacy)})
			continue
		}
		if result.Err != nil {
			_ = out.Error(evidence.ErrorEvent{Collector: "process", Error: result.Err.Error(), SourcePath: result.CommandLine(), SourceType: "native_command", SourceTrust: "medium", RawArtifactRef: filepath.Join("legacy", spec.legacy)})
		}
		if len(result.Output) == 0 {
			continue
		}
		if err := out.WriteLegacyFromSource(spec.legacy, result.Output, "process", result.CommandLine(), "native_command", "medium"); err != nil {
			return err
		}
	}
	return out.WriteLegacyFromSource("process/jobs_-l.out", []byte("not applicable: Go collector has no interactive shell job table\n"), "process", "jobs -l", "generated", "low")
}

func renderPSAux(processes []procfs.Process) string {
	var b strings.Builder
	b.WriteString("USER       PID  PPID STAT COMMAND\n")
	for _, proc := range processes {
		b.WriteString(fmt.Sprintf("%-8d %5d %5d %-4s %s\n", proc.UID, proc.PID, proc.PPID, proc.State, command(proc)))
	}
	return b.String()
}

func renderPSElf(processes []procfs.Process) string {
	var b strings.Builder
	b.WriteString("F S   UID   PID  PPID CMD\n")
	for _, proc := range processes {
		state := proc.State
		if len(state) > 0 {
			state = state[:1]
		}
		b.WriteString(fmt.Sprintf("0 %s %5d %5d %5d %s\n", state, proc.UID, proc.PID, proc.PPID, command(proc)))
	}
	return b.String()
}

func renderLSOF(processes []procfs.Process) string {
	var b strings.Builder
	b.WriteString("COMMAND PID USER FD TYPE NAME\n")
	for _, proc := range processes {
		if proc.Cwd != "" {
			b.WriteString(fmt.Sprintf("%s %d %d cwd DIR %s\n", proc.Name, proc.PID, proc.UID, proc.Cwd))
		}
		if proc.Root != "" {
			b.WriteString(fmt.Sprintf("%s %d %d rtd DIR %s\n", proc.Name, proc.PID, proc.UID, proc.Root))
		}
		if proc.Exe != "" {
			b.WriteString(fmt.Sprintf("%s %d %d txt REG %s\n", proc.Name, proc.PID, proc.UID, proc.Exe))
		}
		for _, fd := range proc.FDs {
			b.WriteString(fmt.Sprintf("%s %d %d %s %s %s\n", proc.Name, proc.PID, proc.UID, fd.FD, fd.Type, fd.Target))
		}
	}
	return b.String()
}

func command(proc procfs.Process) string {
	if len(proc.Cmdline) > 0 {
		return strings.Join(proc.Cmdline, " ")
	}
	if proc.Name != "" {
		return "[" + proc.Name + "]"
	}
	return ""
}

func SetProcRootForTest(root string) func() {
	old := procRoot
	procRoot = root
	return func() {
		procRoot = old
	}
}

func ProcRootExists() bool {
	_, err := os.Stat(procRoot)
	return err == nil
}

func hasIssue(issues []procfs.ReadIssue, kind string) bool {
	for _, issue := range issues {
		if issue.Kind == kind {
			return true
		}
	}
	return false
}

func issueReason(issues []procfs.ReadIssue, kind string) string {
	for _, issue := range issues {
		if issue.Kind == kind {
			return issue.Error
		}
	}
	return ""
}

func rawArtifactRefForIssue(issue procfs.ReadIssue) string {
	return "ai/evidence.jsonl"
}
