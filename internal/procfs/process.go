package procfs

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

const (
	maxEnvPairs     = 80
	maxEnvValueLen  = 512
	maxMapPathItems = 32
)

type Process struct {
	PID       int
	PPID      int
	UID       int
	GID       int
	Name      string
	State     string
	Cmdline   []string
	Environ   map[string]string
	Exe       string
	Cwd       string
	Root      string
	Maps      MapsSummary
	FDs       []FD
	StatusRaw map[string]string
	Issues    []ReadIssue
}

type ReadIssue struct {
	Path   string
	Kind   string
	FD     string
	Error  string
	IsRace bool
}

type EnvironSummary struct {
	Count        int      `json:"count"`
	Keys         []string `json:"keys"`
	RedactedKeys []string `json:"redacted_keys,omitempty"`
	Truncated    bool     `json:"truncated,omitempty"`
}

type MapsSummary struct {
	Exists                  bool     `json:"exists"`
	Count                   int      `json:"count"`
	Bytes                   int64    `json:"bytes"`
	ExecutableCount         int      `json:"executable_count"`
	WritableExecutableCount int      `json:"writable_executable_count"`
	DeletedCount            int      `json:"deleted_count"`
	SamplePaths             []string `json:"sample_paths,omitempty"`
	AbsentReason            string   `json:"absent_reason,omitempty"`
}

type FD struct {
	PID    int
	FD     string
	Target string
	Type   string
}

func ListPIDs(root string) ([]int, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err == nil {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	return pids, nil
}

func ReadProcess(root string, pid int) (Process, error) {
	base := filepath.Join(root, strconv.Itoa(pid))
	statusPath := filepath.Join(base, "status")
	status, err := ParseStatusFile(statusPath)
	if err != nil {
		return Process{}, err
	}
	var issues []ReadIssue

	cmdlinePath := filepath.Join(base, "cmdline")
	cmdline, err := ReadNullSeparated(cmdlinePath)
	if err != nil {
		issues = append(issues, readIssue(cmdlinePath, "cmdline", err))
	}

	environPath := filepath.Join(base, "environ")
	environRaw, err := ReadNullSeparated(environPath)
	if err != nil {
		issues = append(issues, readIssue(environPath, "environ", err))
	}
	environ := RedactEnviron(environRaw)

	exePath := filepath.Join(base, "exe")
	exe, err := os.Readlink(exePath)
	if err != nil {
		issues = append(issues, readIssue(exePath, "exe", err))
	}
	cwdPath := filepath.Join(base, "cwd")
	cwd, err := os.Readlink(cwdPath)
	if err != nil {
		issues = append(issues, readIssue(cwdPath, "cwd", err))
	}
	rootPath := filepath.Join(base, "root")
	rootLink, err := os.Readlink(rootPath)
	if err != nil {
		issues = append(issues, readIssue(rootPath, "root", err))
	}

	mapsPath := filepath.Join(base, "maps")
	maps, err := ReadMapsSummary(mapsPath)
	if err != nil {
		issues = append(issues, readIssue(mapsPath, "maps", err))
	}
	fds, fdIssues, err := ReadFDs(root, pid)
	if err != nil {
		issues = append(issues, readIssue(filepath.Join(base, "fd"), "fd", err))
	}
	issues = append(issues, fdIssues...)

	return Process{
		PID:       pid,
		PPID:      parseInt(status["PPid"]),
		UID:       firstNumber(status["Uid"]),
		GID:       firstNumber(status["Gid"]),
		Name:      status["Name"],
		State:     status["State"],
		Cmdline:   cmdline,
		Environ:   environ,
		Exe:       exe,
		Cwd:       cwd,
		Root:      rootLink,
		Maps:      maps,
		FDs:       fds,
		StatusRaw: status,
		Issues:    issues,
	}, nil
}

func ParseStatusFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	result := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return result, nil
}

func ReadNullSeparated(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw := strings.Split(string(data), "\x00")
	items := make([]string, 0, len(raw))
	for _, item := range raw {
		if item != "" {
			items = append(items, item)
		}
	}
	return items, nil
}

func RedactEnviron(items []string) map[string]string {
	result := map[string]string{}
	for index, item := range items {
		if index >= maxEnvPairs {
			break
		}
		parts := strings.SplitN(item, "=", 2)
		key := parts[0]
		value := ""
		if len(parts) > 1 {
			value = parts[1]
		}
		if isSensitiveEnv(key) {
			value = "[redacted]"
		} else if len(value) > maxEnvValueLen {
			value = value[:maxEnvValueLen] + "...[truncated]"
		}
		result[key] = value
	}
	return result
}

func SummarizeEnviron(env map[string]string) EnvironSummary {
	keys := make([]string, 0, len(env))
	redacted := []string{}
	for key, value := range env {
		keys = append(keys, key)
		if value == "[redacted]" {
			redacted = append(redacted, key)
		}
	}
	sort.Strings(keys)
	sort.Strings(redacted)
	return EnvironSummary{
		Count:        len(env),
		Keys:         keys,
		RedactedKeys: redacted,
		Truncated:    len(env) >= maxEnvPairs,
	}
}

func ReadFDs(root string, pid int) ([]FD, []ReadIssue, error) {
	fdDir := filepath.Join(root, strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, nil, err
	}
	fds := make([]FD, 0, len(entries))
	issues := []ReadIssue{}
	for _, entry := range entries {
		fdPath := filepath.Join(fdDir, entry.Name())
		target, err := os.Readlink(fdPath)
		if err != nil {
			issue := readIssue(fdPath, "fd_entry", err)
			issue.FD = entry.Name()
			issues = append(issues, issue)
			continue
		}
		fds = append(fds, FD{PID: pid, FD: entry.Name(), Target: target, Type: FDType(target)})
	}
	sort.Slice(fds, func(i, j int) bool {
		return fds[i].FD < fds[j].FD
	})
	return fds, issues, nil
}

func ReadMapsSummary(path string) (MapsSummary, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return MapsSummary{Exists: false, AbsentReason: err.Error()}, err
	}
	summary := MapsSummary{Exists: true, Bytes: int64(len(data))}
	seenPaths := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		summary.Count++
		fields := strings.Fields(line)
		if len(fields) > 1 {
			perms := fields[1]
			if strings.Contains(perms, "x") {
				summary.ExecutableCount++
			}
			if strings.Contains(perms, "w") && strings.Contains(perms, "x") {
				summary.WritableExecutableCount++
			}
		}
		if strings.Contains(line, "(deleted)") {
			summary.DeletedCount++
		}
		if len(fields) >= 6 {
			mappedPath := strings.Join(fields[5:], " ")
			if mappedPath != "" && !seenPaths[mappedPath] && len(summary.SamplePaths) < maxMapPathItems {
				seenPaths[mappedPath] = true
				summary.SamplePaths = append(summary.SamplePaths, mappedPath)
			}
		}
	}
	return summary, nil
}

func MapsCountBytes(path string) (int, int64, error) {
	summary, err := ReadMapsSummary(path)
	return summary.Count, summary.Bytes, err
}

func FDType(target string) string {
	switch {
	case strings.HasPrefix(target, "socket:"):
		return "socket"
	case strings.HasPrefix(target, "pipe:"):
		return "pipe"
	case strings.HasPrefix(target, "anon_inode:"):
		return "anon_inode"
	case strings.HasPrefix(target, "/"):
		return "file"
	default:
		return "other"
	}
}

func isSensitiveEnv(key string) bool {
	upper := strings.ToUpper(key)
	for _, token := range []string{"PASS", "TOKEN", "SECRET", "KEY", "CREDENTIAL"} {
		if strings.Contains(upper, token) {
			return true
		}
	}
	return false
}

func readIssue(path, kind string, err error) ReadIssue {
	return ReadIssue{
		Path:   path,
		Kind:   kind,
		Error:  err.Error(),
		IsRace: isRaceError(err),
	}
}

func isRaceError(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}

func parseInt(value string) int {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0
	}
	parsed, _ := strconv.Atoi(fields[0])
	return parsed
}

func firstNumber(value string) int {
	return parseInt(value)
}
