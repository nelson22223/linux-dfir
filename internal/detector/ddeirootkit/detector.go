// Package ddeirootkit detects the "libnet.so / xinetd" LD_PRELOAD rootkit
// family observed on Trend Micro DDEI appliances (case 2026-09, host
// O-BJC-A-COR-DDEI2). The detector is intentionally dependency-free and
// reads only; every check degrades gracefully when an artifact is absent.
//
// Detection anchors (derived from the incident evidence package):
//   - /etc/ld.so.preload referencing /usr/lib64/libnet.so (primary)
//   - family hashes of the dropped library and the replaced xinetd binary
//   - libnet.so mapped into live processes via /proc/*/maps
//   - RWX mapping inside the running malicious xinetd (in-memory payload)
//   - family marker files (/root/sign.txt, /media/vbccsb, /home/vbccsb)
//   - xinetd systemd wants symlink + journal "cannot be preloaded" traces
package ddeirootkit

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Severity ranks a single check result.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityConfirmed
)

func (s Severity) String() string {
	switch s {
	case SeverityConfirmed:
		return "CONFIRMED"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	default:
		return "INFO"
	}
}

// Verdict is the overall machine state assessment.
type Verdict string

const (
	VerdictClean           Verdict = "CLEAN"
	VerdictSuspicious      Verdict = "SUSPICIOUS"
	VerdictLikelyInfected  Verdict = "LIKELY-INFECTED"
	VerdictInfected        Verdict = "INFECTED"
)

// Check is one detection result with its supporting evidence.
type Check struct {
	ID       string  `json:"id"`
	Title    string  `json:"title"`
	Severity Severity `json:"severity"`
	Detail   string  `json:"detail,omitempty"`
}

// ProcHit records a process observed with a family artifact mapped.
type ProcHit struct {
	PID  int    `json:"pid"`
	Comm string `json:"comm,omitempty"`
	Exe  string `json:"exe,omitempty"`
	Note string `json:"note,omitempty"`
}

// Report is the full detector output.
type Report struct {
	Timestamp time.Time `json:"timestamp"`
	Hostname  string    `json:"hostname,omitempty"`
	Verdict   Verdict   `json:"verdict"`
	Summary   string    `json:"summary,omitempty"`
	Checks    []Check   `json:"checks"`
	ProcHits  []ProcHit `json:"proc_hits,omitempty"`
}

// Options tunes the detector. Root allows tests to point the detector at a
// fixture tree; production callers leave it empty for "/".
type Options struct {
	Root          string
	SelfPID       int
	Hostname      string
	LogTailBytes  int64
	ScanProcMaps  bool
	ScanLogTraces bool
}

// Known family indicators (case 2026-09 evidence package).
var (
	FamilyName = "DDEI-libnet/xinetd rootkit"

	preloadPath     = "/etc/ld.so.preload"
	knownBadPreload = []string{"/usr/lib64/libnet.so", "/lib64/libnet.so", "libnet.so"}

	knownLibMD5s = map[string]string{
		"eebbba3f7ff5eb7ab0f64fc5074a6ce5": "/usr/lib64/libnet.so.1 sample (zip)",
	}
	knownLibSHA256s = map[string]string{
		"acf5641c6c84774de63562a6e7080a0c4271451eef6429618f364c2308dd27cc": "/usr/lib64/libnet.so.1 sample (zip)",
	}
	knownXinetdMD5 = "003bf75d53504889e13bf12d6af5b28f"

	// libCandidates are checked for existence + hash; the JVM helper of the
	// same name under /usr/lib/jvm is legitimate and never scanned.
	libCandidates = []string{
		"/usr/lib64/libnet.so",
		"/usr/lib64/libnet.so.1",
		"/lib64/libnet.so",
		"/lib64/libnet.so.1",
	}

	xinetdPath      = "/usr/sbin/xinetd"
	xinetdSizeLimit = int64(1 << 20) // legit CentOS 7 xinetd is ~166 KiB

	markerFiles = []string{
		"/root/sign.txt",
		"/media/vbccsb",
		"/home/vbccsb",
	}

	systemdWantsSymlink = "/etc/systemd/system/multi-user.target.wants/xinetd.service"
	systemdUnitPath     = "/etc/systemd/system/xinetd.service"

	logTraceFiles  = []string{"/var/log/messages", "/var/log/messages.1"}
	logTraceNeedle = "ld.so.preload cannot be preloaded"
)

// Run executes every check and assembles the report.
func Run(opts Options) Report {
	if opts.Root == "" {
		opts.Root = "/"
	}
	if opts.SelfPID == 0 {
		opts.SelfPID = os.Getpid()
	}
	if opts.Hostname == "" {
		if h, err := os.Hostname(); err == nil {
			opts.Hostname = h
		}
	}
	if opts.LogTailBytes <= 0 {
		opts.LogTailBytes = 512 * 1024
	}
	p := func(rel string) string { return filepath.Join(opts.Root, rel) }

	rep := Report{Timestamp: time.Now().UTC(), Hostname: opts.Hostname}

	checkPreload(p, &rep)
	checkLibFiles(p, &rep)
	checkXinetd(p, &rep)
	checkMarkers(p, &rep)
	checkSystemd(p, &rep)
	if opts.ScanProcMaps {
		checkProcMaps(opts, p, &rep)
	}
	if opts.ScanLogTraces {
		checkLogTraces(opts, p, &rep)
	}

	rep.Verdict, rep.Summary = conclude(rep.Checks)
	return rep
}

func conclude(checks []Check) (Verdict, string) {
	var confirmed, high, medium int
	for _, c := range checks {
		switch c.Severity {
		case SeverityConfirmed:
			confirmed++
		case SeverityHigh:
			high++
		case SeverityMedium:
			medium++
		}
	}
	switch {
	case confirmed > 0:
		return VerdictInfected, fmt.Sprintf("%d confirmed family indicator(s)", confirmed)
	case high >= 2:
		return VerdictLikelyInfected, fmt.Sprintf("%d high-confidence indicator(s) without an exact family match", high)
	case high == 1 || medium >= 2:
		return VerdictSuspicious, fmt.Sprintf("weak indicators (high=%d medium=%d); manual review recommended", high, medium)
	default:
		return VerdictClean, "no family indicators observed"
	}
}

func (r *Report) add(c Check) { r.Checks = append(r.Checks, c) }

func checkPreload(p func(string) string, rep *Report) {
	data, err := os.ReadFile(p(preloadPath))
	if err != nil {
		rep.add(Check{ID: "preload_entry", Title: "/etc/ld.so.preload", Severity: SeverityInfo,
			Detail: "file absent or unreadable (clean baseline)"})
		return
	}
	lines := nonEmptyLines(string(data))
	if len(lines) == 0 {
		rep.add(Check{ID: "preload_entry", Title: "/etc/ld.so.preload", Severity: SeverityInfo,
			Detail: "present but empty"})
		return
	}
	for _, line := range lines {
		for _, bad := range knownBadPreload {
			if strings.Contains(line, bad) {
				rep.add(Check{ID: "preload_entry", Title: "/etc/ld.so.preload references libnet.so",
					Severity: SeverityConfirmed,
					Detail: fmt.Sprintf("entry %q matches the DDEI rootkit family loader path", line)})
				return
			}
		}
	}
	rep.add(Check{ID: "preload_entry", Title: "/etc/ld.so.preload has unexpected entries",
		Severity: SeverityHigh,
		Detail: "entries: " + strings.Join(lines, ", ") + " — verify package ownership (rpm -qf)"})
}

func checkLibFiles(p func(string) string, rep *Report) {
	foundAny := false
	for _, cand := range libCandidates {
		full := p(cand)
		info, err := os.Stat(full)
		if err != nil || info.IsDir() {
			continue
		}
		foundAny = true
		md5s, sha := hashFile(full)
		if note, ok := knownLibMD5s[md5s]; ok {
			rep.add(Check{ID: "libnet_file", Title: "family library file present",
				Severity: SeverityConfirmed, Detail: fmt.Sprintf("%s md5=%s (%s)", cand, md5s, note)})
			return
		}
		if note, ok := knownLibSHA256s[sha]; ok {
			rep.add(Check{ID: "libnet_file", Title: "family library file present",
				Severity: SeverityConfirmed, Detail: fmt.Sprintf("%s sha256=%s (%s)", cand, sha, note)})
			return
		}
		rep.add(Check{ID: "libnet_file", Title: "unexpected libnet.so on system library path",
			Severity: SeverityHigh,
			Detail: fmt.Sprintf("%s size=%d md5=%s — not a known family hash and not package-owned on stock CentOS", cand, info.Size(), md5s)})
	}
	if !foundAny {
		rep.add(Check{ID: "libnet_file", Title: "libnet.so on system paths", Severity: SeverityInfo,
			Detail: "no libnet.so under /usr/lib64 or /lib64"})
	}
}

func checkXinetd(p func(string) string, rep *Report) {
	full := p(xinetdPath)
	info, err := os.Stat(full)
	if err != nil {
		rep.add(Check{ID: "xinetd_binary", Title: "/usr/sbin/xinetd", Severity: SeverityInfo,
			Detail: "file absent (host without xinetd package)"})
		return
	}
	md5s, _ := hashFile(full)
	if md5s == knownXinetdMD5 {
		rep.add(Check{ID: "xinetd_binary", Title: "xinetd binary replaced by family dropper",
			Severity: SeverityConfirmed,
			Detail: fmt.Sprintf("md5=%s matches the 5.9 MB Rust dropper sample", md5s)})
		return
	}
	if info.Size() > xinetdSizeLimit {
		rep.add(Check{ID: "xinetd_binary", Title: "xinetd binary size anomaly",
			Severity: SeverityHigh,
			Detail: fmt.Sprintf("size=%d exceeds 1 MiB; stock CentOS 7 xinetd is a ~166 KiB dynamic binary — consistent with a statically linked replacement", info.Size())})
	}
	ctime := ctimeOf(full)
	if !ctime.IsZero() && info.ModTime().Before(ctime.AddDate(0, 0, -180)) {
		rep.add(Check{ID: "xinetd_binary", Title: "xinetd mtime/ctime inversion (timestomp)",
			Severity: SeverityMedium,
			Detail: fmt.Sprintf("mtime=%s ctime=%s — modification time predates inode change by >180 days", info.ModTime().UTC().Format(time.RFC3339), ctime.UTC().Format(time.RFC3339))})
	}
}

func checkMarkers(p func(string) string, rep *Report) {
	hit := false
	for _, m := range markerFiles {
		if _, err := os.Stat(p(m)); err == nil {
			rep.add(Check{ID: "marker_file", Title: "family marker present",
				Severity: SeverityConfirmed, Detail: m + " exists (dropper marker/sign file)"})
			hit = true
		}
	}
	if !hit {
		rep.add(Check{ID: "marker_file", Title: "family marker files", Severity: SeverityInfo,
			Detail: "none of " + strings.Join(markerFiles, ", ") + " found"})
	}
}

func checkSystemd(p func(string) string, rep *Report) {
	link := p(systemdWantsSymlink)
	info, err := os.Lstat(link)
	if err != nil {
		rep.add(Check{ID: "systemd_unit", Title: "xinetd systemd persistence", Severity: SeverityInfo,
			Detail: "no multi-user.target.wants/xinetd.service symlink"})
		return
	}
	ctime := ctimeOf(link)
	detail := fmt.Sprintf("mode=%s", info.Mode().String())
	if !ctime.IsZero() {
		detail += fmt.Sprintf(" created/changed=%s (incident window Aug 2026)", ctime.UTC().Format(time.RFC3339))
	}
	rep.add(Check{ID: "systemd_unit", Title: "xinetd.service enabled via multi-user.target.wants",
		Severity: SeverityMedium, Detail: detail})
}

func checkProcMaps(opts Options, p func(string) string, rep *Report) {
	entries, err := os.ReadDir(p("/proc"))
	if err != nil {
		rep.add(Check{ID: "proc_maps", Title: "/proc maps scan", Severity: SeverityInfo,
			Detail: "cannot enumerate /proc"})
		return
	}
	libProcs := map[int]ProcHit{}
	rwxProcs := map[int]ProcHit{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == opts.SelfPID {
			continue
		}
		mapsPath := p("/proc/" + e.Name() + "/maps")
		data, err := os.ReadFile(mapsPath)
		if err != nil {
			continue
		}
		hit := ProcHit{PID: pid, Comm: commOf(p("/proc/" + e.Name())), Exe: exeOf(p("/proc/" + e.Name()))}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}
			perms, path := fields[1], fields[5]
			if strings.Contains(path, "libnet.so") {
				libProcs[pid] = hit
			}
			if strings.HasPrefix(perms, "rwx") && !strings.HasPrefix(path, "[") && hit.Exe == xinetdPath {
				rwxProcs[pid] = ProcHit{PID: pid, Comm: hit.Comm, Exe: hit.Exe, Note: "rwx region: " + fields[0]}
			}
		}
	}
	if len(libProcs) > 0 {
		pids := sortedPIDs(libProcs)
		rep.ProcHits = append(rep.ProcHits, mapValues(libProcs)...)
		rep.add(Check{ID: "proc_maps", Title: "libnet.so mapped in live processes",
			Severity: SeverityHigh,
			Detail: fmt.Sprintf("%d process(es) map the family library (pids: %s) — library is loaded via ld.so.preload", len(libProcs), pids)})
	}
	if len(rwxProcs) > 0 {
		rep.ProcHits = append(rep.ProcHits, mapValues(rwxProcs)...)
		rep.add(Check{ID: "proc_maps", Title: "RWX region inside running xinetd",
			Severity: SeverityHigh,
			Detail: "xinetd keeps writable+executable memory — matches the in-memory decrypted payload stage"})
	}
	if len(libProcs) == 0 && len(rwxProcs) == 0 {
		rep.add(Check{ID: "proc_maps", Title: "/proc maps scan", Severity: SeverityInfo,
			Detail: "no process maps libnet.so and no xinetd RWX region"})
	}
}

func checkLogTraces(opts Options, p func(string) string, rep *Report) {
	var matched []string
	for _, f := range logTraceFiles {
		path := p(f)
		data, err := readFileTail(path, opts.LogTailBytes)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, logTraceNeedle) || strings.Contains(line, "libnet.so") {
				matched = append(matched, strings.TrimSpace(line))
				if len(matched) >= 5 {
					break
				}
			}
		}
	}
	if len(matched) > 0 {
		rep.add(Check{ID: "log_traces", Title: "loader errors in system logs",
			Severity: SeverityMedium,
			Detail: fmt.Sprintf("%d matching line(s), e.g. %q", len(matched), firstNonEmpty(matched))})
	} else {
		rep.add(Check{ID: "log_traces", Title: "loader errors in system logs", Severity: SeverityInfo,
			Detail: "no ld.so.preload failure lines in recent messages logs"})
	}
}

func hashFile(path string) (md5s, sha string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	m := md5.Sum(data)
	s := sha256.Sum256(data)
	return hex.EncodeToString(m[:]), hex.EncodeToString(s[:])
}

func readFileTail(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	if limit <= 0 || size <= limit {
		data, err := os.ReadFile(path)
		return data, err
	}
	if _, err := f.Seek(size-limit, 0); err != nil {
		return nil, err
	}
	buf := make([]byte, limit)
	n, err := f.Read(buf)
	return buf[:n], err
}

func commOf(procDir string) string {
	data, err := os.ReadFile(procDir + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func exeOf(procDir string) string {
	exe, err := os.Readlink(procDir + "/exe")
	if err != nil {
		return ""
	}
	return exe
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func firstNonEmpty(items []string) string {
	for _, s := range items {
		if s != "" {
			return s
		}
	}
	return ""
}

func sortedPIDs(m map[int]ProcHit) string {
	pids := make([]int, 0, len(m))
	for pid := range m {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	parts := make([]string, len(pids))
	for i, pid := range pids {
		parts[i] = strconv.Itoa(pid)
	}
	return strings.Join(parts, ",")
}

func mapValues(m map[int]ProcHit) []ProcHit {
	out := make([]ProcHit, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}
