// Package ddeirootkit decides whether a host is compromised by the
// "libnet.so / xinetd" LD_PRELOAD rootkit family (DDEI appliance incident,
// 2026-09). The detector is a static Go binary: it does not load libc, so
// LD_PRELOAD hooks have no effect on its view of the filesystem, and it
// anchors on kernel-provided /proc data that user-space rootkits cannot
// hide from it.
//
// Design goals (v2): few checks, each independently decisive, name-agnostic
// where possible. A library is judged by behaviour (which libc symbols it
// DEFINES — a preload hook must define stat/readdir/...), not by file name,
// so renamed or rebuilt variants of the same builder are still caught while
// legitimate same-name libraries (e.g. the libnet-devel packet library) are
// not flagged.
package ddeirootkit

import (
	"crypto/md5"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Verdict answers the single question that matters: is this host compromised?
type Verdict string

const (
	VerdictClean     Verdict = "CLEAN"     // no family indicators
	VerdictReview    Verdict = "REVIEW"    // soft signal only, manual look needed
	VerdictInfected  Verdict = "INFECTED"  // decisive family indicator present
)

// Level of a single finding. Only Compromised findings decide the verdict.
type Level string

const (
	LevelCompromised Level = "COMPROMISED"
	LevelReview      Level = "REVIEW"
	LevelInfo        Level = "INFO"
)

// Finding is one check result.
type Finding struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Level  Level  `json:"level"`
	Detail string `json:"detail,omitempty"`
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
	Findings  []Finding `json:"findings"`
	ProcHits  []ProcHit `json:"proc_hits,omitempty"`
}

// Options tunes the detector. Root allows tests to point at a fixture tree;
// production callers leave it empty for "/".
type Options struct {
	Root         string
	SelfPID      int
	Hostname     string
	ScanProcMaps bool
}

// Family indicators from the incident evidence (exact matches, checked first).
var (
	FamilyName = "DDEI-libnet/xinetd rootkit"

	preloadPath = "/etc/ld.so.preload"

	knownLibMD5s = map[string]string{
		"eebbba3f7ff5eb7ab0f64fc5074a6ce5": "libnet.so.1 sample (2026-09 case)",
	}
	knownLibSHA256s = map[string]string{
		"acf5641c6c84774de63562a6e7080a0c4271451eef6429618f364c2308dd27cc": "libnet.so.1 sample (2026-09 case)",
	}
	knownXinetdMD5    = "003bf75d53504889e13bf12d6af5b28f"
	knownXinetdSHA256 = "8c175c21535907d437cb231a0bb91e2d52df51343ae62a11770b62d28f21d763"

	xinetdPath  = "/usr/sbin/xinetd"
	xinetdLimit = int64(1 << 20) // stock CentOS 7 xinetd is a ~166 KiB dynamic ELF

	markerDirs = []string{"/media/vbccsb", "/home/vbccsb"}
	signFile   = "/root/sign.txt"
)

// hookSymbols: a user-space preload rootkit MUST define these to intercept
// libc callers. A legitimate library may import them but never define them.
var hookSymbols = map[string]bool{
	"stat": true, "stat64": true, "lstat": true, "lstat64": true,
	"xstat": true, "fxstat": true, "lxstat": true, "__lxstat": true,
	"statx": true, "fstatat": true, "newfstatat": true,
	"readdir": true, "readdir64": true,
	"fopen": true, "fopen64": true, "open": true, "open64": true,
	"access": true, "unlink": true, "unlinkat": true,
}

// elfFacts is the behavioural fingerprint of a shared object.
type elfFacts struct {
	IsELF        bool
	HasInterpreter bool // PT_INTERP present => dynamically linked program
	DefinedHooks int    // count of hookSymbols DEFINED (exported)
	DefinedTotal int
}

// inspectELF is a seam: tests replace it to avoid needing real ELF fixtures.
var inspectELF = realInspectELF

func realInspectELF(path string) elfFacts {
	var facts elfFacts
	raw, err := os.Open(path)
	if err != nil {
		return facts
	}
	defer raw.Close()
	f, err := elf.NewFile(raw)
	if err != nil {
		return facts
	}
	defer f.Close()
	facts.IsELF = true
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP && prog.Filesz > 0 {
			buf := make([]byte, prog.Filesz)
			if _, err := raw.ReadAt(buf, int64(prog.Off)); err == nil && len(strings.TrimSpace(string(buf))) > 0 {
				facts.HasInterpreter = true
			}
			break
		}
	}
	syms, err := f.DynamicSymbols()
	if err != nil {
		return facts
	}
	for _, s := range syms {
		// A DEFINED (exported) symbol carries an address; imports do not.
		if s.Value == 0 {
			continue
		}
		facts.DefinedTotal++
		if hookSymbols[s.Name] {
			facts.DefinedHooks++
		}
	}
	return facts
}

// looksLikeHookLib: defines enough libc file-walk symbols to be a preload
// hook. Real shared libraries (libnet packet lib, libesmtp, ...) define their
// own namespace only, so this does not fire on them.
func looksLikeHookLib(f elfFacts) bool {
	return f.IsELF && f.DefinedHooks >= 2
}

// Run executes the checks and assembles the report.
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
	p := func(rel string) string { return filepath.Join(opts.Root, rel) }

	rep := Report{Timestamp: time.Now().UTC(), Hostname: opts.Hostname}

	suspiciousLibs := checkPreload(p, &rep)
	checkXinetd(p, &rep)
	checkMarkers(p, &rep)
	if opts.ScanProcMaps {
		checkProcMaps(opts, p, &rep, suspiciousLibs)
	}

	rep.Verdict, rep.Summary = conclude(rep.Findings)
	return rep
}

func conclude(findings []Finding) (Verdict, string) {
	var compromised, review int
	for _, f := range findings {
		switch f.Level {
		case LevelCompromised:
			compromised++
		case LevelReview:
			review++
		}
	}
	switch {
	case compromised > 0:
		var first string
		for _, f := range findings {
			if f.Level == LevelCompromised {
				first = f.Title
				break
			}
		}
		return VerdictInfected, fmt.Sprintf("%d decisive indicator(s); first: %s", compromised, first)
	case review > 0:
		return VerdictReview, fmt.Sprintf("%d soft indicator(s) without a family match — manual review recommended", review)
	default:
		return VerdictClean, "no family indicators observed"
	}
}

func (r *Report) add(f Finding) { r.Findings = append(r.Findings, f) }

// checkPreload inspects every /etc/ld.so.preload entry. The referenced file
// is judged by behaviour (defined hook symbols) or exact family hash, so the
// check is name-agnostic: renamed family libraries still fire, legitimate
// same-name libraries do not. Returns the paths that looked like hook libs.
func checkPreload(p func(string) string, rep *Report) []string {
	var suspicious []string
	data, err := os.ReadFile(p(preloadPath))
	if err != nil {
		rep.add(Finding{ID: "preload_hooklib", Title: "/etc/ld.so.preload", Level: LevelInfo,
			Detail: "file absent (clean baseline)"})
		return suspicious
	}
	entries := nonEmptyLines(string(data))
	if len(entries) == 0 {
		rep.add(Finding{ID: "preload_hooklib", Title: "/etc/ld.so.preload", Level: LevelInfo,
			Detail: "present but empty"})
		return suspicious
	}
	for _, entry := range entries {
		full := p(strings.TrimSpace(entry))
		info, err := os.Stat(full)
		if err != nil {
			rep.add(Finding{ID: "preload_hooklib", Title: "preload entry points to missing file",
				Level: LevelReview,
				Detail: fmt.Sprintf("%s does not exist (broken or leftover entry)", entry)})
			continue
		}
		if info.IsDir() {
			continue
		}
		md5s, sha := hashFile(full)
		if _, ok := knownLibMD5s[md5s]; ok {
			rep.add(Finding{ID: "preload_hooklib", Title: "family rootkit library is preloaded",
				Level: LevelCompromised,
				Detail: fmt.Sprintf("%s md5=%s (exact family match)", entry, md5s)})
			suspicious = append(suspicious, entry)
			continue
		}
		if _, ok := knownLibSHA256s[sha]; ok {
			rep.add(Finding{ID: "preload_hooklib", Title: "family rootkit library is preloaded",
				Level: LevelCompromised,
				Detail: fmt.Sprintf("%s sha256=%s (exact family match)", entry, sha)})
			suspicious = append(suspicious, entry)
			continue
		}
		if facts := inspectELF(full); looksLikeHookLib(facts) {
			rep.add(Finding{ID: "preload_hooklib", Title: "preload entry is a libc-hook library",
				Level: LevelCompromised,
				Detail: fmt.Sprintf("%s DEFINES %d libc file-walk symbols (stat/readdir/open family) — a legitimate library never exports these", entry, facts.DefinedHooks)})
			suspicious = append(suspicious, entry)
			continue
		}
		rep.add(Finding{ID: "preload_hooklib", Title: "unexpected preload entry (not family)",
			Level: LevelReview,
			Detail: fmt.Sprintf("%s exists but shows no hook behaviour (defined hooks=%d) — verify ownership if unexpected", entry, factsOf(full))})
	}
	return suspicious
}

func factsOf(path string) int { return inspectELF(path).DefinedHooks }

// checkXinetd decides whether /usr/sbin/xinetd was replaced. Stock xinetd is
// a small dynamically linked ELF; the family dropper is a large stripped
// static PIE. Either an exact hash or the static/large shape is decisive.
func checkXinetd(p func(string) string, rep *Report) {
	full := p(xinetdPath)
	info, err := os.Stat(full)
	if err != nil {
		rep.add(Finding{ID: "xinetd_replaced", Title: "/usr/sbin/xinetd", Level: LevelInfo,
			Detail: "file absent (host without xinetd)"})
		return
	}
	md5s, sha := hashFile(full)
	if md5s == knownXinetdMD5 || sha == knownXinetdSHA256 {
		rep.add(Finding{ID: "xinetd_replaced", Title: "xinetd binary is the family dropper",
			Level: LevelCompromised,
			Detail: fmt.Sprintf("hash matches the 5.9 MB Rust dropper sample (md5=%s)", md5s)})
		return
	}
	facts := inspectELF(full)
	if facts.IsELF && !facts.HasInterpreter {
		rep.add(Finding{ID: "xinetd_replaced", Title: "xinetd binary is statically linked",
			Level: LevelCompromised,
			Detail: "no PT_INTERP: stock xinetd is dynamically linked against libc — a static build at /usr/sbin/xinetd is a replacement (family droppers are static PIE)"})
		return
	}
	if info.Size() > xinetdLimit {
		rep.add(Finding{ID: "xinetd_replaced", Title: "xinetd binary size anomaly",
			Level: LevelCompromised,
			Detail: fmt.Sprintf("size=%d exceeds 1 MiB; stock xinetd is ~166 KiB", info.Size())})
		return
	}
	rep.add(Finding{ID: "xinetd_replaced", Title: "/usr/sbin/xinetd", Level: LevelInfo,
		Detail: fmt.Sprintf("size=%d, dynamically linked — consistent with stock package", info.Size())})
}

// checkMarkers looks for family marker files. /root/sign.txt only counts
// when its content is a 64-hex bot id (the dropper's actual format), which
// excludes admin-made files of the same name.
func checkMarkers(p func(string) string, rep *Report) {
	for _, dir := range markerDirs {
		if _, err := os.Stat(p(dir)); err == nil {
			rep.add(Finding{ID: "markers", Title: "family marker directory present",
				Level: LevelCompromised, Detail: dir + " exists (operator-named marker)"})
		}
	}
	data, err := os.ReadFile(p(signFile))
	if err != nil {
		return
	}
	content := strings.TrimSpace(string(data))
	if isHex64(content) {
		rep.add(Finding{ID: "markers", Title: "family infection marker /root/sign.txt",
			Level: LevelCompromised, Detail: "content is a 64-hex bot id: " + content})
	} else if content != "" {
		rep.add(Finding{ID: "markers", Title: "/root/sign.txt present (content not a bot id)",
			Level: LevelInfo, Detail: fmt.Sprintf("content %q is not the family 64-hex format; not counted", truncate(content, 40))})
	}
}

// checkProcMaps anchors on kernel-provided /proc data. Two decisive signs:
// any process mapping a hook-like library (verified by symbols, not name),
// and RWX memory inside a running xinetd (the in-memory payload stage).
func checkProcMaps(opts Options, p func(string) string, rep *Report, suspiciousLibs []string) {
	entries, err := os.ReadDir(p("/proc"))
	if err != nil {
		rep.add(Finding{ID: "live_behavior", Title: "/proc scan", Level: LevelInfo,
			Detail: "cannot enumerate /proc"})
		return
	}
	hookPaths := map[string]bool{}
	for _, lib := range suspiciousLibs {
		hookPaths[strings.TrimSpace(lib)] = true
	}
	hookByPid := map[int]ProcHit{}
	rwxByPid := map[int]ProcHit{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == opts.SelfPID {
			continue
		}
		procDir := p("/proc/" + e.Name())
		data, err := os.ReadFile(procDir + "/maps")
		if err != nil {
			continue
		}
		exe := exeOf(procDir)
		hit := ProcHit{PID: pid, Comm: commOf(procDir), Exe: exe}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}
			perms, path := fields[1], fields[5]
			if strings.HasPrefix(perms, "rwx") && !strings.HasPrefix(path, "[") && exe == xinetdPath {
				rwxByPid[pid] = ProcHit{PID: pid, Comm: hit.Comm, Exe: exe, Note: "rwx region " + fields[0]}
				continue
			}
			if path == "" || hookPaths[path] || strings.HasPrefix(path, "/memfd:") {
				continue
			}
			// verify mapped library by behaviour, not by name
			if _, checked := hookPaths[path]; !checked && strings.HasSuffix(path, ".so") {
				facts := inspectELF(p(path))
				if looksLikeHookLib(facts) {
					hookPaths[path] = true
				} else {
					hookPaths[path] = false
				}
			}
			if hookPaths[path] {
				hookByPid[pid] = hit
			}
		}
	}
	if len(hookByPid) > 0 {
		rep.ProcHits = append(rep.ProcHits, mapValues(hookByPid)...)
		rep.add(Finding{ID: "live_behavior", Title: "hook library mapped in live processes",
			Level: LevelCompromised,
			Detail: fmt.Sprintf("%d process(es) map a libc-hook library (pids: %s)", len(hookByPid), sortedPIDs(hookByPid))})
	}
	if len(rwxByPid) > 0 {
		rep.ProcHits = append(rep.ProcHits, mapValues(rwxByPid)...)
		rep.add(Finding{ID: "live_behavior", Title: "RWX memory inside running xinetd",
			Level: LevelCompromised,
			Detail: "xinetd keeps writable+executable mappings — matches the in-memory decrypted payload stage"})
	}
	if len(hookByPid) == 0 && len(rwxByPid) == 0 {
		rep.add(Finding{ID: "live_behavior", Title: "/proc scan", Level: LevelInfo,
			Detail: "no process maps a hook library; no RWX region in xinetd"})
	}
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
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
