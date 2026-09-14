// Package ddeirootkit evaluates scoped observations against case evidence.
// CLEAN is bounded by coverage and is not proof that a host is uncompromised.
package ddeirootkit

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type Verdict string

const (
	VerdictClean        Verdict = "CLEAN"
	VerdictReview       Verdict = "REVIEW"
	VerdictInconclusive Verdict = "INCONCLUSIVE"
	VerdictInfected     Verdict = "INFECTED"
)

type Level string

const (
	LevelCompromised Level = "COMPROMISED"
	LevelReview      Level = "REVIEW"
	LevelInfo        Level = "INFO"
)

type Finding struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Level  Level  `json:"level"`
	Detail string `json:"detail,omitempty"`
}
type ProcHit struct {
	PID  int    `json:"pid"`
	Comm string `json:"comm,omitempty"`
	Exe  string `json:"exe,omitempty"`
	Note string `json:"note,omitempty"`
}
type Coverage struct {
	Root      bool `json:"root"`
	Proc      bool `json:"proc"`
	Processes int  `json:"processes"`
	Objects   int  `json:"objects"`
	Errors    int  `json:"errors"`
	Skipped   int  `json:"skipped"`
}
type Report struct {
	Timestamp time.Time `json:"timestamp"`
	Hostname  string    `json:"hostname,omitempty"`
	Verdict   Verdict   `json:"verdict"`
	Summary   string    `json:"summary,omitempty"`
	Complete  bool      `json:"complete"`
	Coverage  Coverage  `json:"coverage"`
	Findings  []Finding `json:"findings"`
	ProcHits  []ProcHit `json:"proc_hits,omitempty"`
}
type Options struct {
	Root         string
	SelfPID      int
	Hostname     string
	ScanProcMaps bool
}

var FamilyName = "DDEI-libnet/xinetd rootkit"

const (
	SeptemberLibrarySHA256 = "acf5641c6c84774de63562a6e7080a0c4271451eef6429618f364c2308dd27cc"
	SeptemberXinetdSHA256  = "8c175c21535907d437cb231a0bb91e2d52df51343ae62a11770b62d28f21d763"
	AugustLoaderSHA256     = "96336e90dce02fc7524873dca3c3e5556bf93dba86cafc75ad874b2f97f079c3"
	AugustXinetdSHA256     = "f8d7f90ce69e31ff7a8e04bd60af0475044a03ca854a54ae86bc0b7eb198d374"
	AugustPAMSHA256        = "82e9ebd1455fb44e633aa22dfc234b24ad45ef22053cc99944a8b2bca6b40957"
	knownXinetdMD5         = "003bf75d53504889e13bf12d6af5b28f"
	knownXinetdSHA256      = SeptemberXinetdSHA256
)

var knownLibMD5s = map[string]string{"eebbba3f7ff5eb7ab0f64fc5074a6ce5": "September case"}
var knownLibSHA256s = map[string]string{SeptemberLibrarySHA256: "September case"}

// IDs identify successfully read objects, not names. Replay callers must retain
// evidence provenance and provide observations from one host and collection.
type ObjectObservation struct {
	ID, Path, SHA256, MD5, Role string
	ELF, Static                 bool
	ValidELF                    bool
	ELFError                    string
	Hooks                       int
	HookNames, HookCategories   []string
	ELFType                     string
	Size                        int64
}
type PAMObservation struct {
	Config, Control, Module, ObjectID string
}
type MappingObservation struct {
	ObjectID, Address, Permissions, Path string
	Deleted                              bool
}
type ProcessObservation struct {
	PID                  int
	StartTimeTicks       uint64
	UID, PPID            int
	HasPTY               bool
	Comm, Exe, ExeObject string
	MappedObjects        []string
	AnonymousRWX         bool
	RWX                  bool
	RWXRegions, PTYPaths []string
	Mappings             []MappingObservation
}
type Observations struct {
	Timestamp      time.Time
	Hostname       string
	Coverage       Coverage
	Objects        []ObjectObservation
	Processes      []ProcessObservation
	PreloadObjects []string
	AuthPAMObjects []string
	PAMAuth        []PAMObservation
	NetworkPeers   []NetworkObservation
	Gaps           []string
	Suspicious     []string
}

// Evaluate performs no IO. August hashes are case-associated, not independent
// reverse-engineering identifications. Two active exact components are required.
func Evaluate(o Observations) Report {
	r := Report{Timestamp: o.Timestamp, Hostname: o.Hostname, Coverage: o.Coverage, Findings: []Finding{}}
	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now().UTC()
	}
	r.Coverage.Errors += len(o.Gaps)
	r.Complete = o.Coverage.Root && o.Coverage.Proc && r.Coverage.Errors == 0
	objects := map[string]ObjectObservation{}
	exact := map[string]bool{}
	loader, secondary := false, false
	configured := map[string]bool{}
	mapped := map[string]bool{}
	daemonPayload := false
	add := func(id, title string, level Level, detail string) {
		r.Findings = append(r.Findings, Finding{id, title, level, detail})
	}
	for _, x := range o.Objects {
		objects[x.ID] = x
		if x.ELFError != "" {
			add("object_error", "对象 ELF 验证失败", LevelReview, x.Path+": "+x.ELFError)
			recorded := false
			for _, gap := range o.Gaps {
				if gap == x.Path+": "+x.ELFError {
					recorded = true
					break
				}
			}
			if !recorded {
				r.Coverage.Errors++
			}
			r.Complete = false
		}
		if x.SHA256 == SeptemberLibrarySHA256 || x.SHA256 == SeptemberXinetdSHA256 {
			exact[x.ID] = true
			add("exact_sha256", "September family SHA-256 match", LevelCompromised, x.Path+" sha256="+x.SHA256)
		} else if _, ok := knownLibMD5s[x.MD5]; ok || x.MD5 == knownXinetdMD5 {
			add("legacy_md5", "Legacy MD5 requires SHA-256 confirmation", LevelReview, x.Path)
		}
		if x.SHA256 == AugustLoaderSHA256 || x.SHA256 == AugustPAMSHA256 || x.SHA256 == AugustXinetdSHA256 {
			add("aug_case", "August case-associated object", LevelReview, x.Path+" sha256="+x.SHA256)
		}
		if x.Role == "preload" && (x.Hooks >= 2 || !x.ELF) || x.Role == "pam" && !x.ELF || x.Role == "xinetd" && (x.Static || x.Size > 1<<20 || !x.ELF) {
			add("anomaly", "Unresolved object anomaly", LevelReview, x.Path)
		}
	}
	for _, id := range o.AuthPAMObjects {
		if objects[id].SHA256 == AugustPAMSHA256 {
			secondary = true
		}
	}
	for _, id := range o.PreloadObjects {
		if _, ok := objects[id]; ok {
			configured[id] = true
		}
		if objects[id].SHA256 == AugustLoaderSHA256 {
			loader = true
		}
	}
	for _, p := range o.Processes {
		hit := exact[p.ExeObject]
		if p.UID == 0 && p.PPID == 1 && (p.RWX || p.AnonymousRWX) && p.HasPTY {
			daemonPayload = true
		}
		if objects[p.ExeObject].SHA256 == AugustXinetdSHA256 {
			secondary = true
			hit = true
		}
		for _, id := range p.MappedObjects {
			mapped[id] = true
			if objects[id].SHA256 == AugustLoaderSHA256 {
				loader = true
				hit = true
			}
			if exact[id] {
				hit = true
			}
		}
		if p.RWX || p.AnonymousRWX {
			level := LevelInfo
			if len(configured) > 0 {
				level = LevelReview
			}
			add("rwx", "RWX mapping (also used by legitimate JIT runtimes)", level, fmt.Sprintf("pid=%d exe=%s", p.PID, p.Exe))
		}
		if hit {
			r.ProcHits = append(r.ProcHits, ProcHit{PID: p.PID, Comm: p.Comm, Exe: p.Exe, Note: "case hash observed"})
		}
	}
	activePreload, broadPreload := false, false
	for id := range configured {
		if !mapped[id] {
			continue
		}
		x := objects[id]
		if !x.ValidELF || !x.ELF || x.ELFType != "ET_DYN" {
			continue
		}
		activePreload = true
		names, categories := map[string]bool{}, map[string]bool{}
		for _, name := range x.HookNames {
			if hookSymbols[name] {
				names[name] = true
			}
		}
		for _, category := range x.HookCategories {
			categories[category] = true
		}
		if len(names) >= 5 && len(categories) >= 3 {
			broadPreload = true
		}
	}
	pamControls := map[string]map[string]bool{}
	for _, p := range o.PAMAuth {
		if p.Config == "" || p.ObjectID == "" {
			continue
		}
		if _, ok := objects[p.ObjectID]; !ok {
			continue
		}
		key := p.Config + "\x00" + p.ObjectID
		if pamControls[key] == nil {
			pamControls[key] = map[string]bool{}
		}
		pamControls[key][strings.Join(strings.Fields(p.Control), " ")] = true
	}
	pamPair, validPAMPair := false, false
	for key, controls := range pamControls {
		if controls["[success=1 default=ignore]"] && controls["[success=done default=ignore]"] {
			pamPair = true
			x := objects[strings.SplitN(key, "\x00", 2)[1]]
			if x.ValidELF && x.ELF && x.ELFType == "ET_DYN" {
				validPAMPair = true
			}
		}
	}
	if activePreload && validPAMPair && daemonPayload {
		add("behavior_preload_pam_daemon", "预加载、PAM 认证控制和守护进程行为关联命中", LevelCompromised, behaviorDetail(o, true))
	} else if broadPreload && daemonPayload {
		add("behavior_hooks_daemon", "广泛预加载拦截与守护进程行为关联命中", LevelCompromised, behaviorDetail(o, false))
	}
	if daemonPayload && (activePreload && validPAMPair || broadPreload) {
		seen := map[int]bool{}
		for _, hit := range r.ProcHits {
			seen[hit.PID] = true
		}
		for _, p := range o.Processes {
			participates := p.UID == 0 && p.PPID == 1 && (p.RWX || p.AnonymousRWX) && p.HasPTY
			for _, id := range p.MappedObjects {
				if configured[id] {
					participates = true
				}
			}
			if participates && !seen[p.PID] {
				r.ProcHits = append(r.ProcHits, ProcHit{PID: p.PID, Comm: p.Comm, Exe: p.Exe, Note: "participant in correlated behavioral mechanisms"})
				seen[p.PID] = true
			}
		}
	}
	if pamPair {
		add("pam_control_pair", "PAM 认证模块存在成对跳转控制，需核实", LevelReview, pamDetail(o))
	}
	if loader && secondary {
		add("aug_correlated", "Correlated August case components", LevelCompromised, "Exact case loader configured or mapped, with exact case PAM configured for auth or exact case xinetd running")
	}
	for _, s := range o.Suspicious {
		add("anomaly", "Unresolved observation", LevelReview, s)
	}
	for _, g := range o.Gaps {
		add("coverage_gap", "Required observation unavailable", LevelReview, g)
	}
	if !r.Complete {
		add("coverage_gap", "Coverage incomplete", LevelReview, "Root and live proc coverage without observation errors required")
	}
	r.Findings = append(r.Findings, networkFindings(o)...)
	r.Verdict = VerdictClean
	for _, f := range r.Findings {
		if f.Level == LevelReview {
			r.Verdict = VerdictInconclusive
		}
	}
	for _, f := range r.Findings {
		if f.Level == LevelCompromised {
			r.Verdict = VerdictInfected
			break
		}
	}
	r.Summary = fmt.Sprintf("%s; complete=%t; observation errors=%d; scoped evidence only", r.Verdict, r.Complete, r.Coverage.Errors)
	return r
}
func Run(opts Options) Report                             { return RunContext(context.Background(), opts) }
func RunContext(ctx context.Context, opts Options) Report { return Evaluate(Collect(ctx, opts)) }
