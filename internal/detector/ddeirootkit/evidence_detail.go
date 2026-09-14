package ddeirootkit

import (
	"fmt"
	"strings"
)

func pamDetail(o Observations) string {
	controls := map[string]map[string]bool{}
	for _, p := range o.PAMAuth {
		key := p.Config + "\x00" + p.ObjectID
		if controls[key] == nil {
			controls[key] = map[string]bool{}
		}
		controls[key][strings.Join(strings.Fields(p.Control), " ")] = true
	}
	var details []string
	for _, p := range o.PAMAuth {
		c := controls[p.Config+"\x00"+p.ObjectID]
		if c["[success=1 default=ignore]"] && c["[success=done default=ignore]"] {
			details = append(details, fmt.Sprintf("PAM service=%s module=%s object=%s auth control=%s", p.Config, p.Module, p.ObjectID, p.Control))
		}
	}
	return strings.Join(details, "; ")
}

func behaviorDetail(o Observations, withPAM bool) string {
	objects := map[string]ObjectObservation{}
	for _, x := range o.Objects {
		objects[x.ID] = x
	}
	var parts []string
	for _, id := range o.PreloadObjects {
		x, ok := objects[id]
		if !ok {
			continue
		}
		var pids []int
		for _, p := range o.Processes {
			for _, mapped := range p.MappedObjects {
				if mapped == id {
					pids = append(pids, p.PID)
					break
				}
			}
		}
		if len(pids) == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("preload=%s object=%s mapped_pids=%v exported_hooks=%v categories=%v", x.Path, id, pids, x.HookNames, x.HookCategories))
	}
	if withPAM {
		parts = append(parts, pamDetail(o))
	}
	for _, p := range o.Processes {
		if p.UID == 0 && p.PPID == 1 && (p.RWX || p.AnonymousRWX) && p.HasPTY {
			parts = append(parts, fmt.Sprintf("daemon pid=%d exe=%s uid=%d ppid=%d RWX=true regions=%v PTY=true fd_targets=%v", p.PID, p.Exe, p.UID, p.PPID, p.RWXRegions, p.PTYPaths))
		}
	}
	parts = append(parts, "高特异性行为关联；不代表绝对无误报，也不单独证明攻击者归属")
	return strings.Join(parts, "; ")
}
