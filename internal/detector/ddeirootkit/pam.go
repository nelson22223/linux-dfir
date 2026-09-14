package ddeirootkit

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Architecture facts come only from the inspected snapshot, never the directory
// name or the scanner's architecture. Empty/invalid facts cannot resolve a group.
func pamArchitecture(x ObjectObservation) string {
	if !x.ValidELF || !x.ELF || (x.ELFClass != "ELFCLASS32" && x.ELFClass != "ELFCLASS64") || !strings.HasPrefix(x.ELFMachine, "EM_") || strings.Contains(x.ELFMachine, "+") || x.ELFMachine == "EM_NONE" || (x.ELFData != "ELFDATA2LSB" && x.ELFData != "ELFDATA2MSB") {
		return ""
	}
	return x.ELFClass + ":" + x.ELFMachine + ":" + x.ELFData
}

func (c *collector) pamCandidates(config, control, token string) {
	gapStart := len(c.o.Gaps)
	if strings.ContainsAny(token, "$/") {
		c.gap(token, fmt.Errorf("unresolved PAM module"))
		return
	}
	dirs := []string{"/lib/security", "/lib64/security", "/usr/lib/security", "/usr/lib64/security", "/lib32/security", "/usr/lib32/security"}
	for _, arch := range []string{"x86_64-linux-gnu", "i386-linux-gnu", "aarch64-linux-gnu"} {
		for _, base := range []string{"/lib", "/usr/lib"} {
			dirs = append(dirs, base+"/"+arch+"/security")
		}
	}
	seen := map[string]bool{}
	groups := map[string]int{}
	var candidates []PAMObservation
	found := false
	for _, dir := range dirs {
		path := c.path(dir + "/" + token)
		if _, err := os.Lstat(path); err != nil {
			if !os.IsNotExist(err) {
				c.gap(path, err)
			}
			continue
		}
		found = true
		id := c.object([]string{path}, filepath.Join(dir, token), "pam")
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		var x ObjectObservation
		for _, object := range c.o.Objects {
			if object.ID == id {
				x = object
				break
			}
		}
		arch := pamArchitecture(x)
		if arch == "" || x.ELFType != "ET_DYN" {
			c.gap(path, fmt.Errorf("PAM candidate lacks valid shared-object architecture"))
			arch = ""
		} else {
			groups[arch]++
		}
		candidates = append(candidates, PAMObservation{Config: config, Control: control, Module: token, ObjectID: id, Candidate: true, CandidatePath: filepath.Join(dir, token), Resolution: arch})
	}
	if !found && len(c.o.Gaps) == gapStart {
		c.o.MissingPAM = append(c.o.MissingPAM, MissingPAMReference{Config: config, Control: control, Module: token})
	}
	for _, p := range candidates {
		switch {
		case p.Resolution == "":
			p.Resolution = "invalid"
		case groups[p.Resolution] > 1:
			c.gap(token, fmt.Errorf("ambiguous PAM candidates for %s", p.Resolution))
			p.Resolution = "ambiguous"
		default:
			p.Resolution = "unique_arch_candidate"
		}
		if len(candidates) == 1 && len(c.o.Gaps) == gapStart && p.Resolution == "unique_arch_candidate" {
			p.Candidate = false
			p.Resolution = "unique_search_file"
			c.o.AuthPAMObjects = append(c.o.AuthPAMObjects, p.ObjectID)
		}
		c.o.PAMAuth = append(c.o.PAMAuth, p)
	}
}

func missingPAMFindings(refs []MissingPAMReference) []Finding {
	groups := map[string]map[string]bool{}
	for _, ref := range refs {
		if groups[ref.Module] == nil {
			groups[ref.Module] = map[string]bool{}
		}
		groups[ref.Module][ref.Config+": "+ref.Type+" "+ref.Control] = true
	}
	modules := make([]string, 0, len(groups))
	for module := range groups {
		modules = append(modules, module)
	}
	sort.Strings(modules)
	var out []Finding
	for _, module := range modules {
		var locations []string
		for location := range groups[module] {
			locations = append(locations, location)
		}
		sort.Strings(locations)
		out = append(out, Finding{ID: "pam_missing_reference", Title: "PAM configuration references a module not found in searched locations", Level: LevelInfo, Detail: module + "; references: " + strings.Join(locations, "; ") + "; activation not established; not evidence of infection"})
	}
	return out
}

func compatiblePAMLoader(pam ObjectObservation, objects map[string]ObjectObservation, loaders map[string]bool) bool {
	arch := pamArchitecture(pam)
	if arch == "" {
		return false
	}
	for id := range loaders {
		if pamArchitecture(objects[id]) == arch {
			return true
		}
	}
	return false
}
