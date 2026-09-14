package ddeirootkit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type collector struct {
	ctx        context.Context
	root       string
	o          Observations
	cache      map[string]string
	identities map[string]string
}

func (c *collector) path(s string) string    { return filepath.Join(c.root, s) }
func (c *collector) gap(s string, err error) { c.o.Gaps = append(c.o.Gaps, s+": "+err.Error()) }
func (c *collector) text(path string, optional bool) ([]byte, bool) {
	b, err := readBounded(c.ctx, path, maxText)
	if err != nil {
		if !optional || !os.IsNotExist(err) {
			c.gap(path, err)
		}
		return nil, false
	}
	return b, true
}
func (c *collector) object(paths []string, display, role string) string {
	return c.objectMapped(paths, display, role, "", "")
}
func (c *collector) objectMapped(paths []string, display, role, device, inode string) string {
	var last error
	for _, path := range paths {
		f, err := openRegular(path)
		if err != nil {
			last = err
			continue
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			last = err
			continue
		}
		if inode != "" && !matchesMappingInfo(info, device, inode) {
			f.Close()
			last = fmt.Errorf("mapped device/inode mismatch")
			continue
		}
		key := identityInfo(info, path)
		if id := c.identities[key]; id != "" {
			f.Close()
			return id
		}
		x, err := inspectObjectFD(c.ctx, f)
		f.Close()
		if x.SHA256 != "" && x.ID != key {
			last = fmt.Errorf("object identity changed during inspection")
			continue
		}
		// A valid full hash remains useful even when ELF metadata is malformed.
		if x.SHA256 != "" {
			x.Path = display
			x.Role = role
			c.o.Objects = append(c.o.Objects, x)
			c.o.Coverage.Objects++
			c.cache[path] = x.ID
			c.identities[key] = x.ID
			if err != nil {
				c.gap(display, err)
			}
			return x.ID
		}
		last = err
	}
	if last != nil {
		c.gap(display, last)
	}
	return ""
}
func (c *collector) resolve(token string, pam bool) []string {
	if strings.ContainsAny(token, "$") {
		return nil
	}
	if filepath.IsAbs(token) {
		return []string{c.path(token)}
	}
	if strings.Contains(token, "/") {
		return nil
	}
	dirs := []string{"/lib64", "/usr/lib64", "/lib", "/usr/lib", "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu"}
	var out []string
	seen := map[string]bool{}
	for _, d := range dirs {
		if pam {
			d += "/security"
		}
		path := c.path(d + "/" + token)
		if key, err := fileIdentity(path); err == nil && !seen[key] {
			seen[key] = true
			out = append(out, path)
		}
	}
	// Multiple search-path candidates need a real loader resolution, not guessing.
	if len(out) != 1 {
		return nil
	}
	return out
}
func (c *collector) configs() {
	if b, ok := c.text(c.path("/etc/ld.so.preload"), true); ok {
		for _, token := range nonEmptyLines(string(b)) {
			paths := c.resolve(token, false)
			if len(paths) == 0 {
				c.gap(token, fmt.Errorf("unresolved loader token"))
				continue
			}
			if id := c.object(paths, token, "preload"); id != "" {
				c.o.PreloadObjects = append(c.o.PreloadObjects, id)
			}
		}
	}
	dir := c.path("/etc/pam.d")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			c.gap(dir, err)
		}
		return
	}
	if len(entries) > 4096 {
		c.gap(dir, fmt.Errorf("too many PAM configs"))
		return
	}
	for _, e := range entries {
		name := strings.ToLower(e.Name())
		if e.IsDir() || strings.HasPrefix(name, ".") || strings.HasSuffix(name, "~") || strings.HasSuffix(name, ".bak") || strings.HasSuffix(name, ".old") || strings.HasSuffix(name, ".orig") || strings.HasSuffix(name, ".rpmnew") || strings.HasSuffix(name, ".rpmsave") || strings.HasSuffix(name, ".dpkg-old") || strings.HasSuffix(name, ".dpkg-dist") {
			continue
		}
		b, ok := c.text(filepath.Join(dir, e.Name()), false)
		if !ok {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
			if len(fields) < 3 || strings.TrimPrefix(fields[0], "-") != "auth" {
				continue
			}
			i := 2
			if strings.HasPrefix(fields[1], "[") {
				i = 1
				for i < len(fields) && !strings.HasSuffix(fields[i], "]") {
					i++
				}
				i++
			}
			if i >= len(fields) {
				c.gap(e.Name(), fmt.Errorf("malformed PAM auth line"))
				continue
			}
			if fields[1] == "include" || fields[1] == "substack" {
				continue
			}
			token := fields[i]
			if !filepath.IsAbs(token) {
				before := len(c.o.MissingPAM)
				c.pamCandidates(e.Name(), strings.Join(fields[1:i], " "), token)
				for n := before; n < len(c.o.MissingPAM); n++ {
					c.o.MissingPAM[n].Type = fields[0]
				}
				continue
			}
			paths := c.resolve(token, true)
			if len(paths) == 0 {
				c.gap(token, fmt.Errorf("unresolved PAM module"))
				continue
			}
			if _, err := os.Lstat(paths[0]); os.IsNotExist(err) {
				c.o.MissingPAM = append(c.o.MissingPAM, MissingPAMReference{Config: e.Name(), Type: fields[0], Control: strings.Join(fields[1:i], " "), Module: token})
				continue
			}
			if id := c.object(paths, token, "pam"); id != "" {
				c.o.AuthPAMObjects = append(c.o.AuthPAMObjects, id)
				c.o.PAMAuth = append(c.o.PAMAuth, PAMObservation{Config: e.Name(), Control: strings.Join(fields[1:i], " "), Module: token, ObjectID: id})
			}
		}
	}
}
func (c *collector) gone(dir string) bool {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return true
	}
	b, err := readBounded(c.ctx, dir+"/stat", 65536)
	if err != nil {
		return false
	}
	end := strings.LastIndex(string(b), ")")
	if end < 0 {
		return false
	}
	f := strings.Fields(string(b[end+1:]))
	if len(f) < 7 {
		return false
	}
	if f[0] == "Z" || f[0] == "X" {
		return true
	}
	flags, err := strconv.ParseUint(f[6], 10, 64)
	return err == nil && flags&0x00200000 != 0 // Linux PF_KTHREAD.
}
func (c *collector) procID(dir string) (uint64, error) {
	b, err := readBounded(c.ctx, dir+"/stat", 65536)
	if err != nil {
		return 0, err
	}
	end := strings.LastIndex(string(b), ")")
	if end < 0 {
		return 0, fmt.Errorf("invalid process stat")
	}
	fields := strings.Fields(string(b[end+1:]))
	if len(fields) <= 19 {
		return 0, fmt.Errorf("missing process start time")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}
func mapFields(line string) (address, perms, path string, ok bool) {
	rest := strings.TrimSpace(line)
	fields := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		idx := strings.IndexAny(rest, " \t")
		if idx < 0 {
			if i == 4 && rest != "" {
				fields = append(fields, rest)
				rest = ""
				break
			}
			return
		}
		fields = append(fields, rest[:idx])
		rest = strings.TrimLeft(rest[idx:], " \t")
	}
	if len(fields) != 5 || len(fields[1]) != 4 {
		return
	}
	return fields[0], fields[1], rest, true
}
func (c *collector) processes() {
	entries, err := os.ReadDir(c.path("/proc"))
	if err != nil {
		c.gap("/proc", err)
		return
	}
	c.o.Coverage.Proc = true
	count := 0
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		count++
		if count > 65536 {
			c.gap("/proc", fmt.Errorf("process limit exceeded"))
			break
		}
		if err := c.ctx.Err(); err != nil {
			c.gap("/proc", err)
			break
		}
		dir := c.path("/proc/" + e.Name())
		start, err := c.procID(dir)
		if err != nil {
			if c.gone(dir) {
				c.o.Coverage.Skipped++
				continue
			}
			c.gap(dir+"/stat", err)
			continue
		}
		gapStart := len(c.o.Gaps)
		exeStart, exeStartErr := fileIdentity(dir + "/exe")
		if exeStartErr != nil && !c.gone(dir) {
			c.gap(dir+"/exe", exeStartErr)
		}
		maps, err := readBounded(c.ctx, dir+"/maps", maxText)
		if err != nil {
			if c.gone(dir) {
				c.o.Coverage.Skipped++
				continue
			}
			c.gap(dir+"/maps", err)
			continue
		}
		c.o.Coverage.Processes++
		p := ProcessObservation{PID: pid, UID: -1, PPID: -1, StartTimeTicks: start}
		status, err := readBounded(c.ctx, dir+"/status", 65536)
		if err != nil {
			if !c.gone(dir) {
				c.gap(dir+"/status", err)
			}
		} else {
			for _, line := range strings.Split(string(status), "\n") {
				f := strings.Fields(line)
				if len(f) >= 2 {
					if f[0] == "Uid:" {
						if value, err := strconv.Atoi(f[1]); err == nil {
							p.UID = value
						}
					}
					if f[0] == "PPid:" {
						if value, err := strconv.Atoi(f[1]); err == nil {
							p.PPID = value
						}
					}
				}
			}
			if p.UID < 0 || p.PPID < 0 {
				c.gap(dir+"/status", fmt.Errorf("missing UID/PPID"))
			}
		}
		if b, err := readBounded(c.ctx, dir+"/comm", 65536); err == nil {
			p.Comm = strings.TrimSpace(string(b))
		}
		p.Exe, err = os.Readlink(dir + "/exe")
		if err != nil && !c.gone(dir) {
			c.gap(dir+"/exe", err)
		}
		if filepath.Base(strings.TrimSuffix(p.Exe, " (deleted)")) == "xinetd" || p.Comm == "xinetd" {
			p.ExeObject = c.object([]string{dir + "/exe"}, p.Exe, "xinetd")
		}
		seen := map[string]bool{}
		failures := map[string][]string{}
		for _, line := range strings.Split(string(maps), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			address, perms, path, ok := mapFields(line)
			if !ok {
				c.gap(dir+"/maps", fmt.Errorf("malformed map row"))
				continue
			}
			if strings.HasPrefix(perms, "rwx") && (path == "" || strings.HasPrefix(path, "[")) {
				// JIT RWX in arbitrary applications is not a targeted family signal.
				if p.UID == 0 && p.PPID == 1 || filepath.Base(strings.TrimSuffix(p.Exe, " (deleted)")) == "xinetd" || p.Comm == "xinetd" {
					p.AnonymousRWX = true
				}
			}
			if strings.HasPrefix(perms, "rwx") && (p.UID == 0 && p.PPID == 1 || filepath.Base(strings.TrimSuffix(p.Exe, " (deleted)")) == "xinetd" || p.Comm == "xinetd") {
				p.RWX = true
				p.RWXRegions = append(p.RWXRegions, address+" "+perms+" "+path)
			}
			deleted := strings.HasSuffix(path, " (deleted)")
			clean := strings.TrimSuffix(path, " (deleted)")
			if !strings.HasPrefix(clean, "/") {
				continue
			}
			candidate := strings.Contains(filepath.Base(clean), ".so") || strings.HasPrefix(clean, "/memfd:") || strings.Contains(perms, "x") && clean != strings.TrimSuffix(p.Exe, " (deleted)")
			for _, x := range c.o.Objects {
				if x.Role == "preload" && x.Path == clean {
					candidate = true
				}
			}
			identityFields := strings.Fields(line)
			mapKey := identityFields[3] + ":" + identityFields[4]
			if c.root == "/" && clean == "/dev/zero" && deleted && confirmedSharedZero(dir+"/map_files/"+address, perms, path, identityFields[3], identityFields[4]) {
				p.Mappings = append(p.Mappings, MappingObservation{Address: address, Permissions: perms, Path: clean, Deleted: true, Kind: "shared_anonymous", Device: identityFields[3], Inode: identityFields[4]})
				continue
			}
			if !candidate || seen[mapKey] {
				continue
			}
			paths := []string{dir + "/map_files/" + address, dir + "/root" + clean}
			if !deleted {
				paths = []string{dir + "/root" + clean, dir + "/map_files/" + address}
			}
			// Fixture roots do not have proc root links. Live scans never substitute the
			// scanner's namespace for a process namespace.
			if c.root != "/" && !deleted {
				paths = append(paths, c.path(clean))
			}
			beforeGaps := len(c.o.Gaps)
			id := c.objectMapped(paths, clean, "mapped", identityFields[3], identityFields[4])
			if id != "" {
				seen[mapKey] = true
				delete(failures, mapKey)
				p.MappedObjects = append(p.MappedObjects, id)
				p.Mappings = append(p.Mappings, MappingObservation{ObjectID: id, Address: address, Permissions: perms, Path: clean, Deleted: deleted})
			} else {
				failures[mapKey] = append(failures[mapKey], c.o.Gaps[beforeGaps:]...)
				c.o.Gaps = c.o.Gaps[:beforeGaps]
			}
		}
		for _, gaps := range failures {
			c.o.Gaps = append(c.o.Gaps, gaps...)
		}
		if p.UID == 0 && p.PPID == 1 && p.RWX {
			if p.ExeObject == "" {
				p.ExeObject = c.object([]string{dir + "/exe"}, p.Exe, "daemon")
			}
			fds, err := os.ReadDir(dir + "/fd")
			if err != nil {
				if !c.gone(dir) {
					c.gap(dir+"/fd", err)
				}
			} else if len(fds) > 65536 {
				c.gap(dir+"/fd", fmt.Errorf("fd limit exceeded"))
			} else {
				for _, fd := range fds {
					target, err := os.Readlink(dir + "/fd/" + fd.Name())
					if err != nil {
						if !os.IsNotExist(err) {
							c.gap(dir+"/fd/"+fd.Name(), err)
						}
						continue
					}
					if target == "/dev/ptmx" || target == "/dev/pts/ptmx" || strings.HasPrefix(target, "/dev/pts/") {
						p.HasPTY = true
						p.PTYPaths = append(p.PTYPaths, "fd="+fd.Name()+" "+target)
					}
				}
			}
		}
		end, err := c.procID(dir)
		if err != nil || end != start {
			if c.gone(dir) {
				c.o.Gaps = c.o.Gaps[:gapStart]
				c.o.Coverage.Skipped++
				continue
			}
			c.gap(dir, fmt.Errorf("process identity changed or could not be revalidated"))
			continue
		}
		exeEnd, exeEndErr := fileIdentity(dir + "/exe")
		mapsEnd, mapsEndErr := readBounded(c.ctx, dir+"/maps", maxText)
		if exeStartErr != nil || exeEndErr != nil || exeStart != exeEnd || mapsEndErr != nil || relevantMaps(string(maps)) != relevantMaps(string(mapsEnd)) {
			if c.gone(dir) {
				c.o.Gaps = c.o.Gaps[:gapStart]
				c.o.Coverage.Skipped++
				continue
			}
			c.gap(dir, fmt.Errorf("executable or relevant mappings changed during process observation"))
			continue
		}
		c.o.Processes = append(c.o.Processes, p)
	}
	if count == 0 {
		c.gap("/proc", fmt.Errorf("no process observations"))
	}
}

// Ignore ordinary heap/stack growth, but bind all executable/file-backed rows
// and RWX regions to one observed layout. An exec or relevant remap is a gap.
func relevantMaps(data string) string {
	var rows []string
	for _, line := range strings.Split(data, "\n") {
		_, perms, path, ok := mapFields(line)
		if !ok {
			if strings.TrimSpace(line) != "" {
				rows = append(rows, line)
			}
			continue
		}
		if strings.Contains(perms, "x") || strings.HasPrefix(path, "/") {
			rows = append(rows, line)
		}
	}
	return strings.Join(rows, "\n")
}

// Collect reads only configurations, their referenced modules, xinetd and
// candidate live shared objects. It never walks arbitrary disk trees.
func Collect(ctx context.Context, opts Options) Observations {
	root := opts.Root
	if root == "" {
		root = "/"
	}
	c := collector{ctx: ctx, root: root, cache: map[string]string{}, identities: map[string]string{}, o: Observations{Timestamp: time.Now().UTC(), Hostname: opts.Hostname}}
	if c.o.Hostname == "" {
		c.o.Hostname, _ = os.Hostname()
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		c.gap(root, fmt.Errorf("invalid root"))
		return c.o
	}
	c.o.Coverage.Root = root != "/" || runtime.GOOS == "linux" && os.Geteuid() == 0
	if !c.o.Coverage.Root {
		c.gap(root, fmt.Errorf("Linux root privileges required for complete live coverage"))
	}
	c.configs()
	if _, err := os.Stat(c.path("/usr/sbin/xinetd")); err == nil {
		c.object([]string{c.path("/usr/sbin/xinetd")}, "/usr/sbin/xinetd", "xinetd")
	} else if !os.IsNotExist(err) {
		c.gap("/usr/sbin/xinetd", err)
	}
	for _, path := range []string{"/media/vbccsb", "/home/vbccsb"} {
		if _, err := os.Stat(c.path(path)); err == nil {
			c.o.Suspicious = append(c.o.Suspicious, "case-associated marker path: "+path)
		} else if !os.IsNotExist(err) {
			c.gap(path, err)
		}
	}
	if b, ok := c.text(c.path("/root/sign.txt"), true); ok {
		s := strings.TrimSpace(string(b))
		if len(s) == 64 {
			if _, err := strconv.ParseUint(s[:16], 16, 64); err == nil {
				c.o.Suspicious = append(c.o.Suspicious, "64-character marker candidate /root/sign.txt")
			}
		}
	}
	if opts.ScanProcMaps {
		c.processes()
		c.network()
	}
	return c.o
}
