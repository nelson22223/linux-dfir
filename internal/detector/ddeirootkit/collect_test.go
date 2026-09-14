package ddeirootkit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func newCollector(root string) *collector {
	return &collector{ctx: context.Background(), root: root, cache: map[string]string{}, identities: map[string]string{}}
}
func link(t *testing.T, target, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(path, "/exe") {
		if _, err := os.Stat(target); os.IsNotExist(err) {
			target = filepath.Join(filepath.Dir(path), "fixture-executable")
			if err := os.WriteFile(target, []byte("fixture executable"), 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}
func mappingLine(t *testing.T, path, mapped string) string {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	dev := uint64(st.Dev)
	major := (dev>>8)&0xfff | (dev>>32)&0xfffff000
	minor := dev&0xff | (dev>>12)&0xffffff00
	return fmt.Sprintf("1000-2000 r-xp 00000000 %02x:%02x %d %s\n", major, minor, st.Ino, mapped)
}
func TestCollectVersionedDeletedAndCachedEveryPID(t *testing.T) {
	for _, deleted := range []bool{false, true} {
		t.Run(strconv.FormatBool(deleted), func(t *testing.T) {
			root := fixture(t, map[string]string{"lib/libexample.so.7": string(elfHeader()), "bin/service": "executable"})
			actual := filepath.Join(root, "lib/libexample.so.7")
			path := "/lib/libexample.so.7"
			if deleted {
				path += " (deleted)"
			}
			row := mappingLine(t, actual, path)
			for _, pid := range []string{"21", "22"} {
				dir := filepath.Join(root, "proc", pid)
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
				for name, data := range map[string]string{"maps": row, "status": "Uid:\t0 0 0 0\nPPid:\t1\n", "comm": "service\n", "stat": pid + " (service) S " + strings.Repeat("0 ", 18) + "100\n"} {
					if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0644); err != nil {
						t.Fatal(err)
					}
				}
				link(t, filepath.Join(root, "bin/service"), dir+"/exe")
				if deleted {
					link(t, actual, dir+"/map_files/1000-2000")
				} else {
					link(t, root, dir+"/root")
				}
			}
			c := newCollector(root)
			c.processes()
			if len(c.o.Gaps) > 0 || len(c.o.Processes) != 2 || len(c.o.Objects) != 1 {
				t.Fatalf("%+v", c.o)
			}
			for _, p := range c.o.Processes {
				if len(p.MappedObjects) != 1 || p.MappedObjects[0] != c.o.Objects[0].ID {
					t.Fatalf("%+v", p)
				}
			}
		})
	}
}
func TestMappedReplacementDoesNotCorrelate(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux device/inode verification")
	}
	root := fixture(t, map[string]string{"lib/a.so": string(elfHeader()), "proc/1/maps": "1000-2000 r-xp 00000000 00:00 999999 /lib/a.so\n", "proc/1/status": "Uid: 0\nPPid: 0\n", "proc/1/comm": "init"})
	link(t, "/bin/init", filepath.Join(root, "proc/1/exe"))
	link(t, root, filepath.Join(root, "proc/1/root"))
	c := newCollector(root)
	c.processes()
	if len(c.o.Objects) != 0 || len(c.o.Gaps) == 0 {
		t.Fatalf("%+v", c.o)
	}
}
func TestKernelThreadAndZombieProof(t *testing.T) {
	root := fixture(t, map[string]string{
		"proc/1/stat": "1 (kernel worker) S 0 0 0 0 0 2097152 0",
		"proc/2/stat": "2 (dead) Z 0 0 0 0 0 0 0",
		"proc/3/stat": "3 (ordinary) S 0 0 0 0 0 0 0",
	})
	c := newCollector(root)
	c.processes()
	if c.o.Coverage.Skipped != 2 || len(c.o.Gaps) != 1 {
		t.Fatalf("%+v", c.o)
	}
}
func TestPAMControlsAndPreloadConfig(t *testing.T) {
	root := fixture(t, map[string]string{
		"etc/ld.so.preload":      "/lib/object # trailing comment\n",
		"lib/object":             string(elfHeader()),
		"etc/pam.d/auth-service": "auth [success=1 default=ignore] /lib/security/module.so\nauth [success=done default=ignore] /lib/security/module.so\n# auth sufficient /missing\n",
		"lib/security/module.so": string(elfHeader()),
	})
	c := newCollector(root)
	c.configs()
	if len(c.o.Gaps) > 0 || len(c.o.PreloadObjects) != 1 || len(c.o.PAMAuth) != 2 || c.o.PAMAuth[0].ObjectID != c.o.PAMAuth[1].ObjectID {
		t.Fatalf("%+v", c.o)
	}
	if c.o.PAMAuth[0].Control != "[success=1 default=ignore]" {
		t.Fatalf("%+v", c.o.PAMAuth)
	}
}
func TestRenamedRootDaemonRWXPTY(t *testing.T) {
	root := fixture(t, map[string]string{
		"bin/renamed":   string(elfHeader()),
		"proc/8/status": "Uid: 0 0 0 0\nPPid: 1\n",
		"proc/8/maps":   "1000-2000 rwxp 00000000 00:00 0\n",
		"proc/8/comm":   "renamed",
	})
	link(t, filepath.Join(root, "bin/renamed"), filepath.Join(root, "proc/8/exe"))
	link(t, "/dev/ptmx", filepath.Join(root, "proc/8/fd/0"))
	c := newCollector(root)
	c.processes()
	if len(c.o.Gaps) > 0 || len(c.o.Processes) != 1 {
		t.Fatalf("%+v", c.o)
	}
	p := c.o.Processes[0]
	if p.UID != 0 || p.PPID != 1 || !p.HasPTY || !p.RWX || !p.AnonymousRWX || p.ExeObject == "" {
		t.Fatalf("%+v", p)
	}
}

type mutationContext struct {
	context.Context
	calls  int
	mutate func()
}

func (c *mutationContext) Err() error {
	c.calls++
	if c.calls == 6 {
		c.mutate()
	}
	return nil
}
func TestPIDReuseDiscardsSnapshot(t *testing.T) {
	root := fixture(t, map[string]string{"proc/8/status": "Uid: 0\nPPid: 1\n", "proc/8/maps": "", "proc/8/comm": "service"})
	link(t, "/bin/service", filepath.Join(root, "proc/8/exe"))
	c := newCollector(root)
	c.ctx = &mutationContext{Context: context.Background(), mutate: func() {
		if err := os.WriteFile(filepath.Join(root, "proc/8/stat"), []byte("8 (new) S "+strings.Repeat("0 ", 18)+"200\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}}
	c.processes()
	if len(c.o.Processes) != 0 || len(c.o.Gaps) == 0 {
		t.Fatalf("%+v", c.o)
	}
}
func TestSamePathDistinctInodesAndAlternateMapFiles(t *testing.T) {
	root := fixture(t, map[string]string{"lib/a": string(elfHeader()), "lib/b": string(elfHeader()), "proc/8/status": "Uid: 0\nPPid: 1\n", "proc/8/maps": "", "proc/8/comm": "service"})
	link(t, "/bin/service", filepath.Join(root, "proc/8/exe"))
	a, b := filepath.Join(root, "lib/a"), filepath.Join(root, "lib/b")
	rowA := mappingLine(t, a, "/missing.so (deleted)")
	rowRetry := strings.Replace(rowA, "1000-2000", "2000-3000", 1)
	rowB := strings.Replace(mappingLine(t, b, "/missing.so (deleted)"), "1000-2000", "3000-4000", 1)
	if err := os.WriteFile(filepath.Join(root, "proc/8/maps"), []byte(rowA+rowRetry+rowB), 0644); err != nil {
		t.Fatal(err)
	}
	link(t, a, filepath.Join(root, "proc/8/map_files/2000-3000"))
	link(t, b, filepath.Join(root, "proc/8/map_files/3000-4000"))
	c := newCollector(root)
	c.processes()
	if len(c.o.Gaps) > 0 || len(c.o.Objects) != 2 || len(c.o.Processes) != 1 || len(c.o.Processes[0].MappedObjects) != 2 {
		t.Fatalf("%+v", c.o)
	}
}
func TestInspectUsesOpenedDescriptorAfterPathReplacement(t *testing.T) {
	root := fixture(t, map[string]string{"object": "original object"})
	path := filepath.Join(root, "object")
	f, err := openRegular(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	expected, err := inspectObject(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := inspectObjectFD(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if got.SHA256 != expected.SHA256 {
		t.Fatal("inspector followed replacement path")
	}
}

func TestCachedELFErrorSurvivesDiscardedProcessGaps(t *testing.T) {
	root := fixture(t, map[string]string{"lib/broken.so": "\x7fELFmalformed"})
	c := newCollector(root)
	id := c.object([]string{filepath.Join(root, "lib/broken.so")}, "/lib/broken.so", "mapped")
	if id == "" || len(c.o.Gaps) == 0 {
		t.Fatalf("%+v", c.o)
	}
	c.o.Gaps = nil // A vanished process's transient failures have been discarded.
	if cached := c.object([]string{filepath.Join(root, "lib/broken.so")}, "/lib/broken.so", "mapped"); cached != id {
		t.Fatal("cache miss")
	}
	c.o.Coverage = Coverage{Root: true, Proc: true}
	r := Evaluate(c.o)
	if r.Complete || r.Verdict != VerdictInconclusive || r.Coverage.Errors == 0 {
		t.Fatalf("%+v", r)
	}
}

func TestExecWithoutPIDReuseDiscardsSnapshot(t *testing.T) {
	for _, scenario := range []string{"stable", "exec_changed", "maps_changed"} {
		t.Run(scenario, func(t *testing.T) {
			root := fixture(t, map[string]string{"proc/8/status": "Uid: 0\nPPid: 1\n", "proc/8/maps": "", "proc/8/comm": "service", "bin/initial": "initial executable", "bin/new": "different executable"})
			link(t, filepath.Join(root, "bin/initial"), filepath.Join(root, "proc/8/exe"))
			if _, err := fileIdentity(filepath.Join(root, "proc/8/exe")); err != nil {
				t.Fatal(err)
			}
			c := newCollector(root)
			mutated := false
			c.ctx = &mutationContext{Context: context.Background(), mutate: func() {
				mutated = true
				if scenario == "stable" {
					return
				}
				if scenario == "maps_changed" {
					if err := os.WriteFile(filepath.Join(root, "proc/8/maps"), []byte("1000-2000 rwxp 00000000 00:00 0\n"), 0644); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Remove(filepath.Join(root, "proc/8/exe")); err != nil {
						t.Fatal(err)
					}
					link(t, filepath.Join(root, "bin/new"), filepath.Join(root, "proc/8/exe"))
				}
			}}
			c.processes()
			if !mutated {
				t.Fatal("mutation checkpoint was not reached")
			}
			if scenario == "stable" {
				if len(c.o.Processes) != 1 || len(c.o.Gaps) != 0 {
					t.Fatalf("stable snapshot rejected: %+v", c.o)
				}
				return
			}
			if len(c.o.Processes) != 0 || len(c.o.Gaps) == 0 {
				t.Fatalf("%+v", c.o)
			}
		})
	}
}
