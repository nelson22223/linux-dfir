//go:build linux

package ddeirootkit

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

func TestLiveSharedZeroClassification(t *testing.T) {
	b, err := syscall.Mmap(-1, 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC, syscall.MAP_ANON|syscall.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Munmap(b)
	prefix := fmt.Sprintf("%x-", uintptr(unsafe.Pointer(&b[0])))
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(maps), "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		address, perms, path, ok := mapFields(line)
		if !ok {
			t.Fatal(line)
		}
		f := strings.Fields(line)
		link := "/proc/self/map_files/" + address
		if !confirmedSharedZero(link, perms, path, f[3], f[4]) {
			t.Fatalf("not classified: %s probe=%s", line, sharedZeroDevice())
		}
		if confirmedSharedZero(link, perms, path, "ff:ff", f[4]) || confirmedSharedZero(link, "rwxp", path, f[3], f[4]) || confirmedSharedZero(link, perms, "/dev/zero", f[3], f[4]) || confirmedSharedZero("/proc/self/map_files/absent", perms, path, f[3], f[4]) {
			t.Fatal("unverified mapping accepted")
		}
		c := newCollector("/")
		c.processes()
		for _, p := range c.o.Processes {
			if p.PID != os.Getpid() {
				continue
			}
			for _, m := range p.Mappings {
				if m.Address == address && m.Kind == "shared_anonymous" && m.Device == f[3] && m.Inode == f[4] && m.Permissions == "rwxs" {
					return
				}
			}
		}
		t.Fatalf("live collector lost shared mapping; gaps=%v", c.o.Gaps)
		return
	}
	t.Fatal("mapping not found")
}
