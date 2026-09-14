//go:build linux

package ddeirootkit

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

func checkLiveMappedFile(t *testing.T, path string) bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := syscall.Mmap(int(f.Fd()), 0, 4096, syscall.PROT_READ|syscall.PROT_EXEC, syscall.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Munmap(b)
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("%x-", uintptr(unsafe.Pointer(&b[0])))
	for _, row := range strings.Split(string(maps), "\n") {
		if !strings.HasPrefix(row, prefix) {
			continue
		}
		address, _, display, ok := mapFields(row)
		if !ok {
			t.Fatal(row)
		}
		fields := strings.Fields(row)
		link := fmt.Sprintf("/proc/%d/map_files/%s", os.Getpid(), address)
		mapped, err := openRegular(link)
		if err != nil {
			t.Fatal(err)
		}
		defer mapped.Close()
		info, err := mapped.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyMappedHandle(context.Background(), link, display, fields[3], fields[4], info); err != nil {
			t.Fatal(err)
		}
		if err := verifyMappedHandle(context.Background(), link, display, fields[3], "999999999999999", info); err == nil {
			t.Fatal("wrong map identity accepted")
		}
		if err := verifyMappedHandle(context.Background(), link, display+".wrong", fields[3], fields[4], info); err == nil {
			t.Fatal("wrong display accepted")
		}
		if err := verifyMappedHandle(context.Background(), link, display, "ff:ff", fields[4], info); err == nil {
			t.Fatal("wrong device accepted")
		}
		unrelated, err := os.Stat("/proc/self/exe")
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyMappedHandle(context.Background(), link, display, fields[3], fields[4], unrelated); err == nil {
			t.Fatal("unrelated handle accepted")
		}
		if err := verifyMappedHandle(context.Background(), path, display, fields[3], fields[4], info); err == nil {
			t.Fatal("ordinary pathname accepted")
		}
		c := newCollector("/")
		id := c.objectMapped([]string{link}, display, "mapped", fields[3], fields[4])
		if id == "" || len(c.o.Gaps) != 0 || len(c.o.Objects) != 1 || !c.o.Objects[0].ValidELF {
			t.Fatalf("%+v", c.o)
		}
		// Model a differing maps/fstat view, but use a real map_files handle and
		// actual live maps data for the fallback verification itself.
		mismatch := func(os.FileInfo, string, string) bool { return false }
		c = newCollector("/")
		id = c.objectMappedWithMatcher([]string{link}, display, "mapped", fields[3], fields[4], mismatch)
		if id == "" || len(c.o.Gaps) != 0 || len(c.o.MappingViews) != 1 {
			t.Fatalf("authority fallback not exercised: %+v", c.o)
		}
		c = newCollector("/")
		if id := c.objectMappedWithMatcher([]string{path}, display, "mapped", fields[3], fields[4], mismatch); id != "" || len(c.o.Gaps) == 0 {
			t.Fatal("ordinary path mismatch bypassed")
		}
		lookup, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return !matchesMappingInfo(lookup, fields[3], fields[4])
	}
	t.Fatal("mapping not found")
	return false
}

func TestLiveMappedFileAuthority(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("map_files open requires root capabilities")
	}
	path := filepath.Join(t.TempDir(), "test.so")
	b := make([]byte, 4096)
	copy(b, elfHeader())
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	checkLiveMappedFile(t, path)
}

// Explicit opt-in: mount changes occur only inside a private mount namespace.
func TestOverlayMappedFileAuthority(t *testing.T) {
	if os.Getenv("DFIR_TEST_OVERLAY") != "1" {
		t.Skip("set DFIR_TEST_OVERLAY=1 on a root Linux test VM")
	}
	if os.Getenv("DFIR_TEST_OVERLAY_CHILD") != "1" {
		cmd := exec.Command("unshare", "--mount", "--propagation", "private", os.Args[0], "-test.run=^TestOverlayMappedFileAuthority$", "-test.v")
		cmd.Env = append(os.Environ(), "DFIR_TEST_OVERLAY_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		t.Log(string(out))
		return
	}
	root := t.TempDir()
	for _, name := range []string{"lower", "upper", "work", "merged"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	b := make([]byte, 4096)
	copy(b, elfHeader())
	if err := os.WriteFile(filepath.Join(root, "lower/test.so"), b, 0600); err != nil {
		t.Fatal(err)
	}
	merged := filepath.Join(root, "merged")
	opts := fmt.Sprintf("lowerdir=%s/lower,upperdir=%s/upper,workdir=%s/work,xino=on", root, root, root)
	if err := syscall.Mount("overlay", merged, "overlay", 0, opts); err != nil {
		t.Fatal(err)
	}
	defer syscall.Unmount(merged, 0)
	if !checkLiveMappedFile(t, filepath.Join(merged, "test.so")) {
		t.Log("kernel exposes uniform mapping/path identities; authority checks still verified")
	}
}
