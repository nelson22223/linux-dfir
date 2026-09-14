//go:build linux

package ddeirootkit

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var zeroProbe struct {
	sync.Once
	device string
}

// Calibrate the kernel's internal shmem device, not a fixed minor number.
// This non-executable probe is immediately unmapped and writes no files.
func sharedZeroDevice() string {
	zeroProbe.Do(func() {
		b, err := syscall.Mmap(-1, 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_SHARED)
		if err != nil {
			return
		}
		defer syscall.Munmap(b)
		address := fmt.Sprintf("%x-", uintptr(unsafe.Pointer(&b[0])))
		maps, err := readBounded(context.Background(), "/proc/self/maps", maxText)
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(maps), "\n") {
			if !strings.HasPrefix(line, address) {
				continue
			}
			_, perms, path, ok := mapFields(line)
			fields := strings.Fields(line)
			if ok && perms == "rw-s" && path == "/dev/zero (deleted)" && fields[4] != "0" {
				zeroProbe.device = fields[3]
			}
		}
	})
	return zeroProbe.device
}

func confirmedSharedZero(mapFile, perms, path, device, inode string) bool {
	if !zeroMappingShape(perms, path, device, inode, sharedZeroDevice()) {
		return false
	}
	// The collector also rechecks the complete maps snapshot and process identity.
	target, err := os.Readlink(mapFile)
	return err == nil && target == path
}
