//go:build linux

package ddeirootkit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// procfs map_files binds an address range to its actual mapped file. Layered
// filesystems may expose different inode views in maps and fstat; a pathname
// opened through /proc/PID/root never receives this exception.
func verifyMappedHandle(ctx context.Context, path, display, device, inode string, info os.FileInfo) error {
	parts := strings.Split(path, "/")
	if len(parts) != 5 || parts[1] != "proc" || parts[3] != "map_files" {
		return fmt.Errorf("not a direct proc map_files handle")
	}
	pid, err := strconv.Atoi(parts[2])
	if err != nil || pid <= 0 {
		return fmt.Errorf("invalid map_files PID")
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(filepath.Dir(path), &fs); err != nil {
		return err
	}
	if uint64(fs.Type) != 0x9fa0 {
		return fmt.Errorf("map_files source is not procfs")
	}
	maps, err := readBounded(ctx, "/proc/"+parts[2]+"/maps", maxText)
	if err != nil {
		return err
	}
	found := false
	for _, line := range strings.Split(string(maps), "\n") {
		address, _, name, ok := mapFields(line)
		if !ok || address != parts[4] {
			continue
		}
		fields := strings.Fields(line)
		if fields[3] != device || fields[4] != inode || strings.TrimSuffix(name, " (deleted)") != display {
			return fmt.Errorf("map_files mapping identity changed")
		}
		found = true
		break
	}
	if !found {
		return fmt.Errorf("map_files mapping disappeared")
	}
	current, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !current.Mode().IsRegular() || identityInfo(current, path) != identityInfo(info, path) {
		return fmt.Errorf("map_files handle changed during verification")
	}
	return nil
}

func mappingStatDescription(info os.FileInfo) string {
	st := info.Sys().(*syscall.Stat_t)
	dev := uint64(st.Dev)
	return fmt.Sprintf("%x:%x inode=%d", (dev>>8)&0xfff|(dev>>32)&0xfffff000, dev&0xff|(dev>>12)&0xffffff00, st.Ino)
}
