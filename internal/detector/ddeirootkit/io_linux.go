//go:build linux

package ddeirootkit

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func fileIdentity(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	return identityInfo(info, path), nil
}

func identityInfo(info os.FileInfo, path string) string {
	st := info.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("%d:%d:%d:%d:%d:%d:%d", st.Dev, st.Ino, st.Size, st.Mtim.Sec, st.Mtim.Nsec, st.Ctim.Sec, st.Ctim.Nsec)
}
func matchesMappingInfo(info os.FileInfo, device, inode string) bool {
	st := info.Sys().(*syscall.Stat_t)
	ino, err := strconv.ParseUint(inode, 10, 64)
	if err != nil || ino != st.Ino {
		return false
	}
	parts := strings.Split(device, ":")
	if len(parts) != 2 {
		return false
	}
	major, e1 := strconv.ParseUint(parts[0], 16, 64)
	minor, e2 := strconv.ParseUint(parts[1], 16, 64)
	dev := uint64(st.Dev)
	actualMajor := (dev>>8)&0xfff | (dev>>32)&0xfffff000
	actualMinor := dev&0xff | (dev>>12)&0xffffff00
	return e1 == nil && e2 == nil && major == actualMajor && minor == actualMinor
}

func openRegular(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, syscall.EINVAL
	}
	return f, nil
}
