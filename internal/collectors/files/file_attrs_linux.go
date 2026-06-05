//go:build linux

package files

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	fsImmutableFlag = 0x00000010
	fsAppendFlag    = 0x00000020
)

func enrichPlatformFileAttributes(actualPath string, info os.FileInfo, record *FileAttributeRecord) []FileAttributeIssue {
	var issues []FileAttributeIssue
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		ctime := time.Unix(st.Ctim.Sec, st.Ctim.Nsec).UTC()
		record.CTime = &ctime
	}
	issues = append(issues, collectStatxBirthTime(actualPath, record)...)
	issues = append(issues, collectXattrs(actualPath, record)...)
	issues = append(issues, collectFSFlags(actualPath, info, record)...)
	return issues
}

func collectStatxBirthTime(actualPath string, record *FileAttributeRecord) []FileAttributeIssue {
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, actualPath, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_ALL, &st); err != nil {
		record.BirthTimeStatus = "unsupported"
		return []FileAttributeIssue{{Field: "birth_time", Status: "unsupported", Error: err.Error()}}
	}
	if st.Mask&unix.STATX_BTIME == 0 || st.Btime.Sec == 0 {
		record.BirthTimeStatus = "absent"
		return nil
	}
	birth := time.Unix(st.Btime.Sec, int64(st.Btime.Nsec)).UTC()
	record.BirthTime = &birth
	record.BirthTimeStatus = "ok"
	return nil
}

func collectXattrs(actualPath string, record *FileAttributeRecord) []FileAttributeIssue {
	size, err := unix.Llistxattr(actualPath, nil)
	if err != nil {
		return []FileAttributeIssue{{Field: "xattrs", Status: xattrIssueStatus(err), Error: err.Error()}}
	}
	if size == 0 {
		record.XattrCount = intPtr(0)
		return nil
	}
	buf := make([]byte, size)
	size, err = unix.Llistxattr(actualPath, buf)
	if err != nil {
		return []FileAttributeIssue{{Field: "xattrs", Status: xattrIssueStatus(err), Error: err.Error()}}
	}
	names := parseNullSeparatedNames(buf[:size])
	record.XattrNames = names
	record.XattrCount = intPtr(len(names))
	if !hasName(names, "security.capability") {
		return nil
	}
	return collectLinuxCapability(actualPath, record)
}

func collectLinuxCapability(actualPath string, record *FileAttributeRecord) []FileAttributeIssue {
	size, err := unix.Lgetxattr(actualPath, "security.capability", nil)
	if err != nil {
		return []FileAttributeIssue{{Field: "linux_capability", Status: xattrIssueStatus(err), Error: err.Error()}}
	}
	if size == 0 {
		record.LinuxCapabilitySize = intPtr(0)
		return nil
	}
	buf := make([]byte, size)
	size, err = unix.Lgetxattr(actualPath, "security.capability", buf)
	if err != nil {
		return []FileAttributeIssue{{Field: "linux_capability", Status: xattrIssueStatus(err), Error: err.Error()}}
	}
	value := buf[:size]
	sum := sha256.Sum256(value)
	record.LinuxCapabilityRawHex = hex.EncodeToString(value)
	record.LinuxCapabilitySize = intPtr(len(value))
	record.LinuxCapabilitySHA256 = hex.EncodeToString(sum[:])
	return nil
}

func collectFSFlags(actualPath string, info os.FileInfo, record *FileAttributeRecord) []FileAttributeIssue {
	if info.Mode()&os.ModeSymlink != 0 {
		return []FileAttributeIssue{{Field: "fs_flags", Status: "unsupported", Error: "FS_IOC_GETFLAGS is not collected for symlinks"}}
	}
	fd, err := unix.Open(actualPath, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return []FileAttributeIssue{{Field: "fs_flags", Status: fsFlagIssueStatus(err), Error: err.Error()}}
	}
	defer unix.Close(fd)
	var flags int
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.FS_IOC_GETFLAGS), uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return []FileAttributeIssue{{Field: "fs_flags", Status: fsFlagIssueStatus(errno), Error: errno.Error()}}
	}
	record.FSFlagsHex = fmt.Sprintf("0x%x", flags)
	record.Immutable = boolPtr(flags&fsImmutableFlag != 0)
	record.AppendOnly = boolPtr(flags&fsAppendFlag != 0)
	return nil
}

func xattrIssueStatus(err error) string {
	if err == unix.ENOTSUP || err == unix.EOPNOTSUPP {
		return "unsupported"
	}
	return "error"
}

func fsFlagIssueStatus(err error) string {
	if err == unix.ENOTTY || err == unix.EOPNOTSUPP || err == unix.ENOTSUP || err == unix.EINVAL {
		return "unsupported"
	}
	return "error"
}
