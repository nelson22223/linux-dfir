//go:build darwin

package files

import (
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func enrichPlatformFileAttributes(actualPath string, info os.FileInfo, record *FileAttributeRecord) []FileAttributeIssue {
	var issues []FileAttributeIssue
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		ctime := time.Unix(st.Ctimespec.Sec, st.Ctimespec.Nsec).UTC()
		birth := time.Unix(st.Birthtimespec.Sec, st.Birthtimespec.Nsec).UTC()
		record.CTime = &ctime
		if !birth.IsZero() {
			record.BirthTime = &birth
			record.BirthTimeStatus = "ok"
		} else {
			record.BirthTimeStatus = "absent"
		}
	}
	issues = append(issues, collectDarwinXattrs(actualPath, record)...)
	issues = append(issues,
		FileAttributeIssue{Field: "linux_capability", Status: "unsupported", Error: "Linux security.capability xattr is not supported on darwin"},
		FileAttributeIssue{Field: "fs_flags", Status: "unsupported", Error: "FS_IOC_GETFLAGS is Linux-specific"},
	)
	return issues
}

func collectDarwinXattrs(actualPath string, record *FileAttributeRecord) []FileAttributeIssue {
	size, err := unix.Llistxattr(actualPath, nil)
	if err != nil {
		return []FileAttributeIssue{{Field: "xattrs", Status: darwinXattrIssueStatus(err), Error: err.Error()}}
	}
	if size == 0 {
		record.XattrCount = intPtr(0)
		return nil
	}
	buf := make([]byte, size)
	size, err = unix.Llistxattr(actualPath, buf)
	if err != nil {
		return []FileAttributeIssue{{Field: "xattrs", Status: darwinXattrIssueStatus(err), Error: err.Error()}}
	}
	names := parseNullSeparatedNames(buf[:size])
	record.XattrNames = names
	record.XattrCount = intPtr(len(names))
	return nil
}

func darwinXattrIssueStatus(err error) string {
	if err == unix.ENOTSUP || err == unix.EOPNOTSUPP {
		return "unsupported"
	}
	return "error"
}
