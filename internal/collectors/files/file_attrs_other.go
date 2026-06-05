//go:build !linux && !darwin

package files

import "os"

func enrichPlatformFileAttributes(_ string, _ os.FileInfo, record *FileAttributeRecord) []FileAttributeIssue {
	record.BirthTimeStatus = "unsupported"
	return []FileAttributeIssue{
		{Field: "ctime", Status: "unsupported", Error: "platform ctime collection is not implemented"},
		{Field: "birth_time", Status: "unsupported", Error: "platform birth time collection is not implemented"},
		{Field: "xattrs", Status: "unsupported", Error: "platform xattr collection is not implemented"},
		{Field: "linux_capability", Status: "unsupported", Error: "Linux security.capability xattr is not supported on this platform"},
		{Field: "fs_flags", Status: "unsupported", Error: "FS_IOC_GETFLAGS is Linux-specific"},
	}
}
