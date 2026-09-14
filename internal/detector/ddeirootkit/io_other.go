//go:build !linux

package ddeirootkit

import (
	"fmt"
	"os"
	"path/filepath"
)

func fileIdentity(path string) (string, error) {
	f, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	return identityInfo(f, path), nil
}

func identityInfo(info os.FileInfo, path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		resolved = path
	}
	return fmt.Sprintf("%s:%d:%d", resolved, info.Size(), info.ModTime().UnixNano())
}

// Non-Linux use is fixture-only; live coverage is explicitly incomplete.
func matchesMappingInfo(info os.FileInfo, device, inode string) bool { return true }

func openRegular(path string) (*os.File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("regular file changed: %s", path)
	}
	return f, nil
}
