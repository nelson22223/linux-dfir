//go:build !linux

package ddeirootkit

import (
	"context"
	"fmt"
	"os"
)

func verifyMappedHandle(ctx context.Context, path, display, device, inode string, info os.FileInfo) error {
	return fmt.Errorf("live map_files verification requires Linux")
}
func mappingStatDescription(info os.FileInfo) string { return "unavailable on non-Linux host" }
