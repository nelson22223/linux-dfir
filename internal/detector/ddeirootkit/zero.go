package ddeirootkit

import "strconv"

func zeroMappingShape(perms, path, device, inode, kernelDevice string) bool {
	ino, err := strconv.ParseUint(inode, 10, 64)
	return err == nil && ino != 0 && kernelDevice != "" && device == kernelDevice &&
		path == "/dev/zero (deleted)" && len(perms) == 4 && perms[3] == 's'
}
