//go:build !linux

package ddeirootkit

func confirmedSharedZero(mapFile, perms, path, device, inode string) bool { return false }
