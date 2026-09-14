//go:build linux

package ddeirootkit

import (
	"syscall"
	"time"
)

func ctimeOf(path string) time.Time {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return time.Time{}
	}
	sec, nsec := st.Ctim.Sec, st.Ctim.Nsec
	return time.Unix(int64(sec), int64(nsec))
}
