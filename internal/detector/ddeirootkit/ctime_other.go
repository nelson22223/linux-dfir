//go:build !linux

package ddeirootkit

import "time"

// ctimeOf is a no-op off Linux; the timestomp check only fires on-target.
func ctimeOf(path string) time.Time { return time.Time{} }
