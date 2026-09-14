//go:build linux

package ddeirootkit

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestCtimeNativeStat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	want := time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec))
	if got := ctimeOf(path); !got.Equal(want) {
		t.Fatalf("ctime: got %v want %v", got, want)
	}
	if got := ctimeOf(path + ".missing"); !got.IsZero() {
		t.Fatalf("missing file: got %v", got)
	}
}
