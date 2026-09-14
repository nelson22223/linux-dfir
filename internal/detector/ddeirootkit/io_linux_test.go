//go:build linux

package ddeirootkit

import (
	"context"
	"path/filepath"
	"syscall"
	"testing"
)

func TestFIFOReadDoesNotBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(context.Background(), path, maxText); err == nil {
		t.Fatal("FIFO accepted")
	}
	if _, err := inspectObject(context.Background(), path); err == nil {
		t.Fatal("FIFO hash accepted")
	}
}
