package integrity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.txt")
	if err := os.WriteFile(path, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	hash, err := HashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if hash.Size != 6 {
		t.Fatalf("size mismatch: %d", hash.Size)
	}
	if hash.SHA256 != "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03" {
		t.Fatalf("sha256 mismatch: %s", hash.SHA256)
	}
}
