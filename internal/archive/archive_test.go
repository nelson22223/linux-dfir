package archive

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"linux-dfir/internal/evidence"
	"linux-dfir/internal/integrity"
)

func TestCreateTarGzCreatesArchiveAndSummary(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "evidence")
	writeFile(t, filepath.Join(source, "legacy", "SUMMARY"), "summary\n")
	writeFile(t, filepath.Join(source, "ai", "manifest.json"), manifestJSON(t, 2))
	writeFile(t, filepath.Join(source, "ai", "evidence.jsonl"), "{}\n")

	archivePath := filepath.Join(root, "evidence.tar.gz")
	summary, err := CreateTarGz(source, archivePath, Options{Prefix: "case-001"})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Archive.SHA256 == "" || summary.Archive.MD5 == "" || summary.Archive.Size == 0 {
		t.Fatalf("archive hash fields missing: %+v", summary.Archive)
	}
	if summary.ArtifactCount != 2 {
		t.Fatalf("manifest artifact count not carried into summary: %d", summary.ArtifactCount)
	}
	hash, err := integrity.HashFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Archive.SHA256 != hash.SHA256 || summary.Archive.MD5 != hash.MD5 || summary.Archive.Size != hash.Size {
		t.Fatalf("summary hash mismatch summary=%+v hash=%+v", summary.Archive, hash)
	}
	names := tarNames(t, archivePath)
	assertContains(t, names, "case-001/legacy/SUMMARY")
	assertContains(t, names, "case-001/ai/manifest.json")
	assertContains(t, names, "case-001/ai/evidence.jsonl")
	assertNoUnsafeNames(t, names)

	summaryPath := filepath.Join(source, "ai", "archive_summary.json")
	if err := WriteSummary(summaryPath, summary); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Summary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Archive.SHA256 != summary.Archive.SHA256 {
		t.Fatalf("summary write/read mismatch: %+v", decoded)
	}
}

func TestCreateTarGzSkipsUnsafeExternalSymlink(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "evidence")
	outside := filepath.Join(root, "outside-secret")
	writeFile(t, outside, "secret\n")
	writeFile(t, filepath.Join(source, "ai", "manifest.json"), manifestJSON(t, 1))
	if err := os.Symlink(outside, filepath.Join(source, "legacy-secret")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("ai/manifest.json", filepath.Join(source, "manifest-link")); err != nil {
		t.Fatal(err)
	}

	summary, err := CreateTarGz(source, filepath.Join(root, "evidence.tar.gz"), Options{Prefix: "bundle"})
	if err != nil {
		t.Fatal(err)
	}
	if summary.SkippedCount != 1 || !strings.Contains(summary.Skipped[0].Path, "legacy-secret") {
		t.Fatalf("expected external symlink skip, got %+v", summary.Skipped)
	}
	names := tarNames(t, filepath.Join(root, "evidence.tar.gz"))
	assertContains(t, names, "bundle/manifest-link")
	headers := tarHeaders(t, filepath.Join(root, "evidence.tar.gz"))
	if headers["bundle/manifest-link"].Typeflag != tar.TypeSymlink || headers["bundle/manifest-link"].Linkname != "ai/manifest.json" {
		t.Fatalf("safe symlink should be archived as symlink header: %+v", headers["bundle/manifest-link"])
	}
	for _, name := range names {
		if strings.Contains(name, "legacy-secret") {
			t.Fatalf("external symlink should not be archived: %v", names)
		}
	}
}

func TestCreateTarGzRejectsArchiveInsideSource(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "evidence")
	writeFile(t, filepath.Join(source, "ai", "manifest.json"), manifestJSON(t, 1))
	if _, err := CreateTarGz(source, filepath.Join(source, "self.tar.gz"), Options{}); err == nil {
		t.Fatal("expected archive path inside source to be rejected")
	}
}

func TestCreateTarGzRejectsSourceSymlink(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "evidence")
	writeFile(t, filepath.Join(source, "ai", "manifest.json"), manifestJSON(t, 1))
	link := filepath.Join(root, "source-link")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateTarGz(link, filepath.Join(root, "evidence.tar.gz"), Options{}); err == nil {
		t.Fatal("expected source symlink to be rejected")
	}
}

func TestCreateTarGzRejectsArchiveParentSymlinkIntoSource(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "real", "evidence")
	writeFile(t, filepath.Join(source, "ai", "manifest.json"), manifestJSON(t, 1))
	linkParent := filepath.Join(root, "archive-link")
	if err := os.Symlink(filepath.Join(source, "ai"), linkParent); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateTarGz(source, filepath.Join(linkParent, "inside.tar.gz"), Options{}); err == nil {
		t.Fatal("expected archive parent symlink into source to be rejected")
	}
}

func TestCreateTarGzRejectsArchiveOutputSymlink(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "evidence")
	writeFile(t, filepath.Join(source, "ai", "manifest.json"), manifestJSON(t, 1))
	target := filepath.Join(root, "target.tar.gz")
	link := filepath.Join(root, "out.tar.gz")
	if err := os.WriteFile(target, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateTarGz(source, link, Options{}); err == nil {
		t.Fatal("expected archive output symlink to be rejected")
	}
}

func TestValidateEntryNameRejectsUnsafeNames(t *testing.T) {
	for _, name := range []string{"", "../escape", "/absolute", "bundle/../../escape", ".."} {
		if err := validateEntryName(name); err == nil {
			t.Fatalf("expected unsafe entry to be rejected: %q", name)
		}
	}
	if err := validateEntryName("bundle/ai/manifest.json"); err != nil {
		t.Fatalf("expected safe entry: %v", err)
	}
}

func manifestJSON(t *testing.T, count int) string {
	t.Helper()
	data, err := json.Marshal(evidence.Manifest{SchemaVersion: evidence.SchemaVersion, ArtifactCount: count})
	if err != nil {
		t.Fatal(err)
	}
	return string(data) + "\n"
}

func tarNames(t *testing.T, path string) []string {
	t.Helper()
	headers := tarHeaders(t, path)
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	return names
}

func tarHeaders(t *testing.T, path string) map[string]*tar.Header {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	headers := map[string]*tar.Header{}
	for {
		header, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		copyHeader := *header
		headers[header.Name] = &copyHeader
	}
	return headers
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o640); err != nil {
		t.Fatal(err)
	}
}

func assertContains(t *testing.T, values []string, want string) {
	t.Helper()
	for _, value := range values {
		if value == want {
			return
		}
	}
	t.Fatalf("missing %q in %v", want, values)
}

func assertNoUnsafeNames(t *testing.T, names []string) {
	t.Helper()
	for _, name := range names {
		if filepath.IsAbs(name) || strings.Contains(name, "..") {
			t.Fatalf("unsafe tar name: %q", name)
		}
	}
}
