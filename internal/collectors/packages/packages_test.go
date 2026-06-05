package packages

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
)

func TestParseDPKGStatus(t *testing.T) {
	text := `Package: zlib1g
Status: install ok installed
Architecture: amd64
Version: 1:1.2.13.dfsg-1
Installed-Size: 204
Source: zlib
Maintainer: Debian Zlib Maintainers <pkg-zlib-devel@lists.alioth.debian.org>
Description: compression library - runtime
 zlib is a library implementing the deflate compression method.

Package: bash
Status: install ok installed
Architecture: amd64
Version: 5.2.15-2+b9
Installed-Size: 7164
Description: GNU Bourne Again SHell
`
	pkgs := ParseDPKGStatus(text)
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d: %#v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "bash" || pkgs[0].Version != "5.2.15-2+b9" || pkgs[0].InstalledSize != 7164 {
		t.Fatalf("unexpected sorted bash package: %#v", pkgs[0])
	}
	if pkgs[1].Name != "zlib1g" || !strings.Contains(pkgs[1].Description, "deflate compression") {
		t.Fatalf("unexpected multiline description parse: %#v", pkgs[1])
	}
	if pkgs[1].SourcePackage != "zlib" {
		t.Fatalf("unexpected source package: %#v", pkgs[1])
	}
}

func TestParseDPKGListAndMD5Sums(t *testing.T) {
	paths := ParseDPKGList("/bin/bash\nrelative\n\n/bin/bash\n/usr/share/doc/bash\n")
	if strings.Join(paths, ",") != "/bin/bash,/usr/share/doc/bash" {
		t.Fatalf("unexpected dpkg paths: %#v", paths)
	}
	sums := ParseDPKGMD5Sums("0123456789abcdef0123456789abcdef usr/bin/bash\nbad /tmp/x\nfedcba9876543210fedcba9876543210 /etc/bash.bashrc\n")
	if sums["/usr/bin/bash"] != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("missing normalized relative md5sum: %#v", sums)
	}
	if sums["/etc/bash.bashrc"] != "fedcba9876543210fedcba9876543210" {
		t.Fatalf("missing absolute md5sum: %#v", sums)
	}
	conffiles := ParseDPKGConffiles("/etc/bash.bashrc\nbad\n/etc/ssh/sshd_config 0123\n")
	if !conffiles["/etc/bash.bashrc"] || !conffiles["/etc/ssh/sshd_config"] || conffiles["bad"] {
		t.Fatalf("unexpected conffiles parse: %#v", conffiles)
	}
}

func TestParseRPMQAAndFilesByPackage(t *testing.T) {
	pkgs := ParseRPMQA("bash\t5.2.15\t2.el9\tx86_64\ncoreutils\t9.1\t3.el9\tx86_64\n")
	if len(pkgs) != 2 || pkgs[0].Name != "bash" || pkgs[0].Version != "5.2.15-2.el9" {
		t.Fatalf("unexpected rpm package parse: %#v", pkgs)
	}
	owners := ParseRPMFilesByPackage("bash /bin/bash\ncoreutils   /bin/ls\n/path/without/package\n")
	if len(owners) != 2 {
		t.Fatalf("expected 2 owners, got %d: %#v", len(owners), owners)
	}
	if owners[0].PackageName != "bash" || owners[0].Path != "/bin/bash" {
		t.Fatalf("unexpected filesbypkg owner: %#v", owners[0])
	}
}

func TestCollectWithFixtureDPKGAndRPM(t *testing.T) {
	root := t.TempDir()
	restore := setPackageTestHooks(root)
	defer restore()

	bashData := "fixture bash\n"
	bashMD5 := md5Hex(bashData)
	bashMissingMD5 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	conffileData := "PS1='fixture'\n"
	conffileMD5 := md5Hex(conffileData)
	libfooData := "fixture libfoo\n"
	libfooMD5 := md5Hex(libfooData)

	writeFixtureFile(t, rootPath(root, "/bin/bash"), bashData, 0o755)
	writeFixtureFile(t, rootPath(root, "/etc/bash.bashrc"), conffileData, 0o644)
	writeFixtureFile(t, rootPath(root, "/usr/lib/x86_64-linux-gnu/libfoo.so"), libfooData, 0o644)
	writeFixtureFile(t, rootPath(root, "/var/lib/dpkg/status"), `Package: bash
Status: install ok installed
Architecture: amd64
Version: 5.2.15-2+b9
Installed-Size: 7164
Description: GNU Bourne Again SHell

Package: libfoo
Status: install ok installed
Architecture: amd64
Version: 1.0-1
Source: libfoo-src
Description: multiarch test package
`, 0o640)
	writeFixtureFile(t, rootPath(root, "/var/lib/dpkg/info/bash.list"), "/bin/bash\n/etc/bash.bashrc\n/usr/share/doc/bash\n", 0o640)
	writeFixtureFile(t, rootPath(root, "/var/lib/dpkg/info/bash.md5sums"), bashMD5+" bin/bash\n"+conffileMD5+" etc/bash.bashrc\n"+bashMissingMD5+" usr/share/doc/bash\n", 0o640)
	writeFixtureFile(t, rootPath(root, "/var/lib/dpkg/info/bash.conffiles"), "/etc/bash.bashrc\n", 0o640)
	writeFixtureFile(t, rootPath(root, "/var/lib/dpkg/info/libfoo:amd64.list"), "/usr/lib/x86_64-linux-gnu/libfoo.so\n", 0o640)
	writeFixtureFile(t, rootPath(root, "/var/lib/dpkg/info/libfoo:amd64.md5sums"), libfooMD5+" usr/lib/x86_64-linux-gnu/libfoo.so\n", 0o640)

	commandLookPath = func(name string) (string, error) {
		if name != "rpm" {
			return "", errors.New("unexpected command")
		}
		return "/usr/bin/rpm", nil
	}
	nativeRunner = func(name string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch joined {
		case "-qa --qf %{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n":
			return []byte("rpm-bash\t5.2.15\t2.el9\tx86_64\n"), nil
		case "-q --filesbypkg -a":
			return []byte("rpm-bash /bin/bash\nrpm-bash /usr/share/doc/bash\n"), nil
		default:
			return nil, errors.New("unexpected rpm args: " + joined)
		}
	}

	out, outDir := newOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"manager":"dpkg"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"name":"bash"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"source_package":"libfoo-src"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"manager":"rpm"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"package_name":"bash"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"md5sum":"`+bashMD5+`"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"package_name":"libfoo"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"package_key":"libfoo:amd64"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"version":"1.0-1"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"architecture":"amd64"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"md5sum":"`+libfooMD5+`"`)
	evidencePath := filepath.Join(outDir, "ai/evidence.jsonl")
	assertEvidenceRecord(t, evidencePath, "facts/package_integrity", map[string]any{
		"manager":          "dpkg",
		"package_name":     "bash",
		"package_key":      "bash",
		"path":             "/bin/bash",
		"expected_md5":     bashMD5,
		"actual_md5":       bashMD5,
		"hash_available":   true,
		"file_exists":      true,
		"size":             len(bashData),
		"mode":             "-rwxr-xr-x",
		"package_conffile": false,
	})
	assertEvidenceRecord(t, evidencePath, "facts/package_integrity", map[string]any{
		"manager":          "dpkg",
		"package_name":     "bash",
		"path":             "/etc/bash.bashrc",
		"expected_md5":     conffileMD5,
		"actual_md5":       conffileMD5,
		"hash_available":   true,
		"file_exists":      true,
		"package_conffile": true,
	})
	assertEvidenceRecord(t, evidencePath, "facts/package_integrity", map[string]any{
		"manager":        "dpkg",
		"package_name":   "bash",
		"path":           "/usr/share/doc/bash",
		"expected_md5":   bashMissingMD5,
		"hash_available": true,
		"file_exists":    false,
	})
	assertEvidenceRecordLacksField(t, evidencePath, "facts/package_integrity", map[string]any{
		"package_name": "bash",
		"path":         "/usr/share/doc/bash",
	}, "actual_md5")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"package_name":"rpm-bash"`)
	assertFileContains(t, filepath.Join(outDir, "legacy/enum/dpkg/status.out"), "Package: bash")
	assertFileContains(t, filepath.Join(outDir, "legacy/enum/dpkg/package_files.out"), "/bin/bash")
	assertFileContains(t, filepath.Join(outDir, "legacy/enum/rpm/rpm_-qa.out"), "rpm-bash")
	assertFileContains(t, filepath.Join(outDir, "legacy/enum/rpm/rpm_-q_filesbypkg_-a.out"), "rpm-bash /bin/bash")
}

func TestCollectMissingRootAndRPMWritesAbsent(t *testing.T) {
	root := t.TempDir()
	restore := setPackageTestHooks(filepath.Join(root, "missing-root"))
	defer restore()
	commandLookPath = func(name string) (string, error) {
		return "", errors.New("rpm not found")
	}

	out, outDir := newOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exists":false`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"manager":"dpkg"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"manager":"rpm"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"exists":false`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"stream":"facts/package_integrity"`)
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "/var/lib/dpkg/status")
	assertFileContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), "rpm -qa")
	assertFileNotContains(t, filepath.Join(outDir, "ai/evidence.jsonl"), `"stream":"errors"`)
	assertFileContains(t, filepath.Join(outDir, "legacy/enum/dpkg/status.out"), "unavailable")
	assertFileContains(t, filepath.Join(outDir, "legacy/enum/dpkg/package_files.out"), "unavailable")
	assertFileContains(t, filepath.Join(outDir, "legacy/enum/rpm/rpm_-qa.out"), "unavailable")
	assertFileContains(t, filepath.Join(outDir, "legacy/enum/rpm/rpm_-q_filesbypkg_-a.out"), "unavailable")
}

func setPackageTestHooks(root string) func() {
	oldFilesystemRoot := filesystemRoot
	oldCommandLookPath := commandLookPath
	oldNativeRunner := nativeRunner
	filesystemRoot = root
	commandLookPath = execLookPathUnsupported
	nativeRunner = runNative
	return func() {
		filesystemRoot = oldFilesystemRoot
		commandLookPath = oldCommandLookPath
		nativeRunner = oldNativeRunner
	}
}

func execLookPathUnsupported(name string) (string, error) {
	return "", errors.New("unsupported in test")
}

func newOutput(t *testing.T) (*output.Manager, string) {
	t.Helper()
	outDir := filepath.Join(t.TempDir(), "out")
	out, err := output.New(outDir, "dual", evidence.Session{
		CaseID:    "case-test",
		HostID:    "host-test",
		SessionID: "session-test",
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return out, outDir
}

func writeFixtureFile(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func md5Hex(data string) string {
	sum := md5.Sum([]byte(data))
	return hex.EncodeToString(sum[:])
}

func rootPath(root, sourcePath string) string {
	return filepath.Join(root, strings.TrimPrefix(filepath.Clean(sourcePath), string(filepath.Separator)))
}

func assertFileContains(t *testing.T, path, fragment string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), fragment) {
		t.Fatalf("%s does not contain %q: %s", path, fragment, string(data))
	}
}

func assertFileNotContains(t *testing.T, path, fragment string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), fragment) {
		t.Fatalf("%s unexpectedly contains %q: %s", path, fragment, string(data))
	}
}

func assertEvidenceRecord(t *testing.T, path, stream string, expected map[string]any) {
	t.Helper()
	candidates := evidenceRecordsForStream(t, path, stream)
	for _, candidate := range candidates {
		if evidenceDataMatches(candidate, expected) {
			return
		}
	}
	t.Fatalf("%s does not contain stream %q record matching %#v; candidates: %#v", path, stream, expected, candidates)
}

func assertEvidenceRecordLacksField(t *testing.T, path, stream string, expected map[string]any, field string) {
	t.Helper()
	candidates := evidenceRecordsForStream(t, path, stream)
	for _, candidate := range candidates {
		if !evidenceDataMatches(candidate, expected) {
			continue
		}
		if _, ok := candidate[field]; ok {
			t.Fatalf("%s stream %q record matching %#v unexpectedly contains field %q: %#v", path, stream, expected, field, candidate)
		}
		return
	}
	t.Fatalf("%s does not contain stream %q record matching %#v; candidates: %#v", path, stream, expected, candidates)
}

func evidenceRecordsForStream(t *testing.T, path, stream string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var candidates []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var decoded struct {
			Stream string         `json:"stream"`
			Data   map[string]any `json:"data"`
		}
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatalf("%s is not valid evidence JSONL: %v\n%s", path, err, line)
		}
		if decoded.Stream == stream {
			candidates = append(candidates, decoded.Data)
		}
	}
	return candidates
}

func evidenceDataMatches(data map[string]any, expected map[string]any) bool {
	for key, want := range expected {
		got, ok := data[key]
		if !ok {
			return false
		}
		switch want := want.(type) {
		case int:
			gotNumber, ok := got.(float64)
			if !ok || gotNumber != float64(want) {
				return false
			}
		default:
			if got != want {
				return false
			}
		}
	}
	return true
}
