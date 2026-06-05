package kernel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
)

func TestParseProcModules(t *testing.T) {
	text := "xfs 2211840 1 - Live 0xffffffffc0000000\nbridge 421888 2 br_netfilter,docker0, Live 0xffffffffc0010000\nbad line\n"
	modules := ParseProcModules(text)
	if len(modules) != 2 {
		t.Fatalf("module count mismatch: %+v", modules)
	}
	if modules[0].Name != "xfs" || modules[0].Size != 2211840 || modules[0].RefCount != 1 || modules[0].State != "Live" {
		t.Fatalf("unexpected first module: %+v", modules[0])
	}
	if len(modules[1].UsedBy) != 2 || modules[1].UsedBy[0] != "br_netfilter" || modules[1].UsedBy[1] != "docker0" {
		t.Fatalf("unexpected used_by parse: %+v", modules[1])
	}
}

func TestSplitCommaList(t *testing.T) {
	items := splitCommaList("a,b,,c,")
	if len(items) != 3 || items[2] != "c" {
		t.Fatalf("unexpected split: %+v", items)
	}
}

func TestCollectWithFakeKernelSources(t *testing.T) {
	root := t.TempDir()
	setKernelSourcePaths(t, root)
	setFakeKernelCommands(t, root)

	writeFile(t, procModulesPath, "demo_mod 10 0 - Live 0x1\n")
	writeFile(t, procCmdlinePath, "BOOT_IMAGE=/vmlinuz root=/dev/sda1\n")
	writeFile(t, procTaintedPath, "0\n")
	writeFile(t, kernelReleasePath, "1.2.3-test\n")
	writeFile(t, lockdownPath, "[none] integrity confidentiality\n")
	writeFile(t, lsmPath, "lockdown,capability,yama,apparmor\n")
	writeFile(t, apparmorPath, "Y\n")
	writeFile(t, selinuxPath, "0\n")
	writeFile(t, kptrRestrictPath, "1\n")
	writeFile(t, dmesgRestrictPath, "1\n")
	writeFile(t, modulesDisabledPath, "0\n")
	writeFile(t, filepath.Join(sysModuleRoot, "demo_mod", "version"), "1.0\n")
	writeFile(t, filepath.Join(sysModuleRoot, "demo_mod", "srcversion"), "ABCDEF\n")
	if err := os.MkdirAll(filepath.Join(sysModuleRoot, "demo_mod", "holders", "holder_a"), 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(libModulesRoot, "1.2.3-test", "modules.dep"), "kernel/drivers/demo-mod.ko:\n")
	moduleData := "fake module file\n"
	writeFile(t, filepath.Join(libModulesRoot, "1.2.3-test", "kernel/drivers/demo-mod.ko"), moduleData)

	out, outDir := newTestOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	if data, err := os.ReadFile(filepath.Join(outDir, "legacy/system/kernel/modules.out")); err != nil || !strings.Contains(string(data), "demo_mod") {
		t.Fatalf("legacy modules output missing: err=%v data=%q", err, string(data))
	}
	if data, err := os.ReadFile(filepath.Join(outDir, "legacy/system/kernel/cmdline")); err != nil || !strings.Contains(string(data), "BOOT_IMAGE") {
		t.Fatalf("legacy cmdline output missing: err=%v data=%q", err, string(data))
	}
	if data, err := os.ReadFile(filepath.Join(outDir, "legacy/system/kernel/tainted")); err != nil || strings.TrimSpace(string(data)) != "0" {
		t.Fatalf("legacy tainted output missing: err=%v data=%q", err, string(data))
	}
	if data, err := os.ReadFile(filepath.Join(outDir, "legacy/system/kernel/module/demo_mod.out")); err != nil || !strings.Contains(string(data), "description: fake module demo_mod") {
		t.Fatalf("legacy modinfo output missing: err=%v data=%q", err, string(data))
	}
	if data, err := os.ReadFile(filepath.Join(outDir, "legacy/system/kernel/modprobe_-n-l-v.out")); err != nil || !strings.Contains(string(data), "fake modprobe -n -l -v") {
		t.Fatalf("legacy modprobe output missing: err=%v data=%q", err, string(data))
	}

	modules := readModuleJSONL(t, filepath.Join(outDir, "ai/evidence.jsonl"))
	module, ok := findModule(modules, "demo_mod")
	if !ok {
		t.Fatalf("demo_mod module record missing: %+v", modules)
	}
	if !module.Exists || module.Name != "demo_mod" || module.Version != "1.0" || module.SrcVersion != "ABCDEF" {
		t.Fatalf("unexpected module record: %+v", module)
	}
	if module.ModulePath != filepath.Join(libModulesRoot, "1.2.3-test", "kernel/drivers/demo-mod.ko") {
		t.Fatalf("unexpected module path: %s", module.ModulePath)
	}
	if len(module.Holders) != 1 || module.Holders[0] != "holder_a" {
		t.Fatalf("unexpected holders: %+v", module.Holders)
	}

	evidencePath := filepath.Join(outDir, "ai/evidence.jsonl")
	assertEvidenceRecord(t, evidencePath, "facts/kernel_security", map[string]any{
		"exists":      true,
		"fact_type":   "cmdline",
		"key":         "cmdline",
		"value":       "BOOT_IMAGE=/vmlinuz root=/dev/sda1",
		"source_file": procCmdlinePath,
	})
	assertEvidenceEnvelope(t, evidencePath, "facts/kernel_security", map[string]any{
		"key": "cmdline",
	}, map[string]any{
		"source_type": "procfs",
	})
	assertEvidenceRecord(t, evidencePath, "facts/kernel_security", map[string]any{
		"exists":      true,
		"fact_type":   "lockdown",
		"key":         "lockdown",
		"value":       "[none] integrity confidentiality",
		"source_file": lockdownPath,
	})
	assertEvidenceEnvelope(t, evidencePath, "facts/kernel_security", map[string]any{
		"key": "lockdown",
	}, map[string]any{
		"source_type": "sysfs",
	})
	assertEvidenceRecord(t, evidencePath, "facts/kernel_security", map[string]any{
		"exists":    true,
		"fact_type": "sysctl",
		"key":       "kernel.modules_disabled",
		"value":     "0",
	})
	assertEvidenceRecord(t, evidencePath, "facts/kernel_consistency", map[string]any{
		"exists":               true,
		"module_name":          "demo_mod",
		"loaded":               true,
		"proc_modules_present": true,
		"sysfs_present":        true,
		"sysfs_path":           filepath.Join(sysModuleRoot, "demo_mod"),
		"module_path":          filepath.Join(libModulesRoot, "1.2.3-test", "kernel/drivers/demo-mod.ko"),
		"module_file_exists":   true,
		"module_file_size":     len(moduleData),
		"module_file_sha256":   sha256Hex(moduleData),
		"refcount":             0,
	})
	assertEvidenceRecord(t, evidencePath, "facts/kernel_consistency", map[string]any{
		"exists":               true,
		"module_name":          "apparmor",
		"loaded":               true,
		"proc_modules_present": false,
		"sysfs_present":        true,
		"module_file_exists":   false,
		"module_file_error":    "module path unavailable",
		"refcount":             0,
	})

	entities := readLines(t, filepath.Join(outDir, "ai/evidence.jsonl"))
	if !containsLine(entities, "kernel_module:demo_mod") {
		t.Fatalf("unexpected entities: %+v", entities)
	}
	timeline := readLines(t, filepath.Join(outDir, "ai/evidence.jsonl"))
	if !containsLine(timeline, "file_metadata") || !containsLine(timeline, procCmdlinePath) || !containsLine(timeline, procTaintedPath) {
		t.Fatalf("timeline missing kernel file metadata: %+v", timeline)
	}
}

func TestCollectWritesAbsentRecordsWhenProcAndSysMissing(t *testing.T) {
	root := t.TempDir()
	setKernelSourcePaths(t, root)

	out, outDir := newTestOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	modules := readModuleJSONL(t, filepath.Join(outDir, "ai/evidence.jsonl"))
	if len(modules) != 2 {
		t.Fatalf("expected proc and sysfs absent records, got: %+v", modules)
	}
	for _, module := range modules {
		if module.Exists || module.AbsentReason == "" {
			t.Fatalf("unexpected absent module record: %+v", module)
		}
	}
	errors := readLines(t, filepath.Join(outDir, "ai/evidence.jsonl"))
	if len(errors) < 4 {
		t.Fatalf("expected missing proc/sys errors, got: %+v", errors)
	}
}

func TestModulePathMappingFailureIsRecorded(t *testing.T) {
	root := t.TempDir()
	setKernelSourcePaths(t, root)

	writeFile(t, procModulesPath, "demo_mod 10 0 - Live 0x1\n")
	writeFile(t, procCmdlinePath, "BOOT_IMAGE=/vmlinuz root=/dev/sda1\n")
	writeFile(t, procTaintedPath, "0\n")
	writeFile(t, kernelReleasePath, "1.2.3-test\n")
	if err := os.MkdirAll(filepath.Join(sysModuleRoot, "demo_mod"), 0o750); err != nil {
		t.Fatal(err)
	}

	out, outDir := newTestOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	errors := readLines(t, filepath.Join(outDir, "ai/evidence.jsonl"))
	if !containsLine(errors, "modules.dep") {
		t.Fatalf("expected modules.dep mapping error, got: %+v", errors)
	}
}

func TestModulePathKernelReleaseMissingIsRecorded(t *testing.T) {
	root := t.TempDir()
	setKernelSourcePaths(t, root)

	writeFile(t, procModulesPath, "demo_mod 10 0 - Live 0x1\n")
	writeFile(t, procCmdlinePath, "BOOT_IMAGE=/vmlinuz root=/dev/sda1\n")
	writeFile(t, procTaintedPath, "0\n")
	if err := os.MkdirAll(filepath.Join(sysModuleRoot, "demo_mod"), 0o750); err != nil {
		t.Fatal(err)
	}

	out, outDir := newTestOutput(t)
	if err := Collect(context.Background(), out); err != nil {
		t.Fatal(err)
	}

	errors := readLines(t, filepath.Join(outDir, "ai/evidence.jsonl"))
	if !containsLine(errors, "kernel release unavailable") {
		t.Fatalf("expected kernel release mapping error, got: %+v", errors)
	}
}

func setKernelSourcePaths(t *testing.T, root string) {
	t.Helper()
	oldProcModulesPath := procModulesPath
	oldProcCmdlinePath := procCmdlinePath
	oldProcTaintedPath := procTaintedPath
	oldKernelReleasePath := kernelReleasePath
	oldSysModuleRoot := sysModuleRoot
	oldLibModulesRoot := libModulesRoot
	oldLockdownPath := lockdownPath
	oldLSMPath := lsmPath
	oldApparmorPath := apparmorPath
	oldSELinuxPath := selinuxPath
	oldKptrRestrictPath := kptrRestrictPath
	oldDmesgRestrictPath := dmesgRestrictPath
	oldModulesDisabledPath := modulesDisabledPath

	procModulesPath = filepath.Join(root, "proc/modules")
	procCmdlinePath = filepath.Join(root, "proc/cmdline")
	procTaintedPath = filepath.Join(root, "proc/sys/kernel/tainted")
	kernelReleasePath = filepath.Join(root, "proc/sys/kernel/osrelease")
	sysModuleRoot = filepath.Join(root, "sys/module")
	libModulesRoot = filepath.Join(root, "lib/modules")
	lockdownPath = filepath.Join(root, "sys/kernel/security/lockdown")
	lsmPath = filepath.Join(root, "sys/kernel/security/lsm")
	apparmorPath = filepath.Join(root, "sys/module/apparmor/parameters/enabled")
	selinuxPath = filepath.Join(root, "sys/fs/selinux/enforce")
	kptrRestrictPath = filepath.Join(root, "proc/sys/kernel/kptr_restrict")
	dmesgRestrictPath = filepath.Join(root, "proc/sys/kernel/dmesg_restrict")
	modulesDisabledPath = filepath.Join(root, "proc/sys/kernel/modules_disabled")

	t.Cleanup(func() {
		procModulesPath = oldProcModulesPath
		procCmdlinePath = oldProcCmdlinePath
		procTaintedPath = oldProcTaintedPath
		kernelReleasePath = oldKernelReleasePath
		sysModuleRoot = oldSysModuleRoot
		libModulesRoot = oldLibModulesRoot
		lockdownPath = oldLockdownPath
		lsmPath = oldLSMPath
		apparmorPath = oldApparmorPath
		selinuxPath = oldSELinuxPath
		kptrRestrictPath = oldKptrRestrictPath
		dmesgRestrictPath = oldDmesgRestrictPath
		modulesDisabledPath = oldModulesDisabledPath
	})
}

func setFakeKernelCommands(t *testing.T, root string) {
	t.Helper()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(binDir, "modinfo"), "#!/bin/sh\necho \"filename: /lib/modules/fake/$1.ko\"\necho \"description: fake module $1\"\n")
	writeExecutable(t, filepath.Join(binDir, "modprobe"), "#!/bin/sh\necho \"fake modprobe $*\"\n")
	oldPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Setenv("PATH", oldPath)
	})
}

func newTestOutput(t *testing.T) (*output.Manager, string) {
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

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o640); err != nil {
		t.Fatal(err)
	}
}

func writeExecutable(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o750); err != nil {
		t.Fatal(err)
	}
}

func sha256Hex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func readModuleJSONL(t *testing.T, path string) []Module {
	t.Helper()
	lines := readLines(t, path)
	modules := make([]Module, 0, len(lines))
	for _, line := range lines {
		var envelope struct {
			RecordType string          `json:"record_type"`
			Stream     string          `json:"stream"`
			Data       json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal([]byte(line), &envelope); err != nil {
			t.Fatalf("invalid evidence jsonl %q: %v", line, err)
		}
		if envelope.Stream != "entities/kernel_module" {
			continue
		}
		var module Module
		if err := json.Unmarshal(envelope.Data, &module); err != nil {
			t.Fatalf("invalid module jsonl %q: %v", line, err)
		}
		modules = append(modules, module)
	}
	return modules
}

func findModule(modules []Module, name string) (Module, bool) {
	for _, module := range modules {
		if module.Name == name {
			return module, true
		}
	}
	return Module{}, false
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

func assertEvidenceEnvelope(t *testing.T, path, stream string, dataMatch map[string]any, envelopeMatch map[string]any) {
	t.Helper()
	lines := readLines(t, path)
	var candidates []map[string]any
	for _, line := range lines {
		var envelope struct {
			Stream string         `json:"stream"`
			Data   map[string]any `json:"data"`
		}
		var envelopeMap map[string]any
		if err := json.Unmarshal([]byte(line), &envelope); err != nil {
			t.Fatalf("invalid evidence jsonl %q: %v", line, err)
		}
		if err := json.Unmarshal([]byte(line), &envelopeMap); err != nil {
			t.Fatalf("invalid evidence envelope %q: %v", line, err)
		}
		if envelope.Stream != stream || !evidenceDataMatches(envelope.Data, dataMatch) {
			continue
		}
		candidates = append(candidates, envelopeMap)
		if evidenceDataMatches(envelopeMap, envelopeMatch) {
			return
		}
	}
	t.Fatalf("%s does not contain stream %q envelope matching data %#v and envelope %#v; candidates: %#v", path, stream, dataMatch, envelopeMatch, candidates)
}

func evidenceRecordsForStream(t *testing.T, path, stream string) []map[string]any {
	t.Helper()
	lines := readLines(t, path)
	var candidates []map[string]any
	for _, line := range lines {
		var envelope struct {
			Stream string         `json:"stream"`
			Data   map[string]any `json:"data"`
		}
		if err := json.Unmarshal([]byte(line), &envelope); err != nil {
			t.Fatalf("invalid evidence jsonl %q: %v", line, err)
		}
		if envelope.Stream == stream {
			candidates = append(candidates, envelope.Data)
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

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func containsLine(lines []string, fragment string) bool {
	for _, line := range lines {
		if strings.Contains(line, fragment) {
			return true
		}
	}
	return false
}

func TestModuleNameFromPath(t *testing.T) {
	cases := map[string]string{
		"kernel/fs/xfs/xfs.ko":             "xfs",
		"kernel/drivers/foo/bar-baz.ko.xz": "bar_baz",
		"bridge.ko.zst":                    "bridge",
	}
	for input, want := range cases {
		if got := moduleNameFromPath(input); got != want {
			t.Fatalf("moduleNameFromPath(%q)=%q want %q", input, got, want)
		}
	}
}
