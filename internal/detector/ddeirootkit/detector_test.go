package ddeirootkit

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, data := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for name := range files {
		if strings.HasPrefix(name, "proc/") && strings.HasSuffix(name, "/status") {
			dir := filepath.Join(root, filepath.Dir(name))
			if _, err := os.Stat(dir + "/stat"); os.IsNotExist(err) {
				if err := os.WriteFile(dir+"/stat", []byte("1 (fixture) S "+strings.Repeat("0 ", 18)+"100\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	return root
}
func opts(root string) Options { return Options{Root: root, SelfPID: 999999, ScanProcMaps: true} }
func baseline() Observations   { return Observations{Coverage: Coverage{Root: true, Proc: true}} }
func behavior() Observations {
	o := baseline()
	o.Objects = []ObjectObservation{{ID: "loader", Role: "preload", ELF: true, ValidELF: true, ELFType: "ET_DYN"}, {ID: "pam", Role: "pam", ELF: true, ValidELF: true, ELFType: "ET_DYN"}}
	o.PreloadObjects = []string{"loader"}
	o.Processes = []ProcessObservation{{PID: 42, UID: 0, PPID: 1, RWX: true, HasPTY: true, MappedObjects: []string{"loader"}}}
	o.PAMAuth = []PAMObservation{{Config: "auth-service", ObjectID: "pam", Control: "[success=1 default=ignore]"}, {Config: "auth-service", ObjectID: "pam", Control: "[success=done default=ignore]"}}
	return o
}
func TestBehaviorConjunctionNoHashes(t *testing.T) {
	if r := Evaluate(behavior()); r.Verdict != VerdictInfected {
		t.Fatalf("%+v", r)
	}
	for _, mutate := range []func(*Observations){
		func(o *Observations) { o.PreloadObjects = nil },
		func(o *Observations) { o.Processes[0].MappedObjects = []string{"different-inode"} },
		func(o *Observations) { o.PAMAuth[1].Config = "other-service" },
		func(o *Observations) { o.PAMAuth[1].ObjectID = "other-pam" },
		func(o *Observations) { o.Processes[0].UID = 1000 },
		func(o *Observations) { o.Processes[0].PPID = 50 },
		func(o *Observations) { o.Processes[0].RWX = false },
		func(o *Observations) { o.Processes[0].HasPTY = false },
		func(o *Observations) { o.Objects[0].ValidELF = false },
		func(o *Observations) { o.Objects[1].ValidELF = false },
		func(o *Observations) { o.Objects[0].ELFType = "ET_EXEC" },
		func(o *Observations) { o.Objects[1].ELFType = "ET_EXEC" },
	} {
		o := behavior()
		mutate(&o)
		if r := Evaluate(o); r.Verdict == VerdictInfected {
			t.Fatalf("broken correlation infected: %+v", o)
		}
	}
}
func TestBroadHooksDaemonConjunction(t *testing.T) {
	o := behavior()
	o.PAMAuth = nil
	o.Objects[0].HookNames = []string{"stat", "lstat", "readdir", "open", "unlink"}
	o.Objects[0].HookCategories = []string{"metadata", "directory_enumeration", "file_access", "file_removal"}
	if r := Evaluate(o); r.Verdict != VerdictInfected {
		t.Fatalf("%+v", r)
	}
	o.Objects[0].HookNames = []string{"stat", "stat", "stat", "stat", "stat"}
	if r := Evaluate(o); r.Verdict == VerdictInfected {
		t.Fatal("duplicate hooks counted")
	}
}
func TestCaseHashesAndPartialCoverage(t *testing.T) {
	for _, sha := range []string{SeptemberLibrarySHA256, SeptemberXinetdSHA256} {
		o := Observations{Objects: []ObjectObservation{{ID: "x", SHA256: sha}}}
		r := Evaluate(o)
		if r.Verdict != VerdictInfected || r.Complete {
			t.Fatalf("%+v", r)
		}
	}
	for _, sha := range []string{AugustLoaderSHA256, AugustPAMSHA256, AugustXinetdSHA256} {
		o := baseline()
		o.Objects = []ObjectObservation{{ID: "x", SHA256: sha}}
		if r := Evaluate(o); r.Verdict != VerdictInconclusive {
			t.Fatalf("%+v", r)
		}
	}
	o := baseline()
	o.Objects = []ObjectObservation{{ID: "l", SHA256: AugustLoaderSHA256}, {ID: "p", SHA256: AugustPAMSHA256}, {ID: "x", SHA256: AugustXinetdSHA256}}
	o.PreloadObjects = []string{"l"}
	o.AuthPAMObjects = []string{"p"}
	if r := Evaluate(o); r.Verdict != VerdictInfected {
		t.Fatalf("%+v", r)
	}
	o.AuthPAMObjects = nil
	if r := Evaluate(o); r.Verdict == VerdictInfected {
		t.Fatal("inactive disk xinetd decisive")
	}
	o.Processes = []ProcessObservation{{PID: 10, ExeObject: "x"}}
	if r := Evaluate(o); r.Verdict != VerdictInfected {
		t.Fatalf("%+v", r)
	}
}
func TestNormalAndGenericControls(t *testing.T) {
	o := baseline()
	o.Processes = []ProcessObservation{{PID: 1, UID: 0, PPID: 1, RWX: true}}
	if r := Evaluate(o); r.Verdict != VerdictClean {
		t.Fatalf("standalone JIT RWX: %+v", r)
	}
	o.Objects = []ObjectObservation{{ID: "libc", Role: "mapped", ELF: true, Hooks: 15}}
	o.Processes = []ProcessObservation{{PID: 3, MappedObjects: []string{"libc"}}}
	if r := Evaluate(o); r.Verdict != VerdictClean || !r.Complete {
		t.Fatalf("%+v", r)
	}
	for _, x := range []ObjectObservation{{Role: "preload", ELF: true, Hooks: 2}, {Role: "xinetd", ELF: true, Static: true}, {Role: "xinetd", ELF: true, Size: 2 << 20}} {
		o := baseline()
		o.Objects = []ObjectObservation{x}
		if r := Evaluate(o); r.Verdict != VerdictInconclusive {
			t.Fatalf("%+v", r)
		}
	}
	o = baseline()
	o.Suspicious = []string{"marker"}
	if r := Evaluate(o); r.Verdict != VerdictInconclusive {
		t.Fatalf("%+v", r)
	}
	o = baseline()
	o.Gaps = []string{"denied"}
	if r := Evaluate(o); r.Complete || r.Verdict != VerdictInconclusive || r.Coverage.Errors != 1 {
		t.Fatalf("%+v", r)
	}
}
func TestExactCachedEveryPID(t *testing.T) {
	o := baseline()
	o.Objects = []ObjectObservation{{ID: "x", SHA256: SeptemberLibrarySHA256}}
	o.Processes = []ProcessObservation{{PID: 1, MappedObjects: []string{"x"}}, {PID: 2, MappedObjects: []string{"x"}}}
	if r := Evaluate(o); len(r.ProcHits) != 2 {
		t.Fatalf("%+v", r)
	}
}
func TestLoaderTokensAndMaps(t *testing.T) {
	got := nonEmptyLines(" # comment\n/a.so : /b.so\t/c.so # ignored\n")
	if !reflect.DeepEqual(got, []string{"/a.so", "/b.so", "/c.so"}) {
		t.Fatal(got)
	}
	for _, tc := range []struct{ line, path string }{
		{"1000-2000 rwxp 00000000 00:00 0", ""},
		{"1000-2000 r-xp 00000000 08:01 5 /path with spaces/lib.so.1 (deleted)", "/path with spaces/lib.so.1 (deleted)"},
	} {
		_, _, path, ok := mapFields(tc.line)
		if !ok || path != tc.path {
			t.Fatalf("%q %v", path, ok)
		}
	}
}
func TestBoundedReadsAndCancellation(t *testing.T) {
	root := fixture(t, map[string]string{"data": strings.Repeat("x", 32)})
	if _, err := readBounded(context.Background(), filepath.Join(root, "data"), 8); err == nil {
		t.Fatal("unbounded read")
	}
	if _, err := readBounded(context.Background(), root, 8); err == nil {
		t.Fatal("directory accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readBounded(ctx, filepath.Join(root, "data"), 64); err == nil {
		t.Fatal("cancel ignored")
	}
	f, err := os.Create(filepath.Join(root, "huge"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxObject + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := inspectObject(context.Background(), filepath.Join(root, "huge")); err == nil {
		t.Fatal("oversize accepted")
	}
}
func TestRequiredProcCoverage(t *testing.T) {
	r := Run(opts(t.TempDir()))
	if r.Complete || r.Verdict != VerdictInconclusive {
		t.Fatalf("%+v", r)
	}
}
func TestTrueExportPredicate(t *testing.T) {
	good := elf.Symbol{Name: "open", Section: 1, Info: byte(elf.STB_GLOBAL) << 4, Value: 0}
	if !exported(good) {
		t.Fatal("zero-valued real export rejected")
	}
	for _, s := range []elf.Symbol{
		{Section: elf.SHN_UNDEF, Value: 123, Info: byte(elf.STB_GLOBAL) << 4},
		{Section: 1, Value: 123, Info: byte(elf.STB_LOCAL) << 4},
		{Section: 1, Value: 123, Info: byte(elf.STB_GLOBAL) << 4, Other: byte(elf.STV_HIDDEN)},
	} {
		if exported(s) {
			t.Fatalf("not exported: %+v", s)
		}
	}
}

// Construct actual ELF metadata, not a mocked inspector or fabricated malware.
func elfHeader() []byte {
	b := make([]byte, 64)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(b[16:], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(b[18:], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint16(b[52:], 64)
	binary.LittleEndian.PutUint16(b[54:], 56)
	binary.LittleEndian.PutUint16(b[58:], 64)
	return b
}
func TestOversizedPTInterpNoPanic(t *testing.T) {
	b := append(elfHeader(), make([]byte, 56)...)
	binary.LittleEndian.PutUint64(b[32:], 64)
	binary.LittleEndian.PutUint16(b[56:], 1)
	binary.LittleEndian.PutUint32(b[64:], uint32(elf.PT_INTERP))
	binary.LittleEndian.PutUint64(b[96:], ^uint64(0))
	if _, err := parseELF(bytes.NewReader(b), int64(len(b))); err == nil {
		t.Fatal("oversized interpreter accepted")
	}
}
func TestCompressedELFMetadataRejectedBeforeDecode(t *testing.T) {
	b := append(elfHeader(), make([]byte, 64)...)
	binary.LittleEndian.PutUint64(b[40:], 64)
	binary.LittleEndian.PutUint16(b[60:], 1)
	binary.LittleEndian.PutUint64(b[72:], uint64(elf.SHF_COMPRESSED))
	if _, err := parseELF(bytes.NewReader(b), int64(len(b))); err == nil {
		t.Fatal("compressed section accepted")
	}
}
func TestRealELFExportParsing(t *testing.T) {
	b := elfHeader()
	str := []byte("\x00open\x00stat\x00readdir\x00unlink\x00")
	b = append(b, str...)
	offset := len(b)
	symbols := []elf.Symbol{{}, {Name: "open", Section: 1, Info: byte(elf.STB_GLOBAL) << 4}, {Name: "stat", Section: elf.SHN_UNDEF, Value: 123, Info: byte(elf.STB_GLOBAL) << 4}, {Name: "readdir", Section: 1, Value: 123, Info: byte(elf.STB_GLOBAL) << 4, Other: byte(elf.STV_HIDDEN)}, {Name: "unlink", Section: 1, Info: byte(elf.STB_WEAK) << 4}}
	for _, s := range symbols {
		row := make([]byte, 24)
		n := bytes.Index(str, append([]byte(s.Name), 0))
		if s.Name == "" {
			n = 0
		}
		binary.LittleEndian.PutUint32(row, uint32(n))
		row[4] = s.Info
		row[5] = s.Other
		binary.LittleEndian.PutUint16(row[6:], uint16(s.Section))
		binary.LittleEndian.PutUint64(row[8:], s.Value)
		b = append(b, row...)
	}
	shoff := len(b)
	b = append(b, make([]byte, 3*64)...)
	binary.LittleEndian.PutUint64(b[40:], uint64(shoff))
	binary.LittleEndian.PutUint16(b[60:], 3)
	strsec := b[shoff+64:]
	binary.LittleEndian.PutUint32(strsec[4:], uint32(elf.SHT_STRTAB))
	binary.LittleEndian.PutUint64(strsec[24:], 64)
	binary.LittleEndian.PutUint64(strsec[32:], uint64(len(str)))
	symsec := b[shoff+128:]
	binary.LittleEndian.PutUint32(symsec[4:], uint32(elf.SHT_DYNSYM))
	binary.LittleEndian.PutUint64(symsec[24:], uint64(offset))
	binary.LittleEndian.PutUint64(symsec[32:], uint64(len(symbols)*24))
	binary.LittleEndian.PutUint32(symsec[40:], 1)
	binary.LittleEndian.PutUint64(symsec[56:], 24)
	facts, err := parseELF(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(facts.HookNames, []string{"open", "unlink"}) {
		t.Fatalf("%+v", facts)
	}
}
