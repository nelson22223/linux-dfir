package ddeirootkit

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func pamHeader(class byte, machine elf.Machine, big bool) []byte {
	b := make([]byte, 64)
	copy(b, []byte{0x7f, 'E', 'L', 'F', class, 1, 1})
	var order binary.ByteOrder = binary.LittleEndian
	if big {
		b[5] = 2
		order = binary.BigEndian
	}
	order.PutUint16(b[16:], uint16(elf.ET_DYN))
	order.PutUint16(b[18:], uint16(machine))
	order.PutUint32(b[20:], 1)
	if class == 1 {
		order.PutUint16(b[40:], 52)
	} else {
		order.PutUint16(b[52:], 64)
	}
	return b
}

func TestPAMCandidateCollection(t *testing.T) {
	for _, mode := range []string{"multiarch", "i386", "machine", "endian", "alias", "copy", "damaged", "nonelf", "unknown", "missing", "brokenlink", "directory"} {
		t.Run(mode, func(t *testing.T) {
			files := map[string]string{"etc/pam.d/login": "auth required pam_test.so\n", "lib64/security/pam_test.so": string(elfHeader()), "proc/1/status": "Uid: 0\nPPid: 0\n", "proc/1/maps": "", "proc/1/comm": "init"}
			other := "lib/security/pam_test.so"
			data := pamHeader(1, elf.EM_386, false)
			switch mode {
			case "i386":
				other = "lib/i386-linux-gnu/security/pam_test.so"
			case "machine":
				data = pamHeader(2, elf.EM_AARCH64, false)
			case "endian":
				data = pamHeader(2, elf.EM_X86_64, true)
			case "copy":
				data = elfHeader()
			case "damaged":
				data = []byte("\x7fELFbroken")
			case "nonelf":
				data = []byte("not ELF")
			case "unknown":
				data = pamHeader(2, elf.EM_NONE, false)
			}
			if mode != "alias" && mode != "missing" && mode != "brokenlink" && mode != "directory" {
				files[other] = string(data)
			}
			if mode == "missing" {
				delete(files, "lib64/security/pam_test.so")
			}
			root := fixture(t, files)
			link(t, "/bin/init", filepath.Join(root, "proc/1/exe"))
			link(t, "net:[1]", filepath.Join(root, "proc/self/ns/net"))
			link(t, "net:[1]", filepath.Join(root, "proc/1/ns/net"))
			for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
				path := filepath.Join(root, "proc/net", name)
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("  sl  local_address rem_address st\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.MkdirAll(filepath.Join(root, "proc/1/fd"), 0755); err != nil {
				t.Fatal(err)
			}
			if mode == "alias" {
				link(t, filepath.Join(root, "lib64/security/pam_test.so"), filepath.Join(root, other))
			}
			if mode == "brokenlink" {
				link(t, filepath.Join(root, "absent"), filepath.Join(root, other))
			}
			if mode == "directory" {
				if err := os.MkdirAll(filepath.Join(root, other), 0755); err != nil {
					t.Fatal(err)
				}
			}
			o := Collect(context.Background(), opts(root))
			r := Evaluate(o)
			bad := mode == "copy" || mode == "damaged" || mode == "nonelf" || mode == "unknown" || mode == "brokenlink" || mode == "directory"
			if bad {
				if r.Complete || r.Coverage.Errors == 0 || r.Verdict != VerdictInconclusive {
					t.Fatalf("%+v", r)
				}
			} else if !r.Complete || r.Coverage.Errors != 0 || r.Verdict != VerdictClean {
				t.Fatalf("%+v", r)
			}
			want := 2
			if mode == "alias" || mode == "brokenlink" || mode == "directory" {
				want = 1
			}
			if mode == "missing" {
				want = 0
			}
			wantAuth := 0
			if mode == "alias" {
				wantAuth = 1
			}
			if len(o.Objects) != want || len(o.AuthPAMObjects) != wantAuth {
				t.Fatalf("%+v", o)
			}
			for _, p := range o.PAMAuth {
				if p.Candidate != (mode != "alias") || p.CandidatePath == "" {
					t.Fatalf("%+v", p)
				}
			}
		})
	}
}

func TestMissingPAMReferencesAreGroupedFacts(t *testing.T) {
	c := newCollector(fixture(t, map[string]string{
		"etc/pam.d/smartcard-auth":    "auth [success=done ignore=ignore default=die] pam_pkcs11.so\n",
		"etc/pam.d/smartcard-auth-ac": "auth required pam_pkcs11.so\n",
		"etc/pam.d/sshd.atuin":        "-auth optional pam_reauthorize.so prepare\n",
		"etc/pam.d/absolute":          "auth required /missing/pam_test.so\n",
	}))
	c.configs()
	if len(c.o.Gaps) != 0 || len(c.o.MissingPAM) != 4 {
		t.Fatalf("%+v", c.o)
	}
	c.o.Coverage.Root, c.o.Coverage.Proc = true, true
	r := Evaluate(c.o)
	if !r.Complete || r.Verdict != VerdictClean || r.Coverage.Errors != 0 {
		t.Fatalf("%+v", r)
	}
	if len(r.Findings) != 3 {
		t.Fatalf("%+v", r.Findings)
	}
	text := Text(r)
	for _, want := range []string{"smartcard-auth:", "smartcard-auth-ac:", "-auth optional", "/missing/pam_test.so"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s: %s", want, text)
		}
	}
	c.o.Gaps = append(c.o.Gaps, "required observation: permission denied")
	if r := Evaluate(c.o); r.Complete || r.Verdict != VerdictInconclusive {
		t.Fatalf("%+v", r)
	}
	c.o.Objects = append(c.o.Objects, ObjectObservation{SHA256: SeptemberLibrarySHA256})
	if r := Evaluate(c.o); r.Verdict != VerdictInfected {
		t.Fatalf("%+v", r)
	}
}

func TestPAMCandidateCorrelation(t *testing.T) {
	for _, known := range []bool{false, true} {
		for _, mode := range []string{"unmapped", "matching", "wrongclass", "wrongmachine", "wrongendian", "unknown", "otheridentity"} {
			o := behavior()
			for i := range o.Objects {
				o.Objects[i].ELFClass = "ELFCLASS64"
				o.Objects[i].ELFMachine = "EM_X86_64"
				o.Objects[i].ELFData = "ELFDATA2LSB"
			}
			for i := range o.PAMAuth {
				o.PAMAuth[i].Candidate = true
				o.PAMAuth[i].Resolution = "unique_arch_candidate"
			}
			if known {
				o.Objects[0].SHA256 = AugustLoaderSHA256
				o.Objects[1].SHA256 = AugustPAMSHA256
			}
			if mode != "unmapped" {
				o.Processes[0].MappedObjects = append(o.Processes[0].MappedObjects, "pam")
			}
			switch mode {
			case "wrongclass":
				o.Objects[1].ELFClass = "ELFCLASS32"
			case "wrongmachine":
				o.Objects[1].ELFMachine = "EM_AARCH64"
			case "wrongendian":
				o.Objects[1].ELFData = "ELFDATA2MSB"
			case "unknown":
				o.Objects[1].ELFClass = ""
			case "otheridentity":
				o.Processes[0].MappedObjects = []string{"loader", "same-path-other-inode"}
			}
			r := Evaluate(o)
			if (r.Verdict == VerdictInfected) != (mode == "matching") {
				t.Fatalf("known=%t mode=%s: %+v", known, mode, r)
			}
			if known {
				found := false
				for _, f := range r.Findings {
					if f.ID == "aug_case" {
						found = true
					}
				}
				if !found {
					t.Fatal("candidate hash lost")
				}
			}
		}
	}
}

func TestPreloadAmbiguityUnchanged(t *testing.T) {
	root := fixture(t, map[string]string{"lib/a.so": string(elfHeader()), "lib64/a.so": string(pamHeader(1, elf.EM_386, false))})
	if got := newCollector(root).resolve("a.so", false); got != nil {
		t.Fatalf("%v", got)
	}
}

func TestPAMSingleResolvedConfigurationRetainsBehavior(t *testing.T) {
	for _, token := range []string{"pam_test.so", "/lib64/security/pam_test.so"} {
		for _, multi := range []bool{false, true} {
			files := map[string]string{"lib64/security/pam_test.so": string(elfHeader()), "etc/pam.d/login": "auth [success=1 default=ignore] " + token + "\nauth [success=done default=ignore] " + token + "\n"}
			if multi {
				files["lib/security/pam_test.so"] = string(pamHeader(1, elf.EM_386, false))
			}
			c := newCollector(fixture(t, files))
			c.configs()
			if len(c.o.Gaps) != 0 {
				t.Fatalf("%+v", c.o)
			}
			o := behavior()
			o.Objects = append(o.Objects[:1], c.o.Objects...)
			o.PAMAuth, o.AuthPAMObjects = c.o.PAMAuth, c.o.AuthPAMObjects
			want := !multi || filepath.IsAbs(token)
			if r := Evaluate(o); (r.Verdict == VerdictInfected) != want {
				t.Fatalf("token=%s multi=%t: %+v", token, multi, r)
			}
		}
	}
}

func TestPAMHardlinkIdentity(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux file identity")
	}
	root := fixture(t, map[string]string{"lib/security/pam_test.so": string(elfHeader()), "etc/pam.d/login": "auth required pam_test.so\n"})
	alias := filepath.Join(root, "lib64/security/pam_test.so")
	if err := os.MkdirAll(filepath.Dir(alias), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "lib/security/pam_test.so"), alias); err != nil {
		t.Fatal(err)
	}
	c := newCollector(root)
	c.configs()
	if len(c.o.Gaps) != 0 || len(c.o.Objects) != 1 || len(c.o.AuthPAMObjects) != 1 {
		t.Fatalf("%+v", c.o)
	}
}

func TestPAMMixedControlProvenance(t *testing.T) {
	for _, strongPair := range []bool{false, true} {
		for _, candidateFirst := range []bool{false, true} {
			for _, mapped := range []bool{false, true} {
				strong := "auth [success=1 default=ignore] /lib64/security/pam_test.so\n"
				if strongPair {
					strong += "auth [success=done default=ignore] /lib64/security/pam_test.so\n"
				}
				weak := "auth [success=done default=ignore] pam_test.so\n"
				config := strong + weak
				if candidateFirst {
					config = weak + strong
				}
				c := newCollector(fixture(t, map[string]string{
					"etc/pam.d/login":            config,
					"lib64/security/pam_test.so": string(elfHeader()),
					"lib/security/pam_test.so":   string(pamHeader(1, elf.EM_386, false)),
				}))
				c.configs()
				if len(c.o.Gaps) != 0 || len(c.o.Objects) != 2 {
					t.Fatalf("%+v", c.o)
				}
				o := behavior()
				o.Objects[0].ELFClass, o.Objects[0].ELFMachine, o.Objects[0].ELFData = "ELFCLASS64", "EM_X86_64", "ELFDATA2LSB"
				o.Objects = append(o.Objects[:1], c.o.Objects...)
				o.PAMAuth, o.AuthPAMObjects = c.o.PAMAuth, c.o.AuthPAMObjects
				if mapped {
					for _, x := range c.o.Objects {
						if x.ELFClass == "ELFCLASS64" {
							o.Processes[0].MappedObjects = append(o.Processes[0].MappedObjects, x.ID)
						}
					}
				}
				if r := Evaluate(o); (r.Verdict == VerdictInfected) != (strongPair || mapped) {
					t.Fatalf("strongPair=%t candidateFirst=%t mapped=%t: %+v", strongPair, candidateFirst, mapped, r)
				}
			}
		}
	}
}

func TestPAMMultiarchMappedIdentityAndPositiveHash(t *testing.T) {
	root := fixture(t, map[string]string{"lib/security/pam_test.so": string(pamHeader(1, elf.EM_386, false)), "lib64/security/pam_test.so": string(elfHeader()), "etc/pam.d/login": "auth required pam_test.so\n", "proc/7/status": "Uid: 0\nPPid: 0\n", "proc/7/maps": ""})
	actual := filepath.Join(root, "lib/security/pam_test.so")
	if err := os.WriteFile(filepath.Join(root, "proc/7/maps"), []byte(mappingLine(t, actual, "/lib/security/pam_test.so")), 0644); err != nil {
		t.Fatal(err)
	}
	link(t, "/bin/service", filepath.Join(root, "proc/7/exe"))
	c := newCollector(root)
	c.configs()
	c.processes()
	if len(c.o.Gaps) != 0 || len(c.o.Objects) != 2 || len(c.o.Processes) != 1 || len(c.o.Processes[0].MappedObjects) != 1 {
		t.Fatalf("%+v", c.o)
	}
	id := c.o.Processes[0].MappedObjects[0]
	for i := range c.o.Objects {
		x := &c.o.Objects[i]
		if x.ID == id && x.ELFClass != "ELFCLASS32" {
			t.Fatal("mapped identity associated with wrong architecture")
		}
		// Replay-only hash injection checks evaluation, never fabricates sample bytes.
		if x.ID != id {
			x.SHA256 = SeptemberLibrarySHA256
		}
	}
	if r := Evaluate(c.o); r.Verdict != VerdictInfected {
		t.Fatalf("unmapped exact candidate hash lost: %+v", r)
	}
}
