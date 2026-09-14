package ddeirootkit

import (
	"bytes"
	"compress/zlib"
	"debug/elf"
	"encoding/binary"
	"strings"
	"testing"
)

type compatSection struct {
	name  string
	typ   elf.SectionType
	flags elf.SectionFlag
	data  []byte
	size  uint64
	link  uint32
}

func compatELF(t *testing.T, class32 bool, order binary.ByteOrder, sections []compatSection) []byte {
	t.Helper()
	headerSize, sectionSize := 64, 64
	if class32 {
		headerSize, sectionSize = 52, 40
	}
	b := make([]byte, headerSize)
	copy(b, "\x7fELF")
	b[4], b[5], b[6] = 2, 1, 1
	if class32 {
		b[4] = 1
	}
	if order == binary.BigEndian {
		b[5] = 2
	}
	order.PutUint16(b[16:], uint16(elf.ET_DYN))
	order.PutUint16(b[18:], uint16(elf.EM_X86_64))
	order.PutUint32(b[20:], 1)
	names := []byte{0}
	nameOffsets := make([]uint32, len(sections))
	for i, s := range sections {
		nameOffsets[i] = uint32(len(names))
		names = append(names, s.name...)
		names = append(names, 0)
	}
	sections[1].data = names
	offsets := make([]uint64, len(sections))
	for i, s := range sections {
		offsets[i] = uint64(len(b))
		b = append(b, s.data...)
	}
	shoff := len(b)
	if class32 {
		order.PutUint32(b[32:], uint32(shoff))
		order.PutUint16(b[40:], uint16(headerSize))
		order.PutUint16(b[46:], uint16(sectionSize))
		order.PutUint16(b[48:], uint16(len(sections)))
		order.PutUint16(b[50:], 1)
	} else {
		order.PutUint64(b[40:], uint64(shoff))
		order.PutUint16(b[52:], uint16(headerSize))
		order.PutUint16(b[58:], uint16(sectionSize))
		order.PutUint16(b[60:], uint16(len(sections)))
		order.PutUint16(b[62:], 1)
	}
	for i, s := range sections {
		h := make([]byte, sectionSize)
		order.PutUint32(h, nameOffsets[i])
		order.PutUint32(h[4:], uint32(s.typ))
		size := s.size
		if size == 0 {
			size = uint64(len(s.data))
		}
		if class32 {
			order.PutUint32(h[8:], uint32(s.flags))
			order.PutUint32(h[16:], uint32(offsets[i]))
			order.PutUint32(h[20:], uint32(size))
			order.PutUint32(h[24:], s.link)
		} else {
			order.PutUint64(h[8:], uint64(s.flags))
			order.PutUint64(h[24:], offsets[i])
			order.PutUint64(h[32:], size)
			order.PutUint32(h[40:], s.link)
		}
		b = append(b, h...)
	}
	return b
}

func TestELFSectionCompatibility(t *testing.T) {
	for _, class32 := range []bool{false, true} {
		for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			for _, scenario := range []string{"huge-nobits", "compressed-debug", "legacy-debug", "unused-strtab", "huge-debug-header", "compressed-shstrtab", "compressed-dynsym", "compressed-dynstr", "compressed-versym", "compressed-verdef", "compressed-verneed", "legacy-dynsym", "legacy-dynstr", "legacy-versym", "legacy-verdef", "legacy-verneed", "bad-link", "wrong-link-type", "outside-file"} {
				t.Run(scenario+"/"+order.String()+map[bool]string{true: "/32", false: "/64"}[class32], func(t *testing.T) {
					symSize, chSize := 24, 24
					if class32 {
						symSize, chSize = 16, 12
					}
					syms := make([]byte, 3*symSize)
					for i, name := range []uint32{1, 6} {
						row := syms[(i+1)*symSize:]
						order.PutUint32(row, name)
						if class32 {
							row[12] = byte(elf.STB_GLOBAL) << 4
							order.PutUint16(row[14:], 4)
						} else {
							row[4] = byte(elf.STB_GLOBAL) << 4
							order.PutUint16(row[6:], 4)
						}
					}
					compressed := make([]byte, chSize)
					order.PutUint32(compressed, uint32(elf.COMPRESS_ZLIB))
					if class32 {
						order.PutUint32(compressed[4:], 5)
					} else {
						order.PutUint64(compressed[8:], 5)
					}
					var zipped bytes.Buffer
					zw := zlib.NewWriter(&zipped)
					if _, err := zw.Write([]byte("debug")); err != nil {
						t.Fatal(err)
					}
					if err := zw.Close(); err != nil {
						t.Fatal(err)
					}
					compressed = append(compressed, zipped.Bytes()...)
					legacy := append([]byte("ZLIB"), make([]byte, 8)...)
					binary.BigEndian.PutUint64(legacy[4:], ^uint64(0))
					legacy = append(legacy, zipped.Bytes()...)
					sections := []compatSection{
						{}, {name: ".shstrtab", typ: elf.SHT_STRTAB},
						{name: ".dynstr", typ: elf.SHT_STRTAB, data: []byte("\x00open\x00unlink\x00")},
						{name: ".dynsym", typ: elf.SHT_DYNSYM, data: syms, link: 2},
						{name: ".bss", typ: elf.SHT_NOBITS, size: 1},
						{name: ".gnu.version", typ: elf.SHT_GNU_VERSYM, data: make([]byte, 6)},
						{name: ".gnu.version_d", typ: elf.SHT_GNU_VERDEF},
						{name: ".gnu.version_r", typ: elf.SHT_GNU_VERNEED},
						{name: ".debug_info", typ: elf.SHT_PROGBITS, flags: elf.SHF_COMPRESSED, data: compressed},
					}
					wantError := ""
					switch scenario {
					case "huge-nobits":
						sections[4].size = 1 << 30
					case "compressed-debug":
					case "legacy-debug":
						sections[8].name, sections[8].flags, sections[8].data = ".zdebug_info", 0, legacy
					case "unused-strtab":
						sections[8].typ = elf.SHT_STRTAB
					case "huge-debug-header":
						if class32 {
							order.PutUint32(compressed[4:], ^uint32(0))
						} else {
							order.PutUint64(compressed[8:], ^uint64(0))
						}
					case "compressed-shstrtab":
						sections[1].flags = elf.SHF_COMPRESSED
						wantError = "compressed ELF section name table"
					case "bad-link":
						sections[3].link = 100
						wantError = "dynamic string table link"
					case "wrong-link-type":
						sections[3].link = 4
						wantError = "dynamic string table link"
					case "outside-file":
						sections[8].size = uint64(maxObject) + 1
						wantError = "outside file"
					default:
						parts := strings.SplitN(scenario, "-", 2)
						idx := map[string]int{"dynsym": 3, "dynstr": 2, "versym": 5, "verdef": 6, "verneed": 7}[parts[1]]
						if parts[0] == "legacy" {
							sections[idx].name, sections[idx].data = ".zdebug_metadata", legacy
						} else {
							sections[idx].flags, sections[idx].data = elf.SHF_COMPRESSED, compressed
						}
						wantError = "compressed ELF dynamic metadata"
					}
					b := compatELF(t, class32, order, sections)
					if scenario == "compressed-shstrtab" {
						// The name table is the first payload. Give it a real
						// compression header advertising a hostile decoded size.
						headerSize := 64
						if class32 {
							headerSize = 52
							order.PutUint32(compressed[4:], ^uint32(0))
						} else {
							order.PutUint64(compressed[8:], ^uint64(0))
						}
						copy(b[headerSize:], compressed)
						if err := preflightELF(bytes.NewReader(b), int64(len(b))); err == nil || !strings.Contains(err.Error(), wantError) {
							t.Fatalf("unsafe name table passed preflight: %v", err)
						}
					}
					facts, err := parseELF(bytes.NewReader(b), int64(len(b)))
					if wantError != "" {
						if err == nil || !strings.Contains(err.Error(), wantError) {
							t.Fatalf("want %q, got facts=%+v err=%v", wantError, facts, err)
						}
						return
					}
					if err != nil || !facts.IsELF || facts.DefinedHooks != 2 || facts.DefinedTotal != 2 || strings.Join(facts.HookNames, ",") != "open,unlink" {
						t.Fatalf("facts=%+v err=%v", facts, err)
					}
				})
			}
		}
	}
}
