package ddeirootkit

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

const maxObject = int64(64 << 20)
const maxText = int64(8 << 20)

type elfFacts struct {
	IsELF, HasInterpreter         bool
	DefinedHooks, DefinedTotal    int
	HookNames, HookCategories     []string
	ELFType                       string
	ELFClass, ELFMachine, ELFData string
}

var hookSymbols = map[string]bool{"stat": true, "stat64": true, "lstat": true, "lstat64": true, "xstat": true, "fxstat": true, "lxstat": true, "__lxstat": true, "statx": true, "fstatat": true, "newfstatat": true, "readdir": true, "readdir64": true, "fopen": true, "fopen64": true, "open": true, "open64": true, "access": true, "unlink": true, "unlinkat": true}
var inspectELF = realInspectELF

func looksLikeHookLib(f elfFacts) bool { return f.IsELF && f.DefinedHooks >= 2 }

type contextReader struct {
	ctx context.Context
	r   io.Reader
}
type contextReaderAt struct {
	ctx context.Context
	r   io.ReaderAt
}

func (r contextReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.ReadAt(p, off)
}

// Preflight section metadata before debug/elf can read a compressed string table.
// Extended section counts are deliberately unsupported and produce a coverage gap.
func preflightELF(raw io.ReaderAt, size int64) error {
	var hdr [64]byte
	n, err := raw.ReadAt(hdr[:], 0)
	if n < 52 {
		return fmt.Errorf("truncated ELF header: %w", err)
	}
	var order binary.ByteOrder
	switch hdr[5] {
	case 1:
		order = binary.LittleEndian
	case 2:
		order = binary.BigEndian
	default:
		return fmt.Errorf("invalid ELF byte order")
	}
	var off uint64
	var programOff uint64
	var programCount, programEntry uint16
	var count, entry, namesIndex uint16
	minimum := uint16(40)
	switch hdr[4] {
	case 1:
		off = uint64(order.Uint32(hdr[32:]))
		entry = order.Uint16(hdr[46:])
		count = order.Uint16(hdr[48:])
		namesIndex = order.Uint16(hdr[50:])
		programOff = uint64(order.Uint32(hdr[28:]))
		programEntry = order.Uint16(hdr[42:])
		programCount = order.Uint16(hdr[44:])
	case 2:
		if n < 64 {
			return fmt.Errorf("truncated ELF64 header")
		}
		off = order.Uint64(hdr[40:])
		entry = order.Uint16(hdr[58:])
		count = order.Uint16(hdr[60:])
		namesIndex = order.Uint16(hdr[62:])
		minimum = 64
		programOff = order.Uint64(hdr[32:])
		programEntry = order.Uint16(hdr[54:])
		programCount = order.Uint16(hdr[56:])
	default:
		return fmt.Errorf("invalid ELF class")
	}
	programMinimum := uint16(32)
	if minimum == 64 {
		programMinimum = 56
	}
	if programCount > 0 {
		if programEntry < programMinimum || programOff > uint64(size) || uint64(programCount)*uint64(programEntry) > uint64(size)-programOff {
			return fmt.Errorf("invalid ELF program table")
		}
		for i := uint64(0); i < uint64(programCount); i++ {
			var p [56]byte
			if _, err := raw.ReadAt(p[:programMinimum], int64(programOff+i*uint64(programEntry))); err != nil {
				return err
			}
			var position, length uint64
			if minimum == 64 {
				position = order.Uint64(p[8:])
				length = order.Uint64(p[32:])
			} else {
				position = uint64(order.Uint32(p[4:]))
				length = uint64(order.Uint32(p[16:]))
			}
			if position > uint64(size) || length > uint64(size)-position {
				return fmt.Errorf("ELF program outside file")
			}
			if elf.ProgType(order.Uint32(p[:])) == elf.PT_INTERP && (length == 0 || length > 4096) {
				return fmt.Errorf("invalid PT_INTERP size")
			}
		}
	}
	if off == 0 && count == 0 {
		return nil
	}
	if count == 0 || entry < minimum || off > uint64(size) || uint64(count)*uint64(entry) > uint64(size)-off {
		return fmt.Errorf("invalid or unsupported ELF section table")
	}
	for i := uint64(0); i < uint64(count); i++ {
		var h [64]byte
		if _, err := raw.ReadAt(h[:minimum], int64(off+i*uint64(entry))); err != nil {
			return err
		}
		typ := elf.SectionType(order.Uint32(h[4:]))
		var flags, position, length uint64
		if minimum == 64 {
			flags = order.Uint64(h[8:])
			position = order.Uint64(h[24:])
			length = order.Uint64(h[32:])
		} else {
			flags = uint64(order.Uint32(h[8:]))
			position = uint64(order.Uint32(h[16:]))
			length = uint64(order.Uint32(h[20:]))
		}
		// NewFile calls Data on the section-name table before returning. Other
		// compressed sections only have their fixed-size compression header read.
		if namesIndex != 0 && i == uint64(namesIndex) && elf.SectionFlag(flags)&elf.SHF_COMPRESSED != 0 {
			return fmt.Errorf("compressed ELF section name table")
		}
		if typ != elf.SHT_NOBITS && (position > uint64(size) || length > uint64(size)-position) {
			return fmt.Errorf("ELF section outside file")
		}
	}
	return nil
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
func readBounded(ctx context.Context, path string, limit int64) ([]byte, error) {
	f, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx, f}, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("read limit exceeded: %s", path)
	}
	return data, nil
}
func exported(s elf.Symbol) bool {
	bind := elf.ST_BIND(s.Info)
	visibility := elf.ST_VISIBILITY(s.Other)
	return s.Section != elf.SHN_UNDEF && (bind == elf.STB_GLOBAL || bind == elf.STB_WEAK) && (visibility == elf.STV_DEFAULT || visibility == elf.STV_PROTECTED)
}
func parseELF(raw io.ReaderAt, size int64) (elfFacts, error) {
	var facts elfFacts
	if size < 0 || size > maxObject {
		return facts, fmt.Errorf("invalid ELF input size")
	}
	var magic [4]byte
	if _, err := raw.ReadAt(magic[:], 0); err != nil {
		if size < 4 {
			return facts, nil
		}
		return facts, err
	}
	if string(magic[:]) != "\x7fELF" {
		return facts, nil
	}
	if err := preflightELF(raw, size); err != nil {
		return facts, err
	}
	f, err := elf.NewFile(io.NewSectionReader(raw, 0, size))
	if err != nil {
		return facts, err
	}
	defer f.Close()
	facts.IsELF = true
	facts.ELFType = f.Type.String()
	facts.ELFClass, facts.ELFMachine, facts.ELFData = f.Class.String(), f.Machine.String(), f.Data.String()
	for _, p := range f.Progs {
		if p.Off > uint64(size) || p.Filesz > uint64(size)-p.Off {
			return facts, fmt.Errorf("ELF segment outside file")
		}
		if p.Type == elf.PT_INTERP {
			if p.Filesz == 0 || p.Filesz > 4096 {
				return facts, fmt.Errorf("invalid PT_INTERP size")
			}
			buf := make([]byte, int(p.Filesz))
			if _, err := raw.ReadAt(buf, int64(p.Off)); err != nil {
				return facts, err
			}
			facts.HasInterpreter = len(strings.Trim(string(buf), "\x00 \t\r\n")) > 0
		}
	}
	for _, s := range f.Sections {
		if s.Type != elf.SHT_NOBITS && (s.Offset > uint64(size) || s.FileSize > uint64(size)-s.Offset) {
			return facts, fmt.Errorf("ELF section outside file")
		}
	}
	// DynamicSymbols reads the first DYNSYM, its linked string table and GNU
	// version sections. Never let those Data calls decompress untrusted input,
	// including the legacy name-triggered .zdebug path in Section.Open.
	if dyn := f.SectionByType(elf.SHT_DYNSYM); dyn != nil {
		if dyn.Link == 0 || uint64(dyn.Link) >= uint64(len(f.Sections)) || f.Sections[dyn.Link].Type != elf.SHT_STRTAB {
			return facts, fmt.Errorf("invalid ELF dynamic string table link")
		}
		consumed := []*elf.Section{dyn, f.Sections[dyn.Link]}
		if vs := f.SectionByType(elf.SHT_GNU_VERSYM); vs != nil {
			consumed = append(consumed, vs, f.SectionByType(elf.SHT_GNU_VERDEF), f.SectionByType(elf.SHT_GNU_VERNEED))
		}
		for _, s := range consumed {
			if s != nil && (s.Size > uint64(maxObject) || s.Flags&elf.SHF_COMPRESSED != 0 || strings.HasPrefix(s.Name, ".zdebug")) {
				return facts, fmt.Errorf("unsupported oversized/compressed ELF dynamic metadata")
			}
		}
	}
	syms, err := f.DynamicSymbols()
	if err == elf.ErrNoSymbols {
		return facts, nil
	}
	if err != nil {
		return facts, err
	}
	names, categories := map[string]bool{}, map[string]bool{}
	for _, s := range syms {
		if !exported(s) {
			continue
		}
		facts.DefinedTotal++
		if hookSymbols[s.Name] {
			names[s.Name] = true
			category := "file_access"
			if strings.Contains(s.Name, "stat") {
				category = "metadata"
			}
			if strings.HasPrefix(s.Name, "readdir") {
				category = "directory_enumeration"
			}
			if strings.HasPrefix(s.Name, "unlink") {
				category = "file_removal"
			}
			categories[category] = true
		}
	}
	for name := range names {
		facts.HookNames = append(facts.HookNames, name)
	}
	for category := range categories {
		facts.HookCategories = append(facts.HookCategories, category)
	}
	sort.Strings(facts.HookNames)
	sort.Strings(facts.HookCategories)
	facts.DefinedHooks = len(names)
	return facts, nil
}
func realInspectELF(path string) elfFacts {
	data, err := readBounded(context.Background(), path, maxObject)
	if err != nil {
		return elfFacts{}
	}
	facts, _ := parseELF(bytes.NewReader(data), int64(len(data)))
	return facts
}
func inspectObject(ctx context.Context, path string) (ObjectObservation, error) {
	f, err := openRegular(path)
	if err != nil {
		return ObjectObservation{}, err
	}
	defer f.Close()
	return inspectObjectFD(ctx, f)
}
func inspectObjectFD(ctx context.Context, f *os.File) (ObjectObservation, error) {
	var o ObjectObservation
	before, err := f.Stat()
	if err != nil {
		return o, err
	}
	if before.Size() > maxObject {
		return o, fmt.Errorf("object exceeds %d byte limit", maxObject)
	}
	// Hashing, preflight and parsing share this immutable bounded snapshot. Never
	// let debug/elf revisit mutable host bytes after validating section metadata.
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx, f}, maxObject+1))
	if err != nil {
		return o, err
	}
	n := int64(len(data))
	if n > maxObject {
		return o, fmt.Errorf("object grew beyond limit")
	}
	after, err := f.Stat()
	if err != nil {
		return o, err
	}
	if n != before.Size() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return o, fmt.Errorf("object changed during read")
	}
	if err := ctx.Err(); err != nil {
		return o, err
	}
	m, s := md5.Sum(data), sha256.Sum256(data)
	o.SHA256 = hex.EncodeToString(s[:])
	o.MD5 = hex.EncodeToString(m[:])
	o.Size = n
	o.ID = identityInfo(before, f.Name())
	facts, err := parseELF(contextReaderAt{ctx, bytes.NewReader(data)}, n)
	final, statErr := f.Stat()
	if statErr != nil {
		return ObjectObservation{}, statErr
	}
	if identityInfo(final, f.Name()) != o.ID {
		return ObjectObservation{}, fmt.Errorf("object changed during ELF inspection")
	}
	o.ELF = facts.IsELF && err == nil
	o.ValidELF = o.ELF
	if err != nil {
		o.ELFError = err.Error()
	}
	o.Hooks = facts.DefinedHooks
	o.Static = facts.IsELF && !facts.HasInterpreter
	o.HookNames = facts.HookNames
	o.HookCategories = facts.HookCategories
	o.ELFType = facts.ELFType
	o.ELFClass, o.ELFMachine, o.ELFData = facts.ELFClass, facts.ELFMachine, facts.ELFData
	return o, err
}
func hashFile(path string) (string, string) {
	o, err := inspectObject(context.Background(), path)
	if err != nil {
		return "", ""
	}
	return o.MD5, o.SHA256
}
func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.SplitN(line, "#", 2)[0]
		out = append(out, strings.FieldsFunc(line, func(r rune) bool { return r == ':' || r == ' ' || r == '\t' || r == '\r' })...)
	}
	return out
}
