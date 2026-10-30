//go:build linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os/exec"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lookupSymbols must return exactly the entries debug/elf decodes for the
// requested names: a wrong entry places a uprobe at a wrong offset. The Go
// fixture carries a .symtab and the dynamically linked shell a .dynsym.
func TestLookupSymbolsMatchesDebugELF(t *testing.T) {
	files := map[string]*elf.File{"go fixture": openSymbolFixtureELF(t)}

	if sh, err := exec.LookPath("sh"); err == nil {
		f, err := elf.Open(sh)
		require.NoError(t, err)
		files["sh"] = f
	}

	compared := 0

	for label, f := range files {
		defer f.Close()

		for _, typ := range []elf.SectionType{elf.SHT_SYMTAB, elf.SHT_DYNSYM} {
			all, err := decodeAllSymbols(f, typ)
			if errors.Is(err, elf.ErrNoSymbols) {
				continue
			}
			require.NoError(t, err)

			names := sampleSymbolNames(all)
			names = append(names, "obi.symbol.that.does.not.exist")

			got, err := lookupSymbols(f, typ, names)
			require.NoError(t, err)

			assert.Equal(t, symbolsNamed(all, names), got, "%s %v", label, typ)
			compared++
		}
	}

	require.NotZero(t, compared, "no symbol table to compare against")
}

func TestLookupSymbolsMergedSuffix(t *testing.T) {
	// The linker stored "SSL_read" as the tail of "BIO_SSL_read".
	strtab := []byte("\x00BIO_SSL_read\x00SSL_write\x00")
	symbols := []testSymbol{
		{name: 1, info: funcInfo, value: 0x1000, size: 0x10},
		{name: 5, info: funcInfo, value: 0x2000, size: 0x20},
		{name: 14, info: funcInfo, value: 0x3000, size: 0x30},
	}

	for _, class := range []elf.Class{elf.ELFCLASS64, elf.ELFCLASS32} {
		t.Run(class.String(), func(t *testing.T) {
			f := newTestELF(t, class, strtab, symbols)

			all, err := f.Symbols()
			require.NoError(t, err)
			require.Equal(t, "SSL_read", all[1].Name)

			for _, names := range [][]string{
				{"SSL_read"},
				{"BIO_SSL_read"},
				{"SSL_read", "BIO_SSL_read", "SSL_write"},
				{"read", "SSL_"},
			} {
				got, err := lookupSymbols(f, elf.SHT_SYMTAB, names)
				require.NoError(t, err)

				assert.Equal(t, symbolsNamed(stripVersions(all), names), got, "names %v", names)
			}
		})
	}
}

func TestLookupSymbolsErrors(t *testing.T) {
	f := newTestELF(t, elf.ELFCLASS64, []byte("\x00SSL_read\x00"), []testSymbol{{name: 1, info: funcInfo}})

	_, err := lookupSymbols(f, elf.SHT_DYNSYM, []string{"SSL_read"})
	require.ErrorIs(t, err, elf.ErrNoSymbols)

	f.Sections[1].Size--
	_, err = lookupSymbols(f, elf.SHT_SYMTAB, []string{"SSL_read"})
	require.Error(t, err)

	f.Sections[1].Size++
	f.Sections[1].Link = uint32(len(f.Sections))
	_, err = lookupSymbols(f, elf.SHT_SYMTAB, []string{"SSL_read"})
	require.Error(t, err)
}

func TestFindNameOffsetsAcrossChunks(t *testing.T) {
	strtab := []byte("\x00SSL_read\x00BIO_SSL_read\x00SSL_read_ex\x00x\x00SSL_write\x00SSL_read\x00")
	names := []string{"SSL_read", "SSL_write", "x", "missing", ""}

	want := map[uint32]string{}
	for _, name := range names[:len(names)-1] {
		pattern := append([]byte(name), 0)
		for i := range len(strtab) - len(pattern) + 1 {
			if bytes.Equal(strtab[i:i+len(pattern)], pattern) {
				want[uint32(i)] = name
			}
		}
	}
	require.Len(t, want, 6)

	for chunkSize := 1; chunkSize <= len(strtab)+1; chunkSize++ {
		got, err := findNameOffsets(bytes.NewReader(strtab), names, chunkSize)
		require.NoError(t, err)
		assert.Equal(t, want, got, "chunk size %d", chunkSize)
	}
}

const funcInfo = byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC)

type testSymbol struct {
	name        uint32
	info        byte
	value, size uint64
}

// newTestELF builds an ELF file whose only symbol table is a .symtab of
// symbols, with their names in strtab.
func newTestELF(t *testing.T, class elf.Class, strtab []byte, symbols []testSymbol) *elf.File {
	t.Helper()

	const (
		symtabIndex   = 1
		strtabIndex   = 2
		shstrtabIndex = 3
		sectionCount  = 4
	)

	shstrtab := []byte("\x00.symtab\x00.strtab\x00.shstrtab\x00")
	symtabName, strtabName, shstrtabName := uint32(1), uint32(9), uint32(17)

	var symtab bytes.Buffer
	writeLE(t, &symtab, symbolEntry(class, testSymbol{}))
	for _, s := range symbols {
		writeLE(t, &symtab, symbolEntry(class, s))
	}

	headerSize := uint64(binary.Size(elfHeader(class, 0, 0)))
	symtabOff := headerSize
	strtabOff := symtabOff + uint64(symtab.Len())
	shstrtabOff := strtabOff + uint64(len(strtab))
	sectionsOff := shstrtabOff + uint64(len(shstrtab))
	entrySize, err := symbolEntrySize(class)
	require.NoError(t, err)

	var file bytes.Buffer
	writeLE(t, &file, elfHeader(class, sectionsOff, sectionCount))
	file.Write(symtab.Bytes())
	file.Write(strtab)
	file.Write(shstrtab)

	writeLE(t, &file, sectionHeader(class, elf.Section64{}))
	writeLE(t, &file, sectionHeader(class, elf.Section64{
		Name: symtabName, Type: uint32(elf.SHT_SYMTAB), Off: symtabOff, Size: uint64(symtab.Len()),
		Link: strtabIndex, Entsize: entrySize,
	}))
	writeLE(t, &file, sectionHeader(class, elf.Section64{
		Name: strtabName, Type: uint32(elf.SHT_STRTAB), Off: strtabOff, Size: uint64(len(strtab)),
	}))
	writeLE(t, &file, sectionHeader(class, elf.Section64{
		Name: shstrtabName, Type: uint32(elf.SHT_STRTAB), Off: shstrtabOff, Size: uint64(len(shstrtab)),
	}))

	f, err := elf.NewFile(bytes.NewReader(file.Bytes()))
	require.NoError(t, err)
	require.Equal(t, ".symtab", f.Sections[symtabIndex].Name)
	require.Equal(t, ".shstrtab", f.Sections[shstrtabIndex].Name)

	return f
}

func elfHeader(class elf.Class, sectionsOff uint64, sectionCount uint16) any {
	ident := [elf.EI_NIDENT]byte{0x7f, 'E', 'L', 'F', byte(class), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)}
	shstrndx := sectionCount - 1

	if class == elf.ELFCLASS32 {
		return elf.Header32{
			Ident: ident, Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_386), Version: uint32(elf.EV_CURRENT),
			Shoff: uint32(sectionsOff), Ehsize: uint16(binary.Size(elf.Header32{})),
			Shentsize: uint16(binary.Size(elf.Section32{})), Shnum: sectionCount, Shstrndx: shstrndx,
		}
	}

	return elf.Header64{
		Ident: ident, Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT),
		Shoff: sectionsOff, Ehsize: uint16(binary.Size(elf.Header64{})),
		Shentsize: uint16(binary.Size(elf.Section64{})), Shnum: sectionCount, Shstrndx: shstrndx,
	}
}

func sectionHeader(class elf.Class, s elf.Section64) any {
	if class == elf.ELFCLASS32 {
		return elf.Section32{
			Name: s.Name, Type: s.Type, Off: uint32(s.Off), Size: uint32(s.Size), Link: s.Link, Entsize: uint32(s.Entsize),
		}
	}

	return s
}

func symbolEntry(class elf.Class, s testSymbol) any {
	const section = 1

	if class == elf.ELFCLASS32 {
		return elf.Sym32{Name: s.name, Info: s.info, Shndx: section, Value: uint32(s.value), Size: uint32(s.size)}
	}

	return elf.Sym64{Name: s.name, Info: s.info, Shndx: section, Value: s.value, Size: s.size}
}

func writeLE(t *testing.T, buf *bytes.Buffer, v any) {
	t.Helper()
	require.NoError(t, binary.Write(buf, binary.LittleEndian, v))
}

func decodeAllSymbols(f *elf.File, typ elf.SectionType) ([]elf.Symbol, error) {
	var symbols []elf.Symbol
	var err error

	if typ == elf.SHT_DYNSYM {
		symbols, err = f.DynamicSymbols()
	} else {
		symbols, err = f.Symbols()
	}

	return stripVersions(symbols), err
}

// stripVersions drops the .dynsym version fields, which lookupSymbols does not
// decode and FindExeSymbols does not use.
func stripVersions(symbols []elf.Symbol) []elf.Symbol {
	stripped := make([]elf.Symbol, len(symbols))
	for i, s := range symbols {
		stripped[i] = elf.Symbol{Name: s.Name, Info: s.Info, Other: s.Other, Section: s.Section, Value: s.Value, Size: s.Size}
	}

	return stripped
}

// sampleSymbolNames picks a few hundred names spread over the table, including
// duplicated ones, so the comparison stays fast on a large test binary.
func sampleSymbolNames(symbols []elf.Symbol) []string {
	const maxNames = 300

	step := max(1, len(symbols)/maxNames)
	var names []string

	for i := 0; i < len(symbols); i += step {
		if symbols[i].Name != "" && !slices.Contains(names, symbols[i].Name) {
			names = append(names, symbols[i].Name)
		}
	}

	return names
}

func symbolsNamed(symbols []elf.Symbol, names []string) []elf.Symbol {
	var named []elf.Symbol

	for _, s := range symbols {
		if slices.Contains(names, s.Name) {
			named = append(named, s)
		}
	}

	return named
}
