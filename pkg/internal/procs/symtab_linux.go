// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"bufio"
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"math"
)

// sectionChunkSize bounds the memory used to read a symbol or string table.
// Large statically linked executables carry tables of more than 100 MiB, which
// are never loaded whole.
const sectionChunkSize = 1 << 20

// lookupSymbols returns the entries of the typ symbol table (SHT_SYMTAB or
// SHT_DYNSYM) whose name is one of names. It yields the same entries as
// elf.File.Symbols and elf.File.DynamicSymbols, without their version fields,
// but streams both the symbol and the string table instead of decoding every
// entry, so its memory use does not grow with the size of the executable.
func lookupSymbols(f *elf.File, typ elf.SectionType, names []string) ([]elf.Symbol, error) {
	symtab := f.SectionByType(typ)
	if symtab == nil || symtab.Size == 0 {
		return nil, elf.ErrNoSymbols
	}

	entrySize, err := symbolEntrySize(f.Class)
	if err != nil {
		return nil, err
	}

	if symtab.Size%entrySize != 0 {
		return nil, errors.New("length of symbol section is not a multiple of the symbol entry size")
	}

	if symtab.Link == 0 || symtab.Link >= uint32(len(f.Sections)) {
		return nil, errors.New("section has invalid string table link")
	}

	strtab := f.Sections[symtab.Link]

	nameOffsets, err := findNameOffsets(sectionReader(strtab), names, sectionChunkSize)
	if err != nil {
		return nil, fmt.Errorf("cannot read string table section: %w", err)
	}

	if len(nameOffsets) == 0 {
		return nil, nil
	}

	symbols, err := readNamedSymbols(f, sectionReader(symtab), entrySize, nameOffsets)
	if err != nil {
		return nil, fmt.Errorf("cannot read symbol section: %w", err)
	}

	return symbols, nil
}

func symbolEntrySize(class elf.Class) (uint64, error) {
	switch class {
	case elf.ELFCLASS64:
		return elf.Sym64Size, nil
	case elf.ELFCLASS32:
		return elf.Sym32Size, nil
	}

	return 0, fmt.Errorf("unsupported ELF class %v", class)
}

// sectionReader reads exactly the section contents, as elf.Section.Data does.
// elf.Section.Open alone may read past the end of an uncompressed section.
func sectionReader(s *elf.Section) io.Reader {
	return io.LimitReader(s.Open(), int64(s.Size))
}

// findNameOffsets returns the string table offset of every occurrence of a
// NUL-terminated name. Linkers merge string table suffixes, so a symbol name may
// start in the middle of a longer string: searching for "<name>\x00" anywhere
// finds those occurrences too. The table is read in chunks of chunkSize bytes
// that overlap by the longest pattern, so matches across chunks are not missed.
func findNameOffsets(strtab io.Reader, names []string, chunkSize int) (map[uint32]string, error) {
	patterns := make(map[string][]byte, len(names))
	longest := 0

	for _, name := range names {
		// An empty name would match every NUL byte of the table.
		if name == "" {
			continue
		}

		patterns[name] = append([]byte(name), 0)
		longest = max(longest, len(name)+1)
	}

	offsets := map[uint32]string{}
	if len(patterns) == 0 {
		return offsets, nil
	}

	// The last overlap bytes of a chunk may hold the beginning of a match that
	// ends in the next chunk, so they are searched again as part of it.
	overlap := longest - 1
	buf := make([]byte, overlap+chunkSize)
	carried := 0
	var windowStart uint64

	for {
		n, err := io.ReadFull(strtab, buf[carried:])
		isLast := errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)

		if err != nil && !isLast {
			return nil, err
		}

		window := buf[:carried+n]

		searchEnd := len(window)
		if !isLast {
			searchEnd -= overlap
		}

		for name, pattern := range patterns {
			addPatternOffsets(offsets, window, pattern, searchEnd, windowStart, name)
		}

		if isLast {
			return offsets, nil
		}

		carried = copy(buf, window[searchEnd:])
		windowStart += uint64(searchEnd)
	}
}

// addPatternOffsets records every occurrence of pattern in window that starts
// before searchEnd.
func addPatternOffsets(offsets map[uint32]string, window, pattern []byte, searchEnd int, windowStart uint64, name string) {
	for start := 0; start < searchEnd; {
		idx := bytes.Index(window[start:], pattern)
		if idx < 0 || start+idx >= searchEnd {
			return
		}

		offset := windowStart + uint64(start+idx)
		if offset > math.MaxUint32 {
			// st_name is 32 bits wide, no symbol can reference this offset.
			return
		}

		offsets[uint32(offset)] = name
		start += idx + 1
	}
}

// readNamedSymbols streams a symbol table and decodes only the entries whose
// st_name is one of nameOffsets. The leading null entry is skipped, as
// elf.File.Symbols does.
func readNamedSymbols(f *elf.File, symtab io.Reader, entrySize uint64, nameOffsets map[uint32]string) ([]elf.Symbol, error) {
	r := bufio.NewReaderSize(symtab, sectionChunkSize)
	entry := make([]byte, entrySize)

	if _, err := io.ReadFull(r, entry); err != nil {
		return nil, err
	}

	var symbols []elf.Symbol

	for {
		_, err := io.ReadFull(r, entry)
		if errors.Is(err, io.EOF) {
			return symbols, nil
		}

		if err != nil {
			return nil, err
		}

		name, ok := nameOffsets[f.ByteOrder.Uint32(entry[0:4])]
		if !ok {
			continue
		}

		symbol := decodeSymbol(f, entry)
		symbol.Name = name
		symbols = append(symbols, symbol)
	}
}

// decodeSymbol decodes everything but the name of a raw symbol table entry,
// with the layout of elf.Sym64 or elf.Sym32.
func decodeSymbol(f *elf.File, entry []byte) elf.Symbol {
	if f.Class == elf.ELFCLASS32 {
		return elf.Symbol{
			Value:   uint64(f.ByteOrder.Uint32(entry[4:8])),
			Size:    uint64(f.ByteOrder.Uint32(entry[8:12])),
			Info:    entry[12],
			Other:   entry[13],
			Section: elf.SectionIndex(f.ByteOrder.Uint16(entry[14:16])),
		}
	}

	return elf.Symbol{
		Info:    entry[4],
		Other:   entry[5],
		Section: elf.SectionIndex(f.ByteOrder.Uint16(entry[6:8])),
		Value:   f.ByteOrder.Uint64(entry[8:16]),
		Size:    f.ByteOrder.Uint64(entry[16:24]),
	}
}
