package gho

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// Fixup mode constants for ModifyHeader.
const (
	FixupCD    = "cd"   // Set spanned bit at file offset 584
	FixupCDOff = "cd-"  // Clear spanned bit at file offset 584
	FixupSpan  = "span" // Toggle CD flag at header offset 55
)

// ghofixup PRNG constants (reversed from Norton Ghost ghofixup.exe)
const (
	fixupPRNGSeed = 0xFA08FD9E
	fixupExtended = 1024 // Extended header area (covers byte 584)
)

// ModifyHeader modifies a GHO file's header flags, replicating the
// functionality of Norton Ghost's ghofixup.exe utility.
//
// Modes:
//   - "cd": Set the spanned/CD bit at file offset 584
//   - "cd-": Clear the spanned/CD bit at file offset 584
//   - "span": Toggle the CD flag byte at header offset 55
//
// The header is decrypted, modified, and re-encrypted using the Ghost PRNG cipher.
// Only the necessary portion of the file is read and written back.
//
// Reversed from ghofixup.exe (PDB: c:\depot\ghost\gsstrunk\ghost\utilityapps\ghofixup\).
func ModifyHeader(path string, mode string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("gho fixup: open: %w", err)
	}
	defer f.Close()

	// Determine how much we need to read
	readSize := fixupExtended
	if mode == FixupSpan {
		readSize = HeaderSize // Only need first 512 bytes for span toggle
	}

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("gho fixup: stat: %w", err)
	}
	if fi.Size() < int64(readSize) {
		return fmt.Errorf("gho fixup: file too small (%d bytes)", fi.Size())
	}

	data := make([]byte, readSize)
	if _, err := io.ReadFull(f, data); err != nil {
		return fmt.Errorf("gho fixup: read: %w", err)
	}

	// Verify magic
	magic := binary.LittleEndian.Uint16(data[0:2])
	if magic != FileMagic {
		return fmt.Errorf("gho fixup: not a GHO file (magic %#04x)", magic)
	}

	// Decrypt the entire region we read
	decryptHeader(data)

	// Apply modification
	switch mode {
	case FixupCD:
		data[584] |= 0x01
	case FixupCDOff:
		data[584] &^= 0x01
	case FixupSpan:
		data[55] ^= 0x01
	default:
		return fmt.Errorf("gho fixup: unknown mode %q (use %q, %q, or %q)",
			mode, FixupCD, FixupCDOff, FixupSpan)
	}

	// Re-encrypt
	encryptHeader(data)

	// Write back only what we changed
	if _, err := f.WriteAt(data, 0); err != nil {
		return fmt.Errorf("gho fixup: write: %w", err)
	}
	return nil
}

// fixupPRNG implements the Ghost header cipher PRNG.
//
// Algorithm (reversed from sub_406CF5):
//
//	state starts at seed (0xFA08FD9E)
//	each step: state += ROR(state, 7)
//	key = state & 7 (rotation amount for 16-bit word cipher)
type fixupPRNG struct {
	state uint32
}

func newFixupPRNG() *fixupPRNG {
	return &fixupPRNG{state: fixupPRNGSeed}
}

func (p *fixupPRNG) next() uint32 {
	rotated := (p.state >> 7) | (p.state << (32 - 7))
	p.state += rotated
	return p.state
}

// decryptHeader decrypts a GHO header region in-place.
// The cipher operates on 16-bit words, rotating each by (prng & 7) bits.
// hdr can be any length (512, 1024, etc.) — the PRNG is deterministic.
func decryptHeader(hdr []byte) {
	p := newFixupPRNG()
	for i := 2; i+1 < len(hdr); i += 2 {
		key := p.next() & 7
		word := binary.LittleEndian.Uint16(hdr[i : i+2])
		word = (word << key) | (word >> (16 - key))
		binary.LittleEndian.PutUint16(hdr[i:i+2], word)
	}
}

// encryptHeader encrypts a GHO header region in-place.
func encryptHeader(hdr []byte) {
	p := newFixupPRNG()
	for i := 2; i+1 < len(hdr); i += 2 {
		key := p.next() & 7
		word := binary.LittleEndian.Uint16(hdr[i : i+2])
		word = (word >> key) | (word << (16 - key))
		binary.LittleEndian.PutUint16(hdr[i:i+2], word)
	}
}
