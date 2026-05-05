package gho

import (
	"encoding/binary"
	"fmt"
	"os"
)

// Fixup mode constants for ModifyHeader.
const (
	FixupCD     = "cd"     // Set spanned bit at header offset 584
	FixupCDOff  = "cd-"    // Clear spanned bit at header offset 584
	FixupSpan   = "span"   // Toggle CD flag at header offset 55
)

// ghofixup PRNG constants (reversed from Norton Ghost ghofixup.exe)
const (
	fixupPRNGSeed = 0xFA08FD9E
)

// ModifyHeader modifies a GHO file's header flags, replicating the
// functionality of Norton Ghost's ghofixup.exe utility.
//
// Modes:
//   - "cd": Set the spanned/CD bit at header offset 584
//   - "cd-": Clear the spanned/CD bit at header offset 584
//   - "span": Toggle the CD flag byte at header offset 55
//
// The header is re-encrypted after modification using the Ghost PRNG cipher.
//
// Reversed from ghofixup.exe (PDB: c:\depot\ghost\gsstrunk\ghost\utilityapps\ghofixup\).
func ModifyHeader(path string, mode string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("gho fixup: read: %w", err)
	}
	if len(data) < HeaderSize {
		return fmt.Errorf("gho fixup: file too small (%d bytes)", len(data))
	}

	// Verify magic
	magic := binary.LittleEndian.Uint16(data[0:2])
	if magic != FileMagic {
		return fmt.Errorf("gho fixup: not a GHO file (magic %#04x)", magic)
	}

	// Decrypt header
	decryptHeader(data[:HeaderSize])

	// Apply modification
	switch mode {
	case FixupCD:
		// Set spanned bit at offset 584 (within the 512-byte header area,
		// but Ghost uses extended header space)
		if len(data) > 584 {
			data[584] |= 0x01
		}
	case FixupCDOff:
		if len(data) > 584 {
			data[584] &^= 0x01
		}
	case FixupSpan:
		// Toggle CD flag at offset 55
		data[55] ^= 0x01
	default:
		return fmt.Errorf("gho fixup: unknown mode %q (use %q, %q, or %q)",
			mode, FixupCD, FixupCDOff, FixupSpan)
	}

	// Re-encrypt header
	encryptHeader(data[:HeaderSize])

	// Write back
	if err := os.WriteFile(path, data, 0644); err != nil {
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
	// ROR(state, 7): rotate right by 7 bits
	rotated := (p.state >> 7) | (p.state << (32 - 7))
	p.state += rotated
	return p.state
}

// decryptHeader decrypts a GHO file header in-place.
// The cipher operates on 16-bit words, rotating each by (prng & 7) bits.
func decryptHeader(hdr []byte) {
	p := newFixupPRNG()
	// Process 16-bit words (skip first 2 bytes = magic)
	for i := 2; i+1 < len(hdr); i += 2 {
		key := p.next() & 7
		word := binary.LittleEndian.Uint16(hdr[i : i+2])
		// Reverse rotation: rotate left by key to decrypt
		word = (word << key) | (word >> (16 - key))
		binary.LittleEndian.PutUint16(hdr[i:i+2], word)
	}
}

// encryptHeader encrypts a GHO file header in-place.
func encryptHeader(hdr []byte) {
	p := newFixupPRNG()
	for i := 2; i+1 < len(hdr); i += 2 {
		key := p.next() & 7
		word := binary.LittleEndian.Uint16(hdr[i : i+2])
		// Rotate right by key to encrypt
		word = (word >> key) | (word << (16 - key))
		binary.LittleEndian.PutUint16(hdr[i:i+2], word)
	}
}
