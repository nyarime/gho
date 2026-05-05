// Package gho implements Norton Ghost GHO image format parsing.
//
// GHO files contain disk/partition images created by Symantec Ghost (versions 11.x-12.x).
// The format supports Fast LZ (Z1), High/zlib (Z2-Z9), and no compression modes,
// with optional CRC-16 stream cipher encryption.
//
// File structure:
//
//	[512B File Header (FE EF 01 02)]
//	[Record type 6: Track 0 / MBR data]
//	[Record type 0x0603: Partition descriptor (20B body)]
//	[512B FEEF Partition Header (FE EF 02 02)]
//	[Compressed blocks: 2B stored_len + block_data]
//	[Record type 0x0703: Continuation (20B body)]
//	[512B FEEF Header]
//	[More compressed blocks...]
//	[Record type 0x23: End record (24B body)]
//
// Compressed block format:
//
//	stored_len = LE uint16 (includes the 2-byte length field itself)
//	comp_len = stored_len - 2
//	block_data[0] == 1: uncompressed, output = block_data[4:comp_len]
//	block_data[0] != 1: Fast LZ compressed
//
// Record format:
//
//	[4B type (LE uint32, low 16 = type code, high 16 = flags)]
//	[4B magic (0x012F18D8)]
//	[2B body_len (LE uint16)]
//	[body_len bytes body]
package gho

import (
	"encoding/binary"
	"errors"
)

const (
	// FileMagic is the first 2 bytes of GHO file header and FEEF partition header.
	FileMagic = 0xEFFE

	// RecordMagic appears at offset 4 in every record header.
	RecordMagic = 0x012F18D8

	// HeaderSize is the size of file header and FEEF partition header.
	HeaderSize = 512

	// RecordHeaderSize is the fixed size of a record header.
	RecordHeaderSize = 10

	// BlockSize is the default decompressed block size.
	BlockSize = 32768

	// MaxStoredLen is the maximum valid stored length for a block.
	MaxStoredLen = 33002 // BlockSize + 4 (uncompressed header) + 2 (stored_len)

	// FastLZHashSize is the hash table size for Fast LZ.
	FastLZHashSize = 4096
)

// Record types (low 16 bits of the type field).
const (
	RecordTypeTrack0          = 0x0006 // Track 0 / MBR data
	RecordTypePartition       = 0x0603 // Partition descriptor
	RecordTypeContinuation    = 0x0703 // Partition data continuation
	RecordTypeEnd             = 0x0023 // End of image
)

// Compression types (byte 3 of file header).
const (
	CompressionNone   = 0
	CompressionOld    = 1 // Not supported
	CompressionFast   = 2 // Fast LZ (Z1)
	CompressionHigh3  = 3 // High compression (Z3, zlib)
	CompressionHigh4  = 4
	CompressionHigh5  = 5
	CompressionHigh6  = 6
	CompressionHigh7  = 7
	CompressionHigh8  = 8
	CompressionHigh9  = 9
)

// Track0Header is the 6-byte mini-header before the actual MBR in Track 0 data.
type Track0Header struct {
	Unknown1 byte   // Usually 0x06
	Sectors  byte   // Sectors per track (e.g., 126)
	Unknown2 uint32 // Usually 0
}

// FileHeader represents the 512-byte GHO file header.
type FileHeader struct {
	Magic           uint16   // 0xEFFE
	FileType        byte     // 0x01=first file, 0x09=span file
	Compression     byte     // Compression type (0-9)
	ID              uint32   // CRC/timestamp identifier
	Flags           [3]byte  // bytes 8-10
	Raw             [512]byte // Full raw header
}

// PartitionHeader represents the 512-byte FEEF partition header.
type PartitionHeader struct {
	Magic       uint16
	SubType     byte
	Compression byte
	ID          uint32
	Flags       [3]byte
	Raw         [512]byte
}

// Record represents a GHO record header.
type Record struct {
	Type    uint32 // Full type (low 16 = type code, high 16 = flags)
	Magic   uint32 // Should be RecordMagic
	BodyLen uint16
	Offset  int64  // File offset of this record
}

// TypeCode returns the record type code (low 16 bits).
func (r Record) TypeCode() uint16 {
	return uint16(r.Type & 0xFFFF)
}

// MBRPartitionEntry represents a single MBR partition table entry.
type MBRPartitionEntry struct {
	Status   byte
	CHSStart [3]byte
	Type     byte
	CHSEnd   [3]byte
	LBAStart uint32
	LBASize  uint32
}

// Span represents a contiguous range of compressed blocks in the file.
type Span struct {
	DataStart int64 // File offset where compressed blocks begin
	DataEnd   int64 // File offset where this span ends (next record)
}

// Errors
var (
	ErrInvalidMagic       = errors.New("gho: invalid file magic")
	ErrInvalidRecordMagic = errors.New("gho: invalid record magic")
	ErrUnsupportedCompression = errors.New("gho: unsupported compression type")
	ErrCorruptBlock       = errors.New("gho: corrupt compressed block")
	ErrTruncated          = errors.New("gho: unexpected end of data")
)

// ParseFileHeader parses a 512-byte file header.
func ParseFileHeader(data []byte) (*FileHeader, error) {
	if len(data) < HeaderSize {
		return nil, ErrTruncated
	}
	magic := binary.LittleEndian.Uint16(data[0:2])
	if magic != FileMagic {
		return nil, ErrInvalidMagic
	}
	h := &FileHeader{
		Magic:       magic,
		FileType:    data[2],
		Compression: data[3],
		ID:          binary.LittleEndian.Uint32(data[4:8]),
	}
	copy(h.Flags[:], data[8:11])
	copy(h.Raw[:], data[:HeaderSize])
	return h, nil
}

// ParsePartitionHeader parses a 512-byte FEEF partition header.
func ParsePartitionHeader(data []byte) (*PartitionHeader, error) {
	if len(data) < HeaderSize {
		return nil, ErrTruncated
	}
	magic := binary.LittleEndian.Uint16(data[0:2])
	if magic != FileMagic {
		return nil, ErrInvalidMagic
	}
	h := &PartitionHeader{
		Magic:       magic,
		SubType:     data[2],
		Compression: data[3],
		ID:          binary.LittleEndian.Uint32(data[4:8]),
	}
	copy(h.Flags[:], data[8:11])
	copy(h.Raw[:], data[:HeaderSize])
	return h, nil
}

// ParseRecord reads a record header from data.
func ParseRecord(data []byte, offset int64) (*Record, error) {
	if len(data) < RecordHeaderSize {
		return nil, ErrTruncated
	}
	r := &Record{
		Type:    binary.LittleEndian.Uint32(data[0:4]),
		Magic:   binary.LittleEndian.Uint32(data[4:8]),
		BodyLen: binary.LittleEndian.Uint16(data[8:10]),
		Offset:  offset,
	}
	if r.Magic != RecordMagic {
		return nil, ErrInvalidRecordMagic
	}
	return r, nil
}

// ParseMBRPartitions extracts partition table entries from a 512-byte MBR.
func ParseMBRPartitions(mbr []byte) []MBRPartitionEntry {
	if len(mbr) < 512 {
		return nil
	}
	// Check boot signature
	if mbr[510] != 0x55 || mbr[511] != 0xAA {
		return nil
	}
	var entries []MBRPartitionEntry
	for i := 0; i < 4; i++ {
		off := 446 + i*16
		e := MBRPartitionEntry{
			Status:   mbr[off],
			Type:     mbr[off+4],
			LBAStart: binary.LittleEndian.Uint32(mbr[off+8 : off+12]),
			LBASize:  binary.LittleEndian.Uint32(mbr[off+12 : off+16]),
		}
		copy(e.CHSStart[:], mbr[off+1:off+4])
		copy(e.CHSEnd[:], mbr[off+5:off+8])
		if e.Type != 0 {
			entries = append(entries, e)
		}
	}
	return entries
}
