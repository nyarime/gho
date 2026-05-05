package gho

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Writer creates a new GHO image file.
//
// Usage:
//
//	w, _ := Create("output.gho", CompressionFast)
//	w.WriteTrack0(mbrData)                     // 512+ bytes of MBR/boot sectors
//	w.WritePartition(partitionImageReader)       // raw partition data
//	w.Close()
type Writer struct {
	w           io.WriteSeeker
	compression byte
	id          uint32
	written     int64
}

// Create creates a new GHO image file for writing.
func Create(path string, compression byte) (*Writer, error) {
	f, err := createFile(path)
	if err != nil {
		return nil, err
	}
	return NewWriter(f, compression)
}

// NewWriter wraps an io.WriteSeeker as a GHO writer.
func NewWriter(w io.WriteSeeker, compression byte) (*Writer, error) {
	gw := &Writer{
		w:           w,
		compression: compression,
		id:          0x12345678, // Default ID; overridden by SetID
	}

	// Write file header
	if err := gw.writeFileHeader(); err != nil {
		return nil, err
	}
	return gw, nil
}

// SetID sets the image ID (CRC/timestamp identifier) in the file header.
// Must be called before WriteTrack0 or WritePartition.
func (gw *Writer) SetID(id uint32) {
	gw.id = id
}

func (gw *Writer) writeFileHeader() error {
	var hdr [HeaderSize]byte
	binary.LittleEndian.PutUint16(hdr[0:2], FileMagic)
	hdr[2] = 0x01 // FileType: single file
	hdr[3] = gw.compression
	binary.LittleEndian.PutUint32(hdr[4:8], gw.id)
	n, err := gw.w.Write(hdr[:])
	gw.written += int64(n)
	return err
}

// WriteTrack0 writes the MBR / Track 0 data as a type-6 record.
// track0Data should be the raw MBR + boot sectors (typically 512 * sectors bytes).
// sectors is the sector count field in the Track 0 mini-header (e.g. 63 or 126).
func (gw *Writer) WriteTrack0(track0Data []byte, sectors byte) error {
	// Build body: 6-byte mini-header + track0Data
	body := make([]byte, 6+len(track0Data))
	body[0] = 0x06 // Unknown1 (matches typical GHO)
	body[1] = sectors
	// body[2:6] = 0 (Unknown2)
	copy(body[6:], track0Data)

	return gw.writeRecord(RecordTypeTrack0, body)
}

// WritePartition reads partition data from r and writes it as compressed GHO blocks.
func (gw *Writer) WritePartition(r io.Reader) error {
	// Write partition descriptor record (type 0x0603)
	var descBody [20]byte
	if err := gw.writeRecord(RecordTypePartition, descBody[:]); err != nil {
		return err
	}

	// Write FEEF partition header
	var feef [HeaderSize]byte
	binary.LittleEndian.PutUint16(feef[0:2], FileMagic)
	feef[2] = 0x02 // SubType for partition data
	feef[3] = gw.compression
	binary.LittleEndian.PutUint32(feef[4:8], gw.id)
	n, err := gw.w.Write(feef[:])
	gw.written += int64(n)
	if err != nil {
		return err
	}

	// Read and compress blocks
	buf := make([]byte, BlockSize)
	for {
		nr, err := io.ReadFull(r, buf)
		if nr > 0 {
			if werr := gw.writeBlock(buf[:nr]); werr != nil {
				return werr
			}
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return fmt.Errorf("gho: reading partition data: %w", err)
		}
	}

	return nil
}

func (gw *Writer) writeBlock(data []byte) error {
	var blockData []byte

	switch gw.compression {
	case CompressionNone:
		blockData = data
	case CompressionFast:
		blockData = FastLZCompress(data)
	case CompressionHigh3, CompressionHigh4, CompressionHigh5,
		CompressionHigh6, CompressionHigh7, CompressionHigh8, CompressionHigh9:
		level := int(gw.compression) // Z3=level 3, Z9=level 9
		blockData = ZlibCompress(data, level)
	default:
		return fmt.Errorf("gho: unsupported compression for writing: %d", gw.compression)
	}

	// Write stored_len (2 bytes LE) + block data
	storedLen := uint16(len(blockData) + 2)
	var lenBuf [2]byte
	binary.LittleEndian.PutUint16(lenBuf[:], storedLen)
	if n, err := gw.w.Write(lenBuf[:]); err != nil {
		return err
	} else {
		gw.written += int64(n)
	}
	if n, err := gw.w.Write(blockData); err != nil {
		return err
	} else {
		gw.written += int64(n)
	}
	return nil
}

func (gw *Writer) writeRecord(recType uint16, body []byte) error {
	var hdr [RecordHeaderSize]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(recType))
	binary.LittleEndian.PutUint32(hdr[4:8], RecordMagic)
	binary.LittleEndian.PutUint16(hdr[8:10], uint16(len(body)))
	if n, err := gw.w.Write(hdr[:]); err != nil {
		return err
	} else {
		gw.written += int64(n)
	}
	if len(body) > 0 {
		if n, err := gw.w.Write(body); err != nil {
			return err
		} else {
			gw.written += int64(n)
		}
	}
	return nil
}

// Close writes the end record and closes the underlying writer (if it's a file).
func (gw *Writer) Close() error {
	// Write end record
	var endBody [24]byte
	if err := gw.writeRecord(RecordTypeEnd, endBody[:]); err != nil {
		return err
	}

	if closer, ok := gw.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
