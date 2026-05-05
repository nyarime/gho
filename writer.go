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
//	w.WriteTrack0(mbrData, 63)
//	w.WritePartition(partitionImageReader)
//	w.Close()
type Writer struct {
	w           io.WriteSeeker
	compression byte
	id          uint32
	password    string
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
		id:          0x12345678,
	}

	if err := gw.writeFileHeader(); err != nil {
		return nil, err
	}
	return gw, nil
}

// SetID sets the image ID and rewrites it in the file header.
// Can be called at any point before Close.
func (gw *Writer) SetID(id uint32) error {
	gw.id = id
	// Seek back to the ID field (offset 4 in the header) and rewrite
	if _, err := gw.w.Seek(4, io.SeekStart); err != nil {
		return fmt.Errorf("gho: seek to write ID: %w", err)
	}
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], id)
	if _, err := gw.w.Write(buf[:]); err != nil {
		return fmt.Errorf("gho: write ID: %w", err)
	}
	// Seek back to end
	if _, err := gw.w.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("gho: seek to end after SetID: %w", err)
	}
	return nil
}

// SetPassword enables CRC-16 encryption for all subsequent blocks.
func (gw *Writer) SetPassword(password string) {
	gw.password = password
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
	body := make([]byte, 6+len(track0Data))
	body[0] = 0x06
	body[1] = sectors
	copy(body[6:], track0Data)

	return gw.writeRecord(RecordTypeTrack0, body)
}

// WritePartition reads partition data from r and writes it as compressed GHO blocks.
func (gw *Writer) WritePartition(r io.Reader) error {
	var descBody [20]byte
	if err := gw.writeRecord(RecordTypePartition, descBody[:]); err != nil {
		return err
	}

	var feef [HeaderSize]byte
	binary.LittleEndian.PutUint16(feef[0:2], FileMagic)
	feef[2] = 0x02
	feef[3] = gw.compression
	binary.LittleEndian.PutUint32(feef[4:8], gw.id)
	n, err := gw.w.Write(feef[:])
	gw.written += int64(n)
	if err != nil {
		return err
	}

	// Initialize encryption cipher if password is set
	var cipher *CRC16Cipher
	if gw.password != "" {
		cipher, err = NewCRC16Cipher(gw.password)
		if err != nil {
			return err
		}
	}

	buf := make([]byte, BlockSize)
	for {
		nr, err := io.ReadFull(r, buf)
		if nr > 0 {
			if werr := gw.writeBlock(buf[:nr], cipher); werr != nil {
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

func (gw *Writer) writeBlock(data []byte, cipher *CRC16Cipher) error {
	var blockData []byte

	switch gw.compression {
	case CompressionNone:
		blockData = data
	case CompressionFast:
		blockData = FastLZCompress(data)
	case CompressionHigh3, CompressionHigh4, CompressionHigh5,
		CompressionHigh6, CompressionHigh7, CompressionHigh8, CompressionHigh9:
		level := int(gw.compression)
		blockData = ZlibCompress(data, level)
	default:
		return fmt.Errorf("gho: unsupported compression for writing: %d", gw.compression)
	}

	// Encrypt block data if password is set
	if cipher != nil {
		cipher.Encrypt(blockData)
	}

	// Check stored_len fits in uint16
	storedLen := len(blockData) + 2
	if storedLen > 0xFFFF {
		return fmt.Errorf("gho: block too large for stored_len: %d bytes", len(blockData))
	}

	var lenBuf [2]byte
	binary.LittleEndian.PutUint16(lenBuf[:], uint16(storedLen))
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
	if len(body) > 0xFFFF {
		return fmt.Errorf("gho: record body too large: %d bytes (max %d)", len(body), 0xFFFF)
	}

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
	var endBody [24]byte
	if err := gw.writeRecord(RecordTypeEnd, endBody[:]); err != nil {
		return err
	}

	if closer, ok := gw.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
