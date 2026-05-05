package gho

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// Image represents a parsed GHO image file.
type Image struct {
	Header      *FileHeader
	Track0      []byte          // Raw Track 0 data (MBR at offset 6)
	Track0Hdr   Track0Header    // 6-byte mini-header
	Partitions  []PartitionInfo // Partition descriptors
	EndRecord   *Record
	file        *os.File
	fileLen     int64  // Cached file size
	password    string // For encrypted images
	spanTmpPath string // Temp file for spanned images (cleaned up on Close)
	spanReader  io.Closer // For multiReaderAt cleanup
}

// PartitionInfo holds information about a single partition in the image.
type PartitionInfo struct {
	Descriptor *Record          // Type 0x0603 record
	Header     *PartitionHeader // FEEF partition header
	Spans      []Span           // Data spans (may span multiple continuation records)
	DescBody   [20]byte         // Raw descriptor body
}

// TotalCompressedSize returns the total compressed data size across all spans.
func (p *PartitionInfo) TotalCompressedSize() int64 {
	var total int64
	for _, sp := range p.Spans {
		total += sp.DataEnd - sp.DataStart
	}
	return total
}

// Open opens and parses a GHO image file.
func Open(path string) (*Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}

	img := &Image{file: f, fileLen: fi.Size()}
	if err := img.parse(); err != nil {
		f.Close()
		return nil, err
	}
	return img, nil
}

// SetPassword sets the decryption password for encrypted GHO images.
// Must be called before DecompressPartition on encrypted images.
func (img *Image) SetPassword(password string) {
	img.password = password
}

// IsEncrypted returns true if the image header indicates encryption.
func (img *Image) IsEncrypted() bool {
	return IsEncrypted(img.Header.Raw[:])
}

// Close closes the underlying file and cleans up temporary span files.
func (img *Image) Close() error {
	var err error
	if img.spanReader != nil {
		img.spanReader.Close()
	}
	if img.file != nil {
		err = img.file.Close()
	}
	if img.spanTmpPath != "" {
		os.Remove(img.spanTmpPath)
	}
	return err
}

func (img *Image) parse() error {
	// Read file header
	hdrBuf := make([]byte, HeaderSize)
	if _, err := io.ReadFull(img.file, hdrBuf); err != nil {
		return fmt.Errorf("gho: reading file header: %w", err)
	}
	var err error
	img.Header, err = ParseFileHeader(hdrBuf)
	if err != nil {
		return err
	}

	// Pre-allocate reusable buffers for record scanning
	recBuf := make([]byte, RecordHeaderSize)
	scanBuf := make([]byte, scanChunkSize+10) // Reusable scan buffer

	// Scan records by finding record magic
	offset := int64(HeaderSize)
	for {
		recOff, err := img.findNextRecord(offset, scanBuf)
		if err != nil {
			return err
		}
		if recOff >= img.fileLen {
			break
		}
		offset = recOff

		if _, err := img.file.ReadAt(recBuf, offset); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("gho: reading record at %#x: %w", offset, err)
		}

		rec, err := ParseRecord(recBuf, offset)
		if err != nil {
			return fmt.Errorf("gho: parsing record at %#x: %w", offset, err)
		}

		switch rec.TypeCode() {
		case RecordTypeTrack0:
			body := make([]byte, rec.BodyLen)
			if _, err := img.file.ReadAt(body, offset+RecordHeaderSize); err != nil {
				return fmt.Errorf("gho: reading Track0 body: %w", err)
			}
			if len(body) >= 6 {
				img.Track0Hdr = Track0Header{
					Unknown1: body[0],
					Sectors:  body[1],
					Unknown2: binary.LittleEndian.Uint32(body[2:6]),
				}
				img.Track0 = body[6:]
			}
			offset += RecordHeaderSize + int64(rec.BodyLen)

		case RecordTypePartition:
			pInfo := PartitionInfo{Descriptor: rec}
			body := make([]byte, rec.BodyLen)
			if _, err := img.file.ReadAt(body, offset+RecordHeaderSize); err != nil {
				return fmt.Errorf("gho: reading partition descriptor: %w", err)
			}
			copy(pInfo.DescBody[:], body)
			offset += RecordHeaderSize + int64(rec.BodyLen)

			feefBuf := make([]byte, HeaderSize)
			if _, err := img.file.ReadAt(feefBuf, offset); err != nil {
				return fmt.Errorf("gho: reading FEEF header: %w", err)
			}
			pInfo.Header, err = ParsePartitionHeader(feefBuf)
			if err != nil {
				return fmt.Errorf("gho: parsing FEEF header at %#x: %w", offset, err)
			}
			offset += HeaderSize
			dataStart := offset

			nextRecOff, err := img.findNextRecord(offset, scanBuf)
			if err != nil {
				return err
			}
			pInfo.Spans = append(pInfo.Spans, Span{DataStart: dataStart, DataEnd: nextRecOff})
			offset = nextRecOff
			img.Partitions = append(img.Partitions, pInfo)

		case RecordTypeContinuation:
			body := make([]byte, rec.BodyLen)
			if _, err := img.file.ReadAt(body, offset+RecordHeaderSize); err != nil {
				return fmt.Errorf("gho: reading continuation body: %w", err)
			}
			offset += RecordHeaderSize + int64(rec.BodyLen)

			checkBuf := make([]byte, 4)
			if _, err := img.file.ReadAt(checkBuf, offset); err == nil {
				if binary.LittleEndian.Uint16(checkBuf[0:2]) == FileMagic {
					offset += HeaderSize
				}
			}
			dataStart := offset

			nextRecOff, err := img.findNextRecord(offset, scanBuf)
			if err != nil {
				return err
			}

			if len(img.Partitions) > 0 {
				last := &img.Partitions[len(img.Partitions)-1]
				last.Spans = append(last.Spans, Span{DataStart: dataStart, DataEnd: nextRecOff})
			}
			offset = nextRecOff

		case RecordTypeEnd:
			img.EndRecord = rec
			return nil

		default:
			offset += RecordHeaderSize + int64(rec.BodyLen)
		}
	}
	return nil
}

const scanChunkSize = 65536

// findNextRecord scans forward from offset to find the next record header.
// Records are identified by the magic value 0x012F18D8 at offset 4.
// buf must be at least scanChunkSize+10 bytes.
func (img *Image) findNextRecord(startOff int64, buf []byte) (int64, error) {
	for off := startOff; off < img.fileLen; {
		readLen := int64(scanChunkSize)
		if off+readLen > img.fileLen {
			readLen = img.fileLen - off
		}
		n, err := img.file.ReadAt(buf[:readLen], off)
		if err != nil && err != io.EOF {
			return 0, err
		}
		if n < RecordHeaderSize {
			break
		}

		for i := 0; i <= n-RecordHeaderSize; i++ {
			magic := binary.LittleEndian.Uint32(buf[i+4 : i+8])
			if magic == RecordMagic {
				// Validate record type to reduce false positives
				recType := binary.LittleEndian.Uint16(buf[i : i+2])
				if isKnownRecordType(recType) {
					return off + int64(i), nil
				}
			}
		}
		off += int64(n - 10) // Overlap to catch cross-boundary matches
	}

	return img.fileLen, nil
}

// isKnownRecordType returns true if the type code is a recognized GHO record type.
func isKnownRecordType(t uint16) bool {
	switch t {
	case RecordTypeTrack0, RecordTypePartition, RecordTypeContinuation, RecordTypeEnd:
		return true
	}
	return false
}

// DecompressPartition decompresses all blocks of a partition and writes to w.
// If the image is encrypted, SetPassword must be called first.
func (img *Image) DecompressPartition(partIdx int, w io.Writer) error {
	if partIdx >= len(img.Partitions) {
		return fmt.Errorf("gho: partition index %d out of range", partIdx)
	}

	var cipher *CRC16Cipher
	if img.IsEncrypted() {
		if img.password == "" {
			return fmt.Errorf("gho: image is encrypted but no password set (call SetPassword)")
		}
		var err error
		cipher, err = NewCRC16Cipher(img.password)
		if err != nil {
			return err
		}
	}

	pInfo := &img.Partitions[partIdx]
	dst := make([]byte, BlockSize+1024) // Decompression output buffer
	lenBuf := make([]byte, 2)           // Reusable length buffer
	blockBuf := make([]byte, MaxStoredLen) // Reusable block read buffer

	for _, span := range pInfo.Spans {
		offset := span.DataStart
		for offset+2 <= span.DataEnd {
			if _, err := img.file.ReadAt(lenBuf, offset); err != nil {
				return fmt.Errorf("gho: reading block length at %#x: %w", offset, err)
			}
			storedLen := int(binary.LittleEndian.Uint16(lenBuf))
			if storedLen == 0 {
				break
			}
			compLen := storedLen - 2
			if compLen <= 0 || compLen > MaxStoredLen {
				return fmt.Errorf("gho: invalid block stored_len=%d at %#x", storedLen, offset)
			}

			// Read block data into reusable buffer
			blockData := blockBuf[:compLen]
			if _, err := img.file.ReadAt(blockData, offset+2); err != nil {
				return fmt.Errorf("gho: reading block data at %#x: %w", offset+2, err)
			}

			if cipher != nil {
				cipher.Decrypt(blockData)
			}

			var n int
			var err error
			switch img.Header.Compression {
			case CompressionNone:
				n = copy(dst, blockData)
			case CompressionFast:
				n, err = FastLZDecompress(blockData, compLen, dst)
			case CompressionHigh3, CompressionHigh4, CompressionHigh5,
				CompressionHigh6, CompressionHigh7, CompressionHigh8, CompressionHigh9:
				n, err = ZlibDecompress(blockData, compLen, dst)
			default:
				err = fmt.Errorf("%w: type %d", ErrUnsupportedCompression, img.Header.Compression)
			}
			if err != nil {
				return fmt.Errorf("gho: decompressing block at %#x: %w", offset, err)
			}

			if _, err := w.Write(dst[:n]); err != nil {
				return fmt.Errorf("gho: writing decompressed data: %w", err)
			}

			offset += 2 + int64(compLen)
		}
	}
	return nil
}

// Verify checks the integrity of a partition by decompressing all blocks
// without writing output. Returns nil if all blocks decompress successfully.
func (img *Image) Verify(partIdx int) error {
	return img.DecompressPartition(partIdx, io.Discard)
}

// MBRPartitions returns parsed MBR partition entries from Track 0.
func (img *Image) MBRPartitions() []MBRPartitionEntry {
	if len(img.Track0) < 512 {
		return nil
	}
	return ParseMBRPartitions(img.Track0)
}

// Summary returns a human-readable summary of the GHO image.
func (img *Image) Summary() string {
	s := fmt.Sprintf("GHO Image Summary\n")
	s += fmt.Sprintf("  File Type:   %d (1=single, 9=span)\n", img.Header.FileType)
	s += fmt.Sprintf("  Compression: %d", img.Header.Compression)
	switch img.Header.Compression {
	case CompressionNone:
		s += " (none)\n"
	case CompressionFast:
		s += " (Fast/Z1)\n"
	case CompressionHigh3, CompressionHigh4, CompressionHigh5,
		CompressionHigh6, CompressionHigh7, CompressionHigh8, CompressionHigh9:
		s += fmt.Sprintf(" (High/Z%d)\n", img.Header.Compression)
	default:
		s += " (unknown)\n"
	}
	s += fmt.Sprintf("  Image ID:    %#08x\n", img.Header.ID)

	if len(img.Track0) >= 512 {
		parts := img.MBRPartitions()
		s += fmt.Sprintf("  MBR Partitions: %d\n", len(parts))
		for i, p := range parts {
			sizeMB := float64(p.LBASize) * 512 / 1024 / 1024
			s += fmt.Sprintf("    P%d: type=%#04x LBA=%d size=%d (%.1f MB)\n",
				i, p.Type, p.LBAStart, p.LBASize, sizeMB)
		}
	}

	s += fmt.Sprintf("  Data Partitions: %d\n", len(img.Partitions))
	for i, p := range img.Partitions {
		s += fmt.Sprintf("    Partition %d: %d spans, %d bytes compressed data\n",
			i, len(p.Spans), p.TotalCompressedSize())
	}
	return s
}
