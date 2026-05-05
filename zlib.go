package gho

import (
	"bytes"
	"compress/zlib"
	"io"
)

// ZlibDecompress decompresses a Ghost High/zlib (Z3-Z9) compressed block.
//
// Ghost uses raw zlib (RFC 1950) compression for its "High" modes (Z3-Z9).
// The compression level corresponds to the zlib level (3-9), but the
// decompression is the same for all levels.
//
// Block format (same as Fast LZ):
//   - byte[0] == 1: uncompressed, output = data[4:compLen]
//   - byte[0] != 1: zlib compressed data starting at offset 0
func ZlibDecompress(data []byte, compLen int, dst []byte) (int, error) {
	if compLen <= 0 || len(data) < compLen {
		return 0, ErrTruncated
	}

	// Uncompressed block (same marker as Fast LZ)
	if data[0] == 1 {
		n := compLen - 4
		if n <= 0 || n > len(dst) {
			return 0, ErrCorruptBlock
		}
		copy(dst[:n], data[4:4+n])
		return n, nil
	}

	// Zlib decompression
	r, err := zlib.NewReader(bytes.NewReader(data[:compLen]))
	if err != nil {
		return 0, err
	}
	defer r.Close()

	n, err := io.ReadFull(r, dst)
	if err == io.ErrUnexpectedEOF {
		err = nil // Partial block at end of partition is OK
	}
	return n, err
}

// ZlibCompress compresses src using zlib at the given level (3-9).
// Returns data in GHO block format. Falls back to uncompressed if
// compression doesn't reduce size.
func ZlibCompress(src []byte, level int) []byte {
	if len(src) == 0 {
		return nil
	}

	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, level)
	if err != nil {
		return fastLZStoreUncompressed(src)
	}
	w.Write(src)
	w.Close()

	if buf.Len() < len(src) {
		return buf.Bytes()
	}
	return fastLZStoreUncompressed(src)
}
