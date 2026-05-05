package gho

import (
	"bytes"
	"compress/zlib"
	"io"
	"sync"
)

// zlibReaderPool reuses zlib readers to reduce allocations.
var zlibReaderPool sync.Pool

// ZlibDecompress decompresses a Ghost High/zlib (Z3-Z9) compressed block.
//
// Block format is identical to Fast LZ: byte[0] == 1 means uncompressed.
// Otherwise the data (starting at offset 4) is zlib-compressed.
func ZlibDecompress(data []byte, compLen int, dst []byte) (int, error) {
	if compLen <= 0 || len(data) < compLen {
		return 0, ErrTruncated
	}

	// Uncompressed block
	if data[0] == 1 {
		n := compLen - 4
		if n <= 0 || n > len(dst) {
			return 0, ErrCorruptBlock
		}
		copy(dst[:n], data[4:4+n])
		return n, nil
	}

	// Zlib compressed data starts at offset 4
	br := bytes.NewReader(data[4:compLen])

	var r io.ReadCloser
	if v := zlibReaderPool.Get(); v != nil {
		rr := v.(zlib.Resetter)
		if err := rr.Reset(br, nil); err != nil {
			// Fallback to new reader if reset fails
			var err2 error
			r, err2 = zlib.NewReader(br)
			if err2 != nil {
				return 0, err2
			}
		} else {
			r = v.(io.ReadCloser)
		}
	} else {
		var err error
		r, err = zlib.NewReader(br)
		if err != nil {
			return 0, err
		}
	}

	n, err := io.ReadFull(r, dst)
	if err == io.ErrUnexpectedEOF {
		err = nil // Partial read is fine for last block
	}

	zlibReaderPool.Put(r)
	r.Close()

	return n, err
}

// ZlibCompress compresses src using zlib at the given level (3-9).
//
// The output includes the 4-byte header expected by the GHO block format.
// If compression doesn't reduce size, an uncompressed block is returned.
func ZlibCompress(src []byte, level int) []byte {
	if len(src) == 0 {
		return nil
	}

	var buf bytes.Buffer
	buf.Grow(4 + len(src))
	buf.Write([]byte{0, 0, 0, 0}) // 4-byte header

	w, err := zlib.NewWriterLevel(&buf, level)
	if err != nil {
		return fastLZStoreUncompressed(src)
	}
	if _, err := w.Write(src); err != nil {
		return fastLZStoreUncompressed(src)
	}
	if err := w.Close(); err != nil {
		return fastLZStoreUncompressed(src)
	}

	if buf.Len() >= len(src)+4 {
		return fastLZStoreUncompressed(src)
	}
	return buf.Bytes()
}
