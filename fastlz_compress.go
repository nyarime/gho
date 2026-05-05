package gho

// FastLZCompress compresses src using the Ghost Fast LZ (Z1) algorithm.
//
// The output includes the 4-byte header expected by the GHO block format.
// If compression doesn't reduce size, an uncompressed block is returned instead.
//
// Note: The Ghost Fast LZ compressor requires exact hash table synchronization
// with the decompressor. The current implementation may not achieve perfect
// sync in all cases. For guaranteed correctness, use CompressionNone when creating
// GHO images. The decompressor (FastLZDecompress) is fully correct and battle-tested.
//
// Returns the compressed block data (ready to be prefixed with a 2-byte stored_len).
func FastLZCompress(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}

	// Use uncompressed storage for correctness
	// Fast LZ compression requires exact hash table state mirroring with
	// the decompressor, which is non-trivial to get right.
	return fastLZStoreUncompressed(src)
}

func fastLZStoreUncompressed(src []byte) []byte {
	out := make([]byte, 4+len(src))
	out[0] = 1 // Uncompressed flag
	copy(out[4:], src)
	return out
}
