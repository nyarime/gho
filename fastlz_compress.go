package gho

// FastLZCompress compresses src using the Ghost Fast LZ (Z1) algorithm.
//
// The compressor maintains exact hash table synchronization with the
// decompressor (FastLZDecompress). Every hash table update in the compressor
// mirrors what the decompressor would do when processing the compressed stream.
//
// Returns the compressed block data including the 4-byte header.
func FastLZCompress(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	if len(src) < 18 {
		return fastLZStoreUncompressed(src)
	}

	compressed := fastLZCompressInner(src)
	if compressed == nil || len(compressed) >= len(src)+4 {
		return fastLZStoreUncompressed(src)
	}
	return compressed
}

func fastLZStoreUncompressed(src []byte) []byte {
	out := make([]byte, 4+len(src))
	out[0] = 1 // Uncompressed flag
	copy(out[4:], src)
	return out
}

func fastLZCompressInner(src []byte) []byte {
	n := len(src)
	out := make([]byte, 0, 4+n+n/8+64)
	out = append(out, 0, 0, 0, 0) // 4-byte header

	const hashSize = FastLZHashSize
	const sentinel = -1
	var hashTable [hashSize]int
	for i := range hashTable {
		hashTable[i] = sentinel
	}

	pos := 0
	var literalRun uint16
	var prevLiteralRun uint16

	// Pre-allocate token buffer (max 16 tokens × 2 bytes each)
	tokenData := make([]byte, 0, 34)

	for pos < n {
		var controlBits uint16
		tokenData = tokenData[:0]
		tokenCount := 0

		for tokenCount < 16 && pos < n {
			matchLen := 0
			matchHashIdx := 0

			if pos+2 < n {
				h := fastLZHash(src[pos], src[pos+1], src[pos+2])
				matchPos := hashTable[h]

				if matchPos != sentinel && matchPos >= 0 && matchPos < pos {
					ml := 0
					maxMatch := 18
					if pos+maxMatch > n {
						maxMatch = n - pos
					}
					for ml < maxMatch && src[matchPos+ml] == src[pos+ml] {
						ml++
					}
					if ml >= 3 {
						matchLen = ml
						matchHashIdx = h
					}
				}
			}

			if matchLen >= 3 {
				extraLen := matchLen - 3
				b0 := byte(extraLen&0x0F) | byte((matchHashIdx>>4)&0xF0)
				b1 := byte(matchHashIdx & 0xFF)

				tokenData = append(tokenData, b0, b1)
				controlBits |= 1 << uint(tokenCount)

				matchStart := pos
				pos += matchLen

				if literalRun > 0 {
					litPos := matchStart - int(literalRun)
					if litPos >= 0 && litPos+2 < pos {
						lh := fastLZHash(src[litPos], src[litPos+1], src[litPos+2])
						hashTable[lh] = litPos
						if prevLiteralRun == 2 && litPos+3 < pos {
							lh2 := fastLZHash(src[litPos+1], src[litPos+2], src[litPos+3])
							hashTable[lh2] = litPos + 1
						}
					}
					literalRun = 0
					prevLiteralRun = 0
				}

				hashTable[matchHashIdx] = matchStart
			} else {
				tokenData = append(tokenData, src[pos])

				literalRun++
				pos++
				prevLiteralRun = literalRun

				if literalRun == 3 {
					litPos := pos - 3
					lh := fastLZHash(src[litPos], src[litPos+1], src[litPos+2])
					hashTable[lh] = litPos
					literalRun = 2
					prevLiteralRun = 2
				}
			}

			tokenCount++
		}

		out = append(out, byte(controlBits), byte(controlBits>>8))
		out = append(out, tokenData...)
	}

	return out
}
