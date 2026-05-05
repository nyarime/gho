package gho

// FastLZDecompress decompresses a Ghost Fast LZ (Z1) compressed block.
//
// The algorithm is a custom LZ77 variant with a 4096-entry hash table.
// Each hash entry stores a pointer to a previous position in the output buffer.
//
// Block format:
//   - byte[0] == 1: uncompressed, output = data[4:compLen]
//   - byte[0] != 1: compressed with 16-bit control words
//
// Compressed format uses 16-bit control words where:
//   - bit 0 = literal byte (copy from input)
//   - bit 1 = match reference (2-byte token: hash_idx + extra_len)
//
// Hash function: h = ((-24993 * (b2 ^ (16 * (b1 ^ (16 * b0))))) >> 4) & 0xFFF
//
// Reversed from Norton Ghost 11.5.1 sub_4DDD70 via IDA.
func FastLZDecompress(data []byte, compLen int, dst []byte) (int, error) {
	if compLen <= 0 || len(data) < compLen {
		return 0, ErrTruncated
	}

	// Uncompressed block
	if data[0] == 1 {
		n := compLen - 4
		if n <= 0 {
			return 0, ErrCorruptBlock
		}
		if n > len(dst) {
			return 0, ErrCorruptBlock
		}
		copy(dst[:n], data[4:4+n])
		return n, nil
	}

	// Initialize hash table with sentinel pointers
	// In the original code, hash entries point to a string literal "123456789012345678"
	// We use a sentinel buffer at the start of our workspace
	const sentinelStr = "123456789012345678"
	sentinel := []byte(sentinelStr)

	// Hash table: 4096 entries, each is a slice pointer into dst or sentinel
	type hashEntry struct {
		buf []byte // points to dst or sentinel
	}
	hashTable := make([]hashEntry, FastLZHashSize)
	for i := range hashTable {
		hashTable[i].buf = sentinel
	}

	src := 4 // Skip first 4 bytes
	srcEnd := compLen
	outPos := 0

	var control uint32 = 1 // Triggers reload on first iteration
	var literalRun uint16
	var prevLiteralRun uint16

	for src < srcEnd {
		// Load new 16-bit control word
		if control == 1 {
			if src+1 >= srcEnd {
				break
			}
			control = uint32(data[src]) | uint32(data[src+1])<<8 | 0x10000
			src += 2
		}

		// Token count: 1 if near end, else 16
		nearEnd := srcEnd-32 < src
		tokenCount := 16
		if nearEnd {
			tokenCount = 1
		}

		for t := 0; t < tokenCount; t++ {
			if src >= srcEnd {
				break
			}

			if control&1 != 0 {
				// Match reference
				if src+1 >= srcEnd {
					goto done
				}

				b0 := data[src]
				b1 := data[src+1]

				// Hash index: b1 | (high 4 bits of b0 << 8)
				hashIdx := int(b1) | (int(b0&0xF0) << 4)
				extraLen := int(b0 & 0x0F)

				matchSrc := hashTable[hashIdx].buf
				matchStart := outPos

				// Copy 3 base bytes + extraLen additional bytes from match
				totalCopy := 3 + extraLen
				for j := 0; j < totalCopy; j++ {
					if outPos >= len(dst) {
						return 0, ErrCorruptBlock
					}
					if j < len(matchSrc) {
						dst[outPos] = matchSrc[j]
					} else {
						dst[outPos] = 0
					}
					outPos++
				}

				src += 2

				// Update hash table for accumulated literal run
				if literalRun > 0 {
					pos := matchStart - int(literalRun)
					if pos >= 0 && pos+2 < outPos {
						h := fastLZHash(dst[pos], dst[pos+1], dst[pos+2])
						hashTable[h].buf = dst[pos:]
						if prevLiteralRun == 2 && pos+3 < outPos {
							h2 := fastLZHash(dst[pos+1], dst[pos+2], dst[pos+3])
							hashTable[h2].buf = dst[pos+1:]
						}
					}
					literalRun = 0
					prevLiteralRun = 0
				}

				// Update hash entry to point to match start in output
				hashTable[hashIdx].buf = dst[matchStart:]
			} else {
				// Literal byte
				if outPos >= len(dst) {
					return 0, ErrCorruptBlock
				}
				literalRun++
				dst[outPos] = data[src]
				outPos++
				src++
				prevLiteralRun = literalRun

				if literalRun == 3 {
					pos := outPos - 3
					h := fastLZHash(dst[pos], dst[pos+1], dst[pos+2])
					hashTable[h].buf = dst[pos:]
					literalRun = 2
					prevLiteralRun = 2
				}
			}

			control >>= 1
			if control == 1 {
				break // Need new control word
			}
		}
	}

done:
	return outPos, nil
}

// fastLZHash computes the Ghost Fast LZ hash for 3 consecutive bytes.
// h = ((-24993 * (b2 ^ (16 * (b1 ^ (16 * b0))))) >> 4) & 0xFFF
func fastLZHash(b0, b1, b2 byte) int {
	v := int32(b2) ^ (16 * (int32(b1) ^ (16 * int32(b0))))
	return int((uint32(int32(-24993)*v) >> 4) & 0xFFF)
}
