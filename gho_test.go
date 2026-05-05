package gho

import (
	"bytes"
	"io"
	"os"
	"testing"
)

const testGHO = "/data/ikuai-lab/ikuai_3.7.22.gho"

func TestOpen(t *testing.T) {
	if _, err := os.Stat(testGHO); err != nil {
		t.Skipf("test GHO not found: %s", testGHO)
	}

	img, err := Open(testGHO)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer img.Close()

	t.Log(img.Summary())

	// Verify file header
	if img.Header.Magic != FileMagic {
		t.Errorf("magic = %#x, want %#x", img.Header.Magic, FileMagic)
	}
	if img.Header.FileType != 1 {
		t.Errorf("file type = %d, want 1", img.Header.FileType)
	}
	if img.Header.Compression != CompressionFast {
		t.Errorf("compression = %d, want %d (Fast)", img.Header.Compression, CompressionFast)
	}

	// Verify Track 0
	if len(img.Track0) < 512 {
		t.Fatalf("Track0 too small: %d bytes", len(img.Track0))
	}
	if img.Track0[510] != 0x55 || img.Track0[511] != 0xAA {
		t.Errorf("MBR boot signature: %02x%02x, want 55aa", img.Track0[510], img.Track0[511])
	}

	// Verify MBR partitions
	parts := img.MBRPartitions()
	if len(parts) == 0 {
		t.Fatal("no MBR partitions found")
	}
	if parts[0].Type != 0x83 {
		t.Errorf("partition 0 type = %#x, want 0x83 (Linux)", parts[0].Type)
	}
	if parts[0].LBAStart != 2016 {
		t.Errorf("partition 0 LBA start = %d, want 2016", parts[0].LBAStart)
	}

	// Verify partition info
	if len(img.Partitions) == 0 {
		t.Fatal("no partition data found")
	}
	t.Logf("Partition 0: %d spans", len(img.Partitions[0].Spans))
	for i, sp := range img.Partitions[0].Spans {
		t.Logf("  Span %d: %#x - %#x (%d bytes)", i, sp.DataStart, sp.DataEnd, sp.DataEnd-sp.DataStart)
	}

	// Verify end record
	if img.EndRecord == nil {
		t.Error("no end record found")
	}
}

func TestDecompressPartition(t *testing.T) {
	if _, err := os.Stat(testGHO); err != nil {
		t.Skipf("test GHO not found: %s", testGHO)
	}

	img, err := Open(testGHO)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer img.Close()

	var buf bytes.Buffer
	if err := img.DecompressPartition(0, &buf); err != nil {
		t.Fatalf("DecompressPartition: %v", err)
	}

	t.Logf("Decompressed %d bytes (%.1f MB)", buf.Len(), float64(buf.Len())/1024/1024)

	// Should produce ~51 MB (1632 blocks * 32KB)
	if buf.Len() < 50*1024*1024 || buf.Len() > 55*1024*1024 {
		t.Errorf("unexpected decompressed size: %d bytes", buf.Len())
	}
}

func TestFastLZDecompress(t *testing.T) {
	// Test uncompressed block
	data := make([]byte, 104)
	data[0] = 1 // uncompressed flag
	for i := 4; i < 104; i++ {
		data[i] = byte(i)
	}
	dst := make([]byte, 200)
	n, err := FastLZDecompress(data, 104, dst)
	if err != nil {
		t.Fatalf("decompress uncompressed: %v", err)
	}
	if n != 100 {
		t.Errorf("decompressed len = %d, want 100", n)
	}
	for i := 0; i < 100; i++ {
		if dst[i] != byte(i+4) {
			t.Errorf("dst[%d] = %d, want %d", i, dst[i], i+4)
			break
		}
	}
}

func TestFastLZHash(t *testing.T) {
	// Verify hash function matches known values
	h := fastLZHash(0, 0, 0)
	if h < 0 || h >= FastLZHashSize {
		t.Errorf("hash out of range: %d", h)
	}

	// Hash should be deterministic
	h1 := fastLZHash(0x41, 0x42, 0x43)
	h2 := fastLZHash(0x41, 0x42, 0x43)
	if h1 != h2 {
		t.Errorf("hash not deterministic: %d vs %d", h1, h2)
	}
}

func TestFastLZCompressRoundtrip(t *testing.T) {
	// Test with various data patterns
	tests := []struct {
		name string
		data func() []byte
	}{
		{"zeros", func() []byte { return make([]byte, 4096) }},
		{"sequential", func() []byte {
			d := make([]byte, 4096)
			for i := range d {
				d[i] = byte(i)
			}
			return d
		}},
		{"repetitive", func() []byte {
			d := make([]byte, 4096)
			for i := range d {
				d[i] = byte(i % 7)
			}
			return d
		}},
		{"block_size", func() []byte {
			d := make([]byte, BlockSize)
			for i := range d {
				d[i] = byte(i % 251)
			}
			return d
		}},
		{"highly_compressible", func() []byte {
			d := make([]byte, BlockSize)
			copy(d, []byte("ABCDEFGHIJKLMNOP"))
			for i := 16; i < len(d); i += 16 {
				copy(d[i:], d[:16])
			}
			return d
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := tt.data()
			compressed := FastLZCompress(src)
			if compressed == nil {
				t.Fatal("FastLZCompress returned nil")
			}

			dst := make([]byte, len(src)+1024)
			n, err := FastLZDecompress(compressed, len(compressed), dst)
			if err != nil {
				t.Fatalf("FastLZDecompress: %v", err)
			}
			if n != len(src) {
				t.Errorf("decompressed size = %d, want %d", n, len(src))
			}
			for i := 0; i < n && i < len(src); i++ {
				if dst[i] != src[i] {
					t.Errorf("mismatch at byte %d: got %02x, want %02x", i, dst[i], src[i])
					break
				}
			}

			// Check compression ratio for compressible data
			if tt.name == "highly_compressible" {
				ratio := float64(len(compressed)) / float64(len(src))
				t.Logf("compression ratio: %.2f%% (%d -> %d)", ratio*100, len(src), len(compressed))
				if ratio > 0.5 {
					t.Errorf("poor compression ratio for highly compressible data: %.2f%%", ratio*100)
				}
			}
		})
	}
}

func TestFastLZCompressRealGHO(t *testing.T) {
	if _, err := os.Stat(testGHO); err != nil {
		t.Skipf("test GHO not found: %s", testGHO)
	}

	// Read the real GHO, decompress partition, recompress with FastLZ, verify roundtrip
	img, err := Open(testGHO)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer img.Close()

	var origBuf bytes.Buffer
	if err := img.DecompressPartition(0, &origBuf); err != nil {
		t.Fatalf("DecompressPartition: %v", err)
	}

	origData := origBuf.Bytes()
	t.Logf("Original decompressed: %d bytes (%.1f MB)", len(origData), float64(len(origData))/1024/1024)

	// Compress each block and verify roundtrip
	blockCount := 0
	failCount := 0
	totalOrig := 0
	totalComp := 0

	for off := 0; off < len(origData); off += BlockSize {
		end := off + BlockSize
		if end > len(origData) {
			end = len(origData)
		}
		block := origData[off:end]

		compressed := FastLZCompress(block)
		if compressed == nil {
			t.Fatalf("block %d: FastLZCompress returned nil", blockCount)
		}

		dst := make([]byte, BlockSize+1024)
		n, err := FastLZDecompress(compressed, len(compressed), dst)
		if err != nil {
			t.Errorf("block %d: FastLZDecompress: %v", blockCount, err)
			failCount++
			blockCount++
			continue
		}
		if n != len(block) {
			t.Errorf("block %d: size mismatch: got %d, want %d", blockCount, n, len(block))
			failCount++
			blockCount++
			continue
		}
		for i := 0; i < n; i++ {
			if dst[i] != block[i] {
				t.Errorf("block %d: data mismatch at byte %d", blockCount, i)
				failCount++
				break
			}
		}

		totalOrig += len(block)
		totalComp += len(compressed)
		blockCount++
	}

	ratio := float64(totalComp) / float64(totalOrig) * 100
	t.Logf("Blocks: %d total, %d failed, compression ratio: %.1f%%", blockCount, failCount, ratio)
	if failCount > 0 {
		t.Errorf("%d blocks failed roundtrip", failCount)
	}
}

func TestZlibRoundtrip(t *testing.T) {
	// Create test data with some repetition (compressible)
	src := make([]byte, BlockSize)
	for i := range src {
		src[i] = byte(i % 251) // Prime modulus for variety
	}

	for _, level := range []int{3, 6, 9} {
		compressed := ZlibCompress(src, level)
		if compressed == nil {
			t.Fatalf("ZlibCompress level %d returned nil", level)
		}

		dst := make([]byte, BlockSize+1024)
		n, err := ZlibDecompress(compressed, len(compressed), dst)
		if err != nil {
			t.Fatalf("ZlibDecompress level %d: %v", level, err)
		}
		if n != BlockSize {
			t.Errorf("ZlibDecompress level %d: got %d bytes, want %d", level, n, BlockSize)
		}
		for i := 0; i < n; i++ {
			if dst[i] != src[i] {
				t.Errorf("ZlibDecompress level %d: mismatch at byte %d", level, i)
				break
			}
		}
	}
}

func TestCRC16Cipher(t *testing.T) {
	// Test encrypt/decrypt roundtrip
	original := []byte("Hello, Ghost encryption test! 1234567890")
	data := make([]byte, len(original))
	copy(data, original)

	password := "testpassword"

	enc, _ := NewCRC16Cipher(password)
	enc.Encrypt(data)

	// Encrypted data should differ
	if bytes.Equal(data, original) {
		t.Error("encrypted data matches original")
	}

	dec, _ := NewCRC16Cipher(password)
	dec.Decrypt(data)

	if !bytes.Equal(data, original) {
		t.Errorf("decrypt mismatch: got %q, want %q", data, original)
	}
}

func BenchmarkDecompressPartition(b *testing.B) {
	if _, err := os.Stat(testGHO); err != nil {
		b.Skipf("test GHO not found: %s", testGHO)
	}

	img, err := Open(testGHO)
	if err != nil {
		b.Fatal(err)
	}
	defer img.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := img.DecompressPartition(0, io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFastLZCompress(b *testing.B) {
	// 32KB block of realistic data
	src := make([]byte, BlockSize)
	for i := range src {
		src[i] = byte(i % 251)
	}

	b.ResetTimer()
	b.SetBytes(BlockSize)
	for i := 0; i < b.N; i++ {
		FastLZCompress(src)
	}
}

func TestWriterRoundtrip(t *testing.T) {
	if _, err := os.Stat(testGHO); err != nil {
		t.Skipf("test GHO not found: %s", testGHO)
	}

	// Extract original
	img, err := Open(testGHO)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	var origBuf bytes.Buffer
	if err := img.DecompressPartition(0, &origBuf); err != nil {
		t.Fatalf("DecompressPartition: %v", err)
	}
	origTrack0 := make([]byte, len(img.Track0))
	copy(origTrack0, img.Track0)
	img.Close()

	compressions := []struct {
		name string
		comp byte
	}{
		{"none", CompressionNone},
		{"fastlz", CompressionFast},
		{"zlib6", CompressionHigh6},
	}

	for _, tc := range compressions {
		t.Run(tc.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "gho-rt-*.gho")
			if err != nil {
				t.Fatal(err)
			}
			tmpPath := tmpFile.Name()
			defer os.Remove(tmpPath)

			w, err := NewWriter(tmpFile, tc.comp)
			if err != nil {
				t.Fatal(err)
			}
			w.WriteTrack0(origTrack0, 63)
			w.WritePartition(bytes.NewReader(origBuf.Bytes()))
			w.Close()

			// Check file size
			fi, _ := os.Stat(tmpPath)
			t.Logf("GHO file size: %d bytes (%.1f MB)", fi.Size(), float64(fi.Size())/1024/1024)

			// Re-read and compare
			img2, err := Open(tmpPath)
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}
			defer img2.Close()

			var rtBuf bytes.Buffer
			if err := img2.DecompressPartition(0, &rtBuf); err != nil {
				t.Fatalf("DecompressPartition roundtrip: %v", err)
			}

			if !bytes.Equal(origBuf.Bytes(), rtBuf.Bytes()) {
				t.Errorf("roundtrip mismatch: orig=%d bytes, roundtrip=%d bytes",
					origBuf.Len(), rtBuf.Len())
			}
		})
	}
}
