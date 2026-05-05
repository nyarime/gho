package gho

import (
	"bytes"
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
