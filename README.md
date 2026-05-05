# gho

[![Go Reference](https://pkg.go.dev/badge/github.com/nyarime/gho.svg)](https://pkg.go.dev/github.com/nyarime/gho)
[![Go Report Card](https://goreportcard.com/badge/github.com/nyarime/gho)](https://goreportcard.com/report/github.com/nyarime/gho)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Pure Go library and CLI tool for parsing **Norton Ghost GHO** disk image files.

No C dependencies. No CGo. Single binary.

## Features

- Parse GHO file/partition headers and record structure
- Decompress **Fast LZ (Z1)** compressed partitions
- **Create** GHO images from raw partition data
- **Fixup** GHO headers (ghofixup.exe equivalent — CD/span flag modification with PRNG cipher)
- Extract MBR/Track 0 data and partition table
- Stream decompression (constant memory, arbitrary image sizes)
- Supports Ghost 11.x–12.x format

## Install

```bash
# Library
go get github.com/nyarime/gho

# CLI tool
go install github.com/nyarime/gho/cmd/gho@latest
```

## CLI Usage

```bash
# Show image info
gho info disk.gho

# Extract all partitions to a directory
gho extract disk.gho output/

# Create a GHO image from a partition image (+ optional MBR)
gho create output.gho partition.img mbr.bin

# Modify header flags (ghofixup.exe equivalent)
gho fixup disk.gho cd      # Set spanned/CD bit
gho fixup disk.gho cd-     # Clear spanned/CD bit
gho fixup disk.gho span    # Toggle CD flag
```

Example output:

```
GHO Image Summary
  File Type:   1 (1=single, 9=span)
  Compression: 2 (Fast/Z1)
  Image ID:    0x12345678
  MBR Partitions: 1
    P0: type=0x83 LBA=2016 size=102240 (49.9 MB)
  Data Partitions: 1
    Partition 0: 3 spans, 42816212 bytes compressed data

Decompressing partition 0...
Saved partition 0: output/partition-0.img (51.4 MB)
```

## Library Usage

```go
package main

import (
    "bytes"
    "fmt"
    "log"

    "github.com/nyarime/gho"
)

func main() {
    img, err := gho.Open("disk.gho")
    if err != nil {
        log.Fatal(err)
    }
    defer img.Close()

    // Print summary
    fmt.Print(img.Summary())

    // Access MBR partition table
    for i, p := range img.MBRPartitions() {
        fmt.Printf("Partition %d: type=%#x, LBA=%d, size=%d sectors\n",
            i, p.Type, p.LBAStart, p.LBASize)
    }

    // Decompress partition 0 to memory
    var buf bytes.Buffer
    if err := img.DecompressPartition(0, &buf); err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Decompressed: %d bytes\n", buf.Len())
}
```

### Create a GHO Image

```go
w, _ := gho.Create("output.gho", gho.CompressionNone)
w.WriteTrack0(mbrData, 63)  // MBR + boot sectors
w.WritePartition(partFile)    // raw partition data (io.Reader)
w.Close()
```

### Modify Header Flags (ghofixup)

```go
// Set CD/spanned bit (like ghofixup.exe cd)
gho.ModifyHeader("disk.gho", gho.FixupCD)

// Toggle span flag
gho.ModifyHeader("disk.gho", gho.FixupSpan)
```

## GHO Format

Norton Ghost GHO files store disk/partition images with the following structure:

```
┌──────────────────────────────────────┐
│  File Header (512 bytes)             │  Magic: FE EF, compression type, ID
├──────────────────────────────────────┤
│  Record: Track 0 (type 0x0006)       │  6-byte header + MBR + boot sectors
├──────────────────────────────────────┤
│  Record: Partition (type 0x0603)     │  20-byte partition descriptor
├──────────────────────────────────────┤
│  FEEF Partition Header (512 bytes)   │  Per-partition compression settings
├──────────────────────────────────────┤
│  Compressed Blocks                   │  [2B len][block data]...
│  ├─ Block: 2B stored_len + data      │  32KB decompressed per block
│  ├─ Block: ...                       │
│  └─ Block: ...                       │
├──────────────────────────────────────┤
│  Record: Continuation (type 0x0703)  │  Additional data spans
├──────────────────────────────────────┤
│  (optional FEEF + more blocks)       │
├──────────────────────────────────────┤
│  Record: End (type 0x0023)           │  End of image marker
└──────────────────────────────────────┘
```

**Compression**: Each block is 32KB decompressed. The first byte of block data indicates the type:
- `0x01` → Uncompressed (raw data at offset 4)
- Other → Fast LZ compressed (custom LZ77 variant with 4096-entry hash table)

**Records**: Every record has a 10-byte header: `[4B type][4B magic 0x012F18D8][2B body_len]`

## Fast LZ Algorithm

The Fast LZ decompressor was reverse-engineered from Norton Ghost 11.5.1. It's a custom LZ77 variant using:

- 16-bit control words (bit 0 = literal, bit 1 = match reference)
- 4096-entry hash table with the hash function: `h = ((-24993 * (b2 ^ (16 * (b1 ^ (16 * b0))))) >> 4) & 0xFFF`
- 2-byte match tokens encoding hash index + extra length
- Minimum match length of 3 bytes

## Supported Formats

| Ghost Version | Compression | Status |
|---|---|---|
| 11.x–12.x | None (Z0) | ✅ |
| 11.x–12.x | Fast LZ (Z1) | ✅ |
| 11.x–12.x | High/zlib (Z2–Z9) | 🔧 Planned |
| Encrypted images | CRC-16 cipher | 🔧 Planned |
| Span files (.ghs) | Multi-file | 🔧 Planned |

## Contributing

Contributions welcome! Areas that need work:

- **Fast LZ compressor**: Currently writes uncompressed blocks; implementing the Fast LZ compressor requires exact hash table synchronization with the decompressor
- **Zlib/High compression** (Z3–Z9): Add `compress/flate` decompression path
- **Span file support**: Handle `.ghs` continuation files
- **Encryption**: CRC-16 stream cipher decryption
- **Full disk images**: Currently supports partition-level images; whole-disk with MBR rebuild is planned

## License

MIT — see [LICENSE](LICENSE).

## Credits

Reverse-engineered from Norton Ghost 11.5.1 by [Nyarime](https://github.com/nyarime).

Part of the [Nyarc](https://nyarc.bbie.net) firmware analysis toolkit.
