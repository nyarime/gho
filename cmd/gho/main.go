// Command gho is a CLI tool for inspecting and extracting Norton Ghost GHO disk images.
//
// Usage:
//
//	gho info <image.gho>            Show image metadata
//	gho extract <image.gho> <dir>   Extract decompressed partition data
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nyarime/gho"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "info":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: gho info <image.gho>")
			os.Exit(1)
		}
		cmdInfo(os.Args[2])
	case "extract":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: gho extract <image.gho> <output-dir>")
			os.Exit(1)
		}
		cmdExtract(os.Args[2], os.Args[3])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `gho — Norton Ghost GHO image tool

Usage:
  gho info    <image.gho>             Show image metadata and partition layout
  gho extract <image.gho> <out-dir>   Extract decompressed partition images

`)
}

func cmdInfo(path string) {
	img, err := gho.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer img.Close()

	fmt.Print(img.Summary())

	// Show Track 0 / MBR details
	parts := img.MBRPartitions()
	if len(parts) > 0 {
		fmt.Println("\nMBR Partition Table:")
		for i, p := range parts {
			sizeMB := float64(p.LBASize) * 512 / 1024 / 1024
			fmt.Printf("  %d: status=%#02x type=%#02x LBA=%d-%d (%.1f MB)\n",
				i, p.Status, p.Type, p.LBAStart, p.LBAStart+p.LBASize-1, sizeMB)
		}
	}
}

func cmdExtract(ghoPath, outDir string) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	img, err := gho.Open(ghoPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer img.Close()

	fmt.Print(img.Summary())

	// Save Track 0 / MBR
	if len(img.Track0) > 0 {
		mbrPath := filepath.Join(outDir, "track0.bin")
		if err := os.WriteFile(mbrPath, img.Track0, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "warning: writing track0: %v\n", err)
		} else {
			fmt.Printf("Saved Track 0: %s (%d bytes)\n", mbrPath, len(img.Track0))
		}
	}

	// Extract each partition
	for i := range img.Partitions {
		fmt.Printf("Decompressing partition %d...\n", i)
		var buf bytes.Buffer
		if err := img.DecompressPartition(i, &buf); err != nil {
			fmt.Fprintf(os.Stderr, "error decompressing partition %d: %v\n", i, err)
			continue
		}

		outPath := filepath.Join(outDir, fmt.Sprintf("partition-%d.img", i))
		if err := os.WriteFile(outPath, buf.Bytes(), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing partition %d: %v\n", i, err)
			continue
		}
		fmt.Printf("Saved partition %d: %s (%.1f MB)\n", i, outPath,
			float64(buf.Len())/1024/1024)
	}
}
