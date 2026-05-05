// Command gho is a CLI tool for inspecting, extracting, creating, and fixing Norton Ghost GHO disk images.
//
// Usage:
//
//	gho info    <image.gho>                        Show image metadata
//	gho extract <image.gho> <dir>                  Extract decompressed partition data
//	gho create  <output.gho> <partition.img> [mbr]  Create a GHO image from a partition image
//	gho fixup   <image.gho> <cd|cd-|span>          Modify GHO header flags (like ghofixup.exe)
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
			fmt.Fprintln(os.Stderr, "usage: gho extract <image.gho> <output-dir> [--password=PWD] [--spanned]")
			os.Exit(1)
		}
		password, spanned := parseFlags(os.Args[4:])
		cmdExtract(os.Args[2], os.Args[3], password, spanned)
	case "create":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: gho create <output.gho> <partition.img> [mbr.bin]")
			os.Exit(1)
		}
		mbrPath := ""
		if len(os.Args) >= 5 {
			mbrPath = os.Args[4]
		}
		cmdCreate(os.Args[2], os.Args[3], mbrPath)
	case "fixup":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: gho fixup <image.gho> <cd|cd-|span>")
			os.Exit(1)
		}
		cmdFixup(os.Args[2], os.Args[3])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `gho — Norton Ghost GHO image tool

Usage:
  gho info    <image.gho>                          Show image metadata and partition layout
  gho extract <image.gho> <out-dir> [options]      Extract decompressed partition images
  gho create  <output.gho> <partition.img> [mbr]   Create a GHO from partition image
  gho fixup   <image.gho> <cd|cd-|span>            Modify header flags (ghofixup.exe equivalent)

Extract options:
  --password=PWD   Decrypt encrypted images
  --spanned        Auto-discover .ghs span files

Fixup modes:
  cd     Set the spanned/CD bit (offset 584)
  cd-    Clear the spanned/CD bit
  span   Toggle the CD flag (offset 55)

`)
}

func parseFlags(args []string) (password string, spanned bool) {
	for _, arg := range args {
		if strings.HasPrefix(arg, "--password=") {
			password = strings.TrimPrefix(arg, "--password=")
		}
		if arg == "--spanned" {
			spanned = true
		}
	}
	return
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

func cmdExtract(ghoPath, outDir, password string, spanned bool) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var img *gho.Image
	var err error
	if spanned {
		img, err = gho.OpenSpanned(ghoPath)
	} else {
		img, err = gho.Open(ghoPath)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer img.Close()

	if password != "" {
		img.SetPassword(password)
	}

	if img.IsEncrypted() && password == "" {
		fmt.Fprintln(os.Stderr, "warning: image is encrypted, use --password=PWD to decrypt")
	}

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

func cmdCreate(ghoPath, partPath, mbrPath string) {
	w, err := gho.Create(ghoPath, gho.CompressionFast)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating GHO: %v\n", err)
		os.Exit(1)
	}

	// Write MBR/Track 0 if provided
	if mbrPath != "" {
		mbrData, err := os.ReadFile(mbrPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading MBR: %v\n", err)
			os.Exit(1)
		}
		sectors := byte(len(mbrData) / 512)
		if sectors == 0 {
			sectors = 1
		}
		if err := w.WriteTrack0(mbrData, sectors); err != nil {
			fmt.Fprintf(os.Stderr, "error writing Track 0: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Wrote Track 0: %d bytes (%d sectors)\n", len(mbrData), sectors)
	}

	// Write partition data
	partFile, err := os.Open(partPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening partition: %v\n", err)
		os.Exit(1)
	}
	defer partFile.Close()

	fi, _ := partFile.Stat()
	fmt.Printf("Compressing partition: %s (%.1f MB)...\n", partPath, float64(fi.Size())/1024/1024)

	if err := w.WritePartition(partFile); err != nil {
		fmt.Fprintf(os.Stderr, "error writing partition: %v\n", err)
		os.Exit(1)
	}

	if err := w.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "error closing GHO: %v\n", err)
		os.Exit(1)
	}

	outFi, _ := os.Stat(ghoPath)
	fmt.Printf("Created: %s (%.1f MB, ratio %.1f%%)\n", ghoPath,
		float64(outFi.Size())/1024/1024,
		float64(outFi.Size())/float64(fi.Size())*100)
}

func cmdFixup(ghoPath, mode string) {
	if err := gho.ModifyHeader(ghoPath, mode); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Fixed up %s: mode=%s\n", ghoPath, mode)
}
