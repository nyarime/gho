package gho

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// OpenSpanned opens a multi-file GHO image (primary .gho + span .ghs files).
//
// Norton Ghost splits large images into multiple files:
//   - image.gho  (FileType=0x01) — primary file with headers and initial data
//   - image.ghs  (FileType=0x09) — span continuation files
//
// The span files are auto-discovered in the same directory as the primary file,
// sorted by filename (which Ghost names sequentially).
//
// OpenSpanned concatenates all span files into a virtual single-file view
// and parses the result as a normal GHO image.
func OpenSpanned(primaryPath string) (*Image, error) {
	// Open primary file
	img, err := Open(primaryPath)
	if err != nil {
		return nil, err
	}

	// Check if this is already a complete (non-spanned) image
	if img.Header.FileType != 0x01 {
		return img, nil // Not a primary file, just return as-is
	}

	// Look for span files
	spanFiles := findSpanFiles(primaryPath)
	if len(spanFiles) == 0 {
		return img, nil // No spans found, single file
	}

	// Close the simple reader and reopen with span support
	img.Close()

	// Create concatenated reader
	return openWithSpans(primaryPath, spanFiles)
}

// findSpanFiles discovers .ghs span files for a .gho primary file.
// Ghost names spans sequentially: image.ghs, image.002.ghs, etc.
// We also handle: image.gho → image.ghs, image0001.ghs, image0002.ghs, etc.
func findSpanFiles(primaryPath string) []string {
	dir := filepath.Dir(primaryPath)
	base := filepath.Base(primaryPath)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)

	// Scan directory for matching span files
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var spans []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == base {
			continue // Skip primary file
		}

		// Match patterns:
		// stem.ghs, stem.001.ghs, stem0001.ghs, stemXXX.ghs
		lower := strings.ToLower(name)
		if !strings.HasSuffix(lower, ".ghs") {
			continue
		}

		spanStem := strings.TrimSuffix(name, filepath.Ext(name))
		// Must share the same base stem
		if strings.HasPrefix(strings.ToLower(spanStem), strings.ToLower(stem)) {
			spans = append(spans, filepath.Join(dir, name))
		}
	}

	sort.Strings(spans)
	return spans
}

// openWithSpans creates a concatenated file reader across primary + span files.
func openWithSpans(primaryPath string, spanPaths []string) (*Image, error) {
	// Build list of all files
	allPaths := append([]string{primaryPath}, spanPaths...)

	// Concatenate all files into memory (for simplicity; large images
	// should use a streaming approach in the future)
	var totalSize int64
	for _, p := range allPaths {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("gho span: stat %s: %w", p, err)
		}
		totalSize += fi.Size()
	}

	// Create a temp file with concatenated data
	tmpFile, err := os.CreateTemp("", "gho-spanned-*.gho")
	if err != nil {
		return nil, fmt.Errorf("gho span: create temp: %w", err)
	}
	tmpPath := tmpFile.Name()

	for i, p := range allPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
			return nil, fmt.Errorf("gho span: read %s: %w", p, err)
		}

		if i > 0 {
			// Skip the 512-byte header of span files
			if len(data) > HeaderSize {
				data = data[HeaderSize:]
			}
		}

		if _, err := tmpFile.Write(data); err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
			return nil, fmt.Errorf("gho span: write: %w", err)
		}
	}
	tmpFile.Close()

	// Open the concatenated file
	img, err := Open(tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		return nil, err
	}

	// Store tmpPath for cleanup
	img.spanTmpPath = tmpPath
	return img, nil
}
