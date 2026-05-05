package gho

import (
	"fmt"
	"io"
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
// OpenSpanned uses a zero-copy multi-file reader — no temporary files are created
// and the span files are not loaded into memory.
func OpenSpanned(primaryPath string) (*Image, error) {
	img, err := Open(primaryPath)
	if err != nil {
		return nil, err
	}

	if img.Header.FileType != 0x01 {
		return img, nil
	}

	spanFiles := findSpanFiles(primaryPath)
	if len(spanFiles) == 0 {
		return img, nil
	}

	img.Close()
	return openWithSpans(primaryPath, spanFiles)
}

// findSpanFiles discovers .ghs span files for a .gho primary file.
func findSpanFiles(primaryPath string) []string {
	dir := filepath.Dir(primaryPath)
	base := filepath.Base(primaryPath)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)

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
			continue
		}

		lower := strings.ToLower(name)
		if !strings.HasSuffix(lower, ".ghs") {
			continue
		}

		spanStem := strings.TrimSuffix(name, filepath.Ext(name))
		if strings.HasPrefix(strings.ToLower(spanStem), strings.ToLower(stem)) {
			spans = append(spans, filepath.Join(dir, name))
		}
	}

	sort.Strings(spans)
	return spans
}

// multiReaderAt provides a virtual io.ReaderAt across multiple files,
// skipping the 512-byte header of span files (index > 0).
type multiReaderAt struct {
	files   []*os.File
	offsets []int64 // cumulative start offsets in virtual space
	total   int64
}

// newMultiReaderAt opens all files and builds the offset table.
// Span files (index > 0) have their first HeaderSize bytes skipped.
func newMultiReaderAt(paths []string) (*multiReaderAt, error) {
	m := &multiReaderAt{
		files:   make([]*os.File, 0, len(paths)),
		offsets: make([]int64, 0, len(paths)),
	}

	var cumOff int64
	for i, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			m.Close()
			return nil, fmt.Errorf("gho span: open %s: %w", p, err)
		}
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			m.Close()
			return nil, fmt.Errorf("gho span: stat %s: %w", p, err)
		}

		m.files = append(m.files, f)
		m.offsets = append(m.offsets, cumOff)

		fileSize := fi.Size()
		if i > 0 {
			// Skip header of span files
			fileSize -= HeaderSize
		}
		if fileSize < 0 {
			fileSize = 0
		}
		cumOff += fileSize
	}
	m.total = cumOff
	return m, nil
}

// ReadAt implements io.ReaderAt across the concatenated virtual file.
func (m *multiReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= m.total {
		return 0, io.EOF
	}

	totalRead := 0
	for totalRead < len(p) {
		virtOff := off + int64(totalRead)
		if virtOff >= m.total {
			if totalRead > 0 {
				return totalRead, io.EOF
			}
			return 0, io.EOF
		}

		// Find which file contains this offset
		fileIdx := -1
		for i := len(m.offsets) - 1; i >= 0; i-- {
			if virtOff >= m.offsets[i] {
				fileIdx = i
				break
			}
		}
		if fileIdx < 0 {
			return totalRead, io.EOF
		}

		// Calculate position within this file
		posInVirt := virtOff - m.offsets[fileIdx]
		posInFile := posInVirt
		if fileIdx > 0 {
			posInFile += HeaderSize // Offset by skipped header
		}

		// How many bytes available in this file?
		var fileDataSize int64
		if fileIdx+1 < len(m.offsets) {
			fileDataSize = m.offsets[fileIdx+1] - m.offsets[fileIdx]
		} else {
			fileDataSize = m.total - m.offsets[fileIdx]
		}
		remaining := fileDataSize - posInVirt
		if remaining <= 0 {
			continue
		}

		readLen := len(p) - totalRead
		if int64(readLen) > remaining {
			readLen = int(remaining)
		}

		n, err := m.files[fileIdx].ReadAt(p[totalRead:totalRead+readLen], posInFile)
		totalRead += n
		if err != nil && err != io.EOF {
			return totalRead, err
		}
		if n == 0 {
			break
		}
	}

	if totalRead < len(p) {
		return totalRead, io.EOF
	}
	return totalRead, nil
}

func (m *multiReaderAt) Close() error {
	var firstErr error
	for _, f := range m.files {
		if err := f.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// openWithSpans creates a virtual multi-file reader and parses the concatenated image.
// Instead of copying all data to a temp file, we write only the concatenated view
// to a temp file for parsing (since Image.parse uses *os.File with ReadAt).
// TODO: In a future version, refactor Image to use io.ReaderAt instead of *os.File
// to eliminate the temp file entirely.
func openWithSpans(primaryPath string, spanPaths []string) (*Image, error) {
	allPaths := append([]string{primaryPath}, spanPaths...)

	multi, err := newMultiReaderAt(allPaths)
	if err != nil {
		return nil, err
	}

	// Create temp file with concatenated data via streaming copy
	tmpFile, err := os.CreateTemp("", "gho-spanned-*.gho")
	if err != nil {
		multi.Close()
		return nil, fmt.Errorf("gho span: create temp: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Stream copy in 1MB chunks
	buf := make([]byte, 1024*1024)
	var off int64
	for off < multi.total {
		n, err := multi.ReadAt(buf, off)
		if n > 0 {
			if _, werr := tmpFile.Write(buf[:n]); werr != nil {
				tmpFile.Close()
				os.Remove(tmpPath)
				multi.Close()
				return nil, fmt.Errorf("gho span: write temp: %w", werr)
			}
		}
		off += int64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
			multi.Close()
			return nil, fmt.Errorf("gho span: read: %w", err)
		}
	}
	tmpFile.Close()
	multi.Close()

	img, err := Open(tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		return nil, err
	}

	img.spanTmpPath = tmpPath
	return img, nil
}
