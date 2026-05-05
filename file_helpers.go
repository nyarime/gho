package gho

import "os"

// createFile is a helper that creates a file for writing.
func createFile(path string) (*os.File, error) {
	return os.Create(path)
}
