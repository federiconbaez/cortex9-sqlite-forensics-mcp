// Package osfs is the read-only FileSource over the operating system. Files
// are opened with O_RDONLY only; nothing is ever created next to evidence.
package osfs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/ports"
)

// DefaultMaxBytes bounds how much evidence is loaded into memory (1 GiB).
const DefaultMaxBytes = 1 << 30

// Source implements ports.FileSource.
type Source struct {
	root     string // resolved allowed root ("" = no restriction)
	maxBytes int64
}

// New returns a Source. If root is non-empty every path must resolve (after
// symlinks) inside it.
func New(root string, maxBytes int64) (*Source, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	s := &Source{maxBytes: maxBytes}
	if root != "" {
		r, err := filepath.EvalSymlinks(root)
		if err != nil {
			return nil, fmt.Errorf("evidence root: %w", err)
		}
		if s.root, err = filepath.Abs(r); err != nil {
			return nil, fmt.Errorf("evidence root: %w", err)
		}
	}
	return s, nil
}

// open resolves, checks and opens path read-only.
func (s *Source) open(path string) (*os.File, int64, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, 0, fmt.Errorf("%s: %w", path, ports.ErrNotFound)
		}
		return nil, 0, err
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return nil, 0, err
	}
	if s.root != "" && abs != s.root && !strings.HasPrefix(abs, s.root+string(filepath.Separator)) {
		return nil, 0, fmt.Errorf("%s: %w", path, ports.ErrOutsideRoot)
	}
	f, err := os.OpenFile(abs, os.O_RDONLY, 0) //nolint:gosec // read-only open of an operator-chosen evidence path, confined to root when configured
	if err != nil {
		return nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, 0, fmt.Errorf("%s: %w", path, ports.ErrNotRegular)
	}
	if st.Size() > s.maxBytes {
		_ = f.Close()
		return nil, 0, fmt.Errorf("%s (%d bytes, limit %d): %w", path, st.Size(), s.maxBytes, ports.ErrTooLarge)
	}
	return f, st.Size(), nil
}

// Hash implements ports.FileSource by streaming the file.
func (s *Source) Hash(path string) (string, int64, error) {
	f, _, err := s.open(path)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, s.maxBytes+1))
	if err != nil {
		return "", 0, err
	}
	if n > s.maxBytes {
		return "", 0, fmt.Errorf("%s grew past the limit: %w", path, ports.ErrTooLarge)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// ReadAll implements ports.FileSource; it returns an in-memory copy.
func (s *Source) ReadAll(path string) ([]byte, error) {
	f, _, err := s.open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, s.maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > s.maxBytes {
		return nil, fmt.Errorf("%s grew past the limit: %w", path, ports.ErrTooLarge)
	}
	return b, nil
}
