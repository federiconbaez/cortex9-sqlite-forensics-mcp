// Package fakes holds hand-written in-memory implementations of the ports.
package fakes

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/domain"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/ports"
)

// Files is an in-memory FileSource. Mutate lets a test change a file between
// the hash and the read to simulate evidence tampering.
type Files struct {
	mu       sync.Mutex
	files    map[string][]byte
	MaxBytes int64
	// AfterRead, if set, runs after every ReadAll (used to simulate tampering).
	AfterRead func(path string)
	Reads     int
}

// NewFiles returns an empty fake file source.
func NewFiles() *Files { return &Files{files: map[string][]byte{}} }

// Put stores a copy of b at path.
func (f *Files) Put(path string, b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[path] = append([]byte(nil), b...)
}

func (f *Files) get(path string) ([]byte, error) {
	b, ok := f.files[path]
	if !ok {
		return nil, fmt.Errorf("%s: %w", path, ports.ErrNotFound)
	}
	if f.MaxBytes > 0 && int64(len(b)) > f.MaxBytes {
		return nil, fmt.Errorf("%s: %w", path, ports.ErrTooLarge)
	}
	return b, nil
}

// Hash implements ports.FileSource.
func (f *Files) Hash(path string) (string, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, err := f.get(path)
	if err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), int64(len(b)), nil
}

// ReadAll implements ports.FileSource.
func (f *Files) ReadAll(path string) ([]byte, error) {
	f.mu.Lock()
	b, err := f.get(path)
	var out []byte
	if err == nil {
		out = append([]byte(nil), b...)
		f.Reads++
	}
	hook := f.AfterRead
	f.mu.Unlock()
	if err == nil && hook != nil {
		hook(path)
	}
	return out, err
}

// Clock is a fake clock that advances by Step on every call.
type Clock struct {
	mu   sync.Mutex
	T    time.Time
	Step time.Duration
}

// Now implements ports.Clock.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.T
	c.T = c.T.Add(c.Step)
	return t
}

// Custody is an in-memory append-only custody log.
type Custody struct {
	mu        sync.Mutex
	entries   []domain.CustodyEntry
	AppendErr error
}

// Last implements ports.CustodyLog.
func (c *Custody) Last() (domain.CustodyEntry, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) == 0 {
		return domain.CustodyEntry{}, false, nil
	}
	return c.entries[len(c.entries)-1], true, nil
}

// Append implements ports.CustodyLog. It refuses entries that do not link to
// the current tail, like the real adapter.
func (c *Custody) Append(e domain.CustodyEntry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.AppendErr != nil {
		return c.AppendErr
	}
	if err := domain.VerifyCustodyChain(append(append([]domain.CustodyEntry(nil), c.entries...), e)); err != nil {
		return err
	}
	c.entries = append(c.entries, e)
	return nil
}

// All implements ports.CustodyLog.
func (c *Custody) All() ([]domain.CustodyEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]domain.CustodyEntry(nil), c.entries...), nil
}
