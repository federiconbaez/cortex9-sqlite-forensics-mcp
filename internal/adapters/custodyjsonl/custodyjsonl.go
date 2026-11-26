// Package custodyjsonl stores the chain of custody as an append-only JSON
// Lines file. The file is opened O_APPEND; existing lines are never rewritten.
// On open the whole chain is verified and a broken chain refuses new entries.
package custodyjsonl

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"

	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/domain"
)

// Log implements ports.CustodyLog. Safe for concurrent use within a process.
type Log struct {
	mu      sync.Mutex
	path    string
	entries []domain.CustodyEntry
}

// Open loads and verifies an existing log (or starts an empty one).
func Open(path string) (*Log, error) {
	l := &Log{path: path}
	b, err := os.ReadFile(path) //nolint:gosec // operator-chosen custody log path
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for line := 1; sc.Scan(); line++ {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var e domain.CustodyEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("custody log line %d: %w", line, err)
		}
		l.entries = append(l.entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if err := domain.VerifyCustodyChain(l.entries); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return l, nil
}

// Last implements ports.CustodyLog.
func (l *Log) Last() (domain.CustodyEntry, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) == 0 {
		return domain.CustodyEntry{}, false, nil
	}
	return l.entries[len(l.entries)-1], true, nil
}

// Append implements ports.CustodyLog. The entry must link to the current tail.
func (l *Log) Append(e domain.CustodyEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	next := append(append([]domain.CustodyEntry(nil), l.entries...), e)
	if err := domain.VerifyCustodyChain(next); err != nil {
		return err
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600) //nolint:gosec // operator-chosen custody log path
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	l.entries = next
	return nil
}

// All implements ports.CustodyLog.
func (l *Log) All() ([]domain.CustodyEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]domain.CustodyEntry(nil), l.entries...), nil
}
