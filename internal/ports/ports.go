// Package ports declares the interfaces the application needs from the
// outside world. Adapters implement them; hand-written fakes live in
// internal/fakes and both are checked by the shared contract in porttest.
package ports

import (
	"errors"
	"time"

	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/domain"
)

// Port errors.
var (
	ErrNotFound    = errors.New("evidence file not found")
	ErrNotRegular  = errors.New("evidence path is not a regular file")
	ErrTooLarge    = errors.New("evidence file exceeds the configured size limit")
	ErrOutsideRoot = errors.New("evidence path is outside the allowed root")
)

// FileSource gives read-only access to evidence files.
type FileSource interface {
	// Hash streams the file and returns its lowercase hex SHA-256 and size.
	Hash(path string) (sha256 string, size int64, err error)
	// ReadAll returns an in-memory copy of the file contents.
	ReadAll(path string) ([]byte, error)
}

// Clock supplies the time stamped on custody entries.
type Clock interface {
	Now() time.Time
}

// CustodyLog is an append-only chain-of-custody store.
type CustodyLog interface {
	// Last returns the newest entry, or ok=false when the log is empty.
	Last() (entry domain.CustodyEntry, ok bool, err error)
	// Append stores an entry already sealed with domain.NextCustodyEntry.
	Append(e domain.CustodyEntry) error
	// All returns every entry in order.
	All() ([]domain.CustodyEntry, error)
}
