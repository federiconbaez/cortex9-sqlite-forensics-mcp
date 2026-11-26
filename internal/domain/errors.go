// Package domain holds the pure SQLite forensic parsers: byte slices in,
// typed values out. It performs no I/O and never mutates its inputs.
package domain

import (
	"errors"
	"fmt"
)

// Sentinel error kinds. Every parse error wraps exactly one of them so
// callers can branch with errors.Is.
var (
	ErrTruncated       = errors.New("truncated input")
	ErrBadMagic        = errors.New("bad magic")
	ErrBadPageSize     = errors.New("invalid page size")
	ErrBadVarint       = errors.New("malformed varint")
	ErrBadRecord       = errors.New("malformed record")
	ErrBadPage         = errors.New("malformed b-tree page")
	ErrBadWAL          = errors.New("malformed WAL")
	ErrFreelistCorrupt = errors.New("corrupt freelist")
	ErrChainBroken     = errors.New("custody chain broken")
	ErrInvalidArgument = errors.New("invalid argument")
)

// ParseError locates a failure inside the input.
type ParseError struct {
	Kind   error  // one of the sentinel errors above
	Offset int64  // byte offset in the input where the problem was detected (-1 if unknown)
	Detail string // human readable detail
}

func (e *ParseError) Error() string {
	if e.Offset >= 0 {
		return fmt.Sprintf("%v at offset %d: %s", e.Kind, e.Offset, e.Detail)
	}
	return fmt.Sprintf("%v: %s", e.Kind, e.Detail)
}

// Unwrap lets errors.Is match the sentinel kind.
func (e *ParseError) Unwrap() error { return e.Kind }

func perr(kind error, off int64, format string, args ...any) error {
	return &ParseError{Kind: kind, Offset: off, Detail: fmt.Sprintf(format, args...)}
}
