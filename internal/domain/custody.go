package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// GenesisHash is the PrevHash of the first custody entry.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// CustodyEntry is one append-only chain-of-custody record.
type CustodyEntry struct {
	Seq       uint64    `json:"seq"`
	Time      time.Time `json:"time"`
	Tool      string    `json:"tool"`
	Path      string    `json:"path"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	Note      string    `json:"note,omitempty"`
	PrevHash  string    `json:"prev_hash"`
	EntryHash string    `json:"entry_hash"`
}

// canonical is an unambiguous serialization: every string is quoted so
// embedded newlines cannot forge field boundaries.
func (e CustodyEntry) canonical() string {
	var b strings.Builder
	b.WriteString("cx9-custody-v1\n")
	b.WriteString(strconv.FormatUint(e.Seq, 10) + "\n")
	b.WriteString(e.Time.UTC().Format(time.RFC3339Nano) + "\n")
	for _, s := range []string{e.Tool, e.Path} {
		b.WriteString(strconv.Quote(s) + "\n")
	}
	b.WriteString(strconv.FormatInt(e.Size, 10) + "\n")
	b.WriteString(e.SHA256 + "\n")
	b.WriteString(strconv.Quote(e.Note) + "\n")
	b.WriteString(e.PrevHash + "\n")
	return b.String()
}

// ComputeEntryHash returns the SHA-256 of the canonical form (EntryHash excluded).
func ComputeEntryHash(e CustodyEntry) string {
	sum := sha256.Sum256([]byte(e.canonical()))
	return hex.EncodeToString(sum[:])
}

// NextCustodyEntry links e after prev (nil for the first entry) and seals it.
func NextCustodyEntry(prev *CustodyEntry, e CustodyEntry) (CustodyEntry, error) {
	if !sha256Hex.MatchString(e.SHA256) {
		return CustodyEntry{}, perr(ErrInvalidArgument, -1, "evidence hash must be 64 lowercase hex chars")
	}
	if e.Tool == "" || e.Path == "" {
		return CustodyEntry{}, perr(ErrInvalidArgument, -1, "tool and path are required")
	}
	e.Time = e.Time.UTC()
	if prev == nil {
		e.Seq, e.PrevHash = 1, GenesisHash
	} else {
		e.Seq, e.PrevHash = prev.Seq+1, prev.EntryHash
	}
	e.EntryHash = ComputeEntryHash(e)
	return e, nil
}

// ChainError reports the first entry that breaks the chain.
type ChainError struct {
	Index  int
	Reason string
}

func (e *ChainError) Error() string {
	return "custody chain broken at entry " + strconv.Itoa(e.Index) + ": " + e.Reason
}

// Unwrap lets errors.Is match ErrChainBroken.
func (e *ChainError) Unwrap() error { return ErrChainBroken }

// VerifyCustodyChain checks sequence numbers, prev-hash links and entry hashes.
func VerifyCustodyChain(entries []CustodyEntry) error {
	prev := GenesisHash
	for i, e := range entries {
		switch {
		case e.Seq != uint64(i)+1:
			return &ChainError{Index: i, Reason: "sequence gap"}
		case e.PrevHash != prev:
			return &ChainError{Index: i, Reason: "prev_hash does not match previous entry"}
		case ComputeEntryHash(e) != e.EntryHash:
			return &ChainError{Index: i, Reason: "entry_hash does not match content"}
		}
		prev = e.EntryHash
	}
	return nil
}
