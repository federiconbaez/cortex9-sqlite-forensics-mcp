// Package porttest is the shared contract every FileSource and CustodyLog
// implementation (hand-written fake and real adapter) must satisfy.
package porttest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/domain"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/ports"
)

// FileSourceFixture creates a FileSource holding the given files and returns
// the path under which each name is reachable.
type FileSourceFixture func(t *testing.T, files map[string][]byte, maxBytes int64) (ports.FileSource, func(name string) string)

// RunFileSource checks the FileSource contract.
func RunFileSource(t *testing.T, mk FileSourceFixture) {
	content := []byte("SYNTHETIC evidence bytes \x00\x01\x02")
	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])

	t.Run("hash and read agree", func(t *testing.T) {
		src, p := mk(t, map[string][]byte{"a.db": content}, 0)
		h, n, err := src.Hash(p("a.db"))
		if err != nil || h != want || n != int64(len(content)) {
			t.Fatalf("Hash = %s,%d,%v", h, n, err)
		}
		b, err := src.ReadAll(p("a.db"))
		if err != nil || string(b) != string(content) {
			t.Fatalf("ReadAll = %q,%v", b, err)
		}
		b[0] ^= 0xff // the copy is private
		h2, _, _ := src.Hash(p("a.db"))
		if h2 != want {
			t.Fatal("mutating the returned slice changed the evidence")
		}
	})
	t.Run("missing file", func(t *testing.T) {
		src, p := mk(t, map[string][]byte{}, 0)
		if _, _, err := src.Hash(p("nope.db")); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("Hash err = %v", err)
		}
		if _, err := src.ReadAll(p("nope.db")); !errors.Is(err, ports.ErrNotFound) {
			t.Fatalf("ReadAll err = %v", err)
		}
	})
	t.Run("size limit", func(t *testing.T) {
		src, p := mk(t, map[string][]byte{"big.db": make([]byte, 100)}, 10)
		if _, _, err := src.Hash(p("big.db")); !errors.Is(err, ports.ErrTooLarge) {
			t.Fatalf("Hash err = %v", err)
		}
		if _, err := src.ReadAll(p("big.db")); !errors.Is(err, ports.ErrTooLarge) {
			t.Fatalf("ReadAll err = %v", err)
		}
	})
}

// RunCustodyLog checks the CustodyLog contract. mk must return an empty log;
// reopen (optional) returns a log reloaded from the same storage.
func RunCustodyLog(t *testing.T, mk func(t *testing.T) (ports.CustodyLog, func() (ports.CustodyLog, error))) {
	entry := func(prev *domain.CustodyEntry, i int) domain.CustodyEntry {
		e, err := domain.NextCustodyEntry(prev, domain.CustodyEntry{
			Time: time.Date(2026, 11, 25, 23, 0, i, 0, time.UTC), Tool: "evidence_hash",
			Path: "/cases/synthetic.db", Size: 4096, SHA256: strings.Repeat("ab", 32),
		})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	t.Run("append and read back", func(t *testing.T) {
		l, reopen := mk(t)
		if _, ok, err := l.Last(); ok || err != nil {
			t.Fatalf("empty log Last = %v %v", ok, err)
		}
		e1 := entry(nil, 1)
		e2 := entry(&e1, 2)
		for _, e := range []domain.CustodyEntry{e1, e2} {
			if err := l.Append(e); err != nil {
				t.Fatal(err)
			}
		}
		last, ok, err := l.Last()
		if err != nil || !ok || last.EntryHash != e2.EntryHash {
			t.Fatalf("Last = %+v %v %v", last, ok, err)
		}
		all, err := l.All()
		if err != nil || len(all) != 2 || domain.VerifyCustodyChain(all) != nil {
			t.Fatalf("All = %d %v", len(all), err)
		}
		if reopen != nil {
			l2, err := reopen()
			if err != nil {
				t.Fatal(err)
			}
			all2, _ := l2.All()
			if len(all2) != 2 || all2[1].EntryHash != e2.EntryHash || domain.VerifyCustodyChain(all2) != nil {
				t.Fatalf("reopened log differs: %+v", all2)
			}
		}
	})
	t.Run("rejects unlinked entries", func(t *testing.T) {
		l, _ := mk(t)
		e1 := entry(nil, 1)
		if err := l.Append(e1); err != nil {
			t.Fatal(err)
		}
		orphan := entry(nil, 2) // links to genesis again
		if err := l.Append(orphan); !errors.Is(err, domain.ErrChainBroken) {
			t.Fatalf("err = %v", err)
		}
		all, _ := l.All()
		if len(all) != 1 {
			t.Fatal("rejected entry was stored")
		}
	})
}
