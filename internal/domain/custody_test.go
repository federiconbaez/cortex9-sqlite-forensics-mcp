package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func chain(t *testing.T, n int) []CustodyEntry {
	t.Helper()
	var out []CustodyEntry
	var prev *CustodyEntry
	for i := 0; i < n; i++ {
		e, err := NextCustodyEntry(prev, CustodyEntry{
			Time: time.Date(2026, 11, 25, 12, 0, i, 0, time.FixedZone("ART", -3*3600)),
			Tool: "evidence_hash", Path: "/cases/synthetic.db", Size: int64(100 + i), SHA256: hashA, Note: "n",
		})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
		prev = &out[len(out)-1]
	}
	return out
}

func TestCustodyChain(t *testing.T) {
	c := chain(t, 4)
	if c[0].Seq != 1 || c[0].PrevHash != GenesisHash || c[1].PrevHash != c[0].EntryHash || c[3].Seq != 4 {
		t.Fatalf("%+v", c)
	}
	if c[0].Time.Location() != time.UTC {
		t.Fatal("times must be stored in UTC")
	}
	if err := VerifyCustodyChain(c); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCustodyChain(nil); err != nil {
		t.Fatal(err)
	}
}

func TestCustodyTamperDetection(t *testing.T) {
	mutations := map[string]func(e *CustodyEntry){
		"path":  func(e *CustodyEntry) { e.Path += "x" },
		"hash":  func(e *CustodyEntry) { e.SHA256 = strings.Repeat("b", 64) },
		"size":  func(e *CustodyEntry) { e.Size++ },
		"time":  func(e *CustodyEntry) { e.Time = e.Time.Add(time.Nanosecond) },
		"tool":  func(e *CustodyEntry) { e.Tool = "db_header" },
		"note":  func(e *CustodyEntry) { e.Note = "" },
		"seq":   func(e *CustodyEntry) { e.Seq = 9 },
		"prev":  func(e *CustodyEntry) { e.PrevHash = GenesisHash },
		"entry": func(e *CustodyEntry) { e.EntryHash = GenesisHash },
	}
	for name, m := range mutations {
		t.Run(name, func(t *testing.T) {
			c := chain(t, 3)
			m(&c[1])
			err := VerifyCustodyChain(c)
			var ce *ChainError
			if !errors.Is(err, ErrChainBroken) || !errors.As(err, &ce) || ce.Index != 1 || ce.Error() == "" {
				t.Fatalf("err = %v", err)
			}
		})
	}
	c := chain(t, 3)
	c = append(c[:1], c[2:]...)
	if err := VerifyCustodyChain(c); !errors.Is(err, ErrChainBroken) {
		t.Fatal("removing an entry must break the chain")
	}
}

func TestCustodyCanonicalResistsFieldInjection(t *testing.T) {
	a := CustodyEntry{Tool: "t", Path: "a\n1", Note: "", SHA256: hashA}
	b := CustodyEntry{Tool: "t", Path: "a", Note: "1", SHA256: hashA}
	if ComputeEntryHash(a) == ComputeEntryHash(b) {
		t.Fatal("newline in a field must not collide with a field boundary")
	}
}

func TestNextCustodyEntryValidation(t *testing.T) {
	bad := []CustodyEntry{
		{Tool: "t", Path: "p", SHA256: "xyz"},
		{Tool: "t", Path: "p", SHA256: strings.ToUpper(hashA)},
		{Tool: "", Path: "p", SHA256: hashA},
		{Tool: "t", Path: "", SHA256: hashA},
	}
	for i, e := range bad {
		if _, err := NextCustodyEntry(nil, e); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("case %d: %v", i, err)
		}
	}
}
