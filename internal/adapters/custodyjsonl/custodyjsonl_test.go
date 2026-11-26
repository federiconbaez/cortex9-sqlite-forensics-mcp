package custodyjsonl_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/adapters/custodyjsonl"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/domain"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/ports"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/ports/porttest"
)

func TestJSONLCustodyContract(t *testing.T) {
	porttest.RunCustodyLog(t, func(t *testing.T) (ports.CustodyLog, func() (ports.CustodyLog, error)) {
		path := filepath.Join(t.TempDir(), "custody.jsonl")
		l, err := custodyjsonl.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		return l, func() (ports.CustodyLog, error) { return custodyjsonl.Open(path) }
	})
}

func TestJSONLCustodyDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custody.jsonl")
	l, err := custodyjsonl.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var prev *domain.CustodyEntry
	for i := 0; i < 3; i++ {
		e, err := domain.NextCustodyEntry(prev, domain.CustodyEntry{Time: time.Unix(int64(1700000000+i), 0), Tool: "db_header", Path: "/c/s.db", Size: 1, SHA256: strings.Repeat("0", 64)})
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Append(e); err != nil {
			t.Fatal(err)
		}
		prev = &e
	}
	b, _ := os.ReadFile(path)
	if strings.Count(string(b), "\n") != 3 {
		t.Fatalf("want 3 lines, got %q", b)
	}
	tampered := strings.Replace(string(b), `"size":1`, `"size":2`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := custodyjsonl.Open(path); !errors.Is(err, domain.ErrChainBroken) {
		t.Fatalf("tampered log must not open: %v", err)
	}
	if err := os.WriteFile(path, []byte("{not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := custodyjsonl.Open(path); err == nil {
		t.Fatal("garbage must not open")
	}
	if _, err := custodyjsonl.Open(t.TempDir()); err == nil {
		t.Fatal("a directory is not a log")
	}
}
