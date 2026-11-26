package osfs_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/adapters/osfs"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/ports"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/ports/porttest"
)

func TestOSFileSourceContract(t *testing.T) {
	porttest.RunFileSource(t, func(t *testing.T, files map[string][]byte, maxBytes int64) (ports.FileSource, func(string) string) {
		dir := t.TempDir()
		for n, b := range files {
			if err := os.WriteFile(filepath.Join(dir, n), b, 0o400); err != nil {
				t.Fatal(err)
			}
		}
		src, err := osfs.New(dir, maxBytes)
		if err != nil {
			t.Fatal(err)
		}
		return src, func(n string) string { return filepath.Join(dir, n) }
	})
}

func TestOSFileSourceReadOnlyAndConfined(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	ev := filepath.Join(root, "ev.db")
	if err := os.WriteFile(ev, []byte("synthetic"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "x.db"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "x.db"), filepath.Join(root, "link.db")); err != nil {
		t.Fatal(err)
	}
	src, err := osfs.New(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	// a 0400 file can be hashed and read: proof that no write access is requested
	if _, _, err := src.Hash(ev); err != nil {
		t.Fatal(err)
	}
	if _, err := src.ReadAll(ev); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(outside, "x.db"), filepath.Join(root, "link.db"), filepath.Join(root, "..", filepath.Base(outside), "x.db")} {
		if _, _, err := src.Hash(p); !errors.Is(err, ports.ErrOutsideRoot) {
			t.Errorf("%s: err = %v", p, err)
		}
	}
	if _, err := src.ReadAll(root); !errors.Is(err, ports.ErrNotRegular) {
		t.Errorf("directory: %v", err)
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 2 {
		t.Fatalf("the source created files next to the evidence: %v", entries)
	}
	if _, err := osfs.New(filepath.Join(root, "missing"), 0); err == nil {
		t.Fatal("missing root must fail")
	}
	open, err := osfs.New("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := open.Hash(filepath.Join(outside, "x.db")); err != nil {
		t.Fatalf("no root means no confinement: %v", err)
	}
}
