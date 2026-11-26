package fakes_test

import (
	"testing"

	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/fakes"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/ports"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/ports/porttest"
)

func TestFakeFilesContract(t *testing.T) {
	porttest.RunFileSource(t, func(_ *testing.T, files map[string][]byte, maxBytes int64) (ports.FileSource, func(string) string) {
		f := fakes.NewFiles()
		f.MaxBytes = maxBytes
		for n, b := range files {
			f.Put("/ev/"+n, b)
		}
		return f, func(n string) string { return "/ev/" + n }
	})
}

func TestFakeCustodyContract(t *testing.T) {
	porttest.RunCustodyLog(t, func(*testing.T) (ports.CustodyLog, func() (ports.CustodyLog, error)) {
		return &fakes.Custody{}, nil
	})
}
