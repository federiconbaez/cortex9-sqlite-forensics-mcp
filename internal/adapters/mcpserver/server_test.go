package mcpserver_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/adapters/custodyjsonl"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/adapters/mcpserver"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/adapters/osfs"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/adapters/sysclock"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/app"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/synth"
)

type fixture struct {
	evDir, custody string
	freelist       string
	db, wal        string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	ev := t.TempDir()
	fx, err := synth.BuildFreelistDB(ev, 300, 180)
	if err != nil {
		t.Fatal(err)
	}
	w, err := synth.BuildWALDB(ev)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(ev, "live.db"))
	_ = os.Remove(filepath.Join(ev, "live.db-wal"))
	_ = os.Remove(filepath.Join(ev, "live.db-shm"))
	return fixture{evDir: ev, custody: filepath.Join(t.TempDir(), "custody.jsonl"), freelist: fx.Path, db: w.DBPath, wal: w.WALPath}
}

func listDir(t *testing.T, dir string) string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	return strings.Join(names, ",")
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) map[string]any {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if res.IsError {
		t.Fatalf("%s: tool error %+v", name, res.Content)
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func exercise(t *testing.T, cs *mcp.ClientSession, fx fixture) {
	t.Helper()
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range tools.Tools {
		names = append(names, tl.Name)
		if tl.Name != "evidence_hash" && (tl.Annotations == nil || !tl.Annotations.ReadOnlyHint) {
			t.Errorf("%s must be annotated read-only", tl.Name)
		}
	}
	if strings.Join(names, ",") != "db_header,evidence_hash,freelist_pages,recover_cells,timeline,wal_frames" {
		t.Fatalf("tools %v", names)
	}
	before := listDir(t, fx.evDir)

	h := call(t, cs, "evidence_hash", map[string]any{"path": fx.freelist, "note": "SYN-1"})
	if h["chain_verified"] != true {
		t.Fatalf("%v", h)
	}
	hd := call(t, cs, "db_header", map[string]any{"path": fx.freelist})
	if hd["page_size"].(float64) != 4096 || hd["text_encoding"] != "UTF-8" || hd["integrity"].(map[string]any)["unchanged"] != true {
		t.Fatalf("%v", hd)
	}
	fl := call(t, cs, "freelist_pages", map[string]any{"path": fx.freelist})
	if fl["count_matches"] != true {
		t.Fatalf("%v", fl)
	}
	rc := call(t, cs, "recover_cells", map[string]any{"path": fx.freelist, "min_confidence": "high", "limit": 5})
	cands := rc["candidates"].([]any)
	if len(cands) != 5 || rc["truncated"] != true {
		t.Fatalf("%v", rc["count"])
	}
	first := cands[0].(map[string]any)
	if first["confidence"] != "high" {
		t.Fatalf("%v", first)
	}
	found := false
	for _, v := range first["values"].([]any) {
		if s, ok := v.(map[string]any)["value"].(string); ok && strings.HasPrefix(s, "SYNTH-MSG-") {
			found = true
		}
	}
	if !found {
		t.Fatalf("carved record has no synthetic marker: %v", first)
	}
	tl := call(t, cs, "timeline", map[string]any{"path": fx.freelist, "limit": 3, "from": "2023-01-01T00:00:00Z", "to": "2024-12-31T00:00:00Z"})
	if len(tl["events"].([]any)) != 3 {
		t.Fatalf("%v", tl)
	}
	wf := call(t, cs, "wal_frames", map[string]any{"wal_path": fx.wal, "db_path": fx.db})
	if wf["commit_frames"].(float64) != 3 || wf["header"].(map[string]any)["checksum_valid"] != true || len(wf["integrity"].([]any)) != 2 {
		t.Fatalf("%v", wf)
	}
	// errors are tool errors, not protocol errors
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "db_header", Arguments: map[string]any{"path": filepath.Join(fx.evDir, "missing.db")}})
	if err != nil || !res.IsError {
		t.Fatalf("missing file: %+v %v", res, err)
	}
	res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "timeline", Arguments: map[string]any{"path": fx.freelist, "from": "yesterday"}})
	if err != nil || !res.IsError {
		t.Fatalf("bad from: %+v %v", res, err)
	}
	if after := listDir(t, fx.evDir); after != before {
		t.Fatalf("evidence directory changed: %s -> %s", before, after)
	}
}

func TestInMemoryServer(t *testing.T) {
	fx := newFixture(t)
	src, err := osfs.New(fx.evDir, 0)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := custodyjsonl.Open(fx.custody)
	if err != nil {
		t.Fatal(err)
	}
	srv := mcpserver.New(&app.Service{Files: src, Clock: sysclock.Clock{}, Custody: cl})
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ss.Close() }()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	exercise(t, cs, fx)
	all, _ := cl.All()
	if len(all) != 7 {
		t.Fatalf("custody entries %d", len(all))
	}
}

// TestStdioBinary builds the real command and drives it over stdio JSON-RPC.
func TestStdioBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "sqlite-forensics-mcp")
	build := exec.Command("go", "build", "-o", bin, "../../../cmd/sqlite-forensics-mcp")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	fx := newFixture(t)
	cmd := exec.Command(bin, "-custody-log", fx.custody, "-root", fx.evDir) //nolint:gosec // test binary
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "stdio-test", Version: "0"}, nil).Connect(context.Background(), &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	exercise(t, cs, fx)
	// confinement through the real binary
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "evidence_hash", Arguments: map[string]any{"path": "/etc/hostname"}})
	if err != nil || !res.IsError {
		t.Fatalf("path outside root must be refused: %+v %v", res, err)
	}
	_ = cs.Close()
	b, err := os.ReadFile(fx.custody)
	if err != nil || strings.Count(string(b), "\n") != 7 {
		t.Fatalf("custody log lines: %v\n%s", err, b)
	}
}
