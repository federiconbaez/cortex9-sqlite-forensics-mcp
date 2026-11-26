package app_test

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/app"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/domain"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/fakes"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/ports"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/synth"
)

type env struct {
	svc     *app.Service
	files   *fakes.Files
	custody *fakes.Custody
}

func newEnv(t *testing.T) env {
	t.Helper()
	dir := t.TempDir()
	fx, err := synth.BuildFreelistDB(dir, 300, 180)
	if err != nil {
		t.Fatal(err)
	}
	w, err := synth.BuildWALDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	f := fakes.NewFiles()
	for name, p := range map[string]string{"/ev/freelist.db": fx.Path, "/ev/main.db": w.DBPath, "/ev/main.db-wal": w.WALPath} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		f.Put(name, b)
	}
	f.Put("/ev/junk.bin", []byte("not sqlite at all, synthetic junk bytes for error paths ............................................................."))
	c := &fakes.Custody{}
	return env{
		svc:   &app.Service{Files: f, Clock: &fakes.Clock{T: time.Date(2026, 11, 25, 23, 0, 0, 0, time.UTC), Step: time.Second}, Custody: c},
		files: f, custody: c,
	}
}

func (e env) chain(t *testing.T) []domain.CustodyEntry {
	t.Helper()
	all, _ := e.custody.All()
	if err := domain.VerifyCustodyChain(all); err != nil {
		t.Fatal(err)
	}
	return all
}

func TestEveryToolVerifiesIntegrityAndRecordsCustody(t *testing.T) {
	e := newEnv(t)
	check := func(name string, in app.Integrity, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !in.Unchanged || in.SHA256Before != in.SHA256After || len(in.SHA256Before) != 64 {
			t.Fatalf("%s integrity %+v", name, in)
		}
	}
	h, err := e.svc.EvidenceHash("/ev/freelist.db", "item SYN-1")
	check("evidence_hash", h.Integrity, err)
	if !h.ChainVerified || h.Entry.Seq != 1 || h.Entry.Note != "item SYN-1" {
		t.Fatalf("%+v", h)
	}
	hd, err := e.svc.DBHeader("/ev/freelist.db")
	check("db_header", hd.Integrity, err)
	if hd.Header.PageSize != 4096 || hd.Header.FreelistPageCount == 0 || hd.WALMode {
		t.Fatalf("%+v", hd)
	}
	fl, err := e.svc.FreelistPages("/ev/freelist.db")
	check("freelist_pages", fl.Integrity, err)
	if !fl.Freelist.CountMatches {
		t.Fatalf("%+v", fl.Freelist)
	}
	rc, err := e.svc.RecoverCells("/ev/freelist.db", domain.ConfidenceLow, 0)
	check("recover_cells", rc.Integrity, err)
	if len(rc.Carve.Candidates) == 0 || rc.Carve.Candidates[0].Confidence != domain.ConfidenceHigh {
		t.Fatal("expected sorted candidates, high first")
	}
	lim, err := e.svc.RecoverCells("/ev/freelist.db", domain.ConfidenceHigh, 3)
	check("recover_cells limit", lim.Integrity, err)
	if len(lim.Carve.Candidates) != 3 || !lim.Carve.Truncated {
		t.Fatalf("limit not applied: %d", len(lim.Carve.Candidates))
	}
	tl, err := e.svc.Timeline("/ev/freelist.db", domain.TimelineWindow{}, 5)
	check("timeline", tl.Integrity, err)
	if len(tl.Events) != 5 || tl.Total <= 5 {
		t.Fatalf("timeline %d of %d", len(tl.Events), tl.Total)
	}
	wr, err := e.svc.WALFrames("/ev/main.db-wal", "/ev/main.db", 2)
	if err != nil || len(wr.Integrity) != 2 || !wr.Integrity[0].Unchanged || !wr.Integrity[1].Unchanged {
		t.Fatalf("wal %+v %v", wr.Integrity, err)
	}
	if wr.FramesShown != 2 || wr.TotalFrames <= 2 || !wr.ComparedDB || wr.WAL.CommitFrames != 3 {
		t.Fatalf("wal %+v", wr)
	}
	wo, err := e.svc.WALFrames("/ev/main.db-wal", "", 0)
	if err != nil || wo.ComparedDB || len(wo.Integrity) != 1 {
		t.Fatalf("wal only %+v %v", wo, err)
	}
	wc, err := e.svc.WALRecover("/ev/main.db-wal", "/ev/main.db", domain.ConfidenceLow, 0)
	if err != nil || len(wc.Candidates) == 0 || len(wc.Integrity) != 2 || wc.Encoding != domain.EncodingUTF8 {
		t.Fatalf("wal_recover %d %v", len(wc.Candidates), err)
	}
	wn, err := e.svc.WALRecover("/ev/main.db-wal", "", domain.ConfidenceLow, 1)
	if err != nil || len(wn.Candidates) != 1 || len(wn.Integrity) != 1 {
		t.Fatalf("wal_recover no db %v", err)
	}
	all := e.chain(t)
	if len(all) != 12 {
		t.Fatalf("want 12 custody entries (one per input per call), got %d", len(all))
	}
	if all[3].Tool != "recover_cells" || all[7].Path != "/ev/main.db" {
		t.Fatalf("custody order %+v", all)
	}
}

func TestEvidenceChangedDuringAnalysisIsAnError(t *testing.T) {
	e := newEnv(t)
	orig, _ := e.files.ReadAll("/ev/freelist.db")
	e.files.AfterRead = func(p string) {
		b := append([]byte(nil), orig...)
		b[len(b)-1] ^= 0xff
		e.files.Put(p, b)
	}
	_, err := e.svc.DBHeader("/ev/freelist.db")
	if !errors.Is(err, app.ErrEvidenceChanged) {
		t.Fatalf("err = %v", err)
	}
	if len(e.chain(t)) != 0 {
		t.Fatal("a failed integrity check must not be recorded as a successful analysis")
	}
}

type flakyHash struct {
	*fakes.Files
	calls int
}

func (f *flakyHash) Hash(p string) (string, int64, error) {
	f.calls++
	h, n, err := f.Files.Hash(p)
	if f.calls == 2 {
		return h[:63] + "x", n, err
	}
	return h, n, err
}

func TestHashMismatchPaths(t *testing.T) {
	e := newEnv(t)
	e.svc.Files = &flakyHash{Files: e.files}
	if _, err := e.svc.EvidenceHash("/ev/freelist.db", ""); !errors.Is(err, app.ErrEvidenceChanged) {
		t.Fatalf("evidence_hash: %v", err)
	}
	e.svc.Files = &flakyHash{Files: e.files}
	if _, err := e.svc.DBHeader("/ev/freelist.db"); !errors.Is(err, app.ErrEvidenceChanged) {
		t.Fatalf("db_header read mismatch: %v", err)
	}
}

func TestErrorsPropagate(t *testing.T) {
	e := newEnv(t)
	cases := map[string]func() error{
		"empty path header": func() error { _, err := e.svc.DBHeader(""); return err },
		"empty path hash":   func() error { _, err := e.svc.EvidenceHash("", ""); return err },
		"missing hash":      func() error { _, err := e.svc.EvidenceHash("/ev/nope", ""); return err },
		"missing header":    func() error { _, err := e.svc.DBHeader("/ev/nope"); return err },
		"junk header":       func() error { _, err := e.svc.DBHeader("/ev/junk.bin"); return err },
		"junk freelist":     func() error { _, err := e.svc.FreelistPages("/ev/junk.bin"); return err },
		"junk recover":      func() error { _, err := e.svc.RecoverCells("/ev/junk.bin", 0, 0); return err },
		"junk timeline":     func() error { _, err := e.svc.Timeline("/ev/junk.bin", domain.TimelineWindow{}, 0); return err },
		"junk wal":          func() error { _, err := e.svc.WALFrames("/ev/junk.bin", "", 0); return err },
		"missing wal":       func() error { _, err := e.svc.WALFrames("/ev/nope", "", 0); return err },
		"wal with junk db":  func() error { _, err := e.svc.WALFrames("/ev/main.db-wal", "/ev/junk.bin", 0); return err },
		"walrec junk":       func() error { _, err := e.svc.WALRecover("/ev/junk.bin", "", 0, 0); return err },
		"walrec missing":    func() error { _, err := e.svc.WALRecover("/ev/nope", "", 0, 0); return err },
		"walrec junk db":    func() error { _, err := e.svc.WALRecover("/ev/main.db-wal", "/ev/junk.bin", 0, 0); return err },
		"wal with no db":    func() error { _, err := e.svc.WALFrames("/ev/main.db-wal", "/ev/nope", 0); return err },
		"bad window": func() error {
			_, err := e.svc.Timeline("/ev/freelist.db", domain.TimelineWindow{From: time.Now(), To: time.Now().Add(-time.Hour)}, 0)
			return err
		},
	}
	for name, f := range cases {
		if err := f(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if err := cases["missing header"](); !errors.Is(err, ports.ErrNotFound) {
		t.Errorf("missing file must wrap ports.ErrNotFound: %v", err)
	}
	if err := cases["junk header"](); !errors.Is(err, domain.ErrBadMagic) {
		t.Errorf("junk must wrap domain.ErrBadMagic: %v", err)
	}
	e.custody.AppendErr = errors.New("disk full")
	if _, err := e.svc.DBHeader("/ev/freelist.db"); err == nil {
		t.Error("custody failure must fail the call")
	}
	if _, err := e.svc.EvidenceHash("/ev/freelist.db", ""); err == nil {
		t.Error("custody failure must fail evidence_hash")
	}
	if e.svc.Now().IsZero() {
		t.Error("Now")
	}
}
