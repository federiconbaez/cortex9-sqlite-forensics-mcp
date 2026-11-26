// Package app implements the forensic use cases on top of the ports. Every
// use case verifies evidence integrity before and after analysis and appends
// one entry to the chain-of-custody log.
package app

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/domain"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/ports"
)

// ErrEvidenceChanged means an input file's hash changed while it was analysed.
var ErrEvidenceChanged = errors.New("evidence changed during analysis")

// Service wires the use cases to their ports.
type Service struct {
	Files   ports.FileSource
	Clock   ports.Clock
	Custody ports.CustodyLog
}

// Integrity reports the before/after hashes of one input file.
type Integrity struct {
	Path         string `json:"path"`
	Size         int64  `json:"size"`
	SHA256Before string `json:"sha256_before"`
	SHA256After  string `json:"sha256_after"`
	Unchanged    bool   `json:"unchanged"`
}

// evidence is a loaded, hash-verified input.
type evidence struct {
	path   string
	bytes  []byte
	before string
	size   int64
}

func (s *Service) load(path string) (evidence, error) {
	if path == "" {
		return evidence{}, fmt.Errorf("%w: path is required", domain.ErrInvalidArgument)
	}
	before, size, err := s.Files.Hash(path)
	if err != nil {
		return evidence{}, err
	}
	b, err := s.Files.ReadAll(path)
	if err != nil {
		return evidence{}, err
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != before {
		return evidence{}, fmt.Errorf("%w: %s read bytes hash %s, file hashed %s", ErrEvidenceChanged, path, got, before)
	}
	return evidence{path: path, bytes: b, before: before, size: size}, nil
}

// finish re-hashes the file, records custody and returns the integrity report.
func (s *Service) finish(tool, note string, ev evidence) (Integrity, error) {
	after, size, err := s.Files.Hash(ev.path)
	if err != nil {
		return Integrity{}, err
	}
	in := Integrity{Path: ev.path, Size: size, SHA256Before: ev.before, SHA256After: after, Unchanged: after == ev.before && size == ev.size}
	if !in.Unchanged {
		return in, fmt.Errorf("%w: %s %s -> %s", ErrEvidenceChanged, ev.path, ev.before, after)
	}
	if _, err := s.record(tool, note, ev.path, size, after); err != nil {
		return in, err
	}
	return in, nil
}

func (s *Service) record(tool, note, path string, size int64, sum string) (domain.CustodyEntry, error) {
	last, ok, err := s.Custody.Last()
	if err != nil {
		return domain.CustodyEntry{}, fmt.Errorf("custody log: %w", err)
	}
	var prev *domain.CustodyEntry
	if ok {
		prev = &last
	}
	e, err := domain.NextCustodyEntry(prev, domain.CustodyEntry{
		Time: s.Clock.Now(), Tool: tool, Path: path, Size: size, SHA256: sum, Note: note,
	})
	if err != nil {
		return domain.CustodyEntry{}, err
	}
	if err := s.Custody.Append(e); err != nil {
		return domain.CustodyEntry{}, fmt.Errorf("custody log: %w", err)
	}
	return e, nil
}

// EvidenceHashResult is the outcome of evidence_hash.
type EvidenceHashResult struct {
	Integrity     Integrity           `json:"integrity"`
	Entry         domain.CustodyEntry `json:"custody_entry"`
	ChainLength   int                 `json:"chain_length"`
	ChainVerified bool                `json:"chain_verified"`
}

// EvidenceHash hashes a file, appends a custody entry and verifies the chain.
func (s *Service) EvidenceHash(path, note string) (EvidenceHashResult, error) {
	if path == "" {
		return EvidenceHashResult{}, fmt.Errorf("%w: path is required", domain.ErrInvalidArgument)
	}
	before, size, err := s.Files.Hash(path)
	if err != nil {
		return EvidenceHashResult{}, err
	}
	after, size2, err := s.Files.Hash(path)
	if err != nil {
		return EvidenceHashResult{}, err
	}
	in := Integrity{Path: path, Size: size, SHA256Before: before, SHA256After: after, Unchanged: before == after && size == size2}
	if !in.Unchanged {
		return EvidenceHashResult{Integrity: in}, fmt.Errorf("%w: %s", ErrEvidenceChanged, path)
	}
	e, err := s.record("evidence_hash", note, path, size, before)
	if err != nil {
		return EvidenceHashResult{Integrity: in}, err
	}
	all, err := s.Custody.All()
	if err != nil {
		return EvidenceHashResult{Integrity: in}, err
	}
	verr := domain.VerifyCustodyChain(all)
	return EvidenceHashResult{Integrity: in, Entry: e, ChainLength: len(all), ChainVerified: verr == nil}, verr
}

// HeaderResult is the outcome of db_header.
type HeaderResult struct {
	Integrity Integrity     `json:"integrity"`
	Header    domain.Header `json:"header"`
	Encoding  string        `json:"encoding"`
	Usable    int           `json:"usable_size"`
	Pages     uint32        `json:"page_count"`
	WALMode   bool          `json:"wal_mode"`
}

// DBHeader parses the 100-byte database header.
func (s *Service) DBHeader(path string) (HeaderResult, error) {
	ev, err := s.load(path)
	if err != nil {
		return HeaderResult{}, err
	}
	h, err := domain.ParseHeader(ev.bytes)
	if err != nil {
		return HeaderResult{}, err
	}
	in, err := s.finish("db_header", "", ev)
	return HeaderResult{
		Integrity: in, Header: h, Encoding: h.EncodingName(), Usable: h.UsableSize(),
		Pages: domain.PageCount(h, len(ev.bytes)), WALMode: h.WriteVersion == 2 && h.ReadVersion == 2,
	}, err
}

// WALResult is the outcome of wal_frames.
type WALResult struct {
	Integrity   []Integrity             `json:"integrity"`
	WAL         domain.WAL              `json:"wal"`
	Pages       []domain.WALPageSummary `json:"pages"`
	ComparedDB  bool                    `json:"compared_with_db"`
	FramesShown int                     `json:"frames_shown"`
	TotalFrames int                     `json:"total_frames"`
}

// WALFrames parses a -wal file and, if dbPath is set, compares its newest
// committed page versions with the main database.
func (s *Service) WALFrames(walPath, dbPath string, maxFrames int) (WALResult, error) {
	wev, err := s.load(walPath)
	if err != nil {
		return WALResult{}, err
	}
	w, err := domain.ParseWAL(wev.bytes)
	if err != nil {
		return WALResult{}, err
	}
	var db []byte
	var ps uint32
	var dev *evidence
	if dbPath != "" {
		d, err := s.load(dbPath)
		if err != nil {
			return WALResult{}, err
		}
		h, err := domain.ParseHeader(d.bytes)
		if err != nil {
			return WALResult{}, fmt.Errorf("main database: %w", err)
		}
		db, ps, dev = d.bytes, h.PageSize, &d
	}
	res := WALResult{WAL: w, Pages: domain.SummarizeWALPages(w, db, ps), ComparedDB: dev != nil, TotalFrames: len(w.Frames)}
	if maxFrames > 0 && len(res.WAL.Frames) > maxFrames {
		res.WAL.Frames = res.WAL.Frames[:maxFrames]
	}
	res.FramesShown = len(res.WAL.Frames)
	in, err := s.finish("wal_frames", "", wev)
	res.Integrity = append(res.Integrity, in)
	if err != nil {
		return res, err
	}
	if dev != nil {
		in, err := s.finish("wal_frames", "main database for "+walPath, *dev)
		res.Integrity = append(res.Integrity, in)
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

// FreelistResult is the outcome of freelist_pages.
type FreelistResult struct {
	Integrity Integrity       `json:"integrity"`
	Freelist  domain.Freelist `json:"freelist"`
}

// FreelistPages walks the freelist trunk and leaf pages.
func (s *Service) FreelistPages(path string) (FreelistResult, error) {
	ev, h, err := s.loadDB(path)
	if err != nil {
		return FreelistResult{}, err
	}
	fl, err := domain.WalkFreelist(ev.bytes, h)
	if err != nil {
		return FreelistResult{}, err
	}
	in, err := s.finish("freelist_pages", "", ev)
	return FreelistResult{Integrity: in, Freelist: fl}, err
}

func (s *Service) loadDB(path string) (evidence, domain.Header, error) {
	ev, err := s.load(path)
	if err != nil {
		return evidence{}, domain.Header{}, err
	}
	h, err := domain.ParseHeader(ev.bytes)
	if err != nil {
		return evidence{}, domain.Header{}, err
	}
	return ev, h, nil
}

// carve walks the freelist (tolerating corruption) and carves the image.
func carve(ev evidence, h domain.Header, opt domain.CarveOptions) domain.CarveResult {
	fl, err := domain.WalkFreelist(ev.bytes, h)
	var warn []string
	if err != nil {
		warn = append(warn, "freelist walk failed, partial freelist used: "+err.Error())
	}
	res := domain.CarveDatabase(ev.bytes, h, fl, opt)
	res.Warnings = append(warn, res.Warnings...)
	domain.SortCandidates(res.Candidates)
	return res
}

// RecoverResult is the outcome of recover_cells.
type RecoverResult struct {
	Integrity Integrity          `json:"integrity"`
	Carve     domain.CarveResult `json:"carve"`
	Encoding  uint32             `json:"encoding"`
}

// RecoverCells carves deleted record candidates.
func (s *Service) RecoverCells(path string, minConf domain.Confidence, limit int) (RecoverResult, error) {
	ev, h, err := s.loadDB(path)
	if err != nil {
		return RecoverResult{}, err
	}
	res := carve(ev, h, domain.CarveOptions{MinConfidence: minConf, MaxCandidates: limit})
	in, err := s.finish("recover_cells", "", ev)
	return RecoverResult{Integrity: in, Carve: res, Encoding: h.TextEncoding}, err
}

// TimelineResult is the outcome of timeline.
type TimelineResult struct {
	Integrity Integrity              `json:"integrity"`
	Window    domain.TimelineWindow  `json:"window"`
	Events    []domain.TimelineEvent `json:"events"`
	Total     int                    `json:"total"`
}

// Timeline extracts timestamp-looking values from carved records.
func (s *Service) Timeline(path string, w domain.TimelineWindow, limit int) (TimelineResult, error) {
	if w.From.IsZero() && w.To.IsZero() {
		w = domain.DefaultWindow()
	}
	if w.To.Before(w.From) {
		return TimelineResult{}, fmt.Errorf("%w: window ends before it starts", domain.ErrInvalidArgument)
	}
	ev, h, err := s.loadDB(path)
	if err != nil {
		return TimelineResult{}, err
	}
	res := carve(ev, h, domain.CarveOptions{})
	events := domain.BuildTimeline(res.Candidates, w)
	out := TimelineResult{Window: w, Events: events, Total: len(events)}
	if limit > 0 && len(out.Events) > limit {
		out.Events = out.Events[:limit]
	}
	in, err := s.finish("timeline", "", ev)
	out.Integrity = in
	return out, err
}

// Now exposes the clock for adapters that need a timestamp.
func (s *Service) Now() time.Time { return s.Clock.Now() }
