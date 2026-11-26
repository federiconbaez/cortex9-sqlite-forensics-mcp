// Package mcpserver exposes the forensic use cases as MCP tools over the
// official Go SDK. It only translates arguments and results; all analysis
// lives in internal/app and internal/domain.
package mcpserver

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/app"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/domain"
)

// Version is reported to MCP clients.
const Version = "0.1.0"

// Input types (the SDK derives the JSON schema from them).
type (
	// PathInput selects one evidence file.
	PathInput struct {
		Path string `json:"path" jsonschema:"absolute path of the evidence file (opened read-only)"`
	}
	// HashInput is the evidence_hash input.
	HashInput struct {
		Path string `json:"path" jsonschema:"absolute path of the evidence file (opened read-only)"`
		Note string `json:"note,omitempty" jsonschema:"free text stored in the custody entry, e.g. case or item id"`
	}
	// WALInput is the wal_frames input.
	WALInput struct {
		WALPath   string `json:"wal_path" jsonschema:"path of the -wal file"`
		DBPath    string `json:"db_path,omitempty" jsonschema:"optional main database to compare pages with"`
		MaxFrames int    `json:"max_frames,omitempty" jsonschema:"limit the frames listed (0 = 500)"`
	}
	// RecoverInput is the recover_cells input.
	RecoverInput struct {
		Path          string `json:"path" jsonschema:"path of the database file"`
		MinConfidence string `json:"min_confidence,omitempty" jsonschema:"low, medium or high (default low)"`
		Limit         int    `json:"limit,omitempty" jsonschema:"maximum candidates (0 = 500)"`
	}
	// WALRecoverInput is the wal_recover input.
	WALRecoverInput struct {
		WALPath       string `json:"wal_path" jsonschema:"path of the -wal file"`
		DBPath        string `json:"db_path,omitempty" jsonschema:"optional main database (text encoding and reserved bytes)"`
		MinConfidence string `json:"min_confidence,omitempty" jsonschema:"low, medium or high (default low)"`
		Limit         int    `json:"limit,omitempty" jsonschema:"maximum candidates (0 = 500)"`
	}
	// TimelineInput is the timeline input.
	TimelineInput struct {
		Path  string `json:"path" jsonschema:"path of the database file"`
		From  string `json:"from,omitempty" jsonschema:"RFC 3339 start of the plausible window (default 2005-01-01)"`
		To    string `json:"to,omitempty" jsonschema:"RFC 3339 end of the plausible window (default 2035-12-31)"`
		Limit int    `json:"limit,omitempty" jsonschema:"maximum events (0 = 1000)"`
	}
)

func boolPtr(b bool) *bool { return &b }

func readOnly(title string) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{Title: title, ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: boolPtr(false)}
}

// New builds the MCP server with all tools registered.
func New(svc *app.Service) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "cortex9-sqlite-forensics-mcp", Version: Version}, nil)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "evidence_hash",
		Description: "SHA-256 of an evidence file (opened read-only) and an append-only, hash-chained chain-of-custody entry. Returns the entry and whether the whole chain verifies.",
		Annotations: &mcp.ToolAnnotations{Title: "Hash evidence", ReadOnlyHint: false, DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(false)},
	}, func(_ context.Context, _ *mcp.CallToolRequest, in HashInput) (*mcp.CallToolResult, any, error) {
		r, err := svc.EvidenceHash(in.Path, in.Note)
		if err != nil {
			return nil, nil, err
		}
		return nil, map[string]any{
			"integrity": r.Integrity, "custody_entry": entryDTO(r.Entry),
			"chain_length": r.ChainLength, "chain_verified": r.ChainVerified,
		}, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "db_header",
		Description: "Parse the 100-byte SQLite header: page size, encoding, freelist trunk and count, schema cookie, WAL mode, change counter, application id and warnings.",
		Annotations: readOnly("SQLite header"),
	}, func(_ context.Context, _ *mcp.CallToolRequest, in PathInput) (*mcp.CallToolResult, any, error) {
		r, err := svc.DBHeader(in.Path)
		if err != nil {
			return nil, nil, err
		}
		h := r.Header
		return nil, map[string]any{
			"integrity": r.Integrity, "page_size": h.PageSize, "usable_size": r.Usable, "page_count": r.Pages,
			"in_header_page_count": h.DatabaseSizePages, "in_header_size_valid": h.InHeaderSizeValid(),
			"write_version": h.WriteVersion, "read_version": h.ReadVersion, "wal_mode": r.WALMode,
			"reserved_bytes": h.ReservedBytes, "file_change_counter": h.FileChangeCounter,
			"first_freelist_trunk": h.FirstFreelistTrunk, "freelist_page_count": h.FreelistPageCount,
			"schema_cookie": h.SchemaCookie, "schema_format": h.SchemaFormat, "default_cache_size": h.DefaultCacheSize,
			"largest_root_page": h.LargestRootPage, "auto_vacuum": h.LargestRootPage != 0,
			"incremental_vacuum": h.IncrementalVacuum, "text_encoding": r.Encoding, "user_version": h.UserVersion,
			"application_id": fmt.Sprintf("0x%08x", h.ApplicationID), "version_valid_for": h.VersionValidFor,
			"sqlite_version_number": h.SQLiteVersionNumber, "warnings": nonNil(h.Warnings),
		}, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "wal_frames",
		Description: "Parse a SQLite -wal file: header, salts, checksum validity per frame (SQLite rules), commit frames, uncommitted and stale-salt frames, page versions, and which pages differ from the main database.",
		Annotations: readOnly("WAL frames"),
	}, func(_ context.Context, _ *mcp.CallToolRequest, in WALInput) (*mcp.CallToolResult, any, error) {
		maxFrames := in.MaxFrames
		if maxFrames <= 0 {
			maxFrames = 500
		}
		r, err := svc.WALFrames(in.WALPath, in.DBPath, maxFrames)
		if err != nil {
			return nil, nil, err
		}
		return nil, walDTO(r), nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "freelist_pages",
		Description: "Walk the freelist trunk and leaf pages, detecting cycles and out-of-range pages, and compare the walked count with the header.",
		Annotations: readOnly("Freelist pages"),
	}, func(_ context.Context, _ *mcp.CallToolRequest, in PathInput) (*mcp.CallToolResult, any, error) {
		r, err := svc.FreelistPages(in.Path)
		if err != nil {
			return nil, nil, err
		}
		trunks := make([]map[string]any, 0, len(r.Freelist.Trunks))
		for _, t := range r.Freelist.Trunks {
			trunks = append(trunks, map[string]any{"page": t.PageNo, "next": t.Next, "leaves": nonNilU32(t.Leaves)})
		}
		return nil, map[string]any{
			"integrity": r.Integrity, "trunks": trunks, "leaf_pages": nonNilU32(r.Freelist.LeafPages),
			"total_pages": r.Freelist.TotalPages, "header_count": r.Freelist.HeaderCount,
			"count_matches": r.Freelist.CountMatches, "warnings": nonNil(r.Freelist.Warnings),
		}, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "recover_cells",
		Description: "Carve deleted record candidates from freelist pages, freeblocks and unallocated space of table-leaf pages. Decodes varints and serial types; each candidate has page, offset, source, method, confidence and reasons. Overflow chains are not followed.",
		Annotations: readOnly("Recover deleted cells"),
	}, func(_ context.Context, _ *mcp.CallToolRequest, in RecoverInput) (*mcp.CallToolResult, any, error) {
		limit := in.Limit
		if limit <= 0 {
			limit = 500
		}
		r, err := svc.RecoverCells(in.Path, domain.ParseConfidence(in.MinConfidence), limit)
		if err != nil {
			return nil, nil, err
		}
		cands := make([]map[string]any, 0, len(r.Carve.Candidates))
		for _, c := range r.Carve.Candidates {
			cands = append(cands, candidateDTO(c, r.Encoding))
		}
		return nil, map[string]any{
			"integrity": r.Integrity, "candidates": cands, "count": len(cands), "truncated": r.Carve.Truncated,
			"pages_scanned": r.Carve.PagesScanned, "freelist_pages": r.Carve.FreelistPages, "live_leaf_pages": r.Carve.LivePages,
			"overflow_cells_skipped": r.Carve.OverflowCells, "warnings": nonNil(r.Carve.Warnings),
		}, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "timeline",
		Description: "Extract integer/real values from carved records that look like Unix (s/ms/us), Apple Cocoa (s/ns) or WebKit (us since 1601) timestamps inside a plausible window, sorted by time; ambiguous interpretations are flagged.",
		Annotations: readOnly("Deleted-record timeline"),
	}, func(_ context.Context, _ *mcp.CallToolRequest, in TimelineInput) (*mcp.CallToolResult, any, error) {
		var w domain.TimelineWindow
		var err error
		if in.From != "" || in.To != "" {
			w = domain.DefaultWindow()
			if in.From != "" {
				if w.From, err = time.Parse(time.RFC3339, in.From); err != nil {
					return nil, nil, fmt.Errorf("%w: from: %w", domain.ErrInvalidArgument, err)
				}
			}
			if in.To != "" {
				if w.To, err = time.Parse(time.RFC3339, in.To); err != nil {
					return nil, nil, fmt.Errorf("%w: to: %w", domain.ErrInvalidArgument, err)
				}
			}
		}
		limit := in.Limit
		if limit <= 0 {
			limit = 1000
		}
		r, err := svc.Timeline(in.Path, w, limit)
		if err != nil {
			return nil, nil, err
		}
		events := make([]map[string]any, 0, len(r.Events))
		for _, e := range r.Events {
			ev := map[string]any{
				"time_utc": e.Time.Format(time.RFC3339Nano), "format": e.Format, "column": e.Column,
				"page": e.PageNo, "offset": e.Offset, "source": e.Source, "confidence": e.Confidence.String(),
				"ambiguous": e.Ambiguous,
			}
			if e.IsReal {
				ev["raw"] = strconv.FormatFloat(e.RawReal, 'f', -1, 64)
			} else {
				ev["raw"] = strconv.FormatInt(e.RawInt, 10)
			}
			if e.HasRowID {
				ev["rowid"] = e.RowID
			}
			events = append(events, ev)
		}
		return nil, map[string]any{
			"integrity": r.Integrity, "window_from": r.Window.From.Format(time.RFC3339),
			"window_to": r.Window.To.Format(time.RFC3339), "events": events, "total": r.Total,
		}, nil
	})
	mcp.AddTool(s, &mcp.Tool{
		Name:        "wal_recover",
		Description: "Carve records from every table-leaf page version stored in a -wal file: live cells of older versions (rows later deleted or edited), freeblocks and unallocated space. Each candidate names its WAL frame and whether that frame was committed.",
		Annotations: readOnly("Recover records from WAL"),
	}, func(_ context.Context, _ *mcp.CallToolRequest, in WALRecoverInput) (*mcp.CallToolResult, any, error) {
		limit := in.Limit
		if limit <= 0 {
			limit = 500
		}
		r, err := svc.WALRecover(in.WALPath, in.DBPath, domain.ParseConfidence(in.MinConfidence), limit)
		if err != nil {
			return nil, nil, err
		}
		cands := make([]map[string]any, 0, len(r.Candidates))
		for _, c := range r.Candidates {
			m := candidateDTO(c.Candidate, r.Encoding)
			m["wal_frame"], m["frame_committed"] = c.FrameIndex, c.Committed
			cands = append(cands, m)
		}
		return nil, map[string]any{
			"integrity": r.Integrity, "candidates": cands, "count": len(cands), "truncated": r.Carve.Truncated,
			"page_versions_scanned": r.Carve.PagesScanned, "overflow_cells_skipped": r.Carve.OverflowCells,
			"warnings": nonNil(r.Carve.Warnings),
		}, nil
	})
	return s
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilU32(s []uint32) []uint32 {
	if s == nil {
		return []uint32{}
	}
	return s
}

func entryDTO(e domain.CustodyEntry) map[string]any {
	return map[string]any{
		"seq": e.Seq, "time_utc": e.Time.UTC().Format(time.RFC3339Nano), "tool": e.Tool, "path": e.Path,
		"size": e.Size, "sha256": e.SHA256, "note": e.Note, "prev_hash": e.PrevHash, "entry_hash": e.EntryHash,
	}
}

func walDTO(r app.WALResult) map[string]any {
	h := r.WAL.Header
	frames := make([]map[string]any, 0, len(r.WAL.Frames))
	for _, f := range r.WAL.Frames {
		frames = append(frames, map[string]any{
			"index": f.Index, "offset": f.Offset, "page": f.PageNo, "commit_size": f.CommitSize,
			"is_commit": f.IsCommit(), "salt_match": f.SaltMatch, "checksum_ok": f.ChecksumOK,
			"valid": f.Valid, "committed": f.Committed,
		})
	}
	pages := make([]map[string]any, 0, len(r.Pages))
	for _, p := range r.Pages {
		pages = append(pages, map[string]any{
			"page": p.PageNo, "frames": p.FrameIndexes, "latest_committed_frame": p.LatestCommitted,
			"committed_versions": p.Versions, "status": string(p.Status),
		})
	}
	return map[string]any{
		"integrity": r.Integrity,
		"header": map[string]any{
			"magic": fmt.Sprintf("0x%08x", h.Magic), "big_endian_checksums": h.BigEndianSums,
			"format_version": h.FormatVersion, "page_size": h.PageSize, "checkpoint_seq": h.CheckpointSeq,
			"salt1": fmt.Sprintf("0x%08x", h.Salt1), "salt2": fmt.Sprintf("0x%08x", h.Salt2),
			"checksum_valid": h.ChecksumValid,
		},
		"total_frames": r.TotalFrames, "frames_shown": r.FramesShown,
		"valid_frames": r.WAL.ValidFrames, "committed_frames": r.WAL.CommittedFrames, "commit_frames": r.WAL.CommitFrames,
		"stale_salt_frames": r.WAL.StaleSaltFrames, "trailing_bytes": r.WAL.TrailingBytes,
		"frames": frames, "pages": pages, "compared_with_db": r.ComparedDB, "warnings": nonNil(r.WAL.Warnings),
	}
}

func candidateDTO(c domain.Candidate, enc uint32) map[string]any {
	vals := make([]map[string]any, 0, len(c.Record.Values))
	for _, v := range c.Record.Values {
		m := map[string]any{"type": v.Kind.String(), "serial_type": v.SerialType}
		switch v.Kind {
		case domain.KindInt:
			m["value"] = strconv.FormatInt(v.Int, 10)
		case domain.KindReal:
			if math.IsNaN(v.Real) || math.IsInf(v.Real, 0) {
				m["value"] = strconv.FormatFloat(v.Real, 'g', -1, 64)
			} else {
				m["value"] = v.Real
			}
		case domain.KindText:
			s, ok := domain.DecodeText(v.Bytes, enc)
			m["value"], m["valid_encoding"] = s, ok
		case domain.KindBlob:
			b := v.Bytes
			if len(b) > 256 {
				b = b[:256]
				m["truncated"] = true
			}
			m["hex"], m["length"] = hex.EncodeToString(b), len(v.Bytes)
		}
		vals = append(vals, m)
	}
	out := map[string]any{
		"page": c.PageNo, "offset": c.Offset, "length": c.Length, "source": c.Source, "method": c.Method,
		"confidence": c.Confidence.String(), "values": vals, "reasons": nonNil(c.Reasons),
	}
	if c.HasRowID {
		out["rowid"] = c.RowID
	}
	return out
}
