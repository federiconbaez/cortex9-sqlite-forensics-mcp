package domain

// Sources for records carved out of WAL frames.
const (
	SourceWALFrameCell = "wal-frame-cell" // live cell of an older or newer page version held in the WAL
	SourceWALFrameFree = "wal-frame-free" // freeblock or unallocated space of a WAL page version
)

// WALCandidate is a carved record found in one WAL frame.
type WALCandidate struct {
	Candidate
	FrameIndex int
	Committed  bool
}

// CarveWALFrames decodes every table-leaf page version stored in the WAL:
// its live cells (rows that may have been deleted or changed later) through
// the cell pointer array, plus its freeblocks and unallocated gap. Frames are
// processed whether or not SQLite would consider them valid; Committed tells
// which ones were part of a committed transaction. Page 1 versions use the
// 100-byte header offset.
func CarveWALFrames(w WAL, reservedBytes int, opt CarveOptions) ([]WALCandidate, CarveResult) {
	if opt.MinConfidence == 0 {
		opt.MinConfidence = ConfidenceLow
	}
	if opt.Encoding == 0 {
		opt.Encoding = EncodingUTF8
	}
	usable := int(w.Header.PageSize) - reservedBytes
	var out []WALCandidate
	var res CarveResult
	if usable < 480 || usable > int(w.Header.PageSize) {
		res.Warnings = append(res.Warnings, "usable size out of range; WAL not carved")
		return nil, res
	}
	for _, f := range w.Frames {
		page := f.Data[:usable]
		bp, err := ParseBTreePage(page, f.PageNo, usable)
		if err != nil || bp.Type != PageLeafTable {
			continue
		}
		res.PagesScanned++
		var cands []Candidate
		for _, off := range bp.CellPointers {
			c, ok := cellCandidate(page[off:usable], usable, opt.Encoding, &res)
			if !ok {
				continue
			}
			c.Offset, c.Source, c.Method = off, SourceWALFrameCell, MethodCellPointer
			cands = append(cands, c)
		}
		for _, c := range carveLivePage(page, bp, usable, opt.Encoding, &res) {
			c.Source = SourceWALFrameFree
			cands = append(cands, c)
		}
		for _, c := range cands {
			if c.Confidence < opt.MinConfidence {
				continue
			}
			if opt.MaxCandidates > 0 && len(out) >= opt.MaxCandidates {
				res.Truncated = true
				return out, res
			}
			c.PageNo = f.PageNo
			out = append(out, WALCandidate{Candidate: c, FrameIndex: f.Index, Committed: f.Committed})
		}
	}
	return out, res
}
