package domain

import "sort"

// Confidence grades a carved record candidate.
type Confidence int

// Confidence levels, ordered.
const (
	ConfidenceLow Confidence = iota + 1
	ConfidenceMedium
	ConfidenceHigh
)

func (c Confidence) String() string {
	switch c {
	case ConfidenceHigh:
		return "high"
	case ConfidenceMedium:
		return "medium"
	default:
		return "low"
	}
}

// ParseConfidence maps "low"/"medium"/"high" to a level (default low).
func ParseConfidence(s string) Confidence {
	switch s {
	case "high":
		return ConfidenceHigh
	case "medium":
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

// Carve sources.
const (
	SourceFreedPageCell  = "freelist-page-cell" // freed leaf page, via its stale cell pointer array
	SourceFreedPageScan  = "freelist-page-scan" // freed page, byte scan
	SourceUnallocated    = "unallocated"        // gap between cell pointers and content area of a live page
	SourceFreeblock      = "freeblock"          // freeblock chain of a live page
	MethodCellPointer    = "cell-pointer"       // decoded through an existing cell pointer
	MethodFullCellScan   = "full-cell-scan"     // payload size + rowid + record found by scanning
	MethodRecordOnlyScan = "record-only-scan"   // record header found; cell prefix overwritten
)

// Candidate is a carved record.
type Candidate struct {
	PageNo     uint32
	Offset     int // offset inside the page
	Length     int
	Source     string
	Method     string
	Confidence Confidence
	HasRowID   bool
	RowID      int64
	Record     Record
	Reasons    []string // why the confidence is not higher
}

// CarveOptions tunes the carver.
type CarveOptions struct {
	MinConfidence Confidence
	MaxCandidates int // 0 = unlimited
	Encoding      uint32
}

// CarveResult is the outcome of carving a database image.
type CarveResult struct {
	Candidates    []Candidate
	PagesScanned  int
	FreelistPages int
	LivePages     int
	Truncated     bool // MaxCandidates reached
	OverflowCells int  // cells that spill to overflow pages (not followed)
	SkippedPages  []uint32
	Warnings      []string
}

// CarveDatabase carves record candidates from freelist pages and from the
// unallocated space and freeblocks of live table-leaf pages. It never follows
// overflow chains: such cells are counted and skipped.
func CarveDatabase(db []byte, h Header, fl Freelist, opt CarveOptions) CarveResult {
	if opt.MinConfidence == 0 {
		opt.MinConfidence = ConfidenceLow
	}
	if opt.Encoding == 0 {
		opt.Encoding = h.TextEncoding
	}
	usable := h.UsableSize()
	res := CarveResult{}
	free := map[uint32]bool{}
	for _, t := range fl.Trunks {
		free[t.PageNo] = true
	}
	for _, l := range fl.LeafPages {
		free[l] = true
	}
	add := func(c Candidate) bool {
		if c.Confidence < opt.MinConfidence {
			return true
		}
		if opt.MaxCandidates > 0 && len(res.Candidates) >= opt.MaxCandidates {
			res.Truncated = true
			return false
		}
		res.Candidates = append(res.Candidates, c)
		return true
	}
	n := PageCount(h, len(db))
	for pg := uint32(1); pg <= n; pg++ {
		page, err := PageBytes(db, h.PageSize, pg)
		if err != nil {
			res.SkippedPages = append(res.SkippedPages, pg)
			continue
		}
		page = page[:usable]
		var cands []Candidate
		switch {
		case free[pg] && isTrunk(fl, pg):
			res.FreelistPages++
			// the trunk array overwrote the start; scan the rest
			start := 8 + 4*len(trunkLeaves(fl, pg))
			cands = scanRegion(page, pg, start, usable, SourceFreedPageScan, false, opt.Encoding, usable, &res)
		case free[pg]:
			res.FreelistPages++
			cands = carveFreedPage(page, pg, usable, opt.Encoding, &res)
		default:
			bp, err := ParseBTreePage(page, pg, usable)
			if err != nil || bp.Type != PageLeafTable {
				continue
			}
			res.LivePages++
			cands = carveLivePage(page, bp, usable, opt.Encoding, &res)
		}
		res.PagesScanned++
		for _, c := range cands {
			if !add(c) {
				return res
			}
		}
	}
	return res
}

func isTrunk(fl Freelist, pg uint32) bool {
	for _, t := range fl.Trunks {
		if t.PageNo == pg {
			return true
		}
	}
	return false
}

func trunkLeaves(fl Freelist, pg uint32) []uint32 {
	for _, t := range fl.Trunks {
		if t.PageNo == pg {
			return t.Leaves
		}
	}
	return nil
}

// carveFreedPage uses the stale cell pointer array when the freed page still
// parses as a table leaf, scans its freeblocks, then scans the remaining
// unclaimed bytes of the content area.
func carveFreedPage(page []byte, pg uint32, usable int, enc uint32, res *CarveResult) []Candidate {
	bp, err := ParseBTreePage(page, pg, usable)
	if err != nil || bp.Type != PageLeafTable {
		return scanRegion(page, pg, 0, usable, SourceFreedPageScan, false, enc, usable, res)
	}
	var out []Candidate
	claimed := make([]bool, usable)
	claim := func(from, to int) {
		for i := from; i < to && i < usable; i++ {
			claimed[i] = true
		}
	}
	for _, off := range bp.CellPointers {
		c, ok := cellCandidate(page[off:usable], usable, enc, res)
		if !ok {
			continue
		}
		c.PageNo, c.Offset, c.Source, c.Method = pg, off, SourceFreedPageCell, MethodCellPointer
		out = append(out, c)
		claim(off, off+c.Length)
	}
	for _, fb := range bp.Freeblocks {
		out = append(out, carveFreeblock(page, pg, fb, enc, usable, res)...)
		claim(fb.Offset, fb.Offset+fb.Size)
	}
	start := -1
	for i := bp.UnallocStart; i <= usable; i++ {
		if i < usable && !claimed[i] {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			out = append(out, scanRegion(page, pg, start, i, SourceFreedPageScan, false, enc, usable, res)...)
			start = -1
		}
	}
	return out
}

func carveLivePage(page []byte, bp BTreePage, usable int, enc uint32, res *CarveResult) []Candidate {
	out := scanRegion(page, bp.PageNo, bp.UnallocStart, bp.UnallocEnd, SourceUnallocated, false, enc, usable, res)
	for _, fb := range bp.Freeblocks {
		out = append(out, carveFreeblock(page, bp.PageNo, fb, enc, usable, res)...)
	}
	return out
}

// scanRegion slides over page[start:end] looking for whole table-leaf cells
// and, when recordOnly is set, for bare records whose cell prefix was lost.
func scanRegion(page []byte, pg uint32, start, end int, source string, recordOnly bool, enc uint32, usable int, res *CarveResult) []Candidate {
	var out []Candidate
	for off := start; off < end; {
		if c, ok := cellCandidate(page[off:end], usable, enc, res); ok {
			c.PageNo, c.Offset, c.Source, c.Method = pg, off, source, MethodFullCellScan
			if c.Confidence == ConfidenceHigh {
				c.Confidence = ConfidenceMedium
				c.Reasons = append(c.Reasons, "found by byte scan, not through a cell pointer")
			}
			out = append(out, c)
			off += c.Length
			continue
		}
		if recordOnly {
			if r, err := ParseRecord(page[off:end], false); err == nil && plausibleRecord(r, 2) && textValid(r, enc) {
				out = append(out, Candidate{
					PageNo: pg, Offset: off, Length: r.Len(), Source: source,
					Method: MethodRecordOnlyScan, Confidence: ConfidenceLow, Record: r,
					Reasons: []string{"cell prefix (payload size, rowid) overwritten by the freeblock link"},
				})
				off += r.Len()
				continue
			}
		}
		off++
	}
	return out
}

func textValid(r Record, enc uint32) bool {
	for _, v := range r.Values {
		if v.Kind == KindText {
			if _, ok := DecodeText(v.Bytes, enc); !ok {
				return false
			}
		}
	}
	return true
}

// cellCandidate tries to decode a non-overflow table-leaf cell at b[0].
func cellCandidate(b []byte, usable int, enc uint32, res *CarveResult) (Candidate, bool) {
	if len(b) < 4 || b[0] == 0 {
		return Candidate{}, false
	}
	cell, err := ParseTableLeafCell(b, usable)
	if err != nil {
		return Candidate{}, false
	}
	if cell.Overflow != 0 {
		res.OverflowCells++
		return Candidate{}, false
	}
	r, err := ParseRecord(cell.Local, true)
	if err != nil || !plausibleRecord(r, 1) {
		return Candidate{}, false
	}
	c := Candidate{Length: cell.Len, HasRowID: true, RowID: cell.RowID, Record: r, Confidence: ConfidenceHigh}
	if cell.RowID <= 0 {
		c.Confidence = ConfidenceMedium
		c.Reasons = append(c.Reasons, "non-positive rowid")
	}
	if len(r.Values) < 2 {
		c.Confidence = ConfidenceMedium
		c.Reasons = append(c.Reasons, "single column")
	}
	if !textValid(r, enc) {
		c.Confidence = ConfidenceLow
		c.Reasons = append(c.Reasons, "text not valid in the database encoding")
	}
	return c, true
}

// plausibleRecord rejects records that are structurally valid but almost
// certainly noise: no columns, or nothing but NULL/constant columns.
func plausibleRecord(r Record, minCols int) bool {
	if len(r.Values) < minCols || r.HeaderSize < 2 {
		return false
	}
	for _, v := range r.Values {
		if v.SerialType != 0 && v.SerialType != 8 && v.SerialType != 9 {
			return true
		}
	}
	return false
}

// SortCandidates orders candidates by confidence (desc), then page, offset.
func SortCandidates(c []Candidate) {
	sort.SliceStable(c, func(i, j int) bool {
		if c[i].Confidence != c[j].Confidence {
			return c[i].Confidence > c[j].Confidence
		}
		if c[i].PageNo != c[j].PageNo {
			return c[i].PageNo < c[j].PageNo
		}
		return c[i].Offset < c[j].Offset
	})
}

// carveFreeblock first tries to rebuild a cell whose header start was
// overwritten by the 4-byte freeblock link, then scans the rest.
func carveFreeblock(page []byte, pg uint32, fb Freeblock, enc uint32, usable int, res *CarveResult) []Candidate {
	start := fb.Offset + 4
	var out []Candidate
	if c, ok := reconstructFreeblockCell(page, fb, enc); ok {
		c.PageNo = pg
		out = append(out, c)
		start = fb.Offset + fb.Size
	}
	return append(out, scanRegion(page, pg, start, fb.Offset+fb.Size, SourceFreeblock, true, enc, usable, res)...)
}

// reconstructFreeblockCell assumes the freeblock is exactly one freed cell
// (not coalesced). With a 2-byte payload size and 1-byte rowid the lost byte
// is the record header size (prefix 3); with 1+1 bytes the header size and
// the first serial type are lost (prefix 2) and the first column is assumed
// to be NULL, which is how an INTEGER PRIMARY KEY rowid alias is stored.
// The body must then fill the freeblock exactly, and the implied payload
// size must need exactly the varint length the guess assumes.
func reconstructFreeblockCell(page []byte, fb Freeblock, enc uint32) (Candidate, bool) {
	off, end := fb.Offset, fb.Offset+fb.Size
	for _, prefix := range []int{3, 2} {
		// the payload size varint length must agree with the prefix guess:
		// prefix 3 means a 2-byte varint (payload >= 128), prefix 2 a 1-byte one
		payload := fb.Size - prefix
		if (prefix == 3 && (payload < 128 || payload > 16383)) || (prefix == 2 && payload > 127) {
			continue
		}
		for hs := 2; hs < 128 && off+prefix+hs <= end; hs++ {
			var buf []byte
			if prefix == 3 {
				buf = append([]byte{byte(hs)}, page[off+4:off+3+hs]...)
			} else {
				if hs < 3 {
					continue
				}
				buf = append([]byte{byte(hs), 0x00}, page[off+4:off+2+hs]...)
			}
			buf = append(buf, page[off+prefix+hs:end]...)
			r, err := ParseRecord(buf, true)
			if err != nil || !plausibleRecord(r, 2) || !textValid(r, enc) {
				continue
			}
			reason := "record header size rebuilt from the freeblock size"
			if prefix == 2 {
				reason = "record header size and first serial type rebuilt; first column assumed NULL (rowid alias)"
			}
			return Candidate{
				Offset: off, Length: fb.Size, Source: SourceFreeblock, Method: MethodReconstructed,
				Confidence: ConfidenceLow, Record: r, Reasons: []string{reason},
			}, true
		}
	}
	return Candidate{}, false
}

// MethodReconstructed marks a freeblock cell whose header start was overwritten
// by the freeblock link and rebuilt from the freeblock size.
const MethodReconstructed = "header-reconstructed"
