package domain

import "encoding/binary"

// FreelistTrunk is one trunk page and the leaf pages it lists.
type FreelistTrunk struct {
	PageNo uint32
	Next   uint32
	Leaves []uint32
}

// Freelist is the result of walking the freelist.
type Freelist struct {
	Trunks       []FreelistTrunk
	LeafPages    []uint32
	TotalPages   int  // trunks + leaves actually walked
	HeaderCount  int  // freelist count declared in the header
	CountMatches bool // TotalPages == HeaderCount
	Warnings     []string
}

// Contains reports whether pgno is a trunk or leaf page of the freelist.
func (f Freelist) Contains(pgno uint32) bool {
	for _, t := range f.Trunks {
		if t.PageNo == pgno {
			return true
		}
	}
	for _, l := range f.LeafPages {
		if l == pgno {
			return true
		}
	}
	return false
}

// WalkFreelist follows the trunk chain starting at the header's first trunk
// page. It detects cycles and out-of-range page numbers instead of looping.
func WalkFreelist(db []byte, h Header) (Freelist, error) {
	fl := Freelist{HeaderCount: int(h.FreelistPageCount)}
	total := PageCount(h, len(db))
	seen := map[uint32]bool{}
	usable := h.UsableSize()
	if usable < 8 {
		return fl, perr(ErrInvalidArgument, -1, "usable size %d", usable)
	}
	maxLeaves := uint32(usable/4 - 2) //nolint:gosec // usable is positive and small
	for pg := h.FirstFreelistTrunk; pg != 0; {
		if pg > total {
			return fl, perr(ErrFreelistCorrupt, -1, "trunk page %d beyond %d pages", pg, total)
		}
		if seen[pg] {
			return fl, perr(ErrFreelistCorrupt, -1, "cycle at trunk page %d", pg)
		}
		seen[pg] = true
		page, err := PageBytes(db, h.PageSize, pg)
		if err != nil {
			return fl, err
		}
		t := FreelistTrunk{PageNo: pg, Next: binary.BigEndian.Uint32(page[0:])}
		n := binary.BigEndian.Uint32(page[4:])
		if n > maxLeaves {
			return fl, perr(ErrFreelistCorrupt, int64(pg-1)*int64(h.PageSize)+4, "trunk %d declares %d leaves, max %d", pg, n, maxLeaves)
		}
		for i := uint32(0); i < n; i++ {
			leaf := binary.BigEndian.Uint32(page[8+4*i:])
			if leaf == 0 || leaf > total {
				fl.Warnings = append(fl.Warnings, "leaf page number out of range skipped")
				continue
			}
			if seen[leaf] {
				return fl, perr(ErrFreelistCorrupt, -1, "page %d listed twice", leaf)
			}
			seen[leaf] = true
			t.Leaves = append(t.Leaves, leaf)
			fl.LeafPages = append(fl.LeafPages, leaf)
		}
		fl.Trunks = append(fl.Trunks, t)
		pg = t.Next
	}
	fl.TotalPages = len(seen)
	fl.CountMatches = fl.TotalPages == fl.HeaderCount
	if !fl.CountMatches {
		fl.Warnings = append(fl.Warnings, "walked page count differs from header freelist count")
	}
	return fl, nil
}
