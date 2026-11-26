package domain

import "encoding/binary"

// B-tree page types (byte 0 of the page header).
const (
	PageInteriorIndex uint8 = 2
	PageInteriorTable uint8 = 5
	PageLeafIndex     uint8 = 10
	PageLeafTable     uint8 = 13
)

// Freeblock is a chain element of freed space inside a b-tree page.
type Freeblock struct {
	Offset int
	Size   int
}

// BTreePage is the decoded header of a b-tree page.
type BTreePage struct {
	PageNo          uint32
	HeaderOffset    int // 100 on page 1, 0 elsewhere
	Type            uint8
	FirstFreeblock  int
	CellCount       int
	ContentStart    int
	FragmentedBytes int
	RightChild      uint32
	CellPointers    []int
	Freeblocks      []Freeblock
	UnallocStart    int // first byte after the cell pointer array
	UnallocEnd      int // ContentStart (exclusive end of the unallocated gap)
}

// IsLeaf reports whether the page is a leaf page.
func (p BTreePage) IsLeaf() bool { return p.Type == PageLeafTable || p.Type == PageLeafIndex }

// HeaderLen is 8 for leaf pages and 12 for interior pages.
func (p BTreePage) HeaderLen() int {
	if p.IsLeaf() {
		return 8
	}
	return 12
}

// ParseBTreePage decodes the b-tree header of page pgno. usable is the usable
// page size; the page slice may include the reserved tail.
func ParseBTreePage(page []byte, pgno uint32, usable int) (BTreePage, error) {
	if usable <= 0 || usable > len(page) {
		return BTreePage{}, perr(ErrInvalidArgument, -1, "usable size %d for page of %d bytes", usable, len(page))
	}
	hdr := 0
	if pgno == 1 {
		hdr = HeaderSize
	}
	if hdr+8 > usable {
		return BTreePage{}, perr(ErrTruncated, int64(hdr), "page too small for a b-tree header")
	}
	p := BTreePage{PageNo: pgno, HeaderOffset: hdr, Type: page[hdr]}
	switch p.Type {
	case PageInteriorIndex, PageInteriorTable, PageLeafIndex, PageLeafTable:
	default:
		return BTreePage{}, perr(ErrBadPage, int64(hdr), "page type %d is not a b-tree page", p.Type)
	}
	be := binary.BigEndian
	p.FirstFreeblock = int(be.Uint16(page[hdr+1:]))
	p.CellCount = int(be.Uint16(page[hdr+3:]))
	p.ContentStart = int(be.Uint16(page[hdr+5:]))
	if p.ContentStart == 0 {
		p.ContentStart = 65536
	}
	p.FragmentedBytes = int(page[hdr+7]) //nolint:gosec // hdr+8 <= usable <= len(page) checked above
	hl := p.HeaderLen()
	if hdr+hl > usable {
		return BTreePage{}, perr(ErrTruncated, int64(hdr), "interior header exceeds page")
	}
	if !p.IsLeaf() {
		p.RightChild = be.Uint32(page[hdr+8:])
	}
	ptrStart := hdr + hl
	p.UnallocStart = ptrStart + 2*p.CellCount
	if p.UnallocStart > usable {
		return BTreePage{}, perr(ErrBadPage, int64(hdr+3), "%d cell pointers overflow the page", p.CellCount)
	}
	if p.ContentStart < p.UnallocStart || p.ContentStart > usable {
		return BTreePage{}, perr(ErrBadPage, int64(hdr+5), "cell content start %d outside [%d,%d]", p.ContentStart, p.UnallocStart, usable)
	}
	p.UnallocEnd = p.ContentStart
	p.CellPointers = make([]int, p.CellCount)
	for i := range p.CellPointers {
		off := int(be.Uint16(page[ptrStart+2*i:]))
		if off < p.ContentStart || off >= usable {
			return BTreePage{}, perr(ErrBadPage, int64(ptrStart+2*i), "cell pointer %d -> %d outside content area", i, off)
		}
		p.CellPointers[i] = off
	}
	prevEnd := p.ContentStart
	for off := p.FirstFreeblock; off != 0; {
		if off < prevEnd || off+4 > usable {
			return BTreePage{}, perr(ErrBadPage, int64(off), "freeblock out of order or out of page")
		}
		size := int(be.Uint16(page[off+2:]))
		if size < 4 || off+size > usable {
			return BTreePage{}, perr(ErrBadPage, int64(off), "freeblock size %d invalid", size)
		}
		p.Freeblocks = append(p.Freeblocks, Freeblock{Offset: off, Size: size})
		prevEnd = off + size
		off = int(be.Uint16(page[off:]))
	}
	return p, nil
}

// TableLeafCell is a decoded cell of a table b-tree leaf page.
type TableLeafCell struct {
	Offset      int
	PayloadSize uint64
	RowID       int64
	Local       []byte // payload bytes stored on this page
	Overflow    uint32 // first overflow page, 0 if none
	Len         int    // bytes occupied on the page
}

// MaxLocalTable is X in the SQLite file format: the largest payload a table
// leaf cell stores without spilling to overflow pages.
func MaxLocalTable(usable int) int { return usable - 35 }

func minLocal(usable int) int { return (usable-12)*32/255 - 23 }

// ParseTableLeafCell decodes a table-leaf cell at b[0]. b must extend to the
// end of the usable page area so local payload bounds can be checked.
func ParseTableLeafCell(b []byte, usable int) (TableLeafCell, error) {
	p, n1, err := ReadVarint(b)
	if err != nil {
		return TableLeafCell{}, perr(ErrBadPage, 0, "payload size: %v", err)
	}
	rid, n2, err := ReadVarint(b[n1:])
	if err != nil {
		return TableLeafCell{}, perr(ErrBadPage, int64(n1), "rowid: %v", err)
	}
	c := TableLeafCell{PayloadSize: p, RowID: int64(rid)} //nolint:gosec // rowid is a two's complement int64
	x := uint64(MaxLocalTable(usable))
	local := p
	if p > x {
		m := uint64(minLocal(usable))   //nolint:gosec // usable >= 480
		k := m + (p-m)%uint64(usable-4) //nolint:gosec // usable >= 480
		local = m
		if k <= x {
			local = k
		}
	}
	hdr := uint64(n1 + n2)
	need := hdr + local
	if p > x {
		need += 4
	}
	if need > uint64(len(b)) {
		return TableLeafCell{}, perr(ErrBadPage, 0, "cell needs %d bytes, %d available", need, len(b))
	}
	c.Local = b[hdr : hdr+local]
	if p > x {
		c.Overflow = binary.BigEndian.Uint32(b[hdr+local:])
	}
	c.Len = int(need)
	return c, nil
}
