package domain

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestParseBTreeLeafPage(t *testing.T) {
	c1 := tableCell(1, txt("alpha"), num(10))
	c2 := tableCell(2, txt("beta"), num(20))
	p := leafPage(512, 2, c1, c2)
	bp, err := ParseBTreePage(p, 2, 512)
	if err != nil {
		t.Fatal(err)
	}
	if !bp.IsLeaf() || bp.HeaderLen() != 8 || bp.CellCount != 2 || bp.UnallocStart != 12 || bp.UnallocEnd != 512-len(c1)-len(c2) {
		t.Fatalf("unexpected %+v", bp)
	}
	cell, err := ParseTableLeafCell(p[bp.CellPointers[1]:], 512)
	if err != nil || cell.RowID != 2 || cell.Overflow != 0 || cell.Len != len(c2) {
		t.Fatalf("cell %+v err %v", cell, err)
	}
	r, err := ParseRecord(cell.Local, true)
	if err != nil || string(r.Values[0].Bytes) != "beta" {
		t.Fatalf("record %+v %v", r, err)
	}
}

func TestParseBTreePage1AndInterior(t *testing.T) {
	p := leafPage(512, 1, tableCell(1, txt("x"), num(300)))
	bp, err := ParseBTreePage(p, 1, 512)
	if err != nil || bp.HeaderOffset != 100 {
		t.Fatalf("%+v %v", bp, err)
	}
	q := make([]byte, 512)
	q[0] = PageInteriorTable
	binary.BigEndian.PutUint16(q[5:], 512)
	binary.BigEndian.PutUint32(q[8:], 77)
	bp, err = ParseBTreePage(q, 3, 512)
	if err != nil || bp.IsLeaf() || bp.RightChild != 77 || bp.HeaderLen() != 12 {
		t.Fatalf("%+v %v", bp, err)
	}
	// content start 0 means 65536
	z := make([]byte, 65536)
	z[0] = PageLeafIndex
	bp, err = ParseBTreePage(z, 4, 65536)
	if err != nil || bp.ContentStart != 65536 {
		t.Fatalf("%+v %v", bp, err)
	}
}

func TestParseBTreeFreeblocks(t *testing.T) {
	cells := [][]byte{tableCell(1, txt("one"), num(1000)), tableCell(2, txt("two"), num(2000)), tableCell(3, txt("three"), num(3000))}
	p := leafPage(512, 2, cells...)
	// cell 1 sits in the middle of the content area
	freeCell(p, 2, 1, len(cells[1]))
	bp, err := ParseBTreePage(p, 2, 512)
	if err != nil {
		t.Fatal(err)
	}
	if bp.CellCount != 2 || len(bp.Freeblocks) != 1 || bp.Freeblocks[0].Size != len(cells[1]) {
		t.Fatalf("%+v", bp)
	}
}

func TestParseBTreeErrors(t *testing.T) {
	base := func() []byte { return leafPage(512, 2, tableCell(1, txt("a"), num(500))) }
	be := binary.BigEndian
	cases := []struct {
		name   string
		mut    func(p []byte)
		usable int
		want   error
	}{
		{"not btree", func(p []byte) { p[0] = 7 }, 512, ErrBadPage},
		{"usable too big", func([]byte) {}, 1024, ErrInvalidArgument},
		{"usable zero", func([]byte) {}, 0, ErrInvalidArgument},
		{"too many cells", func(p []byte) { be.PutUint16(p[3:], 400) }, 512, ErrBadPage},
		{"content start before pointers", func(p []byte) { be.PutUint16(p[5:], 4) }, 512, ErrBadPage},
		{"content start past usable", func(p []byte) { be.PutUint16(p[5:], 600) }, 512, ErrBadPage},
		{"pointer outside content", func(p []byte) { be.PutUint16(p[8:], 20) }, 512, ErrBadPage},
		{"freeblock before content", func(p []byte) { be.PutUint16(p[1:], 30) }, 512, ErrBadPage},
		{"freeblock size", func(p []byte) {
			be.PutUint16(p[1:], 508)
			be.PutUint16(p[510:], 2)
		}, 512, ErrBadPage},
		{"freeblock loop", func(p []byte) {
			be.PutUint16(p[1:], 500)
			be.PutUint16(p[500:], 500)
			be.PutUint16(p[502:], 4)
		}, 512, ErrBadPage},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := base()
			c.mut(p)
			if _, err := ParseBTreePage(p, 2, c.usable); !errors.Is(err, c.want) {
				t.Fatalf("err = %v want %v", err, c.want)
			}
		})
	}
	if _, err := ParseBTreePage(make([]byte, 104), 1, 104); !errors.Is(err, ErrTruncated) {
		t.Fatalf("page 1 too small: %v", err)
	}
	q := make([]byte, 110)
	q[100] = PageInteriorTable
	if _, err := ParseBTreePage(q, 1, 110); !errors.Is(err, ErrTruncated) {
		t.Fatalf("interior header past page: %v", err)
	}
}

func TestParseTableLeafCellOverflow(t *testing.T) {
	usable := 512
	x := MaxLocalTable(usable)
	payload := uint64(x + 100)
	b := append(PutVarint(payload), PutVarint(9)...)
	m := (usable-12)*32/255 - 23
	k := m + int(payload-uint64(m))%(usable-4)
	local := m
	if k <= x {
		local = k
	}
	b = append(b, make([]byte, local)...)
	b = binary.BigEndian.AppendUint32(b, 42)
	cell, err := ParseTableLeafCell(b, usable)
	if err != nil || cell.Overflow != 42 || len(cell.Local) != local || cell.RowID != 9 {
		t.Fatalf("%+v %v", cell, err)
	}
	if _, err := ParseTableLeafCell(b[:len(b)-1], usable); !errors.Is(err, ErrBadPage) {
		t.Fatalf("truncated overflow pointer: %v", err)
	}
	// payload so large that K > X: local falls back to M
	big := uint64(x + (usable - 4) - 1 + m)
	b2 := append(PutVarint(big), 1)
	b2 = append(b2, make([]byte, usable)...)
	cell, err = ParseTableLeafCell(b2, usable)
	if err != nil || len(cell.Local) > x {
		t.Fatalf("%+v %v", cell, err)
	}
	for _, bad := range [][]byte{{0x81}, {0x05, 0x81}, {0x7f, 0x01, 0x00}} {
		if _, err := ParseTableLeafCell(bad, usable); !errors.Is(err, ErrBadPage) {
			t.Fatalf("%x: %v", bad, err)
		}
	}
}
