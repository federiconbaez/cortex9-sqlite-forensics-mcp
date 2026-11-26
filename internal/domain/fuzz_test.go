package domain

import (
	"testing"
)

// Fuzz targets: parsers must never panic or index out of bounds on hostile
// input, and successful parses must stay within the input.

func FuzzReadVarint(f *testing.F) {
	f.Add([]byte{0x81, 0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		v, n, err := ReadVarint(b)
		if err == nil {
			if n < 1 || n > len(b) {
				t.Fatalf("n=%d len=%d", n, len(b))
			}
			if got, _, _ := ReadVarint(PutVarint(v)); got != v {
				t.Fatal("re-encode mismatch")
			}
		}
	})
}

func FuzzParseHeader(f *testing.F) {
	b := validHeader().Marshal()
	f.Add(b[:])
	f.Add([]byte("SQLite format 3\x00"))
	f.Fuzz(func(t *testing.T, in []byte) {
		h, err := ParseHeader(in)
		if err != nil {
			return
		}
		out := h.Marshal()
		if string(out[:]) != string(in[:HeaderSize]) {
			t.Fatal("accepted header does not round-trip")
		}
	})
}

func FuzzParseWAL(f *testing.F) {
	f.Add(buildWAL(false, 512, 1, 2, walFrameSpec{pgno: 1, commit: 1}))
	f.Add(buildWAL(true, 512, 3, 4, walFrameSpec{pgno: 2}, walFrameSpec{pgno: 1, commit: 2, badSum: true}))
	f.Fuzz(func(t *testing.T, in []byte) {
		w, err := ParseWAL(in)
		if err != nil {
			return
		}
		if w.CommittedFrames > w.ValidFrames || w.ValidFrames > len(w.Frames) {
			t.Fatalf("counts %d %d %d", w.CommittedFrames, w.ValidFrames, len(w.Frames))
		}
		_ = SummarizeWALPages(w, in, w.Header.PageSize)
	})
}

func FuzzParseBTreePage(f *testing.F) {
	p := leafPage(512, 2, tableCell(1, txt("a"), num(1000)), tableCell(2, txt("b"), num(2000)))
	freeCell(p, 2, 0, len(tableCell(1, txt("a"), num(1000))))
	f.Add(p, uint32(2))
	f.Add(leafPage(512, 1, tableCell(9, txt("x"))), uint32(1))
	f.Fuzz(func(t *testing.T, page []byte, pgno uint32) {
		bp, err := ParseBTreePage(page, pgno, len(page))
		if err != nil {
			return
		}
		for _, off := range bp.CellPointers {
			if bp.Type == PageLeafTable {
				_, _ = ParseTableLeafCell(page[off:], len(page))
			}
		}
		for _, fb := range bp.Freeblocks {
			if fb.Offset+fb.Size > len(page) {
				t.Fatal("freeblock outside page")
			}
		}
	})
}

func FuzzParseRecord(f *testing.F) {
	f.Add(EncodeRecord([]Value{txt("hello"), num(-5), flt(1.5), {Kind: KindNull}}), true)
	f.Add([]byte{0x03, 0x0a, 0x01}, false)
	f.Fuzz(func(t *testing.T, in []byte, exact bool) {
		r, err := ParseRecord(in, exact)
		if err != nil {
			return
		}
		if r.Len() > len(in) || (exact && r.Len() != len(in)) {
			t.Fatalf("record length %d input %d", r.Len(), len(in))
		}
	})
}

func FuzzCarveDatabase(f *testing.F) {
	img := make([]byte, 512*3)
	h := validHeader()
	h.PageSize = 512
	hb := h.Marshal()
	copy(img, hb[:])
	copy(img[512:], leafPage(512, 2, tableCell(1, txt("seed"), num(1700000000))))
	f.Add(img)
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) > 1<<16 {
			return
		}
		h, err := ParseHeader(in)
		if err != nil {
			return
		}
		fl, err := WalkFreelist(in, h)
		if err != nil {
			fl = Freelist{}
		}
		res := CarveDatabase(in, h, fl, CarveOptions{MaxCandidates: 1000})
		_ = BuildTimeline(res.Candidates, DefaultWindow())
	})
}
