package domain

import (
	"encoding/binary"
	"strings"
	"testing"
)

// carveImage builds a 3-page image: page 1 header-only, page 2 a live leaf,
// page 3 a freed leaf page listed as a freelist leaf of trunk page 4.
func carveImage(t *testing.T, live, freed []byte) ([]byte, Header, Freelist) {
	t.Helper()
	const ps = 512
	db := make([]byte, ps*4)
	h := validHeader()
	h.PageSize, h.DatabaseSizePages, h.FirstFreelistTrunk, h.FreelistPageCount = ps, 4, 4, 2
	hb := h.Marshal()
	copy(db, hb[:])
	db[100] = PageLeafTable
	binary.BigEndian.PutUint16(db[105:], ps)
	copy(db[ps:], live)
	copy(db[2*ps:], freed)
	binary.BigEndian.PutUint32(db[3*ps+4:], 1)
	binary.BigEndian.PutUint32(db[3*ps+8:], 3)
	ph, err := ParseHeader(db)
	if err != nil {
		t.Fatal(err)
	}
	fl, err := WalkFreelist(db, ph)
	if err != nil {
		t.Fatal(err)
	}
	return db, ph, fl
}

func texts(res CarveResult) map[string]Candidate {
	out := map[string]Candidate{}
	for _, c := range res.Candidates {
		for _, v := range c.Record.Values {
			if v.Kind == KindText {
				out[string(v.Bytes)] = c
			}
		}
	}
	return out
}

func TestCarveSources(t *testing.T) {
	// live page: cell "gone-mid" freed into a freeblock, "gone-top" freed at the
	// content start (bytes intact in the unallocated gap)
	cells := [][]byte{
		tableCell(1, txt("kept-1"), num(111111)),
		// payload >= 128 bytes and rowid >= 128: the 2+2 byte cell prefix is what
		// the freeblock link overwrites, so the record header survives
		tableCell(300, txt("gone-mid"), txt(strings.Repeat("z", 130))),
		tableCell(3, txt("kept-3"), num(333333)),
		tableCell(4, txt("gone-top"), num(444444)),
	}
	live := leafPage(512, 2, cells...)
	freeCell(live, 2, 1, len(cells[1]))
	// drop the last cell by moving the content start past it
	be := binary.BigEndian
	n := int(be.Uint16(live[3:]))
	be.PutUint16(live[8+2*(n-1):], 0)
	be.PutUint16(live[3:], uint16(n-1))
	be.PutUint16(live[5:], uint16(512-len(cells[0])-len(cells[1])-len(cells[2])))
	freed := leafPage(512, 3, tableCell(10, txt("freed-a"), num(1700000000)), tableCell(11, txt("freed-b"), flt(7.2e8)))

	db, h, fl := carveImage(t, live, freed)
	res := CarveDatabase(db, h, fl, CarveOptions{})
	got := texts(res)
	want := map[string]struct {
		source string
		conf   Confidence
	}{
		"gone-top": {SourceUnallocated, ConfidenceMedium},
		"gone-mid": {SourceFreeblock, ConfidenceLow},

		"freed-a": {SourceFreedPageCell, ConfidenceHigh},
		"freed-b": {SourceFreedPageCell, ConfidenceHigh},
	}
	for text, w := range want {
		c, ok := got[text]
		if !ok {
			t.Errorf("%q not recovered; got %v", text, keys(got))
			continue
		}
		if c.Source != w.source || c.Confidence != w.conf {
			t.Errorf("%q: source %s conf %v, want %s %v (reasons %v)", text, c.Source, c.Confidence, w.source, w.conf, c.Reasons)
		}
	}
	for _, live := range []string{"kept-1", "kept-3"} {
		if _, ok := got[live]; ok {
			t.Errorf("live cell %q must not be carved", live)
		}
	}
	if res.FreelistPages != 2 || res.LivePages != 2 || res.PagesScanned != 4 {
		t.Errorf("counts %+v", res)
	}
	if got["freed-a"].RowID != 10 || !got["freed-a"].HasRowID {
		t.Errorf("rowid %+v", got["freed-a"])
	}

	hi := CarveDatabase(db, h, fl, CarveOptions{MinConfidence: ConfidenceHigh})
	for _, c := range hi.Candidates {
		if c.Confidence != ConfidenceHigh {
			t.Fatal("MinConfidence not applied")
		}
	}
	lim := CarveDatabase(db, h, fl, CarveOptions{MaxCandidates: 1})
	if len(lim.Candidates) != 1 || !lim.Truncated {
		t.Fatalf("limit: %d truncated=%v", len(lim.Candidates), lim.Truncated)
	}
}

func keys(m map[string]Candidate) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestCarveFreedPageWithoutBTreeHeader(t *testing.T) {
	freed := make([]byte, 512)
	freed[0] = 0x00 // header wiped
	c := tableCell(7, txt("orphan"), num(123456))
	copy(freed[300:], c)
	db, h, fl := carveImage(t, make([]byte, 512), freed)
	got := texts(CarveDatabase(db, h, fl, CarveOptions{}))
	if cand, ok := got["orphan"]; !ok || cand.Source != SourceFreedPageScan || cand.Confidence != ConfidenceMedium {
		t.Fatalf("got %+v", got)
	}
}

func TestCarveTrunkPageTail(t *testing.T) {
	db, h, fl := carveImage(t, make([]byte, 512), make([]byte, 512))
	copy(db[3*512+200:], tableCell(5, txt("in-trunk"), num(98765)))
	got := texts(CarveDatabase(db, h, fl, CarveOptions{}))
	if c, ok := got["in-trunk"]; !ok || c.Source != SourceFreedPageScan {
		t.Fatalf("got %+v", got)
	}
}

func TestCarveConfidenceDowngrades(t *testing.T) {
	cases := []struct {
		name string
		cell []byte
		want Confidence
	}{
		{"single column", tableCell(3, txt("solo-column")), ConfidenceMedium},
		{"negative rowid", tableCell(-4, txt("neg"), num(5000)), ConfidenceMedium},
		{"bad utf8", tableCell(5, Value{Kind: KindText, Bytes: []byte{0xff, 0xfe, 'z'}}, num(5000)), ConfidenceLow},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			freed := leafPage(512, 3, c.cell)
			db, h, fl := carveImage(t, make([]byte, 512), freed)
			res := CarveDatabase(db, h, fl, CarveOptions{})
			if len(res.Candidates) != 1 || res.Candidates[0].Confidence != c.want {
				t.Fatalf("%+v", res.Candidates)
			}
		})
	}
}

func TestCarveRejectsNoiseAndCountsOverflow(t *testing.T) {
	// all-constant record (NULL, 0, 1) is not plausible
	noise := leafPage(512, 3, tableCell(1, Value{Kind: KindNull}, num(0), num(1)))
	db, h, fl := carveImage(t, make([]byte, 512), noise)
	if res := CarveDatabase(db, h, fl, CarveOptions{}); len(res.Candidates) != 0 {
		t.Fatalf("noise carved: %+v", res.Candidates)
	}
	// an overflow cell is counted, not decoded
	big := make([]byte, 600)
	rec := EncodeRecord([]Value{{Kind: KindBlob, Bytes: big}})
	cell := append(PutVarint(uint64(len(rec))), 1)
	cell = append(cell, rec[:200]...)
	cell = binary.BigEndian.AppendUint32(cell, 9)
	ov := leafPage(512, 3, cell)
	db, h, fl = carveImage(t, make([]byte, 512), ov)
	if res := CarveDatabase(db, h, fl, CarveOptions{}); res.OverflowCells == 0 {
		t.Fatalf("overflow not counted: %+v", res)
	}
}

func TestCarveSkipsShortImage(t *testing.T) {
	db, h, fl := carveImage(t, make([]byte, 512), make([]byte, 512))
	h.VersionValidFor = h.FileChangeCounter
	res := CarveDatabase(db[:512*3+10], h, Freelist{}, CarveOptions{MinConfidence: ConfidenceLow, Encoding: EncodingUTF8})
	if res.PagesScanned > 3 {
		t.Fatalf("scanned %d", res.PagesScanned)
	}
	_ = fl
}

func TestConfidenceHelpers(t *testing.T) {
	for s, c := range map[string]Confidence{"high": ConfidenceHigh, "medium": ConfidenceMedium, "low": ConfidenceLow, "": ConfidenceLow} {
		if ParseConfidence(s) != c {
			t.Fatal(s)
		}
	}
	if ConfidenceHigh.String() != "high" || ConfidenceMedium.String() != "medium" || ConfidenceLow.String() != "low" {
		t.Fatal("String")
	}
	c := []Candidate{{PageNo: 2, Offset: 5, Confidence: ConfidenceLow}, {PageNo: 3, Confidence: ConfidenceHigh}, {PageNo: 2, Offset: 1, Confidence: ConfidenceLow}, {PageNo: 1, Confidence: ConfidenceLow}}
	SortCandidates(c)
	if c[0].PageNo != 3 || c[1].PageNo != 1 || c[2].Offset != 1 || c[3].Offset != 5 {
		t.Fatalf("%+v", c)
	}
}

func TestCarveFreeblockHeaderReconstruction(t *testing.T) {
	cases := []struct {
		name string
		cell []byte
	}{
		// 2-byte payload size + 1-byte rowid: only the header-size byte is lost
		{"prefix 3", tableCell(7, Value{Kind: KindNull}, txt("rebuilt-three"), txt(strings.Repeat("q", 120)))},
		// 1-byte payload size + 1-byte rowid: header size and first type lost
		{"prefix 2", tableCell(8, Value{Kind: KindNull}, txt("rebuilt-two"), num(1700000000))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			keep := tableCell(1, txt("anchor"), num(99999))
			live := leafPage(512, 2, keep, c.cell, keep)
			freeCell(live, 2, 1, len(c.cell))
			db, h, fl := carveImage(t, live, make([]byte, 512))
			var found *Candidate
			res := CarveDatabase(db, h, fl, CarveOptions{})
			for i, cand := range res.Candidates {
				if cand.Method == MethodReconstructed {
					found = &res.Candidates[i]
				}
			}
			if found == nil || found.Confidence != ConfidenceLow || found.Record.Values[0].Kind != KindNull {
				t.Fatalf("not reconstructed: %+v", res.Candidates)
			}
		})
	}
}
