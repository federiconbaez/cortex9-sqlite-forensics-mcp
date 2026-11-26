package domain

import "testing"

func TestCarveWALFramesHandBuilt(t *testing.T) {
	v1 := leafPage(512, 2, tableCell(1, txt("old-version"), num(1700000000)), tableCell(2, txt("kept"), num(1700000060)))
	v2 := leafPage(512, 2, tableCell(2, txt("kept"), num(1700000060)))
	interior := make([]byte, 512)
	interior[0] = PageInteriorTable
	interior[5], interior[6] = 0x02, 0x00
	w := buildWAL(false, 512, 5, 6,
		walFrameSpec{pgno: 2, commit: 2, data: v1},
		walFrameSpec{pgno: 3, data: interior},
		walFrameSpec{pgno: 2, commit: 3, data: v2},
	)
	parsed, err := ParseWAL(w)
	if err != nil {
		t.Fatal(err)
	}
	cands, res := CarveWALFrames(parsed, 0, CarveOptions{})
	byFrame := map[int][]string{}
	for _, c := range cands {
		for _, v := range c.Record.Values {
			if v.Kind == KindText {
				byFrame[c.FrameIndex] = append(byFrame[c.FrameIndex], string(v.Bytes))
			}
		}
		if !c.Committed || c.Source != SourceWALFrameCell || c.Confidence != ConfidenceHigh {
			t.Errorf("%+v", c)
		}
	}
	if len(byFrame[0]) != 2 || len(byFrame[2]) != 1 || res.PagesScanned != 2 {
		t.Fatalf("by frame %v scanned %d", byFrame, res.PagesScanned)
	}
	if lim, r := CarveWALFrames(parsed, 0, CarveOptions{MaxCandidates: 1}); len(lim) != 1 || !r.Truncated {
		t.Fatal("limit")
	}
	if hi, _ := CarveWALFrames(parsed, 0, CarveOptions{MinConfidence: ConfidenceHigh, Encoding: EncodingUTF8}); len(hi) != 3 {
		t.Fatalf("high only: %d", len(hi))
	}
	if none, r := CarveWALFrames(parsed, 100, CarveOptions{}); none != nil || len(r.Warnings) == 0 {
		t.Fatal("usable below 480 must be refused")
	}
}
