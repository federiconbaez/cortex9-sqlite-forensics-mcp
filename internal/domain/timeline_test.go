package domain

import (
	"math"
	"testing"
	"time"
)

func TestInterpretInt(t *testing.T) {
	w := DefaultWindow()
	at := func(s string) time.Time { tt, _ := time.Parse(time.RFC3339, s); return tt }
	cases := []struct {
		v    int64
		want map[string]time.Time
	}{
		{1700000000, map[string]time.Time{FormatUnixSeconds: at("2023-11-14T22:13:20Z")}},
		{1700000000123, map[string]time.Time{FormatUnixMillis: at("2023-11-14T22:13:20Z").Add(123 * time.Millisecond)}},
		{1700000000000000, map[string]time.Time{FormatUnixMicros: at("2023-11-14T22:13:20Z")}},
		{721692800, map[string]time.Time{FormatCocoaSeconds: at("2023-11-14T22:13:20Z")}},
		{721692800000000000, map[string]time.Time{FormatCocoaNanos: at("2023-11-14T22:13:20Z")}},
		{13344473600000000, map[string]time.Time{FormatWebKit: at("2023-11-14T22:13:20Z")}},
		{42, map[string]time.Time{}},
		{-5, map[string]time.Time{}},
		{math.MaxInt64, map[string]time.Time{}},
	}
	for _, c := range cases {
		got := InterpretInt(c.v, w)
		if len(got) != len(c.want) {
			t.Errorf("%d: got %v want %v", c.v, got, c.want)
			continue
		}
		for f, tt := range c.want {
			if !got[f].Equal(tt) {
				t.Errorf("%d %s: got %v want %v", c.v, f, got[f], tt)
			}
		}
	}
}

func TestInterpretReal(t *testing.T) {
	w := DefaultWindow()
	got := InterpretReal(721692800.5, w)
	if len(got) != 1 || got[FormatCocoaSeconds].Nanosecond() != 5e8 {
		t.Fatalf("%v", got)
	}
	if got := InterpretReal(1700000000.0, w); len(got) != 1 || got[FormatUnixSeconds].IsZero() {
		t.Fatalf("%v", got)
	}
	for _, v := range []float64{math.NaN(), math.Inf(1), 1e15, 3.5} {
		if len(InterpretReal(v, w)) != 0 {
			t.Fatalf("%v should not be a timestamp", v)
		}
	}
}

func TestBuildTimeline(t *testing.T) {
	cands := []Candidate{
		{PageNo: 4, Offset: 9, HasRowID: true, RowID: 2, Confidence: ConfidenceHigh, Source: SourceFreedPageCell,
			Record: Record{Values: []Value{num(1700000600), txt("x"), {Kind: KindInt, SerialType: 1, Int: 5}}}},
		{PageNo: 2, Offset: 1, Confidence: ConfidenceLow, Source: SourceFreeblock,
			Record: Record{Values: []Value{flt(721692800.0), {Kind: KindInt, SerialType: 4, Int: 1200000000}}}},
	}
	// encode serial types like the parser would
	cands[0].Record.Values[0].SerialType = 4
	cands[1].Record.Values[0].SerialType = 7
	wide := TimelineWindow{From: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), To: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)}
	ev := BuildTimeline(cands, wide)
	if len(ev) < 3 {
		t.Fatalf("got %d events: %+v", len(ev), ev)
	}
	for i := 1; i < len(ev); i++ {
		if ev[i].Time.Before(ev[i-1].Time) {
			t.Fatal("not sorted")
		}
	}
	amb := 0
	for _, e := range ev {
		if e.Ambiguous {
			amb++
		}
		if e.RawInt == 5 {
			t.Fatal("1-byte integers cannot be timestamps")
		}
	}
	if amb < 2 {
		t.Fatalf("in a 2000-2100 window 1200000000 fits unix and cocoa seconds; want ambiguity, events %+v", ev)
	}
	// identical times sort by format, then page/offset
	same := []Candidate{
		{PageNo: 9, Record: Record{Values: []Value{{Kind: KindInt, SerialType: 4, Int: 1700000000}}}},
		{PageNo: 3, Offset: 7, Record: Record{Values: []Value{{Kind: KindInt, SerialType: 4, Int: 1700000000}}}},
		{PageNo: 3, Offset: 2, Record: Record{Values: []Value{{Kind: KindInt, SerialType: 4, Int: 1700000000}}}},
	}
	ev = BuildTimeline(same, DefaultWindow())
	if ev[0].PageNo != 3 || ev[0].Offset != 2 || ev[2].PageNo != 9 {
		t.Fatalf("%+v", ev)
	}
}

// With the default 2005-2035 window, Unix seconds and Cocoa seconds cannot
// overlap: the last Cocoa second of 2035 is below the first Unix second of 2005.
func TestDefaultWindowSeparatesUnixAndCocoa(t *testing.T) {
	w := DefaultWindow()
	for v := int64(1104000000); v <= 1105000000; v += 1000 {
		m := InterpretInt(v, w)
		_, u := m[FormatUnixSeconds]
		_, c := m[FormatCocoaSeconds]
		if u && c {
			t.Fatalf("%d is ambiguous", v)
		}
	}
}
