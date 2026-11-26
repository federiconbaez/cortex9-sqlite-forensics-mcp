package domain

import (
	"math"
	"sort"
	"time"
)

// Timestamp encodings recognised by the timeline extractor.
const (
	FormatUnixSeconds  = "unix-seconds"
	FormatUnixMillis   = "unix-milliseconds"
	FormatUnixMicros   = "unix-microseconds"
	FormatCocoaSeconds = "apple-cocoa-seconds"     // seconds since 2001-01-01 UTC
	FormatCocoaNanos   = "apple-cocoa-nanoseconds" // nanoseconds since 2001-01-01 UTC
	FormatWebKit       = "webkit-microseconds"     // microseconds since 1601-01-01 UTC (Chrome/WebKit)
)

const (
	cocoaEpochUnix  = 978307200    // 2001-01-01T00:00:00Z
	webkitEpochUnix = -11644473600 // 1601-01-01T00:00:00Z
)

// TimelineEvent is one plausible timestamp interpretation of a carved value.
type TimelineEvent struct {
	Time       time.Time
	Format     string
	Column     int
	IsReal     bool
	RawInt     int64
	RawReal    float64
	PageNo     uint32
	Offset     int
	HasRowID   bool
	RowID      int64
	Source     string
	Confidence Confidence
	Ambiguous  bool // the same value fits more than one format inside the window
}

// TimelineWindow restricts interpretations to a plausible time range.
type TimelineWindow struct {
	From, To time.Time
}

// DefaultWindow covers 2005-01-01 to 2035-12-31, the smartphone era.
func DefaultWindow() TimelineWindow {
	return TimelineWindow{
		From: time.Date(2005, 1, 1, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2035, 12, 31, 23, 59, 59, 0, time.UTC),
	}
}

// InterpretInt returns every timestamp format under which v falls inside w.
func InterpretInt(v int64, w TimelineWindow) map[string]time.Time {
	out := map[string]time.Time{}
	try := func(f string, sec, nsec int64) {
		t := time.Unix(sec, nsec).UTC()
		if !t.Before(w.From) && !t.After(w.To) {
			out[f] = t
		}
	}
	try(FormatUnixSeconds, v, 0)
	try(FormatUnixMillis, v/1e3, (v%1e3)*1e6)
	try(FormatUnixMicros, v/1e6, (v%1e6)*1e3)
	if v <= math.MaxInt64-cocoaEpochUnix {
		try(FormatCocoaSeconds, v+cocoaEpochUnix, 0)
	}
	try(FormatCocoaNanos, v/1e9+cocoaEpochUnix, v%1e9)
	try(FormatWebKit, v/1e6+webkitEpochUnix, (v%1e6)*1e3)
	return out
}

// InterpretReal returns the formats under which a REAL value fits w
// (iOS stores Cocoa seconds as doubles; some apps store Unix seconds).
func InterpretReal(v float64, w TimelineWindow) map[string]time.Time {
	out := map[string]time.Time{}
	if math.IsNaN(v) || math.IsInf(v, 0) || math.Abs(v) > 1e12 {
		return out
	}
	sec, frac := math.Modf(v)
	try := func(f string, s int64) {
		t := time.Unix(s, int64(frac*1e9)).UTC()
		if !t.Before(w.From) && !t.After(w.To) {
			out[f] = t
		}
	}
	try(FormatUnixSeconds, int64(sec))
	try(FormatCocoaSeconds, int64(sec)+cocoaEpochUnix)
	return out
}

// BuildTimeline extracts timestamp-looking values from carved candidates and
// returns them sorted by time. Values matching several formats are emitted
// once per format and flagged Ambiguous.
func BuildTimeline(cands []Candidate, w TimelineWindow) []TimelineEvent {
	var ev []TimelineEvent
	for _, c := range cands {
		for col, v := range c.Record.Values {
			var m map[string]time.Time
			switch {
			case v.Kind == KindInt && v.SerialType >= 3 && v.SerialType <= 6:
				// 1- and 2-byte integers cannot hold a timestamp in any format
				m = InterpretInt(v.Int, w)
			case v.Kind == KindReal:
				m = InterpretReal(v.Real, w)
			}
			for f, t := range m {
				ev = append(ev, TimelineEvent{
					Time: t, Format: f, Column: col, IsReal: v.Kind == KindReal,
					RawInt: v.Int, RawReal: v.Real, PageNo: c.PageNo, Offset: c.Offset,
					HasRowID: c.HasRowID, RowID: c.RowID, Source: c.Source,
					Confidence: c.Confidence, Ambiguous: len(m) > 1,
				})
			}
		}
	}
	sort.SliceStable(ev, func(i, j int) bool {
		if !ev[i].Time.Equal(ev[j].Time) {
			return ev[i].Time.Before(ev[j].Time)
		}
		if ev[i].Format != ev[j].Format {
			return ev[i].Format < ev[j].Format
		}
		if ev[i].PageNo != ev[j].PageNo {
			return ev[i].PageNo < ev[j].PageNo
		}
		return ev[i].Offset < ev[j].Offset
	})
	return ev
}
