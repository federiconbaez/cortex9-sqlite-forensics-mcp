package domain

import (
	"bytes"
	"errors"
	"testing"
)

func page(fill byte, n int) []byte { return bytes.Repeat([]byte{fill}, n) }

func TestParseWALValidCommitted(t *testing.T) {
	for _, bigEndian := range []bool{false, true} {
		w := buildWAL(bigEndian, 512, 11, 22,
			walFrameSpec{pgno: 1, data: page(1, 512)},
			walFrameSpec{pgno: 2, commit: 2, data: page(2, 512)},
			walFrameSpec{pgno: 2, commit: 2, data: page(3, 512)},
			walFrameSpec{pgno: 3, data: page(4, 512)}, // uncommitted tail
		)
		got, err := ParseWAL(append(w, 0xde, 0xad))
		if err != nil {
			t.Fatal(err)
		}
		if !got.Header.ChecksumValid || got.Header.BigEndianSums != bigEndian {
			t.Fatalf("header %+v", got.Header)
		}
		if got.ValidFrames != 4 || got.CommittedFrames != 3 || got.CommitFrames != 2 || got.TrailingBytes != 2 {
			t.Fatalf("be=%v counts valid=%d committed=%d commits=%d trailing=%d", bigEndian, got.ValidFrames, got.CommittedFrames, got.CommitFrames, got.TrailingBytes)
		}
		if !got.Frames[1].IsCommit() || got.Frames[3].Committed || len(got.Warnings) != 1 {
			t.Fatalf("frames %+v warnings %v", got.Frames, got.Warnings)
		}
	}
}

func TestParseWALChainStopsAtBadFrame(t *testing.T) {
	cases := []struct {
		name  string
		frame walFrameSpec
	}{
		{"bad checksum", walFrameSpec{pgno: 2, commit: 2, badSum: true}},
		{"stale salt", walFrameSpec{pgno: 2, commit: 2, badSalt: true}},
		{"page zero", walFrameSpec{pgno: 0, commit: 2}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := buildWAL(false, 512, 1, 2,
				walFrameSpec{pgno: 1, commit: 1},
				c.frame,
				walFrameSpec{pgno: 3, commit: 3},
			)
			got, err := ParseWAL(w)
			if err != nil {
				t.Fatal(err)
			}
			if got.ValidFrames != 1 || got.CommittedFrames != 1 || got.Frames[2].Valid {
				t.Fatalf("valid=%d committed=%d", got.ValidFrames, got.CommittedFrames)
			}
			if c.name == "stale salt" && got.StaleSaltFrames != 1 {
				t.Fatalf("stale=%d", got.StaleSaltFrames)
			}
		})
	}
}

func TestParseWALHeaderProblems(t *testing.T) {
	w := buildWAL(false, 512, 1, 2, walFrameSpec{pgno: 1, commit: 1})
	bad := append([]byte(nil), w...)
	bad[24] ^= 1
	got, err := ParseWAL(bad)
	if err != nil || got.Header.ChecksumValid || got.ValidFrames != 0 || len(got.Warnings) == 0 {
		t.Fatalf("%+v %v", got, err)
	}
	ver := append([]byte(nil), w...)
	ver[7] ^= 1
	got, err = ParseWAL(ver)
	if err != nil || len(got.Warnings) < 2 {
		t.Fatalf("format version change must warn: %v %v", got.Warnings, err)
	}
	cases := []struct {
		in   []byte
		want error
	}{
		{w[:31], ErrTruncated},
		{append([]byte{0, 0, 0, 0}, w[4:]...), ErrBadMagic},
		{append(append(append([]byte(nil), w[:8]...), 0, 0, 3, 0), w[12:]...), ErrBadPageSize},
	}
	for i, c := range cases {
		if _, err := ParseWAL(c.in); !errors.Is(err, c.want) {
			t.Errorf("case %d: err = %v want %v", i, err, c.want)
		}
	}
}

func TestSummarizeWALPages(t *testing.T) {
	db := make([]byte, 512*3)
	copy(db[512:], page(2, 512)) // page 2 in db == WAL version
	w := buildWAL(false, 512, 1, 2,
		walFrameSpec{pgno: 1, data: page(9, 512)},
		walFrameSpec{pgno: 2, commit: 3, data: page(2, 512)},
		walFrameSpec{pgno: 1, commit: 3, data: page(8, 512)},
		walFrameSpec{pgno: 7, commit: 7, data: page(7, 512)},
		walFrameSpec{pgno: 5, data: page(5, 512)}, // uncommitted
	)
	parsed, err := ParseWAL(w)
	if err != nil {
		t.Fatal(err)
	}
	got := SummarizeWALPages(parsed, db, 512)
	want := map[uint32]struct {
		status   PageDiffStatus
		versions int
		latest   int
	}{
		1: {DiffDiffers, 2, 2}, 2: {DiffSame, 1, 1}, 7: {DiffBeyondDB, 1, 3}, 5: {DiffBeyondDB, 0, -1},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d pages", len(got))
	}
	for _, s := range got {
		w := want[s.PageNo]
		if s.Status != w.status || s.Versions != w.versions || s.LatestCommitted != w.latest {
			t.Errorf("page %d: %+v want %+v", s.PageNo, s, w)
		}
	}
	for _, s := range SummarizeWALPages(parsed, nil, 0) {
		if s.Status != DiffIncomparable {
			t.Fatalf("no db: %+v", s)
		}
	}
	for _, s := range SummarizeWALPages(parsed, db, 1024) {
		if s.Status != DiffIncomparable {
			t.Fatalf("page size mismatch: %+v", s)
		}
	}
}
