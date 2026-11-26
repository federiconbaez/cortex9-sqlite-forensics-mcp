package domain

import (
	"errors"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

func validHeader() Header {
	return Header{
		PageSize: 4096, WriteVersion: 1, ReadVersion: 1, MaxPayloadFraction: 64,
		MinPayloadFraction: 32, LeafPayloadFraction: 32, FileChangeCounter: 7,
		DatabaseSizePages: 3, SchemaCookie: 2, SchemaFormat: 4, TextEncoding: EncodingUTF8,
		VersionValidFor: 7, SQLiteVersionNumber: 3046000,
	}
}

func TestParseHeaderValid(t *testing.T) {
	b := validHeader().Marshal()
	h, err := ParseHeader(b[:])
	if err != nil {
		t.Fatal(err)
	}
	if h.PageSize != 4096 || h.UsableSize() != 4096 || h.EncodingName() != "UTF-8" || !h.InHeaderSizeValid() {
		t.Fatalf("unexpected header %+v", h)
	}
	if len(h.Warnings) != 0 {
		t.Fatalf("unexpected warnings %v", h.Warnings)
	}
}

func TestParseHeaderErrors(t *testing.T) {
	good := validHeader().Marshal()
	mut := func(f func(b []byte)) []byte {
		b := append([]byte(nil), good[:]...)
		f(b)
		return b
	}
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrTruncated},
		{"99 bytes", good[:99], ErrTruncated},
		{"magic", mut(func(b []byte) { b[0] = 'X' }), ErrBadMagic},
		{"page size 0", mut(func(b []byte) { b[16], b[17] = 0, 0 }), ErrBadPageSize},
		{"page size 1000", mut(func(b []byte) { b[16], b[17] = 0x03, 0xe8 }), ErrBadPageSize},
		{"page size 256", mut(func(b []byte) { b[16], b[17] = 0x01, 0x00 }), ErrBadPageSize},
		{"page size 65535", mut(func(b []byte) { b[16], b[17] = 0xff, 0xff }), ErrBadPageSize},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseHeader(c.in)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			var pe *ParseError
			if !errors.As(err, &pe) || pe.Error() == "" {
				t.Fatalf("want *ParseError, got %T", err)
			}
		})
	}
}

func TestHeaderPageSize65536(t *testing.T) {
	h := validHeader()
	h.PageSize = 65536
	b := h.Marshal()
	if b[16] != 0 || b[17] != 1 {
		t.Fatalf("65536 must serialize as 1, got %x", b[16:18])
	}
	got, err := ParseHeader(b[:])
	if err != nil || got.PageSize != 65536 {
		t.Fatalf("got %d %v", got.PageSize, err)
	}
}

func TestHeaderWarnings(t *testing.T) {
	h := validHeader()
	h.WriteVersion, h.ReadVersion = 9, 9
	h.MaxPayloadFraction = 1
	h.ReservedBytes = 200
	h.PageSize = 512
	h.TextEncoding = 7
	h.SchemaFormat = 9
	h.FreelistPageCount, h.FirstFreelistTrunk = 3, 0
	h.ReservedForExpansion[3] = 1
	b := h.Marshal()
	got, err := ParseHeader(b[:])
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Warnings) != 8 {
		t.Fatalf("want 8 warnings, got %d: %v", len(got.Warnings), got.Warnings)
	}
	if got.EncodingName() != "unknown" {
		t.Fatal(got.EncodingName())
	}
	for enc, name := range map[uint32]string{2: "UTF-16le", 3: "UTF-16be"} {
		if (Header{TextEncoding: enc}).EncodingName() != name {
			t.Fatal(name)
		}
	}
}

// Property: Parse(Marshal(h)) == h for every header with a legal page size.
func TestHeaderMarshalParseProperty(t *testing.T) {
	f := func(h Header, psExp uint8) bool {
		h.PageSize = 512 << (psExp % 8)
		h.Warnings = nil
		b := h.Marshal()
		got, err := ParseHeader(b[:])
		if err != nil {
			return false
		}
		got.Warnings = nil
		return reflect.DeepEqual(got, h)
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 5000}); err != nil {
		t.Fatal(err)
	}
}

// Property: Marshal(Parse(b)) == b for every 100-byte input that parses.
func TestHeaderParseMarshalProperty(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 5000; i++ {
		b := make([]byte, HeaderSize)
		r.Read(b)
		copy(b, Magic)
		exp := r.Intn(8)
		ps := 512 << exp
		if ps == 65536 {
			ps = 1
		}
		b[16], b[17] = byte(ps>>8), byte(ps)
		h, err := ParseHeader(b)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if out := h.Marshal(); string(out[:]) != string(b) {
			t.Fatalf("iteration %d: round trip differs", i)
		}
	}
}

func TestPageCountAndPageBytes(t *testing.T) {
	h := validHeader()
	h.PageSize = 512
	img := make([]byte, 512*4)
	if PageCount(h, len(img)) != 3 {
		t.Fatal("in-header size should win when valid")
	}
	h.VersionValidFor = 0
	if PageCount(h, len(img)) != 4 {
		t.Fatal("image length should win when header size is stale")
	}
	h.VersionValidFor, h.DatabaseSizePages = h.FileChangeCounter, 99
	if PageCount(h, len(img)) != 4 {
		t.Fatal("header size larger than the image must not be trusted")
	}
	if _, err := PageBytes(img, 512, 0); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
	if _, err := PageBytes(img, 512, 5); !errors.Is(err, ErrTruncated) {
		t.Fatal(err)
	}
	if p, err := PageBytes(img, 512, 4); err != nil || len(p) != 512 {
		t.Fatal(err)
	}
}

func TestParseErrorWithoutOffset(t *testing.T) {
	e := &ParseError{Kind: ErrBadWAL, Offset: -1, Detail: "x"}
	if e.Error() != "malformed WAL: x" {
		t.Fatal(e.Error())
	}
}
