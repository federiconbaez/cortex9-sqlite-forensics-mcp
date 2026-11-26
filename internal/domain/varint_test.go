package domain

import (
	"bytes"
	"errors"
	"testing"
	"testing/quick"
)

func TestVarintKnownEncodings(t *testing.T) {
	cases := []struct {
		v   uint64
		enc []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{127, []byte{0x7f}},
		{128, []byte{0x81, 0x00}},
		{240, []byte{0x81, 0x70}},
		{16383, []byte{0xff, 0x7f}},
		{16384, []byte{0x81, 0x80, 0x00}},
		{1<<56 - 1, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}},
		{1 << 56, []byte{0x80, 0xc0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}},
		{^uint64(0), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, c := range cases {
		if got := PutVarint(c.v); !bytes.Equal(got, c.enc) {
			t.Errorf("PutVarint(%d) = %x, want %x", c.v, got, c.enc)
		}
		v, n, err := ReadVarint(append(append([]byte{}, c.enc...), 0xAA, 0xBB))
		if err != nil || v != c.v || n != len(c.enc) {
			t.Errorf("ReadVarint(%x) = %d,%d,%v want %d,%d", c.enc, v, n, err, c.v, len(c.enc))
		}
	}
}

func TestVarintTruncated(t *testing.T) {
	for _, b := range [][]byte{nil, {0x80}, {0xff, 0xff}, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}} {
		if _, _, err := ReadVarint(b); !errors.Is(err, ErrBadVarint) {
			t.Errorf("ReadVarint(%x) err = %v, want ErrBadVarint", b, err)
		}
	}
}

// Property: every uint64 round-trips and the encoding is the shortest possible.
func TestVarintRoundTripProperty(t *testing.T) {
	f := func(v uint64, shift uint8) bool {
		v >>= shift % 64 // exercise every length class
		enc := PutVarint(v)
		got, n, err := ReadVarint(enc)
		if err != nil || got != v || n != len(enc) {
			return false
		}
		want := 9
		for l := 1; l <= 8; l++ {
			if v < 1<<(7*uint(l)) {
				want = l
				break
			}
		}
		return len(enc) == want
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 20000}); err != nil {
		t.Fatal(err)
	}
}

// Property: decoding arbitrary bytes never reads past the input and,
// when it succeeds, re-encoding the value reproduces a prefix-consistent value.
func TestVarintArbitraryBytesProperty(t *testing.T) {
	f := func(b []byte) bool {
		v, n, err := ReadVarint(b)
		if err != nil {
			return n == 0
		}
		if n < 1 || n > len(b) || n > MaxVarintLen {
			return false
		}
		v2, _, err := ReadVarint(PutVarint(v))
		return err == nil && v2 == v
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 20000}); err != nil {
		t.Fatal(err)
	}
}
