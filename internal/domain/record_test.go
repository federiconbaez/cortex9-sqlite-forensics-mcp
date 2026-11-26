package domain

import (
	"bytes"
	"errors"
	"math"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

func TestSerialTypeSizes(t *testing.T) {
	cases := map[uint64]struct {
		size uint64
		ok   bool
	}{
		0: {0, true}, 1: {1, true}, 2: {2, true}, 3: {3, true}, 4: {4, true}, 5: {6, true},
		6: {8, true}, 7: {8, true}, 8: {0, true}, 9: {0, true}, 10: {0, false}, 11: {0, false},
		12: {0, true}, 13: {0, true}, 14: {1, true}, 15: {1, true}, 113: {50, true},
	}
	for st, want := range cases {
		size, ok := SerialTypeSize(st)
		if size != want.size || ok != want.ok {
			t.Errorf("SerialTypeSize(%d) = %d,%v want %d,%v", st, size, ok, want.size, want.ok)
		}
	}
}

func TestParseRecordValues(t *testing.T) {
	vals := []Value{
		{Kind: KindNull}, num(0), num(1), num(-1), num(127), num(-129), num(-8388608),
		num(1 << 40), num(-(1 << 47)), num(math.MinInt64), num(math.MaxInt64),
		flt(3.25), txt("héllo"), {Kind: KindBlob, Bytes: []byte{0, 1, 2}}, txt(""),
	}
	enc := EncodeRecord(vals)
	r, err := ParseRecord(enc, true)
	if err != nil {
		t.Fatal(err)
	}
	if r.Len() != len(enc) || len(r.Values) != len(vals) {
		t.Fatalf("len %d/%d values %d", r.Len(), len(enc), len(r.Values))
	}
	for i, v := range vals {
		g := r.Values[i]
		if g.Kind != v.Kind || g.Int != v.Int || g.Real != v.Real || !bytes.Equal(g.Bytes, v.Bytes) {
			t.Errorf("value %d: got %+v want %+v", i, g, v)
		}
	}
	// returned bytes must not alias the input
	enc[len(enc)-1] ^= 0xff
	if r.Values[13].Bytes[2] != 2 {
		t.Fatal("decoded blob aliases the input slice")
	}
}

func TestParseRecordErrors(t *testing.T) {
	cases := []struct {
		name  string
		in    []byte
		exact bool
	}{
		{"empty", nil, false},
		{"header size beyond input", []byte{0x05, 0x01}, false},
		{"header size zero", []byte{0x00}, false},
		{"reserved type 10", []byte{0x02, 0x0a}, false},
		{"reserved type 11", []byte{0x02, 0x0b}, false},
		{"body overflow", []byte{0x02, 0x06, 0x01}, false},
		{"truncated serial varint", []byte{0x02, 0x81}, false},
		{"exact mismatch", append(EncodeRecord([]Value{num(5)}), 0x00), true},
		{"huge text", []byte{0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseRecord(c.in, c.exact); !errors.Is(err, ErrBadRecord) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	if _, err := ParseRecord(append(EncodeRecord([]Value{num(5)}), 0x00), false); err != nil {
		t.Fatalf("non-exact parse must ignore trailing bytes: %v", err)
	}
}

func TestParseRecordColumnLimit(t *testing.T) {
	vals := make([]Value, MaxColumns+1)
	if _, err := ParseRecord(EncodeRecord(vals), true); !errors.Is(err, ErrBadRecord) {
		t.Fatalf("want column limit error, got %v", err)
	}
}

// Property: EncodeRecord / ParseRecord round-trips arbitrary values.
func TestRecordRoundTripProperty(t *testing.T) {
	gen := func(r *rand.Rand) []Value {
		n := 1 + r.Intn(12)
		out := make([]Value, n)
		for i := range out {
			switch r.Intn(5) {
			case 0:
				out[i] = Value{Kind: KindNull}
			case 1:
				out[i] = num(r.Int63() >> uint(r.Intn(63)) * int64(1-2*r.Intn(2)))
			case 2:
				out[i] = flt(r.NormFloat64() * 1e9)
			case 3:
				b := make([]byte, r.Intn(300))
				for j := range b {
					b[j] = byte('a' + r.Intn(26))
				}
				out[i] = Value{Kind: KindText, Bytes: b}
			default:
				b := make([]byte, r.Intn(300))
				r.Read(b)
				out[i] = Value{Kind: KindBlob, Bytes: b}
			}
		}
		return out
	}
	f := func(seed int64) bool {
		vals := gen(rand.New(rand.NewSource(seed)))
		rec, err := ParseRecord(EncodeRecord(vals), true)
		if err != nil || len(rec.Values) != len(vals) {
			return false
		}
		for i := range vals {
			a, b := vals[i], rec.Values[i]
			if a.Kind != b.Kind || a.Int != b.Int || a.Real != b.Real || !bytes.Equal(a.Bytes, b.Bytes) {
				return false
			}
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 3000}); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeText(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		enc  uint32
		want string
		ok   bool
	}{
		{"utf8", []byte("ñandú"), EncodingUTF8, "ñandú", true},
		{"utf8 invalid", []byte{0xff, 'a'}, EncodingUTF8, "\ufffda", false},
		{"utf16le", []byte{'h', 0, 'i', 0}, EncodingUTF16LE, "hi", true},
		{"utf16be", []byte{0, 'h', 0, 'i'}, EncodingUTF16BE, "hi", true},
		{"utf16 odd length", []byte{'h', 0, 'i'}, EncodingUTF16LE, "h", false},
		{"utf16 surrogate pair", []byte{0x3d, 0xd8, 0x00, 0xde}, EncodingUTF16LE, "\U0001F600", true},
		{"utf16 lone high", []byte{0x3d, 0xd8, 'a', 0}, EncodingUTF16LE, "\ufffda", false},
		{"utf16 lone low", []byte{0x00, 0xde}, EncodingUTF16LE, "\ufffd", false},
		{"utf16 high at end", []byte{0x3d, 0xd8}, EncodingUTF16LE, "\ufffd", false},
	}
	for _, c := range cases {
		got, ok := DecodeText(c.in, c.enc)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: got %q,%v want %q,%v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestValueKindString(t *testing.T) {
	got := []string{KindNull.String(), KindInt.String(), KindReal.String(), KindText.String(), KindBlob.String()}
	if !reflect.DeepEqual(got, []string{"null", "integer", "real", "text", "blob"}) {
		t.Fatal(got)
	}
}
