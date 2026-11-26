package domain

import (
	"encoding/binary"
	"math"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxColumns bounds how many serial types a record header may declare
// (SQLITE_MAX_COLUMN hard limit is 32767).
const MaxColumns = 32767

// ValueKind is the storage class of a decoded record value.
type ValueKind uint8

// Storage classes.
const (
	KindNull ValueKind = iota
	KindInt
	KindReal
	KindText
	KindBlob
)

func (k ValueKind) String() string {
	switch k {
	case KindNull:
		return "null"
	case KindInt:
		return "integer"
	case KindReal:
		return "real"
	case KindText:
		return "text"
	default:
		return "blob"
	}
}

// Value is one decoded column. Bytes aliases a copy, never the input slice.
type Value struct {
	SerialType uint64
	Kind       ValueKind
	Int        int64
	Real       float64
	Bytes      []byte // raw text or blob bytes
}

// Record is a decoded SQLite record (header + body).
type Record struct {
	HeaderSize int
	BodySize   int
	Values     []Value
}

// Len is the total encoded size of the record.
func (r Record) Len() int { return r.HeaderSize + r.BodySize }

// SerialTypeSize returns the body size of a serial type and whether the type is legal.
func SerialTypeSize(t uint64) (uint64, bool) {
	switch {
	case t <= 4:
		return [...]uint64{0, 1, 2, 3, 4}[t], true
	case t == 5:
		return 6, true
	case t == 6 || t == 7:
		return 8, true
	case t == 8 || t == 9:
		return 0, true
	case t == 10 || t == 11:
		return 0, false
	default:
		return (t - 12) / 2, true
	}
}

// ParseRecord decodes a record that starts at b[0]. When exact is true the
// record must consume all of b; otherwise trailing bytes are ignored.
func ParseRecord(b []byte, exact bool) (Record, error) {
	hs, n, err := ReadVarint(b)
	if err != nil {
		return Record{}, perr(ErrBadRecord, 0, "header size: %v", err)
	}
	if hs < uint64(n) || hs > uint64(len(b)) {
		return Record{}, perr(ErrBadRecord, 0, "header size %d outside [%d,%d]", hs, n, len(b))
	}
	var types []uint64
	var body uint64
	for off := n; off < int(hs); {
		t, m, err := ReadVarint(b[off:hs])
		if err != nil {
			return Record{}, perr(ErrBadRecord, int64(off), "serial type: %v", err)
		}
		sz, ok := SerialTypeSize(t)
		if !ok {
			return Record{}, perr(ErrBadRecord, int64(off), "reserved serial type %d", t)
		}
		if len(types) >= MaxColumns {
			return Record{}, perr(ErrBadRecord, int64(off), "more than %d columns", MaxColumns)
		}
		body += sz
		if body > uint64(len(b))-hs {
			return Record{}, perr(ErrBadRecord, int64(off), "body exceeds %d available bytes", uint64(len(b))-hs)
		}
		types = append(types, t)
		off += m
	}
	if exact && hs+body != uint64(len(b)) {
		return Record{}, perr(ErrBadRecord, 0, "record is %d bytes, payload is %d", hs+body, len(b))
	}
	r := Record{HeaderSize: int(hs), BodySize: int(body), Values: make([]Value, len(types))}
	pos := int(hs)
	for i, t := range types {
		sz, _ := SerialTypeSize(t)
		r.Values[i] = decodeValue(t, b[pos:pos+int(sz)])
		pos += int(sz)
	}
	return r, nil
}

func decodeValue(t uint64, b []byte) Value {
	v := Value{SerialType: t}
	switch {
	case t == 0:
		v.Kind = KindNull
	case t >= 1 && t <= 6:
		v.Kind = KindInt
		var u uint64
		for _, c := range b {
			u = u<<8 | uint64(c)
		}
		shift := 64 - 8*uint(len(b))
		v.Int = int64(u<<shift) >> shift //nolint:gosec // two's complement sign extension
	case t == 7:
		v.Kind = KindReal
		v.Real = math.Float64frombits(binary.BigEndian.Uint64(b))
	case t == 8 || t == 9:
		v.Kind = KindInt
		v.Int = int64(t - 8) //nolint:gosec // 0 or 1
	case t%2 == 0:
		v.Kind = KindBlob
		v.Bytes = append([]byte(nil), b...)
	default:
		v.Kind = KindText
		v.Bytes = append([]byte(nil), b...)
	}
	return v
}

// DecodeText converts raw text bytes in the database encoding to a Go string,
// reporting whether they were valid in that encoding.
func DecodeText(b []byte, encoding uint32) (string, bool) {
	switch encoding {
	case EncodingUTF16LE, EncodingUTF16BE:
		if len(b)%2 != 0 {
			return string(utf16.Decode(u16(b[:len(b)-1], encoding))), false
		}
		u := u16(b, encoding)
		s := string(utf16.Decode(u))
		return s, !containsReplacement(u)
	default:
		if utf8.Valid(b) {
			return string(b), true
		}
		return string([]rune(string(b))), false
	}
}

func u16(b []byte, enc uint32) []uint16 {
	out := make([]uint16, len(b)/2)
	for i := range out {
		if enc == EncodingUTF16LE {
			out[i] = binary.LittleEndian.Uint16(b[2*i:])
		} else {
			out[i] = binary.BigEndian.Uint16(b[2*i:])
		}
	}
	return out
}

func containsReplacement(u []uint16) bool {
	for i := 0; i < len(u); i++ {
		c := u[i]
		switch {
		case c >= 0xD800 && c < 0xDC00:
			if i+1 >= len(u) || u[i+1] < 0xDC00 || u[i+1] > 0xDFFF {
				return true
			}
			i++
		case c >= 0xDC00 && c <= 0xDFFF:
			return true
		}
	}
	return false
}

// EncodeRecord builds a record from values (used by tests and synthetic
// fixtures; it chooses the smallest integer serial type).
func EncodeRecord(vals []Value) []byte {
	var hdr, body []byte
	for _, v := range vals {
		t, data := encodeValue(v)
		hdr = append(hdr, PutVarint(t)...)
		body = append(body, data...)
	}
	// header size includes its own varint
	hs := uint64(len(hdr) + 1)
	for uint64(len(PutVarint(hs)))+uint64(len(hdr)) != hs {
		hs = uint64(len(PutVarint(hs))) + uint64(len(hdr))
	}
	out := append(PutVarint(hs), hdr...)
	return append(out, body...)
}

func encodeValue(v Value) (uint64, []byte) {
	switch v.Kind {
	case KindNull:
		return 0, nil
	case KindInt:
		switch v.Int {
		case 0:
			return 8, nil
		case 1:
			return 9, nil
		}
		for _, c := range []struct {
			t    uint64
			size uint
		}{{1, 1}, {2, 2}, {3, 3}, {4, 4}, {5, 6}} {
			lim := int64(1) << (8*c.size - 1)
			if v.Int >= -lim && v.Int < lim {
				return c.t, beInt(v.Int, c.size)
			}
		}
		return 6, beInt(v.Int, 8)
	case KindReal:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], math.Float64bits(v.Real))
		return 7, b[:]
	case KindText:
		return uint64(len(v.Bytes))*2 + 13, v.Bytes
	default:
		return uint64(len(v.Bytes))*2 + 12, v.Bytes
	}
}

func beInt(x int64, size uint) []byte {
	out := make([]byte, size)
	u := uint64(x) //nolint:gosec // two's complement bytes
	for i := int(size) - 1; i >= 0; i-- {
		out[i] = byte(u)
		u >>= 8
	}
	return out
}
