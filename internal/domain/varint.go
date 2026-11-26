package domain

// MaxVarintLen is the longest SQLite varint encoding.
const MaxVarintLen = 9

// ReadVarint decodes a SQLite big-endian varint (1..9 bytes) from b.
// It returns the value and the number of bytes consumed.
func ReadVarint(b []byte) (uint64, int, error) {
	var v uint64
	for i := 0; i < 8; i++ {
		if i >= len(b) {
			return 0, 0, perr(ErrBadVarint, int64(i), "varint needs more than %d bytes", len(b))
		}
		c := b[i]
		v = v<<7 | uint64(c&0x7f)
		if c&0x80 == 0 {
			return v, i + 1, nil
		}
	}
	if len(b) < 9 {
		return 0, 0, perr(ErrBadVarint, 8, "9-byte varint truncated")
	}
	return v<<8 | uint64(b[8]), 9, nil
}

// PutVarint returns the canonical (shortest) SQLite encoding of v.
func PutVarint(v uint64) []byte {
	if v&0xff00000000000000 != 0 {
		buf := make([]byte, 9)
		buf[8] = byte(v)
		v >>= 8
		for i := 7; i >= 0; i-- {
			buf[i] = byte(v&0x7f) | 0x80
			v >>= 7
		}
		return buf
	}
	var tmp [9]byte
	n := 0
	for {
		tmp[n] = byte(v&0x7f) | 0x80
		n++
		v >>= 7
		if v == 0 {
			break
		}
	}
	tmp[0] &= 0x7f
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = tmp[n-1-i]
	}
	return out
}
