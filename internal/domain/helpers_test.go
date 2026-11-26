package domain

import "encoding/binary"

func txt(s string) Value  { return Value{Kind: KindText, Bytes: []byte(s)} }
func num(i int64) Value   { return Value{Kind: KindInt, Int: i} }
func flt(f float64) Value { return Value{Kind: KindReal, Real: f} }

func tableCell(rowid int64, vals ...Value) []byte {
	rec := EncodeRecord(vals)
	out := PutVarint(uint64(len(rec)))
	out = append(out, PutVarint(uint64(rowid))...)
	return append(out, rec...)
}

// leafPage lays cells out from the end of the page like SQLite does.
func leafPage(size int, pgno uint32, cells ...[]byte) []byte {
	p := make([]byte, size)
	hdr := 0
	if pgno == 1 {
		hdr = HeaderSize
	}
	p[hdr] = PageLeafTable
	end := size
	for i, c := range cells {
		end -= len(c)
		copy(p[end:], c)
		binary.BigEndian.PutUint16(p[hdr+8+2*i:], uint16(end))
	}
	binary.BigEndian.PutUint16(p[hdr+3:], uint16(len(cells)))
	binary.BigEndian.PutUint16(p[hdr+5:], uint16(end))
	return p
}

// freeCell removes cell idx and turns its bytes into a freeblock (the
// pointer array is compacted, the first 4 bytes are overwritten).
func freeCell(p []byte, pgno uint32, idx, cellLen int) {
	hdr := 0
	if pgno == 1 {
		hdr = HeaderSize
	}
	be := binary.BigEndian
	n := int(be.Uint16(p[hdr+3:]))
	off := int(be.Uint16(p[hdr+8+2*idx:]))
	copy(p[hdr+8+2*idx:], p[hdr+8+2*idx+2:hdr+8+2*n])
	be.PutUint16(p[hdr+8+2*(n-1):], 0)
	be.PutUint16(p[hdr+3:], uint16(n-1))
	// insert in ascending freeblock order (tests free in ascending offsets)
	first := int(be.Uint16(p[hdr+1:]))
	be.PutUint16(p[off:], 0)
	be.PutUint16(p[off+2:], uint16(cellLen))
	if first == 0 || off < first {
		be.PutUint16(p[off:], uint16(first))
		be.PutUint16(p[hdr+1:], uint16(off))
		return
	}
	cur := first
	for {
		next := int(be.Uint16(p[cur:]))
		if next == 0 || next > off {
			be.PutUint16(p[off:], uint16(next))
			be.PutUint16(p[cur:], uint16(off))
			return
		}
		cur = next
	}
}

type walFrameSpec struct {
	pgno, commit uint32
	data         []byte
	badSalt      bool
	badSum       bool
}

func buildWAL(bigEndian bool, pageSize uint32, salt1, salt2 uint32, frames ...walFrameSpec) []byte {
	be := binary.BigEndian
	h := make([]byte, WALHeaderSize)
	magic := uint32(WALMagicLE)
	if bigEndian {
		magic = WALMagicBE
	}
	be.PutUint32(h[0:], magic)
	be.PutUint32(h[4:], WALFormatVersion)
	be.PutUint32(h[8:], pageSize)
	be.PutUint32(h[12:], 1)
	be.PutUint32(h[16:], salt1)
	be.PutUint32(h[20:], salt2)
	s0, s1 := WALChecksum(bigEndian, h[:24], 0, 0)
	be.PutUint32(h[24:], s0)
	be.PutUint32(h[28:], s1)
	out := h
	for _, f := range frames {
		fh := make([]byte, WALFrameHeaderSize)
		be.PutUint32(fh[0:], f.pgno)
		be.PutUint32(fh[4:], f.commit)
		s1a, s2a := salt1, salt2
		if f.badSalt {
			s1a++
		}
		be.PutUint32(fh[8:], s1a)
		be.PutUint32(fh[12:], s2a)
		data := make([]byte, pageSize)
		copy(data, f.data)
		n0, n1 := WALChecksum(bigEndian, fh[:8], s0, s1)
		n0, n1 = WALChecksum(bigEndian, data, n0, n1)
		if f.badSum {
			n0++
		} else {
			s0, s1 = n0, n1
		}
		be.PutUint32(fh[16:], n0)
		be.PutUint32(fh[20:], n1)
		out = append(out, fh...)
		out = append(out, data...)
	}
	return out
}
