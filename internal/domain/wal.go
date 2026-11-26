package domain

import (
	"bytes"
	"encoding/binary"
)

// WAL constants from the SQLite file format.
const (
	WALHeaderSize      = 32
	WALFrameHeaderSize = 24
	WALMagicLE         = 0x377f0682 // checksums use little-endian words
	WALMagicBE         = 0x377f0683 // checksums use big-endian words
	WALFormatVersion   = 3007000
)

// WALHeader is the 32-byte WAL file header.
type WALHeader struct {
	Magic            uint32
	BigEndianSums    bool
	FormatVersion    uint32
	PageSize         uint32
	CheckpointSeq    uint32
	Salt1, Salt2     uint32
	Checksum1        uint32
	Checksum2        uint32
	ChecksumValid    bool
	ComputedChecksum [2]uint32
}

// WALFrame describes one frame. Data aliases the input WAL bytes.
type WALFrame struct {
	Index      int    // 0-based frame index
	Offset     int64  // byte offset of the frame header in the WAL file
	PageNo     uint32 // database page this frame holds
	CommitSize uint32 // non-zero: commit frame, DB size in pages after commit
	Salt1      uint32
	Salt2      uint32
	SaltMatch  bool
	ChecksumOK bool
	Valid      bool   // salts and cumulative checksum valid and no earlier invalid frame
	Committed  bool   // valid and at or before the last valid commit frame
	Data       []byte `json:"-"`
}

// IsCommit reports whether the frame ends a transaction.
func (f WALFrame) IsCommit() bool { return f.CommitSize != 0 }

// WAL is a parsed write-ahead log.
type WAL struct {
	Header          WALHeader
	Frames          []WALFrame
	ValidFrames     int
	CommittedFrames int
	CommitFrames    int // valid commit frames
	TrailingBytes   int // bytes after the last whole frame
	StaleSaltFrames int // frames whose salts belong to an older WAL generation
	Warnings        []string
}

// WALChecksum is the SQLite WAL checksum over data (len multiple of 8),
// continuing from (s0,s1).
func WALChecksum(bigEndian bool, data []byte, s0, s1 uint32) (uint32, uint32) {
	var order binary.ByteOrder = binary.LittleEndian
	if bigEndian {
		order = binary.BigEndian
	}
	for i := 0; i+8 <= len(data); i += 8 {
		s0 += order.Uint32(data[i:]) + s1
		s1 += order.Uint32(data[i+4:]) + s0
	}
	return s0, s1
}

// ParseWALHeader decodes and validates the WAL header checksum.
func ParseWALHeader(b []byte) (WALHeader, error) {
	if len(b) < WALHeaderSize {
		return WALHeader{}, perr(ErrTruncated, int64(len(b)), "WAL header needs %d bytes", WALHeaderSize)
	}
	be := binary.BigEndian
	h := WALHeader{Magic: be.Uint32(b[0:])}
	if h.Magic != WALMagicLE && h.Magic != WALMagicBE {
		return WALHeader{}, perr(ErrBadMagic, 0, "WAL magic 0x%08x", h.Magic)
	}
	h.BigEndianSums = h.Magic&1 == 1
	h.FormatVersion = be.Uint32(b[4:])
	h.PageSize = be.Uint32(b[8:])
	if !ValidPageSize(h.PageSize) {
		return WALHeader{}, perr(ErrBadPageSize, 8, "WAL page size %d", h.PageSize)
	}
	h.CheckpointSeq = be.Uint32(b[12:])
	h.Salt1, h.Salt2 = be.Uint32(b[16:]), be.Uint32(b[20:])
	h.Checksum1, h.Checksum2 = be.Uint32(b[24:]), be.Uint32(b[28:])
	c0, c1 := WALChecksum(h.BigEndianSums, b[:24], 0, 0)
	h.ComputedChecksum = [2]uint32{c0, c1}
	h.ChecksumValid = c0 == h.Checksum1 && c1 == h.Checksum2
	return h, nil
}

// ParseWAL decodes every whole frame in the WAL and applies SQLite's validity
// rules: a frame is valid only if its salts match the header, its cumulative
// checksum matches, and every earlier frame was valid.
func ParseWAL(b []byte) (WAL, error) {
	h, err := ParseWALHeader(b)
	if err != nil {
		return WAL{}, err
	}
	w := WAL{Header: h}
	if h.FormatVersion != WALFormatVersion {
		w.Warnings = append(w.Warnings, "unexpected WAL format version")
	}
	if !h.ChecksumValid {
		w.Warnings = append(w.Warnings, "WAL header checksum mismatch: SQLite would ignore every frame")
	}
	be := binary.BigEndian
	frameLen := int64(WALFrameHeaderSize) + int64(h.PageSize)
	s0, s1 := h.Checksum1, h.Checksum2
	chainOK := h.ChecksumValid
	lastCommit := -1
	off := int64(WALHeaderSize)
	for ; off+frameLen <= int64(len(b)); off += frameLen {
		fh := b[off : off+WALFrameHeaderSize]
		f := WALFrame{
			Index:      len(w.Frames),
			Offset:     off,
			PageNo:     be.Uint32(fh[0:]),
			CommitSize: be.Uint32(fh[4:]),
			Salt1:      be.Uint32(fh[8:]),
			Salt2:      be.Uint32(fh[12:]),
			Data:       b[off+WALFrameHeaderSize : off+frameLen],
		}
		f.SaltMatch = f.Salt1 == h.Salt1 && f.Salt2 == h.Salt2
		n0, n1 := WALChecksum(h.BigEndianSums, fh[:8], s0, s1)
		n0, n1 = WALChecksum(h.BigEndianSums, f.Data, n0, n1)
		f.ChecksumOK = n0 == be.Uint32(fh[16:]) && n1 == be.Uint32(fh[20:])
		if !f.SaltMatch {
			w.StaleSaltFrames++
		}
		if chainOK && f.SaltMatch && f.ChecksumOK && f.PageNo != 0 {
			f.Valid = true
			s0, s1 = n0, n1
			w.ValidFrames++
			if f.IsCommit() {
				lastCommit = f.Index
				w.CommitFrames++
			}
		} else {
			chainOK = false
		}
		w.Frames = append(w.Frames, f)
	}
	w.TrailingBytes = int(int64(len(b)) - off)
	for i := 0; i <= lastCommit; i++ {
		w.Frames[i].Committed = true
		w.CommittedFrames++
	}
	if w.ValidFrames > w.CommittedFrames {
		w.Warnings = append(w.Warnings, "valid frames after the last commit are an uncommitted transaction")
	}
	return w, nil
}

// PageDiffStatus classifies a WAL page against the main database image.
type PageDiffStatus string

// Diff statuses.
const (
	DiffSame     PageDiffStatus = "same"
	DiffDiffers  PageDiffStatus = "differs"
	DiffBeyondDB PageDiffStatus = "beyond-db"
	// DiffIncomparable means no database image or a different page size.
	DiffIncomparable PageDiffStatus = "incomparable"
)

// WALPageSummary groups the frames of one page.
type WALPageSummary struct {
	PageNo          uint32
	FrameIndexes    []int // every frame (any validity) holding this page
	LatestCommitted int   // index of the newest committed frame, -1 if none
	Status          PageDiffStatus
	Versions        int // committed frames for the page (historical versions)
}

// SummarizeWALPages groups frames per page and compares the newest committed
// version of each page with the main database image (or the newest frame when
// none is committed). With no image or a different page size the status is
// incomparable.
func SummarizeWALPages(w WAL, db []byte, dbPageSize uint32) []WALPageSummary {
	idx := map[uint32]int{}
	var out []WALPageSummary
	for _, f := range w.Frames {
		i, ok := idx[f.PageNo]
		if !ok {
			i = len(out)
			idx[f.PageNo] = i
			out = append(out, WALPageSummary{PageNo: f.PageNo, LatestCommitted: -1})
		}
		s := &out[i]
		s.FrameIndexes = append(s.FrameIndexes, f.Index)
		if f.Committed {
			s.LatestCommitted = f.Index
			s.Versions++
		}
	}
	for i := range out {
		s := &out[i]
		ref := s.LatestCommitted
		if ref < 0 {
			ref = s.FrameIndexes[len(s.FrameIndexes)-1]
		}
		data := w.Frames[ref].Data
		page, err := PageBytes(db, dbPageSize, s.PageNo)
		switch {
		case len(db) == 0 || dbPageSize != w.Header.PageSize:
			s.Status = DiffIncomparable
		case err != nil:
			s.Status = DiffBeyondDB
		case bytes.Equal(page, data):
			s.Status = DiffSame
		default:
			s.Status = DiffDiffers
		}
	}
	return out
}
