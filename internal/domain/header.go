package domain

import "encoding/binary"

// HeaderSize is the size of the SQLite database file header.
const HeaderSize = 100

// Magic is the 16-byte SQLite file signature.
const Magic = "SQLite format 3\x00"

// TextEncoding values stored at header offset 56.
const (
	EncodingUTF8    uint32 = 1
	EncodingUTF16LE uint32 = 2
	EncodingUTF16BE uint32 = 3
)

// Header is the decoded 100-byte SQLite database header. Every field is kept,
// including the reserved area, so Marshal(ParseHeader(b)) reproduces b.
type Header struct {
	PageSize             uint32 // decoded: the on-disk value 1 means 65536
	WriteVersion         uint8  // 1 legacy rollback journal, 2 WAL
	ReadVersion          uint8
	ReservedBytes        uint8
	MaxPayloadFraction   uint8
	MinPayloadFraction   uint8
	LeafPayloadFraction  uint8
	FileChangeCounter    uint32
	DatabaseSizePages    uint32
	FirstFreelistTrunk   uint32
	FreelistPageCount    uint32
	SchemaCookie         uint32
	SchemaFormat         uint32
	DefaultCacheSize     uint32
	LargestRootPage      uint32 // non-zero means auto-vacuum / incremental vacuum
	TextEncoding         uint32
	UserVersion          uint32
	IncrementalVacuum    uint32
	ApplicationID        uint32
	ReservedForExpansion [20]byte
	VersionValidFor      uint32
	SQLiteVersionNumber  uint32
	Warnings             []string // non-fatal oddities; not serialized
}

// UsableSize is the page size minus the reserved bytes at the end of each page.
func (h Header) UsableSize() int { return int(h.PageSize) - int(h.ReservedBytes) }

// InHeaderSizeValid reports whether DatabaseSizePages can be trusted
// (SQLite rule: non-zero and change counter equals version-valid-for).
func (h Header) InHeaderSizeValid() bool {
	return h.DatabaseSizePages != 0 && h.FileChangeCounter == h.VersionValidFor
}

// EncodingName returns a readable name for the text encoding.
func (h Header) EncodingName() string {
	switch h.TextEncoding {
	case EncodingUTF8:
		return "UTF-8"
	case EncodingUTF16LE:
		return "UTF-16le"
	case EncodingUTF16BE:
		return "UTF-16be"
	default:
		return "unknown"
	}
}

// ValidPageSize reports whether n is a legal SQLite page size.
func ValidPageSize(n uint32) bool {
	return n >= 512 && n <= 65536 && n&(n-1) == 0
}

// ParseHeader decodes the first 100 bytes of b. Fatal problems (truncation,
// magic, page size) are errors; other deviations are reported as Warnings.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, perr(ErrTruncated, int64(len(b)), "need %d header bytes, have %d", HeaderSize, len(b))
	}
	if string(b[:16]) != Magic {
		return Header{}, perr(ErrBadMagic, 0, "not a SQLite 3 database")
	}
	be := binary.BigEndian
	raw := uint32(be.Uint16(b[16:18]))
	ps := raw
	if raw == 1 {
		ps = 65536
	}
	if !ValidPageSize(ps) {
		return Header{}, perr(ErrBadPageSize, 16, "page size field %d", raw)
	}
	h := Header{
		PageSize:            ps,
		WriteVersion:        b[18],
		ReadVersion:         b[19],
		ReservedBytes:       b[20],
		MaxPayloadFraction:  b[21],
		MinPayloadFraction:  b[22],
		LeafPayloadFraction: b[23],
		FileChangeCounter:   be.Uint32(b[24:]),
		DatabaseSizePages:   be.Uint32(b[28:]),
		FirstFreelistTrunk:  be.Uint32(b[32:]),
		FreelistPageCount:   be.Uint32(b[36:]),
		SchemaCookie:        be.Uint32(b[40:]),
		SchemaFormat:        be.Uint32(b[44:]),
		DefaultCacheSize:    be.Uint32(b[48:]),
		LargestRootPage:     be.Uint32(b[52:]),
		TextEncoding:        be.Uint32(b[56:]),
		UserVersion:         be.Uint32(b[60:]),
		IncrementalVacuum:   be.Uint32(b[64:]),
		ApplicationID:       be.Uint32(b[68:]),
		VersionValidFor:     be.Uint32(b[92:]),
		SQLiteVersionNumber: be.Uint32(b[96:]),
	}
	copy(h.ReservedForExpansion[:], b[72:92])
	h.Warnings = h.check()
	return h, nil
}

func (h Header) check() []string {
	var w []string
	if h.WriteVersion != 1 && h.WriteVersion != 2 {
		w = append(w, "write version is neither 1 (rollback) nor 2 (WAL)")
	}
	if h.ReadVersion != 1 && h.ReadVersion != 2 {
		w = append(w, "read version is neither 1 (rollback) nor 2 (WAL)")
	}
	if h.MaxPayloadFraction != 64 || h.MinPayloadFraction != 32 || h.LeafPayloadFraction != 32 {
		w = append(w, "payload fractions differ from the mandatory 64/32/32")
	}
	if h.UsableSize() < 480 {
		w = append(w, "usable page size below 480 bytes")
	}
	if h.TextEncoding < 1 || h.TextEncoding > 3 {
		w = append(w, "unknown text encoding")
	}
	if h.SchemaFormat > 4 {
		w = append(w, "schema format number above 4")
	}
	if h.FreelistPageCount > 0 && h.FirstFreelistTrunk == 0 {
		w = append(w, "freelist count is non-zero but there is no trunk page")
	}
	for _, c := range h.ReservedForExpansion {
		if c != 0 {
			w = append(w, "reserved-for-expansion bytes are not zero")
			break
		}
	}
	return w
}

// Marshal serializes the header back to its 100-byte on-disk form.
func (h Header) Marshal() [HeaderSize]byte {
	var b [HeaderSize]byte
	be := binary.BigEndian
	copy(b[:16], Magic)
	ps := h.PageSize
	if ps == 65536 {
		ps = 1
	}
	be.PutUint16(b[16:], uint16(ps)) //nolint:gosec // validated page size fits after the 65536->1 mapping
	b[18], b[19], b[20] = h.WriteVersion, h.ReadVersion, h.ReservedBytes
	b[21], b[22], b[23] = h.MaxPayloadFraction, h.MinPayloadFraction, h.LeafPayloadFraction
	for _, f := range []struct {
		off int
		v   uint32
	}{
		{24, h.FileChangeCounter}, {28, h.DatabaseSizePages}, {32, h.FirstFreelistTrunk},
		{36, h.FreelistPageCount}, {40, h.SchemaCookie}, {44, h.SchemaFormat},
		{48, h.DefaultCacheSize}, {52, h.LargestRootPage}, {56, h.TextEncoding},
		{60, h.UserVersion}, {64, h.IncrementalVacuum}, {68, h.ApplicationID},
		{92, h.VersionValidFor}, {96, h.SQLiteVersionNumber},
	} {
		be.PutUint32(b[f.off:], f.v)
	}
	copy(b[72:92], h.ReservedForExpansion[:])
	return b
}

// PageCount returns how many pages the image holds, preferring the in-header
// size when SQLite would trust it and it fits in the image.
func PageCount(h Header, imageLen int) uint32 {
	byLen := uint32(imageLen / int(h.PageSize)) //nolint:gosec // image size bounded by caller
	if h.InHeaderSizeValid() && h.DatabaseSizePages <= byLen {
		return h.DatabaseSizePages
	}
	return byLen
}

// PageBytes returns the bytes of 1-based page pgno, or an error if absent.
func PageBytes(db []byte, pageSize uint32, pgno uint32) ([]byte, error) {
	if pgno == 0 {
		return nil, perr(ErrInvalidArgument, -1, "page numbers start at 1")
	}
	start := int64(pgno-1) * int64(pageSize)
	end := start + int64(pageSize)
	if end > int64(len(db)) {
		return nil, perr(ErrTruncated, start, "page %d beyond image of %d bytes", pgno, len(db))
	}
	return db[start:end], nil
}
