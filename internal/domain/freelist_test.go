package domain

import (
	"encoding/binary"
	"errors"
	"testing"
)

// image builds a database image of n pages with a header that points at the
// freelist described by trunks (page -> leaves) chained in order.
func image(n int, count uint32, trunks ...[]uint32) []byte {
	const ps = 512
	db := make([]byte, ps*n)
	h := validHeader()
	h.PageSize = ps
	h.DatabaseSizePages = uint32(n)
	h.FreelistPageCount = count
	if len(trunks) > 0 {
		h.FirstFreelistTrunk = trunks[0][0]
	}
	hb := h.Marshal()
	copy(db, hb[:])
	for i, t := range trunks {
		if int(t[0]) > n {
			continue
		}
		pg := db[(int(t[0])-1)*ps:]
		next := uint32(0)
		if i+1 < len(trunks) {
			next = trunks[i+1][0]
		}
		binary.BigEndian.PutUint32(pg[0:], next)
		binary.BigEndian.PutUint32(pg[4:], uint32(len(t)-1))
		for j, l := range t[1:] {
			binary.BigEndian.PutUint32(pg[8+4*j:], l)
		}
	}
	return db
}

func TestWalkFreelist(t *testing.T) {
	db := image(8, 5, []uint32{2, 3, 4}, []uint32{5, 6})
	h, _ := ParseHeader(db)
	fl, err := WalkFreelist(db, h)
	if err != nil {
		t.Fatal(err)
	}
	if len(fl.Trunks) != 2 || len(fl.LeafPages) != 3 || fl.TotalPages != 5 || !fl.CountMatches {
		t.Fatalf("%+v", fl)
	}
	if !fl.Contains(5) || !fl.Contains(4) || fl.Contains(7) {
		t.Fatal("Contains is wrong")
	}
}

func TestWalkFreelistEmptyAndMismatch(t *testing.T) {
	db := image(3, 0)
	h, _ := ParseHeader(db)
	fl, err := WalkFreelist(db, h)
	if err != nil || fl.TotalPages != 0 || !fl.CountMatches {
		t.Fatalf("%+v %v", fl, err)
	}
	db = image(6, 9, []uint32{2, 3})
	h, _ = ParseHeader(db)
	fl, err = WalkFreelist(db, h)
	if err != nil || fl.CountMatches || len(fl.Warnings) == 0 {
		t.Fatalf("%+v %v", fl, err)
	}
	db = image(6, 2, []uint32{2, 0, 99, 3})
	h, _ = ParseHeader(db)
	fl, err = WalkFreelist(db, h)
	if err != nil || len(fl.LeafPages) != 1 || len(fl.Warnings) == 0 {
		t.Fatalf("out-of-range leaves must be skipped with a warning: %+v %v", fl, err)
	}
}

func TestWalkFreelistCorrupt(t *testing.T) {
	cases := map[string][]byte{
		"trunk beyond image": image(4, 1, []uint32{9}),
		"duplicate leaf":     image(6, 3, []uint32{2, 3, 3}),
		"leaf is trunk":      image(6, 2, []uint32{2, 2}),
	}
	tooMany := image(4, 1, []uint32{2})
	binary.BigEndian.PutUint32(tooMany[512+4:], 1000)
	cases["leaf count too large"] = tooMany
	cycle := image(6, 2, []uint32{2}, []uint32{3})
	binary.BigEndian.PutUint32(cycle[2*512:], 2) // page 3 points back to page 2
	cases["cycle"] = cycle
	for name, db := range cases {
		t.Run(name, func(t *testing.T) {
			h, _ := ParseHeader(db)
			if _, err := WalkFreelist(db, h); !errors.Is(err, ErrFreelistCorrupt) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	h := validHeader()
	h.PageSize, h.ReservedBytes = 512, 255
	h.PageSize = 512
	h.ReservedBytes = 0
	h.FirstFreelistTrunk = 1
	h.DatabaseSizePages = 0
	if _, err := WalkFreelist(nil, h); !errors.Is(err, ErrFreelistCorrupt) {
		t.Fatalf("trunk in empty image: %v", err)
	}
	h2 := Header{PageSize: 4, FirstFreelistTrunk: 1}
	if _, err := WalkFreelist(make([]byte, 8), h2); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("tiny usable size: %v", err)
	}
}
