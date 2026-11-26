// Package synth builds SYNTHETIC SQLite databases for tests. Every value is
// generated; no real personal data is ever used. It is imported only by
// _test.go files, so it never ships in the server binary.
package synth

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, test fixtures only
)

// Marker returns the unique text planted in row id, so tests can tell
// recovered rows apart.
func Marker(id int) string { return fmt.Sprintf("SYNTH-MSG-%04d", id) }

// BaseUnix is the sent_at of row 0 (2023-11-14T22:13:20Z).
const BaseUnix = 1700000000

// CocoaOffset converts Unix seconds to Apple Cocoa seconds.
const CocoaOffset = 978307200

// Body returns the synthetic body text of row id.
func Body(id int) string {
	return Marker(id) + " " + strings.Repeat("lorem ipsum ", 8+id%5)
}

// FreelistDB is a database where rows were deleted so that both freeblocks
// inside live pages and whole freed pages (freelist) exist.
type FreelistDB struct {
	Path     string
	Rows     int
	Deleted  []int // ids that were deleted
	PageSize int
}

func open(path string, pragmas ...string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}
	return db, nil
}

const schema = `CREATE TABLE messages(id INTEGER PRIMARY KEY, sender TEXT, body TEXT, sent_at INTEGER, read_at REAL)`

func insert(tx *sql.Tx, id int) error {
	_, err := tx.Exec(`INSERT INTO messages VALUES(?,?,?,?,?)`,
		id, fmt.Sprintf("synthetic-user-%02d", id%7), Body(id), BaseUnix+id*60, float64(BaseUnix+id*60-CocoaOffset)+0.5)
	return err
}

// BuildFreelistDB writes the database into dir and returns its description.
// Rows 1..rows are inserted; ids divisible by 3 and ids above keep are deleted.
func BuildFreelistDB(dir string, rows, keep int) (FreelistDB, error) {
	path := filepath.Join(dir, "freelist.db")
	db, err := open(path, "PRAGMA page_size=4096", "PRAGMA auto_vacuum=NONE",
		"PRAGMA journal_mode=DELETE", "PRAGMA secure_delete=OFF")
	if err != nil {
		return FreelistDB{}, err
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(schema); err != nil {
		return FreelistDB{}, err
	}
	tx, err := db.Begin()
	if err != nil {
		return FreelistDB{}, err
	}
	for id := 1; id <= rows; id++ {
		if err := insert(tx, id); err != nil {
			_ = tx.Rollback()
			return FreelistDB{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return FreelistDB{}, err
	}
	out := FreelistDB{Path: path, Rows: rows, PageSize: 4096}
	for id := 1; id <= rows; id++ {
		if id%3 == 0 || id > keep {
			out.Deleted = append(out.Deleted, id)
		}
	}
	if _, err := db.Exec(`DELETE FROM messages WHERE id % 3 = 0 OR id > ?`, keep); err != nil {
		return FreelistDB{}, err
	}
	return out, db.Close()
}

// WALDB describes a snapshot of a database in WAL mode copied while the
// writer was still open, so the -wal file holds uncheckpointed frames.
type WALDB struct {
	DBPath       string
	WALPath      string
	Transactions int // committed write transactions after the checkpoint
	PageSize     int
}

// BuildWALDB writes main.db and main.db-wal copies into dir.
func BuildWALDB(dir string) (WALDB, error) {
	live := filepath.Join(dir, "live.db")
	db, err := open(live, "PRAGMA page_size=4096", "PRAGMA journal_mode=WAL",
		"PRAGMA wal_autocheckpoint=0", "PRAGMA secure_delete=OFF")
	if err != nil {
		return WALDB{}, err
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(schema); err != nil {
		return WALDB{}, err
	}
	// first batch, then checkpoint so the main file holds it
	if err := batch(db, 1, 40); err != nil {
		return WALDB{}, err
	}
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return WALDB{}, err
	}
	txs := 0
	if err := batch(db, 41, 80); err != nil {
		return WALDB{}, err
	}
	txs++
	if _, err := db.Exec(`UPDATE messages SET sender='synthetic-edited' WHERE id <= 10`); err != nil {
		return WALDB{}, err
	}
	txs++
	if _, err := db.Exec(`DELETE FROM messages WHERE id BETWEEN 20 AND 30`); err != nil {
		return WALDB{}, err
	}
	txs++
	out := WALDB{DBPath: filepath.Join(dir, "main.db"), WALPath: filepath.Join(dir, "main.db-wal"), Transactions: txs, PageSize: 4096}
	if err := copyFile(live, out.DBPath); err != nil {
		return WALDB{}, err
	}
	if err := copyFile(live+"-wal", out.WALPath); err != nil {
		return WALDB{}, err
	}
	return out, nil
}

func batch(db *sql.DB, from, to int) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for id := from; id <= to; id++ {
		if err := insert(tx, id); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // test fixture path built by this package
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(dst) //nolint:gosec // test fixture path built by this package
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// Pragma returns an integer PRAGMA value of a database (read-only open).
func Pragma(path, name string) (int64, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return 0, err
	}
	defer func() { _ = db.Close() }()
	var v int64
	err = db.QueryRow("PRAGMA " + name).Scan(&v)
	return v, err
}
