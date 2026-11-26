# CONTRACT — cortex9-sqlite-forensics-mcp

Read-only MCP server (stdio, JSON-RPC 2.0) for forensic analysis of SQLite
databases extracted from mobile devices. Defensive and analytical use only.

## Invariants (must always hold)

1. **Evidence is never modified.** Evidence files are opened with `O_RDONLY`
   only. The server never opens evidence with a SQLite engine, never creates
   `-shm`, `-wal` or `-journal` files and never writes next to the evidence.
   depguard forbids `database/sql` and `modernc.org/sqlite` outside tests.
2. **Integrity is verified on every call.** Each tool hashes every input file
   (SHA-256) before reading it and again after analysis, checks that the bytes
   analysed hash to the same value, and reports `sha256_before`,
   `sha256_after` and `unchanged`. A mismatch is an error (`ErrEvidenceChanged`),
   never a silent result.
3. **Chain of custody is append-only and hash-chained.** Every tool run appends
   one entry to a JSONL custody log: `seq`, UTC `time`, `tool`, `path`, `size`,
   `sha256`, `note`, `prev_hash`, `entry_hash`. `entry_hash` is SHA-256 over a
   canonical, quoted serialization that includes `prev_hash`; the first entry
   links to 64 zeros. Editing, removing or reordering any entry is detected by
   `VerifyCustodyChain`. The log lives outside the evidence directory by
   configuration; it is the only file the server writes.
4. **Parsers are total.** The domain parsers accept arbitrary bytes and return
   either a value or a typed error (`*ParseError` wrapping a sentinel such as
   `ErrTruncated`, `ErrBadMagic`, `ErrBadWAL`…). They never panic and never
   read outside the input (native Go fuzzing enforces this).
5. **Pure domain.** `internal/domain` imports only the standard library and no
   I/O packages (`os`, `io`, `net`, `database/sql`, `encoding/json`). depguard
   enforces it.
6. **Honest confidence.** Every carved record carries a confidence
   (`high`/`medium`/`low`), the method that found it and the reasons it is not
   higher. Timestamp interpretations that fit several formats are flagged
   `ambiguous`.
7. **Synthetic test data only.** Tests generate their databases with the real
   SQLite engine (modernc.org/sqlite) from invented values. No real personal
   data exists in this repository.

## Tools (exposed over MCP)

| Tool | Input | Output |
| --- | --- | --- |
| `evidence_hash` | `path`, `note?` | SHA-256, size, custody entry, chain verified |
| `db_header` | `path` | all 100-byte header fields, warnings |
| `wal_frames` | `wal_path`, `db_path?` | WAL header, salts, checksum validity per frame, commit frames, per-page versions and diff vs main DB |
| `freelist_pages` | `path` | trunk/leaf pages, walked count vs header count |
| `recover_cells` | `path`, `min_confidence?`, `limit?` | carved records with page, offset, source, method, confidence |
| `timeline` | `path`, `from?`, `to?`, `limit?` | timestamp-looking values from carved records, sorted |

## Domain semantics

- Varints: SQLite big-endian 1–9 bytes; `PutVarint` emits the shortest form.
- WAL validity follows SQLite: a frame is valid only if its salts equal the
  header salts, its cumulative checksum matches, and every earlier frame was
  valid. Frames after the last valid commit frame are *uncommitted*. Frames
  with other salts are counted as `stale_salt_frames` (older WAL generation).
- Freelist walk detects cycles, duplicate pages and out-of-range page numbers
  instead of looping or panicking.
- Carving scans (a) freed table-leaf pages through their stale cell pointer
  array (`high`), (b) byte scans of freed pages and of the unallocated gap of
  live leaf pages (`medium`), (c) freeblocks of live pages: header rebuilt from
  the freeblock size or record-only scan (`low`). Cells that spill to overflow
  pages are counted, not decoded.

## Out of scope

Encrypted databases (SQLCipher, SEE), overflow-chain reassembly, index b-tree
carving, rollback-journal (`-journal`) parsing, schema-aware column naming,
writing or repairing databases, any offensive capability.
