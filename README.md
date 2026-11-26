# cortex9-sqlite-forensics-mcp

Read-only [MCP](https://modelcontextprotocol.io) server (stdio, JSON-RPC 2.0)
for forensic analysis of SQLite databases extracted from mobile devices:
header, WAL frames, freelist, deleted-record carving, timestamp timeline and a
hash-chained chain-of-custody log.

Pure Go byte parsers. **Evidence is never opened with a SQLite engine**, never
opened for writing, and no `-shm`/`-wal`/`-journal` file is ever created. Every
call hashes its inputs before and after the analysis and reports whether they
stayed unchanged. Defensive and analytical use only.

- Contract and invariants: [CONTRACT.md](CONTRACT.md)
- Architecture decision: [docs/adr/0001](docs/adr/0001-pure-byte-parsers-no-sqlite-engine.md)

## Tools

| Tool | What it returns |
| --- | --- |
| `evidence_hash` | SHA-256 and size of a file, a new chain-of-custody entry (`seq`, `prev_hash`, `entry_hash`) and whether the whole chain verifies |
| `db_header` | every field of the 100-byte header: page size, usable size, encoding, WAL mode, freelist trunk/count, schema cookie, change counter, auto-vacuum, application id, warnings |
| `wal_frames` | WAL header (magic, salts, checksum validity), per-frame salt/checksum/valid/committed flags following SQLite rules, commit frames, uncommitted tail, stale-salt frames, per-page versions and `same` / `differs` / `beyond-db` against the main database |
| `freelist_pages` | trunk and leaf pages; cycles, duplicates and out-of-range pages are detected; walked count vs header count |
| `recover_cells` | carved record candidates with page, offset, length, rowid, decoded values, `source`, `method`, `confidence` and `reasons` |
| `wal_recover` | records carved from every table-leaf page version held in the `-wal` file: live cells of older versions (rows later deleted or edited) at `high`, plus freeblocks and unallocated space; each names its WAL frame and whether it was committed |
| `timeline` | integer/real values from carved records that look like Unix s/ms/µs, Apple Cocoa s/ns or WebKit µs timestamps inside a window, sorted, with `ambiguous` flags |

All tools except `evidence_hash` are annotated `readOnlyHint: true`.
`evidence_hash` is not read-only only because it appends to the custody log;
it never touches the evidence. In fact every tool appends one custody entry per
input file it analysed, so the log is a full record of what was examined.

Each result carries an `integrity` block:

```json
{"path": "/cases/0042/msgstore.db", "size": 1228800,
 "sha256_before": "9f2c…", "sha256_after": "9f2c…", "unchanged": true}
```

If the hash changes during the call the tool fails with
`evidence changed during analysis` instead of returning data.

## Install and register

```sh
go install github.com/federiconbaez/cortex9-sqlite-forensics-mcp/cmd/sqlite-forensics-mcp@latest
```

Flags:

| Flag | Meaning |
| --- | --- |
| `-custody-log` | **required**. Append-only JSONL file. Keep it outside the evidence directory. A log whose chain does not verify refuses to open. |
| `-root` | optional. Only files that resolve (after symlinks) inside this directory can be analysed. |
| `-max-bytes` | largest file loaded into memory (default 1 GiB). |

MCP client configuration (any client that launches stdio servers uses this
shape):

```json
{
  "mcpServers": {
    "sqlite-forensics": {
      "command": "sqlite-forensics-mcp",
      "args": ["-custody-log", "/cases/0042/custody.jsonl", "-root", "/cases/0042/evidence"]
    }
  }
}
```

Work on a copy of the extraction, mounted read-only if possible. The server
does not need write access to the evidence: the tests run it on `0400` files.

## Example calls

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"evidence_hash",
 "arguments":{"path":"/cases/0042/evidence/sms.db","note":"item 0042-03"}}}

{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"wal_frames",
 "arguments":{"wal_path":"/cases/0042/evidence/sms.db-wal","db_path":"/cases/0042/evidence/sms.db"}}}

{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"recover_cells",
 "arguments":{"path":"/cases/0042/evidence/sms.db","min_confidence":"medium","limit":200}}}

{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"wal_recover",
 "arguments":{"wal_path":"/cases/0042/evidence/sms.db-wal","db_path":"/cases/0042/evidence/sms.db","min_confidence":"high"}}}

{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"timeline",
 "arguments":{"path":"/cases/0042/evidence/sms.db","from":"2024-01-01T00:00:00Z","to":"2024-12-31T23:59:59Z"}}}
```

A carved candidate looks like:

```json
{"page": 7, "offset": 3611, "length": 157, "rowid": 42, "source": "freelist-page-cell",
 "method": "cell-pointer", "confidence": "high", "reasons": [],
 "values": [{"type":"null","serial_type":0},
            {"type":"text","serial_type":43,"value":"synthetic-user-00","valid_encoding":true},
            {"type":"integer","serial_type":4,"value":"1700002520"}]}
```

Integers are returned as strings so 64-bit values survive JSON clients.

## How carving works and what confidence means

| Source | Method | Confidence |
| --- | --- | --- |
| freed table-leaf page still listed in the freelist | its stale cell pointer array | `high` (downgraded for 1 column, non-positive rowid or invalid text) |
| freed page without a usable header, freelist trunk tail, unallocated gap of a live leaf page | byte scan for payload-size + rowid + record that fit exactly | `medium` |
| freeblock of a live or freed page | header rebuilt from the freeblock size, or record-only scan | `low` |

When SQLite frees a cell inside a page it overwrites its first 4 bytes with
the freeblock link, destroying the payload size, the rowid and, for small
cells, the start of the record header. The carver rebuilds the header from the
freeblock size when the payload-size varint length is unambiguous
(1 byte if payload ≤127, 2 bytes if ≥128); with a 1-byte prefix it assumes the
first column is `NULL`, which is how an `INTEGER PRIMARY KEY` alias is stored.
That guess is why those candidates are `low`.

Measured on the synthetic fixture (400 rows, 233 deleted: every third row plus
a tail that frees whole pages): **221 of 233 deleted rows recovered (94.8%)**,
126 of them at `high` confidence. On the synthetic WAL fixture the 11 rows
deleted by the last transaction are all recovered by `wal_recover` from older
page versions, at `high` confidence.

## Verification

| Gate | Result |
| --- | --- |
| tests | 63 top-level tests, 138 passing test cases incl. subtests; `go test -race` clean |
| domain coverage | 98.7% of statements (`internal/domain`) |
| app / adapters coverage | app 91.3%, mcpserver 84.6%, osfs 82.5%, custody log 80.9% |
| property tests | varint round trip and canonical length, header Parse∘Marshal and Marshal∘Parse, record encode/decode (`testing/quick`) |
| fuzzing | native Go fuzz on varint, header, WAL, b-tree page, record and whole-database carving; 20 s each locally: 1.44 M, 1.43 M, 0.81 M (0.67 M once WAL carving was added to the target), 2.04 M, 1.10 M and 31 k execs, no failures; CI runs 15 s each |
| golden tests | databases generated by the real SQLite engine (modernc.org/sqlite) from invented data; header fields equal `PRAGMA page_size/freelist_count/schema_version/page_count`; WAL commit frames equal the transactions written after the checkpoint |
| contract tests | the same `porttest` suites run against the hand-written fakes and the real `osfs` and JSONL adapters |
| end to end | the real binary is built and driven over stdio by the official MCP Go SDK client; the evidence directory listing is identical before and after |
| lint | gofmt, go vet, staticcheck, golangci-lint (gosec, errorlint, revive, depguard) |
| supply chain | gitleaks on the full history, govulncheck in CI |

depguard enforces the hexagon: `internal/domain` imports only the standard
library and none of `os`, `io`, `net`, `database/sql`, `encoding/json`;
`internal/app` cannot import adapters or `os`; no server code may import
`database/sql` or `modernc.org/sqlite`.

## Limitations (honest list)

- **No encrypted databases** (SQLCipher, SEE, WhatsApp crypt files): the header
  parse fails with `bad magic`.
- **Overflow pages are not followed.** Cells whose payload spills to overflow
  pages are counted (`overflow_cells_skipped`) but not decoded, so long text or
  blobs that were deleted are not recovered.
- Only **table** b-tree leaves are carved; index b-trees are ignored.
- Freeblock reconstruction assumes one freed cell per freeblock; when adjacent
  freed cells coalesce, only the cells after the first are found (by scan).
- Builds compiled with `SQLITE_SECURE_DELETE`, or `PRAGMA secure_delete=ON`,
  zero freed content: nothing is left to carve. `auto_vacuum=FULL` returns
  freed pages to the OS.
- Page classification for carving is heuristic (a page that parses as a table
  leaf); it does not walk the schema b-trees, so results are not labelled with
  table or column names.
- `wal_recover` carves WAL page versions independently; it does not yet
  deduplicate them against rows that are still live in the main file, so the
  same row can appear once per page version.
- Rollback journals (`-journal`) are not parsed.
- The whole file is loaded into memory (bounded by `-max-bytes`).
- Timestamp detection is a heuristic: a value is listed for every format that
  lands inside the window. With the default 2005–2035 window Unix seconds and
  Cocoa seconds cannot collide, but other windows can produce `ambiguous`
  events.

## Development

```sh
go test -race ./...
go test -run='^$' -fuzz=FuzzParseWAL -fuzztime=30s ./internal/domain/
golangci-lint run ./...
```

Test databases are generated at test time from invented values
(`internal/synth`). There is no real personal data in this repository.

## License

Apache-2.0. See [LICENSE](LICENSE).
