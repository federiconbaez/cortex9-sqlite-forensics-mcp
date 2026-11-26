# ADR 0001 — Pure byte parsers, no SQLite engine on evidence

Status: accepted (CX9-6208)

## Context

Opening an evidence database with SQLite, even with `mode=ro`, can create a
`-shm` file, replay or checkpoint a `-wal`, and hides exactly the bytes a
forensic examiner cares about: freelist pages, freeblocks, unallocated space
and uncommitted or superseded WAL frames.

## Decision

- The server reads evidence bytes with `O_RDONLY` and parses the file format
  directly in a pure domain package (`internal/domain`): header, varints,
  records, b-tree pages, freelist, WAL, carving, timeline, custody chain.
- The SQLite engine (modernc.org/sqlite) is used **only in tests**, to generate
  synthetic golden databases and to cross-check parser output with PRAGMAs.
- Hexagonal layout: `domain` (pure) ← `app` (use cases, depends on ports) ←
  adapters (`osfs` file source, `custodyjsonl` log, `sysclock`, `mcpserver`).
  Ports: `FileSource`, `Clock`, `CustodyLog`. depguard enforces the direction
  and bans `database/sql` / `modernc.org/sqlite` from non-test server code.
- Evidence is loaded into memory (bounded by `-max-bytes`) and hashed before
  and after analysis; the in-memory copy is what the parsers see.

## Consequences

- Full control and visibility of deleted content; no risk of the engine
  touching the evidence.
- We must re-implement format details and keep them honest with golden tests
  against the real engine and fuzzing.
- Files larger than `-max-bytes` are refused instead of streamed (acceptable for
  typical app databases; documented limit).
