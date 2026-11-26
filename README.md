# cortex9-sqlite-forensics-mcp

Read-only MCP server (stdio) for forensic analysis of SQLite databases from
mobile devices: header, WAL frames, freelist, deleted-record carving, timeline
and a hash-chained chain-of-custody log. Pure Go byte parsers; evidence is
never opened with a SQLite engine.

> Status: **stage 1** — contract, ADR and the pure domain with tests. The MCP
> adapter lands in stage 2. See [CONTRACT.md](CONTRACT.md) and
> [docs/adr](docs/adr).

License: Apache-2.0.
