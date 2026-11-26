// Command sqlite-forensics-mcp is a read-only MCP server (stdio) for SQLite
// mobile forensics. Logs go to stderr; stdout carries only JSON-RPC.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/adapters/custodyjsonl"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/adapters/mcpserver"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/adapters/osfs"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/adapters/sysclock"
	"github.com/federiconbaez/cortex9-sqlite-forensics-mcp/internal/app"
)

func main() {
	logger := log.New(os.Stderr, "sqlite-forensics-mcp: ", log.LstdFlags)
	custody := flag.String("custody-log", "", "append-only JSONL chain-of-custody file (required; keep it outside the evidence directory)")
	root := flag.String("root", "", "if set, only files inside this directory can be analysed")
	maxBytes := flag.Int64("max-bytes", osfs.DefaultMaxBytes, "largest evidence file loaded into memory")
	version := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *version {
		fmt.Println(mcpserver.Version)
		return
	}
	if *custody == "" {
		logger.Fatal("-custody-log is required")
	}
	if *root != "" {
		if abs, err := filepath.Abs(*custody); err == nil {
			if r, err := filepath.Abs(*root); err == nil && filepath.Dir(abs) == r {
				logger.Print("warning: custody log is inside the evidence root")
			}
		}
	}
	src, err := osfs.New(*root, *maxBytes)
	if err != nil {
		logger.Fatal(err)
	}
	cl, err := custodyjsonl.Open(*custody)
	if err != nil {
		logger.Fatal(err)
	}
	svc := &app.Service{Files: src, Clock: sysclock.Clock{}, Custody: cl}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := mcpserver.New(svc).Run(ctx, &mcp.StdioTransport{}); err != nil && ctx.Err() == nil {
		logger.Fatal(err)
	}
}
