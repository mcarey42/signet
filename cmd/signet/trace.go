package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/mcarey42/signet/internal/trace"
)

// `signet trace` exists mostly to be read.
//
// The command itself does little — tracing is switched on with a flag to
// `serve` — but somebody deciding whether to send us a trace file needs to know
// what is in it, and a doc page they have to go find is a doc page they will
// not read. So the answer lives in the tool, next to the thing it describes.

const traceUsage = `signet trace — diagnostic tracing

Tracing is OFF unless you switch it on, and costs nothing while off.

  signet serve -data-dir DIR -trace-file /tmp/signet.trace
  signet serve -data-dir DIR -trace-file /tmp/signet.trace -trace-areas authz,apply

Reproduce the problem while it runs, then stop the server. The file is
newline-delimited JSON, one object per event.

AREAS

  %s

  "all" is the default. Narrow it when you know roughly where the problem is:
  a wide trace on a busy node produces a lot of noise to read through.

WHAT IS IN THE FILE

  Recorded:     resource paths, principal and binding identifiers, role and
                scope names, route patterns, timings, decisions and errors.
  NOT recorded: secret values, tokens, private keys, or the contents of
                anything sealed. Bearer credentials appear only as a salted
                digest ("r:..."), which lets you follow one token through a
                trace without the file ever containing it. The salt is random
                per process, so digests mean nothing outside that one file.

  This is a deliberate line rather than a guarantee of harmlessness: a secret's
  PATH is not the secret, but it does tell a reader that a secret by that name
  exists, and identifiers reveal the shape of your deployment. Read a trace
  before sending it. It is plain text, one event per line, and skimming it is
  the point.

BEFORE YOU SEND ONE

  head -50 /tmp/signet.trace     # see the shape
  grep '"area":"authz"' ...      # the usual reason a trace was taken
`

func traceAreaList() string {
	names := make([]string, 0, len(trace.AllAreas))
	for _, a := range trace.AllAreas {
		names = append(names, string(a))
	}
	return strings.Join(names, ",")
}

func cmdTrace(args []string) error {
	if len(args) > 0 && args[0] != "help" && args[0] != "-h" && args[0] != "--help" {
		return fmt.Errorf(
			"trace: %q is not a subcommand — tracing is switched on with `serve -trace-file`. "+
				"Run `signet trace help` for what a trace contains", args[0])
	}
	fmt.Printf(traceUsage, describeAreas())
	_ = os.Stdout.Sync()
	return nil
}

func describeAreas() string {
	descs := map[trace.Area]string{
		trace.AreaAuthz:   "authorization decisions — why access was allowed or refused",
		trace.AreaApply:   "consensus and the state machine — what each committed entry did",
		trace.AreaStore:   "transactions and sealing",
		trace.AreaSeal:    "seal and key custody operations",
		trace.AreaHTTP:    "request routing and outcomes",
		trace.AreaTrust:   "bundles, anchors, and certificate verification",
		trace.AreaAudit:   "the hash chain, checkpoints, and witnessing",
		trace.AreaPAM:     "activation requests, approvals, and kills",
		trace.AreaAttest:  "login and evidence verification",
		trace.AreaDialect: "per-protocol serialization",
	}
	var b strings.Builder
	for i, a := range trace.AllAreas {
		if i > 0 {
			b.WriteString("\n  ")
		}
		fmt.Fprintf(&b, "%-9s %s", a, descs[a])
	}
	return b.String()
}
