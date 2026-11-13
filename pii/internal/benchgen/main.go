// Command benchgen writes the PII detection bench corpus (see package gen):
//
//	go run ./pii/internal/benchgen -out pii/testdata/bench
//
// The corpus is deterministic: running it again gives the same files.
// TestBenchCorpusUpToDate fails when the checked-in corpus differs.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/DavidGodefroid/lockkit/pii/internal/benchgen/gen"
)

func main() {
	out := flag.String("out", "pii/testdata/bench", "directory to write the corpus files to")
	flag.Parse()
	if err := gen.Write(*out); err != nil {
		fmt.Fprintln(os.Stderr, "benchgen:", err)
		os.Exit(1)
	}
}
