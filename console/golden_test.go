//go:build unix

package console

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/fingerprint"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden files of the console")

// checkGolden compares what io saw, call by call and colours kept, with
// testdata/golden/<name>.txt. What the human sees must stay
// byte-identical: go test ./console -run Golden -update rewrites the files
// only when a change of it is meant.
func checkGolden(t *testing.T, name string, io *fakeIO, replace ...string) {
	t.Helper()
	io.mu.Lock()
	got := strings.Join(io.trace, "\n") + "\n"
	io.mu.Unlock()
	got = strings.NewReplacer(replace...).Replace(got)
	got = goldenPeer.ReplaceAllString(got, "requested by <peer>")
	path := filepath.Join("testdata", "golden", name+".txt")
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if got != string(want) {
		t.Fatalf("%s differs from %s:\n%s", name, path, lineDiff(string(want), got))
	}
}

// goldenPeer is the requester line, which names this test process.
var goldenPeer = regexp.MustCompile(`requested by uid \d+ \([^)]*\) · pid \d+(?: · exe [^\\"]+)?`)

// lineDiff names the first line that differs.
func lineDiff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < max(len(w), len(g)); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			return "line " + strconv.Itoa(i+1) + ":\n- " + wl + "\n+ " + gl
		}
	}
	return ""
}

// Level 2: a typed yes and a finger approve; a non-matching finger denies.
func TestGoldenLevel2(t *testing.T) {
	v := &fingerprint.Fake{Results: []error{nil, fingerprint.ErrNoMatch}}
	h := newHarness(t, uat(), func(c *ServerConfig) {
		c.Level = 2
		c.Approver = NewFingerprintApprover(c.IO, v, "left-index-finger", time.Second)
	})
	h.io.answers = []string{"y", "y"}
	h.call(t, context.Background(), "op.read", map[string]any{"queue": "orders"})
	h.call(t, context.Background(), "op.read", map[string]any{"queue": "orders"})
	checkGolden(t, "level2", h.io)
}
