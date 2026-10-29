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
// testdata/golden/<name>.txt. The standalone terminal console must stay
// byte-identical: go test ./console -run Golden -update rewrites the files
// only when a change of what the human sees is meant.
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
var goldenPeer = regexp.MustCompile(`requested by uid \d+ \([^)]*\) · pid \d+ · exe [^\\"]+`)

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

// goldenSession runs a standalone console, sends each request in order
// once the socket is up, then ends the console and returns its socket.
func goldenSession(t *testing.T, b *fakeBackend, io *fakeIO, o Options, requests []map[string]any) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	done := make(chan error, 1)
	o.IO, o.StateDir, o.Isolation, o.Quantum = io, t.TempDir(), runEnv(t), -1
	o.Harden = func() error { return nil }
	o.Ready = func(s string) { ready <- s }
	go func() { done <- Run(ctx, testProduct, b, o) }()
	var socket string
	select {
	case socket = <-ready:
	case err := <-done:
		t.Fatalf("Run: %v\n%s", err, io.plain())
	case <-time.After(10 * time.Second):
		t.Fatal("no socket")
	}
	for _, params := range requests {
		dialAndCall(t, socket, "op.read", params)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the console did not end")
	}
	return socket
}

// The standalone console of a non-production profile: first start, an
// approval, two denials (one with a reason) and an approval timeout.
func TestGoldenStandalone(t *testing.T) {
	io := &fakeIO{answers: []string{"y", "y", "n", "no not now"}, secrets: []string{"pw"}}
	socket := goldenSession(t, &fakeBackend{policy: uat()}, io, Options{Profile: "uat"}, []map[string]any{
		{"queue": "orders"}, {"queue": "orders"}, {"queue": "orders"}, {"queue": "orders"},
	})
	checkGolden(t, "standalone", io, socket, "<socket>")
}

// A production profile: the typed profile name at start and to approve.
func TestGoldenStandaloneProduction(t *testing.T) {
	io := &fakeIO{answers: []string{"y", "prod", "prod", "y"}, secrets: []string{"pw"}}
	socket := goldenSession(t, &fakeBackend{policy: prod()}, io, Options{Profile: "prod"}, []map[string]any{
		{"queue": "orders"}, {"queue": "orders"},
	})
	checkGolden(t, "standalone-production", io, socket, "<socket>")
}

// Auto mode: a request runs unprompted, one that asks for a human every
// time is prompted.
func TestGoldenStandaloneAuto(t *testing.T) {
	io := &fakeIO{answers: []string{"y", "y"}, secrets: []string{"pw"}}
	socket := goldenSession(t, &fakeBackend{policy: uat()}, io, Options{Profile: "uat", Auto: true}, []map[string]any{
		{"queue": "orders"}, {"queue": "orders", "never_auto": true},
	})
	checkGolden(t, "standalone-auto", io, socket, "<socket>")
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
