package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/ticket"
)

func appendAll(t *testing.T, l *Log, events ...string) {
	t.Helper()
	for _, e := range events {
		if err := l.Append(Base{Event: e}); err != nil {
			t.Fatal(err)
		}
	}
}

func rawLines(t *testing.T, path string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n"))
}

func writeLines(t *testing.T, path string, lines [][]byte) {
	t.Helper()
	if err := os.WriteFile(path, append(bytes.Join(lines, []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func verifyFile(t *testing.T, path string) (Summary, error) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return Verify(f)
}

// Each record carries the hash of the line before it; the first one of an
// empty log starts the chain.
func TestChainLinksRecords(t *testing.T) {
	l, err := Open(testProduct, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	appendAll(t, l, EventLogin, EventApproved, EventRun)
	lines := rawLines(t, l.Path())
	got := readLines(t, l.Path())
	if got[0]["prev_hash"] != Genesis {
		t.Errorf("first prev_hash = %v, want %q", got[0]["prev_hash"], Genesis)
	}
	for i := 1; i < len(lines); i++ {
		if want := LineHash(lines[i-1]); got[i]["prev_hash"] != want {
			t.Errorf("line %d: prev_hash = %v, want %s", i+1, got[i]["prev_hash"], want)
		}
	}
	if !bytes.HasPrefix(lines[1], []byte(`{"ts":"`)) || !bytes.Contains(lines[1], []byte(`","prev_hash":"sha256:`)) {
		t.Errorf("line layout: %s", lines[1])
	}
	s, err := verifyFile(t, l.Path())
	if err != nil || s.Records != 3 || s.Legacy != 0 || s.Last != LineHash(lines[2]) {
		t.Fatalf("Verify = %+v, %v", s, err)
	}
}

// Logs opened apart on one file, and a write from outside, still chain:
// the hash is taken from the file, not from what this Log last wrote.
func TestChainAcrossLogs(t *testing.T) {
	dir := t.TempDir()
	l1, err := Open(testProduct, dir)
	if err != nil {
		t.Fatal(err)
	}
	l2, err := Open(testProduct, dir)
	if err != nil {
		t.Fatal(err)
	}
	appendAll(t, l1, EventLogin)
	appendAll(t, l2, EventApproved)
	appendAll(t, l1, EventRun)
	if s, err := verifyFile(t, l1.Path()); err != nil || s.Records != 3 {
		t.Fatalf("Verify = %+v, %v", s, err)
	}
}

func TestVerifyDetectsBrokenChain(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(testProduct, dir)
	if err != nil {
		t.Fatal(err)
	}
	appendAll(t, l, EventLogin, EventApproved, EventRun, EventLogout)
	orig := rawLines(t, l.Path())
	clone := func() [][]byte {
		out := make([][]byte, len(orig))
		for i, b := range orig {
			out[i] = bytes.Clone(b)
		}
		return out
	}
	unchained := []byte(`{"ts":"2026-01-01T00:00:00.000Z","event":"approved"}`)
	for name, c := range map[string]struct {
		lines [][]byte
		line  int
	}{
		"edited record": {func() [][]byte {
			x := clone()
			x[1] = bytes.Replace(x[1], []byte("approved"), []byte("denied!!"), 1)
			return x
		}(), 3},
		"deleted record":  {func() [][]byte { x := clone(); return append(x[:1], x[2:]...) }(), 2},
		"swapped records": {func() [][]byte { x := clone(); x[1], x[2] = x[2], x[1]; return x }(), 2},
		"inserted record": {func() [][]byte { x := clone(); return append(x[:2], append([][]byte{unchained}, x[2:]...)...) }(), 3},
		"first removed":   {clone()[1:], 1},
		"not JSON":        {func() [][]byte { x := clone(); x[2] = []byte("garbage"); return x }(), 3},
		"chain restarted": {func() [][]byte {
			x := clone()
			x[2] = bytes.Replace(x[2], []byte(`"prev_hash":"`+LineHash(orig[1])+`"`), []byte(`"prev_hash":"`+Genesis+`"`), 1)
			return x
		}(), 3},
	} {
		p := filepath.Join(dir, name+".log")
		writeLines(t, p, c.lines)
		_, err := verifyFile(t, p)
		var ce *ChainError
		if !errors.As(err, &ce) || ce.Line != c.line {
			t.Errorf("%s: got %v, want a break at line %d", name, err, c.line)
		}
	}
}

// Records written before the chain stay readable: they are counted as
// legacy, and the first chained record links to the last of them.
func TestVerifyReadsOldFormat(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "locksql", "audit.log")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	old := [][]byte{
		[]byte(`{"ts":"2025-01-01T00:00:00.000Z","event":"login","profile":"uat","decision":"ok"}`),
		[]byte(`{"ts":"2025-01-01T00:00:01.000Z","event":"approved","profile":"uat"}`),
	}
	writeLines(t, p, old)
	if s, err := verifyFile(t, p); err != nil || s.Records != 2 || s.Legacy != 2 || s.Last != "" {
		t.Fatalf("old log alone: %+v, %v", s, err)
	}
	l, err := Open(testProduct, dir)
	if err != nil {
		t.Fatal(err)
	}
	appendAll(t, l, EventRun, EventLogout)
	got := readLines(t, p)
	if got[2]["prev_hash"] != LineHash(old[1]) {
		t.Errorf("first chained prev_hash = %v, want the hash of the last old line", got[2]["prev_hash"])
	}
	if s, err := verifyFile(t, p); err != nil || s.Records != 4 || s.Legacy != 2 {
		t.Fatalf("Verify = %+v, %v", s, err)
	}
	// An old record after the chain started is a break.
	lines := rawLines(t, p)
	writeLines(t, p, append(lines, old[0]))
	if _, err := verifyFile(t, p); err == nil {
		t.Fatal("an unchained record after the chain was accepted")
	}
}

// A failed write returns its error and leaves the log as it was; the next
// write chains to what the file really holds.
func TestAppendWriteFailure(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix permissions that bind the test")
	}
	l, err := Open(testProduct, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	appendAll(t, l, EventLogin)
	before, _ := os.ReadFile(l.Path())
	if err := os.Chmod(l.Path(), 0o400); err != nil {
		t.Fatal(err)
	}
	// open() restores 0600 on a file it can open: make it unopenable.
	if err := os.Chmod(filepath.Dir(l.Path()), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(Base{Event: EventApproved}); err == nil {
		t.Fatal("a write to an unwritable log succeeded")
	}
	if err := os.Chmod(filepath.Dir(l.Path()), 0o700); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(l.Path())
	if !bytes.Equal(before, after) {
		t.Fatalf("a failed write changed the log:\n%s", after)
	}
	if err := os.Chmod(l.Path(), 0o600); err != nil {
		t.Fatal(err)
	}
	appendAll(t, l, EventRun)
	if s, err := verifyFile(t, l.Path()); err != nil || s.Records != 2 {
		t.Fatalf("Verify = %+v, %v", s, err)
	}
}

// A last line cut short (a crash mid-write) is kept apart: the next record
// starts on its own line, and Verify reports the cut line.
func TestAppendAfterCutLine(t *testing.T) {
	l, err := Open(testProduct, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	appendAll(t, l, EventLogin)
	f, err := os.OpenFile(l.Path(), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"ts":"2026`); err != nil {
		t.Fatal(err)
	}
	f.Close()
	appendAll(t, l, EventRun)
	lines := rawLines(t, l.Path())
	if len(lines) != 3 || !strings.HasPrefix(string(lines[2]), `{"ts":"`) {
		t.Fatalf("lines: %q", lines)
	}
	var ce *ChainError
	if _, err := verifyFile(t, l.Path()); !errors.As(err, &ce) || ce.Line != 2 {
		t.Fatalf("Verify: %v, want a break at line 2", err)
	}
}

// The hub fields name the ticket, who approved it, where, and the hub's
// signature of the decision.
func TestHubFields(t *testing.T) {
	l, err := Open(testProduct, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rec := Base{Event: EventApproved, Ticket: "01JB0000000000000000000000", Approver: &ticket.Approver{ID: "u1", Display: "David"},
		Facade: "tty", HubSig: "c2ln"}
	if err := l.Append(rec); err != nil {
		t.Fatal(err)
	}
	got := readLines(t, l.Path())[0]
	ap, _ := got["approver"].(map[string]any)
	if got["ticket"] != rec.Ticket || got["facade"] != "tty" || got["hub_sig"] != "c2ln" || ap["id"] != "u1" || ap["display"] != "David" {
		t.Fatalf("hub fields: %v", got)
	}
	// Standalone records carry none of them.
	appendAll(t, l, EventLogin)
	for _, k := range []string{"ticket", "approver", "facade", "hub_sig"} {
		if _, ok := readLines(t, l.Path())[1][k]; ok {
			t.Errorf("standalone record has %q", k)
		}
	}
}
