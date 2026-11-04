//go:build unix

package console

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ipc"
)

func TestQuestionPath(t *testing.T) {
	for in, want := range map[string]string{
		"/run/locksql/1a2b3c4d-prod.sock": "/run/locksql/1a2b3c4d-prod.question",
		"/run/x/1a2b3c4d-~0123.sock":      "/run/x/1a2b3c4d-~0123.question",
		"/run/x/odd":                      "/run/x/odd.question",
	} {
		if got := QuestionPath(in); got != want {
			t.Errorf("QuestionPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// waitFile waits for path to hold want (true) or to be gone (want "").
func waitFile(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		b, err := os.ReadFile(path)
		if want == "" && os.IsNotExist(err) || want != "" && err == nil && string(b) == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %q (%v), want %q", path, b, err, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// While the Terminal waits for an answer, its question (the prompt,
// colours dropped, never the answer) is in the question file; once
// answered the file is gone. A file left by an earlier console is removed
// when the file is set (#127).
func TestTerminalRecordsQuestion(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	term := NewTerminal(r, io.Discard)
	path := filepath.Join(t.TempDir(), "1a2b3c4d-prod.question")
	if err := os.WriteFile(path, []byte("Stale question\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	term.SetQuestionFile(path)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a stale question file stayed: %v", err)
	}

	got := make(chan string, 1)
	go func() {
		a, _ := term.Ask(context.Background(), red+`Type the profile name "prod" to continue: `+reset, time.Minute)
		got <- a
	}()
	waitFile(t, path, "Type the profile name \"prod\" to continue:\n")
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("question file mode: %v %v", fi, err)
	}
	if _, err := w.WriteString("prod\n"); err != nil {
		t.Fatal(err)
	}
	if a := <-got; a != "prod" {
		t.Fatalf("answer %q", a)
	}
	waitFile(t, path, "")

	secret := make(chan string, 1)
	go func() {
		b, _ := term.AskSecret(context.Background(), "Vault token for https://vault.example.com:8200: ")
		secret <- string(b)
	}()
	waitFile(t, path, "Vault token for https://vault.example.com:8200:\n")
	if _, err := w.WriteString("s.tok3n\n"); err != nil {
		t.Fatal(err)
	}
	if s := <-secret; s != "s.tok3n" {
		t.Fatalf("secret %q", s)
	}
	waitFile(t, path, "")

	// A question that ends unanswered (cancelled) is removed too.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		term.Ask(ctx, "Apply these changes? [y/N] ", time.Minute)
	}()
	waitFile(t, path, "Apply these changes? [y/N]\n")
	cancel()
	<-done
	waitFile(t, path, "")

	// Off: nothing is written.
	term.SetQuestionFile("")
	go func() { term.Ask(context.Background(), "User: ", time.Minute) }()
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("question recorded after SetQuestionFile(\"\"): %v", err)
	}
	_, _ = w.WriteString("x\n")
}

// A question file that cannot be written does not stop the question.
func TestTerminalQuestionFileUnwritable(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	term := NewTerminal(r, io.Discard)
	term.SetQuestionFile(filepath.Join(t.TempDir(), "missing", "x.question"))
	// Typed once the prompt waits: type-ahead never answers a prompt.
	go func() {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.WriteString("ro\n")
	}()
	if a, ok := term.Ask(context.Background(), "User: ", 5*time.Second); !ok || a != "ro" {
		t.Fatalf("Ask = %q %v", a, ok)
	}
}

// questionIO is a fakeIO that records where Run asked it to keep its
// questions, and how many prompts came before.
type questionIO struct {
	*fakeIO
	path   string
	before int
}

func (q *questionIO) SetQuestionFile(path string) {
	q.path, q.before = path, q.promptCount()
}

// Run keeps the questions next to the console's socket from before the
// first one is asked.
func TestRunRecordsQuestions(t *testing.T) {
	env := runEnv(t)
	io := &questionIO{fakeIO: &fakeIO{answers: []string{"y"}, secrets: []string{"pw"}}}
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), testProduct, &fakeBackend{policy: uat()}, Options{Profile: "uat", Hub: testHub(t), IO: io,
			StateDir: t.TempDir(), Isolation: env, Harden: func() error { return nil }, Ready: func(s string) { ready <- s }})
	}()
	var socket string
	select {
	case socket = <-ready:
	case err := <-done:
		t.Fatalf("Run: %v\n%s", err, io.plain())
	case <-time.After(10 * time.Second):
		t.Fatal("no socket")
	}
	if r := dialAndCall(t, socket, ipc.MethodLogout, nil); r.Error != nil {
		t.Fatal(r.Error)
	}
	<-done
	if io.path != QuestionPath(socket) || io.before != 0 || !strings.HasSuffix(io.path, ".question") {
		t.Fatalf("question file %q set after %d prompts, socket %q", io.path, io.before, socket)
	}
}
