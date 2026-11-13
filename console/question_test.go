//go:build unix

package console

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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

// The question file holds the prompt on its first line (what older readers
// take), then, after QuestionContextMark, the lines printed above it:
// escapes stripped, bounded, and nothing when there are none.
func TestQuestionFileFormat(t *testing.T) {
	if got := formatQuestion("User: ", nil); got != "User:\n" {
		t.Fatalf("no context: %q", got)
	}
	got := formatQuestion(red+"Apply these changes? [y/N] "+reset, []string{"", bold + "policy changes:" + reset, "  + allow write\x07", ""})
	want := "Apply these changes? [y/N]\n" + QuestionContextMark + "\npolicy changes:\n  + allow write\\x07\n"
	if got != want {
		t.Fatalf("format:\n%q\nwant\n%q", got, want)
	}
	prompt, lines := ParseQuestion(got)
	if prompt != "Apply these changes? [y/N]" || strings.Join(lines, "|") != "policy changes:|  + allow write\\x07" {
		t.Fatalf("parse: %q %q", prompt, lines)
	}
	if p, l := ParseQuestion("User:\n"); p != "User:" || l != nil {
		t.Fatalf("parse without context: %q %q", p, l)
	}
	if p, l := ParseQuestion("User:\nnot a mark\n"); p != "User:" || l != nil {
		t.Fatalf("parse of an unknown second line: %q %q", p, l)
	}

	// Bounds: the last MaxQuestionLines lines, at most MaxQuestionBytes,
	// the first saying how many earlier ones were left out (#160).
	var many []string
	for i := range 100 {
		many = append(many, "line "+strconv.Itoa(i))
	}
	_, lines = ParseQuestion(formatQuestion("Q?", many))
	if len(lines) != MaxQuestionLines || lines[0] != "… 61 earlier lines not shown" || lines[1] != "line 61" || lines[len(lines)-1] != "line 99" {
		t.Fatalf("line bound: %d lines, %q, %q..%q", len(lines), lines[0], lines[1], lines[len(lines)-1])
	}
	_, lines = ParseQuestion(formatQuestion("Q?", many[:MaxQuestionLines]))
	if len(lines) != MaxQuestionLines || lines[0] != "line 0" {
		t.Fatalf("a context that fits is cut: %d lines, %q", len(lines), lines[0])
	}
	long := strings.Repeat("é", 3000) // 6000 bytes each
	f := formatQuestion("Q?", []string{"first", long, long})
	_, lines = ParseQuestion(f)
	total := 0
	for _, l := range lines {
		total += len(l) + 1
		if !utf8.ValidString(l) {
			t.Fatalf("cut inside a rune: %q", l)
		}
	}
	if total > MaxQuestionBytes || len(lines) != 2 || lines[0] != "… 2 earlier lines not shown" || lines[1] != long {
		t.Fatalf("byte bound: %d bytes, %d lines", total, len(lines))
	}
	_, lines = ParseQuestion(formatQuestion("Q?", []string{strings.Repeat("x", 3*MaxQuestionBytes)}))
	if len(lines) != 1 || len(lines[0])+1 > MaxQuestionBytes || !strings.HasSuffix(lines[0], "…") {
		t.Fatalf("one long line: %d lines, %d bytes", len(lines), len(lines[0]))
	}
}

// The Terminal records, with each question, the context lines it printed
// (PrintContext) since the previous question: the policy diff above "Apply
// these changes?", the host key fingerprint above its prompt. What the
// human types (echoed or not) is never written (#152).
func TestTerminalRecordsQuestionContext(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	term := NewTerminal(r, io.Discard)
	term.echo = true // as in cbreak mode: the Terminal echoes what is typed
	path := filepath.Join(t.TempDir(), "1a2b3c4d-prod.question")
	term.PrintContext(red + bold + "PRODUCTION" + reset)
	term.SetQuestionFile(path)

	term.PrintContext("Policy changes for prod:")
	term.PrintContext(green + "  + tables: orders (write)" + reset + "\n  - masked: email")
	got := make(chan string, 1)
	go func() {
		a, _ := term.Ask(context.Background(), "Apply these changes? [y/N] ", time.Minute)
		got <- a
	}()
	waitFile(t, path, "Apply these changes? [y/N]\n"+QuestionContextMark+"\nPRODUCTION\nPolicy changes for prod:\n  + tables: orders (write)\n  - masked: email\n")
	if _, err := w.WriteString("y\n"); err != nil {
		t.Fatal(err)
	}
	if a := <-got; a != "y" {
		t.Fatalf("answer %q", a)
	}
	waitFile(t, path, "")

	// A password prompt: the secret typed never reaches a question file.
	secret := make(chan string, 1)
	go func() {
		b, _ := term.AskSecret(context.Background(), "Password for app@db: ")
		secret <- string(b)
	}()
	waitFile(t, path, "Password for app@db:\n")
	if _, err := w.WriteString("hunter2-s3cret\n"); err != nil {
		t.Fatal(err)
	}
	if s := <-secret; s != "hunter2-s3cret" {
		t.Fatalf("secret %q", s)
	}
	waitFile(t, path, "")

	// Only the lines since the previous question come with the next one.
	term.PrintContext("Host db.example.com:22 is not known.")
	term.PrintContext("ED25519 key fingerprint is SHA256:abcdEFGH12345678.")
	go func() {
		a, _ := term.Ask(context.Background(), "Type the last 8 characters of the fingerprint to trust it: ", time.Minute)
		got <- a
	}()
	want := "Type the last 8 characters of the fingerprint to trust it:\n" + QuestionContextMark +
		"\nHost db.example.com:22 is not known.\nED25519 key fingerprint is SHA256:abcdEFGH12345678.\n"
	waitFile(t, path, want)
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "hunter2") || strings.Contains(string(b), "Policy changes") {
		t.Fatalf("question file holds an answer or an earlier context: %q", b)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("question file mode: %v %v", fi, err)
	}
	if _, err := w.WriteString("12345678\n"); err != nil {
		t.Fatal(err)
	}
	if a := <-got; a != "12345678" {
		t.Fatalf("answer %q", a)
	}
	waitFile(t, path, "")

	// The echoed answer is not among the lines of the next question.
	go func() { term.Ask(context.Background(), "User: ", time.Minute) }()
	waitFile(t, path, "User:\n")
	_, _ = w.WriteString("x\n")
}

// Only the lines a caller opted in (PrintContext) reach a question file:
// what Println prints, a clear result or a value shown unmasked, stays on
// the terminal, however it is interleaved with context lines.
func TestTerminalQuestionContextOptIn(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	var screen strings.Builder
	term := NewTerminal(r, &screen)
	path := filepath.Join(t.TempDir(), "1a2b3c4d-prod.question")
	term.SetQuestionFile(path)

	term.PrintContext("Policy changes for prod:")
	term.Println(red + "result in clear (shown here only; the agent got it masked)" + reset)
	term.Println("| email              | iban                |\n| ann@example.com    | BE71096123456769    |")
	term.PrintContext("  + tables: orders (write)")
	term.Println("unmasked: ann@example.com")
	got := make(chan string, 1)
	go func() {
		a, _ := term.Ask(context.Background(), "Apply these changes? [y/N] ", time.Minute)
		got <- a
	}()
	waitFile(t, path, "Apply these changes? [y/N]\n"+QuestionContextMark+"\nPolicy changes for prod:\n  + tables: orders (write)\n")
	if _, err := w.WriteString("n\n"); err != nil {
		t.Fatal(err)
	}
	<-got
	waitFile(t, path, "")

	// Println alone: the question comes without context.
	term.Println("| ann@example.com    | BE71096123456769    |")
	go func() {
		a, _ := term.Ask(context.Background(), "Approve? [y/N] ", time.Minute)
		got <- a
	}()
	waitFile(t, path, "Approve? [y/N]\n")
	_, _ = w.WriteString("n\n")
	<-got
	waitFile(t, path, "")
	if !strings.Contains(screen.String(), "ann@example.com") {
		t.Fatalf("Println did not print: %q", screen.String())
	}
}

// PrintContext prints on any IO: on one that records no context, as
// Println.
func TestPrintContextFallback(t *testing.T) {
	f := &fakeIO{}
	PrintContext(f, "PRODUCTION")
	if !strings.Contains(f.plain(), "PRODUCTION") {
		t.Fatalf("not printed: %q", f.plain())
	}
}

// contextIO is a fakeIO that keeps apart the lines printed as question
// context.
type contextIO struct {
	*fakeIO
	context []string
}

func (c *contextIO) PrintContext(s string) {
	c.context = append(c.context, s)
	c.fakeIO.Println(s)
}

// Run prints the PRODUCTION banner and the policy under review as context
// of the question that follows them; what else it prints stays out of it.
func TestRunPrintsQuestionContext(t *testing.T) {
	io := &contextIO{fakeIO: &fakeIO{answers: []string{"prod"}}}
	// Ends at the password prompt, which gets no answer.
	_ = Run(context.Background(), testProduct, &fakeBackend{policy: prod()}, Options{Profile: "prod", Hub: testHub(t), IO: io,
		StateDir: t.TempDir(), Isolation: runEnv(t), Harden: func() error { return nil }})
	got := ansi.ReplaceAllString(strings.Join(io.context, "\n"), "")
	for _, want := range []string{"First start of profile prod: review its policy.", "PRODUCTION profile prod"} {
		if !strings.Contains(got, want) {
			t.Fatalf("context lacks %q:\n%s\nprinted:\n%s", want, got, io.plain())
		}
	}
	if strings.Contains(got, "approved policy)") {
		t.Fatalf("a line that is no question's context was recorded:\n%s", got)
	}
}

// A product prints context through its Env: the Server passes it on.
var _ ContextPrinter = (*Server)(nil)

// The pending policy diff shown at :review is context of its decision: it
// reaches the question file with the prompt, so a human answering from
// lockhub or a phone sees what they apply (#160). The change requests
// from clients, printed with Println, stay on the terminal.
func TestReviewRecordsPolicyDiffInQuestion(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	term := NewTerminal(r, io.Discard)
	path := filepath.Join(t.TempDir(), "1a2b3c4d-uat.question")
	term.SetQuestionFile(path)
	h := newHarness(t, uat(), func(c *ServerConfig) { c.IO = term })

	looser := uat()
	looser.Tier = "peek"
	h.b.policy = looser
	h.s.CheckPolicy()
	h.s.requests = []string{"agent asks: widen orders"}
	diff := formatChangesOf(h.b, looser.Diff(uat()))
	if len(diff) == 0 {
		t.Fatal("no diff lines")
	}
	done := make(chan struct{})
	go func() {
		h.s.Command(context.Background(), ":review")
		close(done)
	}()
	want := "Apply these changes? [y/N]\n" + QuestionContextMark + "\npending policy change for profile uat:\n"
	for _, line := range diff {
		want += ansi.ReplaceAllString(line, "") + "\n"
	}
	waitFile(t, path, want)
	if _, err := w.WriteString("y\n"); err != nil {
		t.Fatal(err)
	}
	<-done
	waitFile(t, path, "")
	if h.s.PolicyPending() {
		t.Fatal("loosening still pending after y")
	}
}

// pathTerminal is a Terminal that tells where Run keeps its questions.
type pathTerminal struct {
	*Terminal
	path chan string
}

func (p *pathTerminal) SetQuestionFile(path string) {
	p.Terminal.SetQuestionFile(path)
	select {
	case p.path <- path:
	default:
	}
}

// End to end: a console run in a Terminal records, in the question file
// next to its socket, the diff of a policy reloaded from the config files
// with the :review decision about it, and the answer applies it (#160).
func TestRunReviewQuestionFileShowsReloadDiff(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for a policy poll")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	screen := &lockedBuffer{}
	term := &pathTerminal{Terminal: NewTerminal(r, screen), path: make(chan string, 1)}
	b := &fakeBackend{policy: uat()}
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), testProduct, b, Options{Profile: "uat", Hub: testHub(t), IO: term,
			StateDir: t.TempDir(), Isolation: runEnv(t), Harden: func() error { return nil }, Ready: func(s string) { ready <- s }})
	}()
	path := <-term.path
	answer := func(line string) {
		t.Helper()
		if _, err := w.WriteString(line + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	// The questions of the start (the policy, the password), answered as
	// they reach the question file.
	var socket string
	asked := ""
	for socket == "" {
		select {
		case socket = <-ready:
			continue
		case err := <-done:
			t.Fatalf("Run: %v\n%s", err, screen)
		case <-time.After(10 * time.Millisecond):
		}
		f, err := os.ReadFile(path)
		if err != nil || string(f) == asked {
			continue
		}
		asked = string(f)
		if prompt, _ := ParseQuestion(asked); strings.HasPrefix(prompt, "Password") {
			answer("pw")
		} else {
			answer("y")
		}
	}
	if path != QuestionPath(socket) {
		t.Fatalf("question file %q, socket %q", path, socket)
	}
	waitFile(t, path, "")

	looser := uat()
	looser.Tier = "peek"
	b.mu.Lock()
	b.policy = looser
	b.mu.Unlock()
	waitScreen(t, screen, "pending policy change (loosening)", 3*PolicyPoll)
	answer(":review")
	want := "Apply these changes? [y/N]\n" + QuestionContextMark + "\npending policy change for profile uat:\n"
	for _, line := range formatChangesOf(b, looser.Diff(uat())) {
		want += ansi.ReplaceAllString(line, "") + "\n"
	}
	waitFile(t, path, want)
	answer("y")
	waitFile(t, path, "")
	waitScreen(t, screen, "policy change applied", 5*time.Second)
	if r := dialAndCall(t, socket, ipc.MethodLogout, nil); r.Error != nil {
		t.Fatal(r.Error)
	}
	<-done
}

// waitScreen waits until the screen shows want.
func waitScreen(t *testing.T, screen *lockedBuffer, want string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !strings.Contains(screen.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("screen without %q:\n%s", want, screen)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// firstStartQuestion runs a console of pol in a Terminal on its very first
// start after boot, the runtime directory not made yet, and returns the
// first question file it writes, read while the question waits, and the
// file's path; the question is then answered with answer, and the start
// ended at the next one (#180).
func firstStartQuestion(t *testing.T, pol fakePolicy, answer string) (string, string) {
	t.Helper()
	env := runEnv(t)
	rt := filepath.Join(os.Getenv("LOCKMQ_RUNTIME_DIR"), "fresh")
	t.Setenv("LOCKMQ_RUNTIME_DIR", rt)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	screen := &lockedBuffer{}
	term := &pathTerminal{Terminal: NewTerminal(r, screen), path: make(chan string, 1)}
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), testProduct, &fakeBackend{policy: pol}, Options{Profile: pol.Name, Hub: testHub(t), IO: term,
			StateDir: t.TempDir(), Isolation: env, Harden: func() error { return nil }})
	}()
	var path string
	select {
	case path = <-term.path:
	case err := <-done:
		t.Fatalf("Run: %v\n%s", err, screen)
	}
	if !strings.HasPrefix(path, rt+string(filepath.Separator)) {
		t.Fatalf("question file %q outside %q", path, rt)
	}
	deadline := time.Now().Add(5 * time.Second)
	var q []byte
	for {
		if q, err = os.ReadFile(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no question file %s: %v\n%s", path, err, screen)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if fi, err := os.Lstat(filepath.Dir(path)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("socket dir: %v %v", fi, err)
	}
	if _, err := w.WriteString(answer + "\n"); err != nil {
		t.Fatal(err)
	}
	// Answered: the next question (the password) replaces it; no answer
	// to that one ends the start, and its file goes.
	for {
		f, err := os.ReadFile(path)
		if err != nil || string(f) != string(q) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("question still pending after %q\n%s", answer, screen)
		}
		time.Sleep(5 * time.Millisecond)
	}
	w.Close()
	<-done
	waitFile(t, path, "")
	if strings.Contains(screen.String(), "shown on this terminal only") {
		t.Errorf("warned on a socket dir it could make:\n%s", screen)
	}
	return string(q), path
}

// On the very first start, the runtime directory not made yet, the policy
// review is in the question file while it waits, with the policy printed
// above it.
func TestRunFirstStartRecordsReview(t *testing.T) {
	q, _ := firstStartQuestion(t, uat(), "y")
	prompt, above := ParseQuestion(q)
	if prompt != "Apply these changes? [y/N]" || !strings.Contains(q, "\n"+QuestionContextMark+"\n") ||
		len(above) == 0 || above[0] != "First start of profile uat: review its policy." {
		t.Fatalf("question file:\n%s", q)
	}
}

// Same for the typed name of a PRODUCTION profile on its first start.
func TestRunFirstStartRecordsProductionName(t *testing.T) {
	q, _ := firstStartQuestion(t, prod(), "prod")
	prompt, above := ParseQuestion(q)
	if prompt != `Apply these changes? Type the profile name "prod" to apply them:` ||
		len(above) == 0 || above[0] != "First start of profile prod: review its policy." {
		t.Fatalf("question file:\n%s", q)
	}
}

// A socket directory that cannot be made keeps the questions on the
// terminal, with one warning; the start is refused at the socket.
func TestRunSocketDirUnmade(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes in a read-only directory")
	}
	env := runEnv(t)
	ro := os.Getenv("LOCKMQ_RUNTIME_DIR")
	if err := os.Chmod(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })
	io := &fakeIO{answers: []string{"y"}, secrets: []string{"pw"}}
	err := Run(context.Background(), testProduct, &fakeBackend{policy: uat()}, Options{Profile: "uat", Hub: testHub(t), IO: io,
		StateDir: t.TempDir(), Isolation: env, Harden: func() error { return nil }})
	if err == nil {
		t.Fatal("served without a socket directory")
	}
	if n := strings.Count(io.plain(), "shown on this terminal only"); n != 1 {
		t.Errorf("%d warnings:\n%s", n, io.plain())
	}
	if p := io.promptList(); len(p) == 0 || !strings.Contains(p[0], "Apply these changes") {
		t.Errorf("prompts: %q", p)
	}
}
