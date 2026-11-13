// Package console is the human side of a lockkit product: it holds the
// credentials and the only backend connection, enforces the approved
// policy, shows every request that needs a human decision on an approval
// screen, and writes the audit trail. Clients (a product's CLI and MCP
// server) reach it over the per-profile socket and never see a secret.
//
// A product supplies a Backend (its methods, its connection, its checks
// and its policy) and calls Run. The pieces Run is made of — the terminal,
// the approvers, the isolation checks, the request loop — are exported for
// products that assemble their own console.
package console

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/DavidGodefroid/lockkit/sanitize"
	"github.com/DavidGodefroid/lockkit/ui"
)

// Timeouts of a console session. The idle timeout and the maximum session
// length are the profile's.
const (
	// ApprovalTimeout bounds every human answer.
	ApprovalTimeout = 5 * time.Minute
	// PolicyPoll is how often the config files are checked for changes.
	PolicyPoll = 2 * time.Second
	// ResponseQuantum levels the response time of a request whose answer
	// could otherwise tell the agent how long a human or a backend took.
	ResponseQuantum = 250 * time.Millisecond
)

// IO is the console's terminal. Ask and AskSecret discard pending input
// before prompting, so type-ahead never answers a prompt.
type IO interface {
	Println(s string)
	// Ask prints prompt and reads one line. It returns false when no answer
	// came within timeout, when ctx ended (Ctrl-C, client gone) or when the
	// terminal is closed.
	Ask(ctx context.Context, prompt string, timeout time.Duration) (string, bool)
	// AskSecret reads a line with echo off.
	AskSecret(ctx context.Context, prompt string) ([]byte, error)
}

// Beller is implemented by an IO that can ring the terminal bell, so that
// a human away from the console notices a prompt waiting for them.
type Beller interface {
	Bell()
}

// Bell rings io's bell when it has one.
func Bell(io IO) {
	if b, ok := io.(Beller); ok {
		b.Bell()
	}
}

// LineSource is implemented by an IO that also delivers the lines the human
// types between requests (console commands such as :review).
type LineSource interface {
	Lines() <-chan string
}

// KeySource is implemented by an IO that reports the control keys pressed
// in the console: on Keys between prompts, to the handler during one.
type KeySource interface {
	Keys() <-chan Key
	SetKeyHandler(func(Key))
}

// StatusLine is implemented by an IO that keeps a status row on screen.
type StatusLine interface {
	SetStatus(string)
}

// QuestionRecorder is implemented by an IO that records the question it
// waits for in a file (Terminal), so that what attaches to the console
// later (`lox attach`, lea) can show it: the question was printed before
// they attached and is not printed again. SetQuestionFile("") stops it.
type QuestionRecorder interface {
	SetQuestionFile(path string)
}

// QuestionPath is the file that holds the question the console of socket
// waits for: next to the socket, its name with .question for .sock
// (/run/locksql/1a2b3c4d-prod.question). It holds the prompt and the
// context lines printed above it (PrintContext), never an answer nor a
// line printed with Println (ParseQuestion reads it); the file is mode
// 0600 and is removed once the question is answered.
func QuestionPath(socket string) string {
	return strings.TrimSuffix(socket, ".sock") + ".question"
}

// Bounds of the context kept with a question: the last MaxQuestionLines
// lines printed above it, at most MaxQuestionBytes bytes (newlines
// counted), a line saying how many earlier ones were left out included.
const (
	MaxQuestionLines = 40
	MaxQuestionBytes = 8 << 10
)

// QuestionContextMark is the second line of a question file whose question
// comes with the lines printed above it.
const QuestionContextMark = "--- printed above the question ---"

// The format of a question file (ParseQuestion reads it):
//
//	<prompt>
//	--- printed above the question ---
//	<line printed above it>
//	...
//
// The prompt is the first line, as in files without context, so that a
// reader taking the first line still gets the question. The mark and the
// lines that follow it, oldest first, are there when the console printed
// context (PrintContext, never Println) since the previous question (or
// since it started: the PRODUCTION banner, the policy diff, a host key
// fingerprint). Every line has its colours dropped and its control characters escaped for a
// terminal (sanitize.Terminal); blank lines at either end of the context
// are left out. What the human types, echoed or not, is never in it.

// formatQuestion is the question file of prompt and the lines printed
// above it.
func formatQuestion(prompt string, above []string) string {
	lines := make([]string, 0, len(above))
	for _, l := range above {
		lines = append(lines, questionLine(l))
	}
	for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		lines = lines[1:]
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	// The oldest lines go first; when any goes, a first line says how many,
	// so a reader never takes a cut context (a policy diff) for a whole one.
	total := len(lines)
	fit := func(reserve string) {
		maxLines, maxBytes := MaxQuestionLines, MaxQuestionBytes
		if reserve != "" {
			maxLines, maxBytes = maxLines-1, maxBytes-len(reserve)-1
		}
		if len(lines) > maxLines {
			lines = lines[len(lines)-maxLines:]
		}
		size := 0
		for _, l := range lines {
			size += len(l) + 1
		}
		for len(lines) > 0 && size > maxBytes {
			size -= len(lines[0]) + 1
			lines = lines[1:]
		}
	}
	fit("")
	marker := ""
	for len(lines) < total {
		m := fmt.Sprintf("… %d earlier lines not shown", total-len(lines))
		if m == marker {
			break
		}
		marker = m
		fit(marker)
	}
	if marker != "" {
		lines = append([]string{marker}, lines...)
	}
	var b strings.Builder
	b.WriteString(strings.TrimSpace(questionLine(prompt)) + "\n")
	if len(lines) > 0 {
		b.WriteString(QuestionContextMark + "\n")
		for _, l := range lines {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

// questionLine is one printed line as a question file holds it: colours
// dropped, controls escaped, trailing spaces trimmed, cut to fit
// MaxQuestionBytes.
func questionLine(s string) string {
	s = strings.TrimRight(sanitize.Terminal(ansiSeq.ReplaceAllString(s, ""), false), " ")
	const ellipsis = "…"
	if max := MaxQuestionBytes - 1; len(s) > max {
		cut := max - len(ellipsis)
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + ellipsis
	}
	return s
}

// ParseQuestion reads a question file: its prompt and the lines printed
// above it (nil when the file has none, as one written by an older
// console).
func ParseQuestion(file string) (prompt string, above []string) {
	lines := strings.Split(strings.TrimRight(file, "\n"), "\n")
	if len(lines) > 2 && lines[1] == QuestionContextMark {
		above = lines[2:]
	}
	return lines[0], above
}

// ContextPrinter is implemented by an IO that records a question's
// context (Terminal): PrintContext prints s as Println does and keeps it as
// context of the next question. Println is never recorded, so a line
// reaches the question file only when its caller opted it in: a clear
// result or a value shown unmasked never does.
type ContextPrinter interface {
	PrintContext(s string)
}

// PrintContext prints s on p, kept as context of the next question when p
// is a ContextPrinter (a Terminal, or a Server, which passes it to its
// IO); it is Println otherwise. Print with it only what the agents may
// read: the PRODUCTION banner, a policy diff, a host key fingerprint, never
// a result or a value of the backend's data.
func PrintContext(p interface{ Println(string) }, s string) {
	if c, ok := p.(ContextPrinter); ok {
		c.PrintContext(s)
		return
	}
	p.Println(s)
}

// ansiSeq matches the CSI sequences (colours) a printed line may carry.
var ansiSeq = regexp.MustCompile("\x1b\\[[0-9;?]*[A-Za-z]")

// RecordQuestions makes io record its questions in the QuestionPath of
// socket, when io is a QuestionRecorder; it does nothing otherwise.
func RecordQuestions(io IO, socket string) {
	if r, ok := io.(QuestionRecorder); ok && socket != "" {
		r.SetQuestionFile(QuestionPath(socket))
	}
}

// Sized is implemented by an IO that knows its width in columns.
type Sized interface {
	Width() int
}

// ANSI colours of the console, which always runs in a terminal.
const (
	red   = ui.Red
	green = ui.Green
	bold  = ui.Bold
	reset = ui.Reset
)

// Paint styles console lines.
var Paint = ui.Painter{On: true}
