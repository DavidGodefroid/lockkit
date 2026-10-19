// Package refusal names why a console refused a request. Every refusal
// carries a stable code an agent can act on, the place of the request it
// points at when one is known, and a rewrite hint.
//
// Products register their codes at init time (Register); lockkit itself
// defines only Policy, the fail-closed code. A refusal never carries more
// than the agent could already see: the reason and the hint are written
// by the product (never a backend's text), and the token of a span is a
// word or a punctuation sign of the agent's own request, never a literal.
package refusal

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// Code is a stable refusal code. Codes are part of the client protocol
// and of the agent instructions: never rename one.
type Code string

// Policy is the fail-closed code of a refusal no check named: it should
// never be seen, and is a bug to report.
const Policy Code = "E_POLICY"

// Retry is what an agent may do after a refusal.
type Retry string

const (
	// RetryRewrite: the statement can be fixed. Rewrite it as the hint
	// says and plan it again; the console checks the new one in full.
	RetryRewrite Retry = "rewrite"
	// RetryAskUser: only the human can lift this. Tell the user; the
	// product's change request may queue a proposal.
	RetryAskUser Retry = "ask_user"
	// RetryStop: final for this question. Tell the user; do not reword,
	// split or retry it.
	RetryStop Retry = "stop"
)

type entry struct {
	retry Retry
	title string
	hint  string
}

var (
	mu    sync.RWMutex
	table = map[Code]entry{
		Policy: {RetryStop, "refused by the policy (no more specific code: please report it)", "tell the user"},
	}
	// retired codes are no longer emitted: they stay known for past audit
	// records, and Codes leaves them out.
	retired = map[Code]bool{}
)

var codeName = regexp.MustCompile(`^E_[A-Z][A-Z0-9_]*[A-Z0-9]$`)

// Register defines a product code: what an agent may do after it, a short
// title and the default hint. Call it from init; it panics on a duplicate,
// a malformed name, an empty title or hint, or an unknown retry rule.
func Register(c Code, retry Retry, title, hint string) {
	switch {
	case !codeName.MatchString(string(c)):
		panic(fmt.Sprintf("refusal: code %q is not an E_UPPER_SNAKE name", c))
	case retry != RetryRewrite && retry != RetryAskUser && retry != RetryStop:
		panic(fmt.Sprintf("refusal: code %s: unknown retry %q", c, retry))
	case title == "" || hint == "":
		panic(fmt.Sprintf("refusal: code %s: title and hint are required", c))
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := table[c]; dup {
		panic(fmt.Sprintf("refusal: code %s registered twice", c))
	}
	table[c] = entry{retry, title, hint}
}

// Retire keeps a registered code known (past audit records carry it) but
// drops it from Codes: no refusal carries it any more.
func Retire(c Code) {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := table[c]; !ok {
		panic(fmt.Sprintf("refusal: retire of unknown code %s", c))
	}
	retired[c] = true
}

func lookup(c Code) (entry, bool) {
	mu.RLock()
	defer mu.RUnlock()
	e, ok := table[c]
	return e, ok
}

// Codes lists every code a refusal may carry, sorted; retired codes are
// left out.
func Codes() []Code {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Code, 0, len(table))
	for c := range table {
		if !retired[c] {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return out
}

// Known reports whether c is a defined code.
func (c Code) Known() bool { _, ok := lookup(c); return ok }

// Retry is what an agent may do after a refusal with code c.
func (c Code) Retry() Retry {
	if e, ok := lookup(c); ok {
		return e.retry
	}
	return RetryStop
}

// Title is a short description of the refusals of code c.
func (c Code) Title() string { e, _ := lookup(c); return e.title }

// Hint is the default rewrite hint of code c.
func (c Code) Hint() string { e, _ := lookup(c); return e.hint }

// MaxToken bounds the token of a span, in bytes.
const MaxToken = 40

// Span is where a refusal points in the request the agent sent: line
// and column count from 1, the column in characters.
type Span struct {
	Line  int    `json:"line"`
	Col   int    `json:"col"`
	Token string `json:"token,omitempty"`
}

// Info is the structured form of a refusal, sent to clients next to the
// prose message.
type Info struct {
	Code  Code   `json:"code"`
	Retry Retry  `json:"retry"`
	Hint  string `json:"hint,omitempty"`
	Span  *Span  `json:"span,omitempty"`
}

// Error is a refused statement. Reason is the prose message; it never
// quotes a literal of the statement nor any text from the database.
type Error struct {
	Code   Code
	Reason string
	// Hint overrides the code's default hint.
	Hint string
	// Pos is the byte offset, in the text the check read, of what the
	// refusal points at; -1 when unknown. Token is the word or
	// punctuation sign found there, "" for a literal or a quoted name.
	Pos   int
	Token string
	// Secret marks a statement that may carry a secret (a password): its
	// literals must not be recorded.
	Secret bool
}

func (e *Error) Error() string { return e.Reason }

// New returns a refusal without position.
func New(code Code, reason string) *Error { return &Error{Code: code, Reason: reason, Pos: -1} }

// Newf is New with a formatted reason.
func Newf(code Code, format string, args ...any) *Error {
	return New(code, fmt.Sprintf(format, args...))
}

// WithHint sets the rewrite hint and returns e.
func (e *Error) WithHint(hint string) *Error { e.Hint = hint; return e }

// At sets the position and the token and returns e. Pass "" as the token
// of a literal or a quoted name.
func (e *Error) At(pos int, token string) *Error { e.Pos, e.Token = pos, token; return e }

// Shift moves a known position by off bytes, when the text the check
// read starts off bytes into a larger one.
func (e *Error) Shift(off int) {
	if e.Pos >= 0 {
		e.Pos += off
	}
}

// From returns the refusal err is or wraps. An error without a known code
// is still a refusal (fail closed), under the Policy code.
func From(err error) *Error {
	var r *Error
	if errors.As(err, &r) && r.Code.Known() {
		return r
	}
	if r != nil {
		c := *r
		c.Code = Policy
		return &c
	}
	return New(Policy, err.Error())
}

// Info is the structured form of e. src is the statement the agent sent
// and base the offset in src of the text e's position counts in. A
// position outside src, or inside a character, gives no span.
func (e *Error) Info(src string, base int) Info {
	in := Info{Code: e.Code, Retry: e.Code.Retry(), Hint: e.Hint}
	if !e.Code.Known() {
		in.Code, in.Retry = Policy, Policy.Retry()
	}
	if in.Hint == "" {
		in.Hint = in.Code.Hint()
	}
	if e.Pos < 0 {
		return in
	}
	pos := base + e.Pos
	if pos < 0 || pos > len(src) || (pos < len(src) && !utf8.RuneStart(src[pos])) {
		return in
	}
	head := src[:pos]
	line := 1 + strings.Count(head, "\n")
	col := 1 + utf8.RuneCountInString(head[strings.LastIndexByte(head, '\n')+1:])
	tok := e.Token
	if n := len(tok); n > 0 && pos+n <= len(src) && strings.EqualFold(src[pos:pos+n], tok) {
		tok = src[pos : pos+n] // as written, not as folded by the lexer
	}
	in.Span = &Span{Line: line, Col: col, Token: cleanToken(tok)}
	return in
}

// cleanToken bounds a token and drops one holding a control or format
// character.
func cleanToken(t string) string {
	for _, r := range t {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ""
		}
	}
	if len(t) <= MaxToken {
		return t
	}
	cut := MaxToken
	for cut > 0 && !utf8.RuneStart(t[cut]) {
		cut--
	}
	return t[:cut]
}
