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
	"time"

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
