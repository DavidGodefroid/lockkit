package console

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// fakeIO answers prompts from a script.
type fakeIO struct {
	mu      sync.Mutex
	out     []string
	prompts []string
	answers []string
	timeout bool // answer every prompt with a timeout
	// block makes Ask wait for its context to end.
	block   bool
	blocked chan struct{}
	// onAsk, when set, runs before each scripted answer (e.g. to let time pass).
	onAsk func()
	// secrets answer AskSecret, in order; none left fails the prompt.
	secrets []string
	// bells counts the terminal bells, kept out of out.
	bells int
	// status is the last status line set (StatusLine).
	status string
	// trace is every call in order, colours kept (golden tests).
	trace []string
}

func (f *fakeIO) SetStatus(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = s
	f.trace = append(f.trace, "status "+strconv.Quote(s))
}

func (f *fakeIO) statusLine() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return ansi.ReplaceAllString(f.status, "")
}

func (f *fakeIO) Bell() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bells++
	f.trace = append(f.trace, "bell")
}

func (f *fakeIO) Println(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.out = append(f.out, s)
	f.trace = append(f.trace, "print  "+strconv.Quote(s))
}

func (f *fakeIO) Ask(ctx context.Context, prompt string, _ time.Duration) (string, bool) {
	f.mu.Lock()
	f.prompts = append(f.prompts, prompt)
	f.trace = append(f.trace, "ask    "+strconv.Quote(prompt))
	if f.block {
		ch := f.blocked
		f.mu.Unlock()
		if ch != nil {
			close(ch)
		}
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
		}
		return "", false
	}
	defer f.mu.Unlock()
	if f.onAsk != nil {
		f.onAsk()
	}
	if f.timeout || len(f.answers) == 0 {
		f.trace = append(f.trace, "answer (none)")
		return "", false
	}
	a := f.answers[0]
	f.answers = f.answers[1:]
	f.trace = append(f.trace, "answer "+strconv.Quote(a))
	return a, true
}

func (f *fakeIO) AskSecret(_ context.Context, prompt string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prompts = append(f.prompts, prompt)
	f.trace = append(f.trace, "secret "+strconv.Quote(prompt))
	if len(f.secrets) == 0 {
		return nil, errors.New("no answer")
	}
	s := f.secrets[0]
	f.secrets = f.secrets[1:]
	return []byte(s), nil
}

func (f *fakeIO) promptCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.prompts)
}

func (f *fakeIO) promptList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.prompts...)
}

// ansi matches terminal colour sequences.
var ansi = regexp.MustCompile("\x1b\\[[0-9;]*m")

func (f *fakeIO) output() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.out, "\n")
}

// plain is the output without colours.
func (f *fakeIO) plain() string { return ansi.ReplaceAllString(f.output(), "") }
