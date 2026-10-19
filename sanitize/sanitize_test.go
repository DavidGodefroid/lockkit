package sanitize

import (
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/secrets"
)

// The defaults scrub what locksql scrubbed before lockkit: the secrets it
// knows, in every form a driver may print (secrets.SanitizeString), and
// nothing else.
func TestDefaultsScrubAsBefore(t *testing.T) {
	s := New()
	pw := []byte("p@ss w/rd%")
	for _, in := range []string{
		"connect: access denied for 'alice' using p@ss w/rd% and again p@ss w/rd%",
		"dial " + url.QueryEscape(string(pw)) + " failed",
		"dial " + url.PathEscape(string(pw)) + " failed",
		"dial " + url.UserPassword("u", string(pw)).String() + " failed",
		`quoted "p@ss w/rd%"`,
		"plain message, no secret",
		"",
	} {
		if got, want := s.Clean(in, pw), secrets.SanitizeString(in, pw); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
	// No pattern by default: a URL that carries no known secret is kept,
	// as locksql kept it.
	if got := s.Clean("dial postgres://ro@db.example.com:5432/shop failed"); got != "dial postgres://ro@db.example.com:5432/shop failed" {
		t.Errorf("default changed a message: %q", got)
	}
	if got := s.Error(errors.New("a=abc b=abcdef"), []byte("abc"), []byte("abcdef")); strings.Contains(got, "abc") || strings.Contains(got, "def") {
		t.Errorf("Error = %q", got)
	}
	if s.Error(nil) != "" {
		t.Error("nil error")
	}
}

func TestRegisteredPattern(t *testing.T) {
	s := New()
	s.Register(URLUserinfo)
	for in, want := range map[string]string{
		"amqps://u:p@h":                         "amqps://h",
		"dial amqp://guest:guest@rabbit:5672/ ": "dial amqp://rabbit:5672/ ",
		"get https://lockmq-ro@broker.example.com:15671/api/overview: 401": "get https://broker.example.com:15671/api/overview: 401",
		"no url here":                "no url here",
		"mailto:someone@example.com": "mailto:someone@example.com",
	} {
		if got := s.Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
	// A pattern without a group replaces the whole match.
	s.Register(regexp.MustCompile(`Authorization: [^\r\n]*`))
	if got := s.Clean("header Authorization: Basic Z3Vlc3Q6Z3Vlc3Q=\nnext"); got != "header ***\nnext" {
		t.Errorf("whole match: %q", got)
	}
	// Secrets go first, then patterns.
	if got := s.Clean("amqps://u:hunter2@h hunter2", []byte("hunter2")); got != "amqps://h ***" {
		t.Errorf("order: %q", got)
	}
	// New with patterns is New then Register.
	if got := New(URLUserinfo).Clean("amqps://u:p@h"); got != "amqps://h" {
		t.Errorf("New(patterns): %q", got)
	}
}

// Terminal text: what the console prints for the human must not drive or
// spoof the terminal (locksql's safeText, verbatim).
func TestTerminal(t *testing.T) {
	for in, want := range map[string]string{
		"plain é":    "plain é",
		"a\x1b[31mb": `a\x1b[31mb`,
		"tab\tnl\n":  `tab\x09nl\x0a`,
		"c1\u0085":   `c1\x85`,
		"del\x7f":    `del\x7f`,
	} {
		if got := Terminal(in, false); got != want {
			t.Errorf("Terminal(%q) = %q, want %q", in, got, want)
		}
	}
	// Bidi and other format characters, built from their code points.
	for _, r := range []rune{0x202e, 0x202a, 0x2066, 0x2069, 0x200e, 0x200f, 0x061c} {
		in := "a" + string(r) + "b"
		want := "a" + `\` + "u" + strings.ToLower(strconv.FormatInt(int64(r)+0x10000, 16)[1:]) + "b"
		if got := Terminal(in, false); got != want {
			t.Errorf("Terminal(%U) = %q, want %q", r, got, want)
		}
	}
	if got := Terminal("a\tb\nc\x1b", true); got != "a\tb\nc\\x1b" {
		t.Errorf("multiline: %q", got)
	}
}
