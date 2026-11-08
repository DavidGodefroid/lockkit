package sanitize

import (
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

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

// Invisible and format characters (#116): zero-width, soft hyphen, the
// Mongolian vowel separator, variation selectors, tag characters and
// interlinear annotations are escaped too, so that a client cannot hide or
// smuggle text in what the human reads.
func TestTerminalInvisible(t *testing.T) {
	for r, want := range map[rune]string{
		0x00ad:  `\u00ad`,     // soft hyphen
		0x180e:  `\u180e`,     // Mongolian vowel separator
		0x200b:  `\u200b`,     // zero width space
		0x200c:  `\u200c`,     // zero width non-joiner
		0x200d:  `\u200d`,     // zero width joiner
		0x2060:  `\u2060`,     // word joiner
		0x2064:  `\u2064`,     // invisible plus
		0xfeff:  `\ufeff`,     // BOM
		0xfe00:  `\ufe00`,     // variation selector-1
		0xfe0f:  `\ufe0f`,     // variation selector-16
		0xfff9:  `\ufff9`,     // interlinear annotation anchor
		0xfffb:  `\ufffb`,     // interlinear annotation terminator
		0x115f:  `\u115f`,     // Hangul choseong filler
		0x3164:  `\u3164`,     // Hangul filler
		0xe0000: `\U000e0000`, // unassigned tag block start
		0xe0001: `\U000e0001`, // language tag
		0xe0041: `\U000e0041`, // tag latin capital letter A
		0xe007f: `\U000e007f`, // cancel tag
		0xe0100: `\U000e0100`, // variation selector-17
		0xe01ef: `\U000e01ef`, // variation selector-256
	} {
		in := "a" + string(r) + "b"
		if got := Terminal(in, false); got != "a"+want+"b" {
			t.Errorf("Terminal(%U) = %q, want %q", r, got, "a"+want+"b")
		}
	}
	// The issue's example: no raw invisible character left.
	in := "trust label zero\u200bwidth\u200c\u200djoin\ufeffbom"
	if got, want := Terminal(in, false), `trust label zero\u200bwidth\u200c\u200djoin\ufeffbom`; got != want {
		t.Errorf("Terminal(%q) = %q, want %q", in, got, want)
	}
	// A hidden ASCII string in tag characters shows as escapes.
	hidden := "ok"
	for _, c := range "rm -rf" {
		hidden += string(0xe0000 + c)
	}
	if got := Terminal(hidden, false); got != `ok\U000e0072\U000e006d\U000e0020\U000e002d\U000e0072\U000e0066` {
		t.Errorf("tags: %q", got)
	}
	// Visible text around them is kept, as are visible non-ASCII letters,
	// symbols and spaces.
	for _, keep := range []string{"café ñ 日本 ❤ €", "a\u00a0b", "a\u3000b", "→ ✓"} {
		if got := Terminal(keep, false); got != keep {
			t.Errorf("Terminal(%q) = %q, want it unchanged", keep, got)
		}
	}
}

// Whatever the input, the output holds no control, format, default
// ignorable or variation selector character (but tab and newline when
// multiline), and plain printable text is unchanged.
func FuzzTerminal(f *testing.F) {
	for _, s := range []string{"plain", "a\x1b[31mb", "zero\u200bwidth", "tag\U000e0041", "vs\ufe0f", "bidi\u202e", "\xff\xfe", "a\tb\nc"} {
		f.Add(s, false)
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, s string, multiline bool) {
		out := Terminal(s, multiline)
		for _, r := range out {
			if multiline && (r == '\n' || r == '\t') {
				continue
			}
			if invisibleRef(r) {
				t.Fatalf("Terminal(%q, %t) = %q holds %U", s, multiline, out, r)
			}
		}
		if !strings.ContainsFunc(s, func(r rune) bool { return invisibleRef(r) || r == utf8.RuneError || r == '\n' || r == '\t' }) && out != s {
			t.Fatalf("Terminal(%q) = %q, want it unchanged", s, out)
		}
	})
}

// invisibleRef is the test's own oracle of what Terminal must escape.
func invisibleRef(r rune) bool {
	return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector)
}
