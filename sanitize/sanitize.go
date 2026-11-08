// Package sanitize cleans text before it leaves the console: error
// messages for a client or the audit log (known secrets in every encoded
// form, then the product's registered patterns), and any text printed for
// the human (control and bidi characters escaped, so that client-supplied
// text cannot drive or spoof the terminal).
package sanitize

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"github.com/DavidGodefroid/lockkit/secrets"
)

// URLUserinfo matches the userinfo of a URL ("user:password@" in
// "amqps://user:password@host"); registered, it drops it. It is not a
// default: products whose errors carry such URLs register it.
var URLUserinfo = regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9+.-]*://([^\s/?#@]+@)`)

// Sanitizer scrubs error text. The zero value is not usable: call New.
type Sanitizer struct {
	mu       sync.RWMutex
	patterns []*regexp.Regexp
}

// New returns a sanitizer with the given patterns registered.
func New(patterns ...*regexp.Regexp) *Sanitizer {
	s := &Sanitizer{}
	for _, p := range patterns {
		s.Register(p)
	}
	return s
}

// Register adds a pattern. In each match, the text of every capturing
// group is removed; a pattern without a group has its whole match replaced
// by secrets.Redacted.
func (s *Sanitizer) Register(p *regexp.Regexp) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.patterns = append(s.patterns, p)
}

// Clean removes every known secret from text, then applies the patterns.
func (s *Sanitizer) Clean(text string, known ...[]byte) string {
	text = secrets.SanitizeString(text, known...)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.patterns {
		text = apply(p, text)
	}
	return text
}

// Error is Clean of err's message; a nil err gives "".
func (s *Sanitizer) Error(err error, known ...[]byte) string {
	if err == nil {
		return ""
	}
	return s.Clean(err.Error(), known...)
}

func apply(p *regexp.Regexp, text string) string {
	if p.NumSubexp() == 0 {
		return p.ReplaceAllLiteralString(text, secrets.Redacted)
	}
	var b strings.Builder
	last := 0
	for _, m := range p.FindAllStringSubmatchIndex(text, -1) {
		for g := 1; g*2+1 < len(m); g++ {
			start, end := m[g*2], m[g*2+1]
			if start < 0 || start < last {
				continue
			}
			b.WriteString(text[last:start])
			last = end
		}
	}
	b.WriteString(text[last:])
	return b.String()
}

// Terminal escapes s for the human's terminal: C0 and C1 controls and DEL
// as \xNN; format characters (bidi and directional marks, zero-width
// characters, the BOM, soft hyphen, tag characters, interlinear
// annotations), the other default-ignorable code points and variation
// selectors as \uNNNN or \UNNNNNNNN; so that client-supplied text cannot
// drive or spoof the terminal, nor hide text from the human. An emoji's
// variation selector or joiner is escaped too. Newlines and tabs are kept
// when multiline is set.
func Terminal(s string, multiline bool) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case multiline && (r == '\n' || r == '\t'):
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			fmt.Fprintf(&b, "\\x%02x", r)
		case r > 0xffff && invisible(r):
			fmt.Fprintf(&b, "\\U%08x", r)
		case invisible(r):
			fmt.Fprintf(&b, "\\u%04x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// invisible reports a format character (category Cf, the bidi controls
// among them), another default-ignorable code point or a variation
// selector: a rune a terminal shows as nothing, or that changes how the
// text around it shows.
func invisible(r rune) bool {
	return unicode.In(r, unicode.Cf, unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector)
}
