package ticket

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrNotCanonicalizable is wrapped by every error of CanonicalizeJSON:
// input that is not I-JSON (RFC 7493), the subset RFC 8785 defines.
var ErrNotCanonicalizable = errors.New("ticket: not canonicalizable JSON")

// maxDepth bounds the nesting of the JSON CanonicalizeJSON accepts.
const maxDepth = 64

// Canonical is the RFC 8785 (JCS) form of v: json.Marshal, then
// CanonicalizeJSON. Signatures and hashes are computed over it.
func Canonical(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return CanonicalizeJSON(b)
}

// CanonicalizeJSON is the RFC 8785 (JCS) form of one JSON value: object
// members sorted by their UTF-16 code units, no whitespace, strings with
// the minimal escapes, numbers as ECMAScript prints them. It refuses what
// I-JSON refuses: invalid UTF-8, lone surrogates, duplicate member names,
// numbers out of the IEEE 754 double range, and trailing data.
func CanonicalizeJSON(b []byte) ([]byte, error) {
	if !utf8.Valid(b) {
		return nil, fmt.Errorf("%w: invalid UTF-8", ErrNotCanonicalizable)
	}
	p := &parser{s: b}
	p.ws()
	var out bytes.Buffer
	if err := p.value(&out, 0); err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.s) {
		return nil, p.errf("trailing data")
	}
	return out.Bytes(), nil
}

type parser struct {
	s []byte
	i int
}

func (p *parser) errf(format string, a ...any) error {
	return fmt.Errorf("%w: offset %d: %s", ErrNotCanonicalizable, p.i, fmt.Sprintf(format, a...))
}

func (p *parser) ws() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) lit(word string) error {
	if !bytes.HasPrefix(p.s[p.i:], []byte(word)) {
		return p.errf("invalid literal")
	}
	p.i += len(word)
	return nil
}

func (p *parser) value(out *bytes.Buffer, depth int) error {
	if depth > maxDepth {
		return p.errf("nested deeper than %d", maxDepth)
	}
	if p.i >= len(p.s) {
		return p.errf("unexpected end")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object(out, depth)
	case c == '[':
		return p.array(out, depth)
	case c == '"':
		s, err := p.str()
		if err != nil {
			return err
		}
		writeString(out, s)
		return nil
	case c == 't':
		out.WriteString("true")
		return p.lit("true")
	case c == 'f':
		out.WriteString("false")
		return p.lit("false")
	case c == 'n':
		out.WriteString("null")
		return p.lit("null")
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number(out)
	default:
		return p.errf("unexpected %q", c)
	}
}

type member struct {
	key  string
	sort []uint16
	val  []byte
}

func (p *parser) object(out *bytes.Buffer, depth int) error {
	p.i++ // {
	var ms []member
	seen := map[string]bool{}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		out.WriteString("{}")
		return nil
	}
	for {
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return p.errf("expected a member name")
		}
		k, err := p.str()
		if err != nil {
			return err
		}
		if seen[k] {
			return p.errf("duplicate member %q", k)
		}
		seen[k] = true
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return p.errf("expected ':'")
		}
		p.i++
		p.ws()
		var v bytes.Buffer
		if err := p.value(&v, depth+1); err != nil {
			return err
		}
		ms = append(ms, member{key: k, sort: utf16.Encode([]rune(k)), val: v.Bytes()})
		p.ws()
		if p.i >= len(p.s) {
			return p.errf("unexpected end")
		}
		if p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.s[p.i] == '}' {
			p.i++
			break
		}
		return p.errf("expected ',' or '}'")
	}
	sort.Slice(ms, func(a, b int) bool { return lessUTF16(ms[a].sort, ms[b].sort) })
	out.WriteByte('{')
	for n, m := range ms {
		if n > 0 {
			out.WriteByte(',')
		}
		writeString(out, m.key)
		out.WriteByte(':')
		out.Write(m.val)
	}
	out.WriteByte('}')
	return nil
}

func lessUTF16(a, b []uint16) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func (p *parser) array(out *bytes.Buffer, depth int) error {
	p.i++ // [
	out.WriteByte('[')
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		out.WriteByte(']')
		return nil
	}
	for n := 0; ; n++ {
		if n > 0 {
			out.WriteByte(',')
		}
		p.ws()
		if err := p.value(out, depth+1); err != nil {
			return err
		}
		p.ws()
		if p.i >= len(p.s) {
			return p.errf("unexpected end")
		}
		if p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.s[p.i] == ']' {
			p.i++
			out.WriteByte(']')
			return nil
		}
		return p.errf("expected ',' or ']'")
	}
}

// str reads one JSON string at p.i (on its opening quote) and returns its
// value. Lone surrogates are refused (I-JSON).
func (p *parser) str() (string, error) {
	p.i++ // "
	var sb strings.Builder
	for {
		if p.i >= len(p.s) {
			return "", p.errf("unterminated string")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return sb.String(), nil
		case c < 0x20:
			return "", p.errf("control character in string")
		case c == '\\':
			p.i++
			if p.i >= len(p.s) {
				return "", p.errf("unterminated escape")
			}
			e := p.s[p.i]
			p.i++
			switch e {
			case '"', '\\', '/':
				sb.WriteByte(e)
			case 'b':
				sb.WriteByte('\b')
			case 'f':
				sb.WriteByte('\f')
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case 'u':
				r, err := p.hex4()
				if err != nil {
					return "", err
				}
				if utf16.IsSurrogate(r) {
					if r >= 0xDC00 || !bytes.HasPrefix(p.s[p.i:], []byte(`\u`)) {
						return "", p.errf("lone surrogate")
					}
					p.i += 2
					r2, err := p.hex4()
					if err != nil {
						return "", err
					}
					d := utf16.DecodeRune(r, r2)
					if d == utf8.RuneError {
						return "", p.errf("lone surrogate")
					}
					r = d
				}
				sb.WriteRune(r)
			default:
				return "", p.errf("invalid escape")
			}
		default:
			r, n := utf8.DecodeRune(p.s[p.i:])
			sb.WriteRune(r)
			p.i += n
		}
	}
}

func (p *parser) hex4() (rune, error) {
	if p.i+4 > len(p.s) {
		return 0, p.errf("short \\u escape")
	}
	v, err := strconv.ParseUint(string(p.s[p.i:p.i+4]), 16, 16)
	if err != nil {
		return 0, p.errf("invalid \\u escape")
	}
	p.i += 4
	return rune(v), nil
}

func (p *parser) number(out *bytes.Buffer) error {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	digits := func() int {
		n := 0
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
			n++
		}
		return n
	}
	if p.i < len(p.s) && p.s[p.i] == '0' {
		p.i++
	} else if digits() == 0 {
		return p.errf("invalid number")
	}
	if p.i < len(p.s) && p.s[p.i] == '.' {
		p.i++
		if digits() == 0 {
			return p.errf("invalid number")
		}
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		p.i++
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.i++
		}
		if digits() == 0 {
			return p.errf("invalid number")
		}
	}
	f, err := strconv.ParseFloat(string(p.s[start:p.i]), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return p.errf("number out of range")
	}
	out.WriteString(formatNumber(f))
	return nil
}

// formatNumber prints f as ECMAScript's Number.prototype.toString does
// (ECMA-262 Number::toString), which RFC 8785 adopts.
func formatNumber(f float64) string {
	if f == 0 {
		return "0" // -0 too
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	// Shortest round-trip digits and exponent: d.ddde±x.
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, exp, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	x, _ := strconv.Atoi(exp)
	k := len(digits)
	n := x + 1 // value = 0.digits × 10^n
	var s string
	switch {
	case k <= n && n <= 21:
		s = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		s = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		s = "0." + strings.Repeat("0", -n) + digits
	default:
		s = digits[:1]
		if k > 1 {
			s += "." + digits[1:]
		}
		s += "e"
		if n-1 >= 0 {
			s += "+"
		}
		s += strconv.Itoa(n - 1)
	}
	return sign + s
}

// writeString writes s as JCS does: escape '"', '\\' and the controls
// below U+0020 (short forms for \b \t \n \f \r, \u00xx lower-case
// otherwise), everything else verbatim.
func writeString(out *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	out.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			out.WriteByte('\\')
			out.WriteByte(c)
		case c == '\b':
			out.WriteString(`\b`)
		case c == '\t':
			out.WriteString(`\t`)
		case c == '\n':
			out.WriteString(`\n`)
		case c == '\f':
			out.WriteString(`\f`)
		case c == '\r':
			out.WriteString(`\r`)
		case c < 0x20:
			out.WriteString(`\u00`)
			out.WriteByte(hex[c>>4])
			out.WriteByte(hex[c&0xF])
		default:
			out.WriteByte(c)
		}
	}
	out.WriteByte('"')
}
