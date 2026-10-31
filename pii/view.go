package pii

import (
	"html"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// View is a text derived from a source text (normalised, decoded) with
// the map back to it: Source gives the range of the source each range of
// Text was written with. The zero map means Text is the source itself.
type View struct {
	Text string
	// lo[k], hi[k]: byte k of Text comes from source[lo[k]:hi[k]]; both
	// non-decreasing in k.
	lo, hi []int32
	srcLen int
	// cut: the view stopped at maxViewBytes; source bytes from cutAt on
	// are not in it.
	cut   bool
	cutAt int
}

// Source returns the range of the source text that Text[start:end] was
// written with. It covers every source character dropped inside the range
// (a zero-width character between two digits) and every escape it decodes
// whole ("%40", "&#64;", "@"). Out-of-range arguments are clamped.
func (v View) Source(start, end int) (int, int) {
	start = min(max(start, 0), len(v.Text))
	end = min(max(end, start), len(v.Text))
	if v.lo == nil {
		return start, end
	}
	if start == end {
		if start == len(v.Text) {
			return v.srcLen, v.srcLen
		}
		return int(v.lo[start]), int(v.lo[start])
	}
	return int(v.lo[start]), int(v.hi[end-1])
}

func (v View) sourceLen() int {
	if v.lo == nil {
		return len(v.Text)
	}
	return v.srcLen
}

// compose maps w, a view of v.Text, to v's source.
func compose(v, w View) View {
	if v.lo == nil {
		w.srcLen = len(v.Text)
		return w
	}
	if w.lo == nil {
		return View{Text: w.Text, lo: v.lo, hi: v.hi, srcLen: v.srcLen, cut: v.cut, cutAt: v.cutAt}
	}
	cut, cutAt := v.cut, v.cutAt
	if w.cut {
		at, _ := v.Source(w.cutAt, w.cutAt)
		if !cut || at < cutAt {
			cut, cutAt = true, at
		}
	}
	lo := make([]int32, len(w.Text))
	hi := make([]int32, len(w.Text))
	for k := 0; k < len(w.Text); k++ {
		l, h := v.Source(int(w.lo[k]), int(w.hi[k]))
		lo[k], hi[k] = int32(l), int32(h)
	}
	return View{Text: w.Text, lo: lo, hi: hi, srcLen: v.srcLen, cut: cut, cutAt: cutAt}
}

// viewBuilder writes a view byte by byte, each from a range of the source.
type viewBuilder struct {
	b      []byte
	lo, hi []int32
}

func (vb *viewBuilder) add(p []byte, from, to int) {
	vb.b = append(vb.b, p...)
	for range p {
		vb.lo, vb.hi = append(vb.lo, int32(from)), append(vb.hi, int32(to))
	}
}

func (vb *viewBuilder) addString(p string, from, to int) {
	vb.b = append(vb.b, p...)
	for range len(p) {
		vb.lo, vb.hi = append(vb.lo, int32(from)), append(vb.hi, int32(to))
	}
}

func (vb *viewBuilder) view(srcLen int) View {
	return View{Text: string(vb.b), lo: vb.lo, hi: vb.hi, srcLen: srcLen}
}

// DetectionView is s as the detectors should see it: the characters fold
// knows mapped to ASCII (the spaces digits are grouped with, full-width
// digits), NFKC-normalised (full-width letters, ligatures, other
// compatibility look-alikes), and without default-ignorable characters
// (Unicode Cf: zero-width spaces and joiners, bidi controls, the soft
// hyphen; variation selectors, the combining grapheme joiner, Hangul
// fillers). An
// invalid UTF-8 byte is kept as is. Texts longer than DetectLimit are cut
// as by Find.
func DetectionView(s string) View {
	t, _ := scanned(s)
	return detectionView(t)
}

func detectionView(s string) View {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		return View{Text: s} // ASCII is NFKC and has no format character
	}
	var vb viewBuilder
	vb.b = make([]byte, 0, len(s))
	vb.lo, vb.hi = make([]int32, 0, len(s)), make([]int32, 0, len(s))
	var it norm.Iter
	it.InitString(norm.NFKC, s)
	for !it.Done() {
		from := it.Pos()
		if len(vb.b) >= maxViewBytes {
			v := vb.view(len(s))
			v.cut, v.cutAt = true, backOverValue(s, from)
			return v
		}
		seg := it.Next()
		to := it.Pos()
		for len(seg) > 0 {
			r, n := utf8.DecodeRune(seg)
			switch c, folded := foldRune(r); {
			case r == utf8.RuneError && n == 1:
				vb.add(seg[:1], from, to)
			case folded:
				vb.add([]byte{c}, from, to)
			case ignorable(r):
				// dropped: the next byte's range starts after it, and a
				// range of the view spanning it covers it
			default:
				vb.add(seg[:n], from, to)
			}
			seg = seg[n:]
		}
	}
	return vb.view(len(s))
}

// ignorable reports whether r is a default-ignorable code point (format
// characters, variation selectors, combining grapheme joiner, Hangul
// fillers...): invisible, so it may sit inside a value and hide it.
func ignorable(r rune) bool {
	return unicode.In(r, unicode.Cf, unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector)
}

// backOverValue returns where the unscanned part of s must start when a
// view stops at source offset at: back over up to cutTail value-like or
// ignorable characters, as CutAt does, so that a value the stop splits is
// masked whole rather than left in part.
func backOverValue(s string, at int) int {
	for back := 0; back < cutTail && at > 0; back++ {
		r, size := utf8.DecodeLastRuneInString(s[:at])
		if !valueRune(r) && !ignorable(r) {
			break
		}
		at -= size
	}
	return at
}

// maxViewBytes caps a view's text: NFKC can expand a text about tenfold.
// A view cut there makes the rest of the source one match (find).
const maxViewBytes = 2 * DetectLimit

// DetectionViews returns the detection view of s, then the detection view
// of each decoding of s that changes it: percent-decoded once and twice,
// JSON string escapes, HTML character references. Texts are distinct.
// Texts longer than DetectLimit are cut as by Find.
func DetectionViews(s string) []View {
	s, _ = scanned(s)
	base := detectionView(s)
	out := []View{base}
	seen := map[string]bool{base.Text: true}
	addDecoded := func(v View, ok bool) {
		if !ok {
			return
		}
		dv := compose(v, detectionView(v.Text))
		if !seen[dv.Text] {
			seen[dv.Text] = true
			out = append(out, dv)
		}
	}
	src := View{Text: s}
	if p, ok := decodePercent(s); ok {
		pv := compose(src, p)
		addDecoded(pv, true)
		if pp, ok := decodePercent(pv.Text); ok {
			addDecoded(compose(pv, pp), true)
		}
	}
	if j, ok := decodeJSONEscapes(s); ok {
		addDecoded(compose(src, j), true)
	}
	if h, ok := decodeHTML(s); ok {
		addDecoded(compose(src, h), true)
	}
	return out
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// decodePercent decodes every "%XX" of s; false when there is none.
func decodePercent(s string) (View, bool) {
	if !strings.Contains(s, "%") {
		return View{}, false
	}
	var vb viewBuilder
	vb.b = make([]byte, 0, len(s))
	changed := false
	for i := 0; i < len(s); {
		if s[i] == '%' && i+2 < len(s) {
			h, ok1 := unhex(s[i+1])
			l, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				vb.add([]byte{h<<4 | l}, i, i+3)
				i += 3
				changed = true
				continue
			}
		}
		vb.add([]byte{s[i]}, i, i+1)
		i++
	}
	return vb.view(len(s)), changed
}

// decodeJSONEscapes decodes the escapes of a JSON string ("@",
// surrogate pairs, "\n", "\""...) wherever they appear in s; a lone
// surrogate becomes U+FFFD. False when there is none.
func decodeJSONEscapes(s string) (View, bool) {
	if !strings.Contains(s, `\`) {
		return View{}, false
	}
	var vb viewBuilder
	vb.b = make([]byte, 0, len(s))
	changed := false
	hex4 := func(i int) (rune, bool) {
		if i+6 > len(s) || s[i] != '\\' || s[i+1] != 'u' {
			return 0, false
		}
		var r rune
		for k := i + 2; k < i+6; k++ {
			d, ok := unhex(s[k])
			if !ok {
				return 0, false
			}
			r = r<<4 | rune(d)
		}
		return r, true
	}
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+1 < len(s) {
			if r, ok := hex4(i); ok {
				n := 6
				if utf16.IsSurrogate(r) {
					r2, ok2 := hex4(i + 6)
					if d := utf16.DecodeRune(r, r2); ok2 && d != utf8.RuneError {
						r, n = d, 12
					} else {
						r = utf8.RuneError
					}
				}
				vb.addString(string(r), i, i+n)
				i += n
				changed = true
				continue
			}
			if c, ok := jsonSimpleEscape(s[i+1]); ok {
				vb.add([]byte{c}, i, i+2)
				i += 2
				changed = true
				continue
			}
		}
		vb.add([]byte{s[i]}, i, i+1)
		i++
	}
	return vb.view(len(s)), changed
}

func jsonSimpleEscape(c byte) (byte, bool) {
	switch c {
	case '"', '\\', '/':
		return c, true
	case 'b':
		return '\b', true
	case 'f':
		return '\f', true
	case 'n':
		return '\n', true
	case 'r':
		return '\r', true
	case 't':
		return '\t', true
	}
	return 0, false
}

// maxEntity bounds the length of an HTML character reference, "&" and ";"
// included ("&CounterClockwiseContourIntegral;" is the longest name).
const maxEntity = 40

// decodeHTML decodes the HTML character references of s: named ones
// ("&commat;", "&amp;") and numeric ones ("&#64;", "&#x40;", with or
// without the ";"). False when there is none.
func decodeHTML(s string) (View, bool) {
	if !strings.Contains(s, "&") {
		return View{}, false
	}
	var vb viewBuilder
	vb.b = make([]byte, 0, len(s))
	changed := false
	for i := 0; i < len(s); {
		if s[i] == '&' {
			if n := entityLen(s[i:]); n > 0 {
				if dec := html.UnescapeString(s[i : i+n]); dec != s[i:i+n] {
					vb.addString(dec, i, i+n)
					i += n
					changed = true
					continue
				}
			}
		}
		vb.add([]byte{s[i]}, i, i+1)
		i++
	}
	return vb.view(len(s)), changed
}

// entityLen returns the length of the character reference s starts with,
// or 0: "&name;", "&#digits;" or "&#xhex;", the ";" optional after a
// number.
func entityLen(s string) int {
	if len(s) < 3 {
		return 0
	}
	if s[1] == '#' {
		k := 2
		isHex := k < len(s) && (s[k] == 'x' || s[k] == 'X')
		if isHex {
			k++
		}
		from := k
		for k < len(s) && k < maxEntity {
			if _, ok := unhex(s[k]); ok && (isHex || isDigit(s[k])) {
				k++
				continue
			}
			break
		}
		if k == from {
			return 0
		}
		if k < len(s) && s[k] == ';' {
			k++
		}
		return k
	}
	for k := 1; k < len(s) && k < maxEntity; k++ {
		c := s[k]
		if c == ';' {
			if k == 1 {
				return 0
			}
			return k + 1
		}
		if !(isDigit(c) || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return 0
		}
	}
	return 0
}
