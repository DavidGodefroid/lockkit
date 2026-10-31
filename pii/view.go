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
// whole ("%40", "&#64;", "\u0040"). Out-of-range arguments are clamped.
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

func detectionView(s string) View { return cleanView(s) }

// ansiView is the detection view of s without its terminal sequences, or
// false when it has none. It is one more view, never a replacement: text
// inside a sequence (an OSC title) is still scanned in the others.
func ansiView(s string) (View, bool) {
	if strings.IndexByte(s, 0x1b) < 0 && strings.IndexByte(s, 0xc2) < 0 {
		return View{}, false
	}
	a, ok := stripANSI(s)
	if !ok {
		return View{}, false
	}
	return compose(a, cleanView(a.Text)), true
}

// stripANSI drops terminal control sequences (CSI "ESC [ ... final", OSC
// "ESC ] ... BEL" or "ESC ] ... ESC \\", and two-byte escapes) whole:
// colour codes inside a value would split it.
func stripANSI(s string) (View, bool) {
	var vb viewBuilder
	vb.b = make([]byte, 0, len(s))
	changed := false
	for i := 0; i < len(s); {
		// The introducer: ESC and a byte, or a C1 control (UTF-8 C2 80-9F).
		var kind byte
		body, intro := i, 0
		switch {
		case s[i] == 0x1b && i+1 < len(s):
			kind, body, intro = s[i+1], i+2, 1
		case s[i] == 0xc2 && i+1 < len(s) && s[i+1] >= 0x80 && s[i+1] <= 0x9f:
			kind, body, intro = s[i+1]-0x40, i+2, 2 // C1 x is ESC (x - 0x40)
		default:
			vb.add([]byte{s[i]}, i, i+1)
			i++
			continue
		}
		// A sequence is dropped whole only when well formed and short;
		// otherwise only its introducer is (the rest stays visible).
		end := -1
		j := body
		switch {
		case kind == '[': // CSI: parameters, intermediates, a final byte
			for j < len(s) && j-body < maxSeq && s[j] >= 0x20 && s[j] <= 0x3f {
				j++
			}
			for j < len(s) && j-body < maxSeq && s[j] >= 0x20 && s[j] <= 0x2f {
				j++
			}
			if j < len(s) && s[j] >= 0x40 && s[j] <= 0x7e {
				end = j + 1
			}
		case kind == ']' || kind == 'P' || kind == 'X' || kind == '^' || kind == '_':
			// OSC, DCS, SOS, PM, APC: a string up to BEL or ST.
			for j < len(s) && j-body < maxSeq {
				if s[j] == 0x07 {
					end = j + 1
					break
				}
				if j+1 < len(s) && (s[j] == 0x1b && s[j+1] == '\\' || s[j] == 0xc2 && s[j+1] == 0x9c) {
					end = j + 2
					break
				}
				j++
			}
		case kind >= 0x20 && kind <= 0x2f && intro == 1: // nF ("ESC ( B")
			j = body
			for j < len(s) && j-body < 4 && s[j] >= 0x20 && s[j] <= 0x2f {
				j++
			}
			if j < len(s) && s[j] >= 0x30 && s[j] <= 0x7e {
				end = j + 1
			}
		case kind >= 0x40 && kind <= 0x5f && intro == 1: // two-byte Fe escapes
			end = body
		}
		if end < 0 {
			end = i + 1 // the introducer alone (C1: its two bytes)
			if intro == 2 {
				end = i + 2
			}
		}
		i = end
		changed = true
	}
	return vb.view(len(s)), changed
}

// separateANSI is s with every terminal-sequence introducer (ESC and the
// byte after it, a C1 control) and every final or terminator byte written
// as a space, the rest kept: a value inside a sequence (an OSC title) or
// glued to one ("ESC P" + an IBAN) stands as its own word. Byte for byte:
// the map is the identity.
func separateANSI(s string) (string, bool) {
	b := []byte(s)
	changed := false
	blank := func(from, to int) {
		for k := from; k < to && k < len(b); k++ {
			b[k] = ' '
		}
		changed = true
	}
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == 0x1b && i+1 < len(s) && s[i+1] < 0x80:
			blank(i, i+2)
			i++
		case s[i] == 0x1b:
			blank(i, i+1)
		case s[i] == 0xc2 && i+1 < len(s) && s[i+1] >= 0x80 && s[i+1] <= 0x9f:
			blank(i, i+2)
			i++
		case s[i] == 0x07:
			blank(i, i+1)
		}
	}
	// The final byte of a CSI: blank it when a CSI introducer precedes it.
	for i := 0; i+1 < len(s); i++ {
		if s[i] == 0x1b && s[i+1] == '[' || s[i] == 0xc2 && s[i+1] == 0x9b {
			j := i + 2
			for j < len(s) && j-i < maxSeq && s[j] >= 0x20 && s[j] <= 0x3f {
				j++
			}
			for j < len(s) && j-i < maxSeq && s[j] >= 0x20 && s[j] <= 0x2f {
				j++
			}
			if j < len(s) && s[j] >= 0x40 && s[j] <= 0x7e {
				blank(j, j+1)
			}
		}
	}
	return string(b), changed
}

// maxSeq bounds a terminal sequence the view drops whole.
const maxSeq = 256

func cleanView(s string) View {
	plain := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= utf8.RuneSelf || dropControl(rune(c)) {
			plain = false
			break
		}
	}
	if plain {
		return View{Text: s} // printable ASCII is NFKC and has nothing to drop
	}
	var vb viewBuilder
	vb.b = make([]byte, 0, len(s))
	vb.lo, vb.hi = make([]int32, 0, len(s)), make([]int32, 0, len(s))
	cut, cutAt := false, 0
	var it norm.Iter
	it.InitString(norm.NFKC, s)
	for !it.Done() {
		from := it.Pos()
		if len(vb.b) >= maxViewBytes && !cut {
			cut, cutAt = true, from
		}
		if len(vb.b) >= maxViewBytes+viewOverlap {
			break // past the overlap: the rest is the source's from cutAt on
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
			case droppedInView(r):
				// dropped (invisible, a control, a mark on a digit): the
				// next byte's range starts after it, and a range of the view
				// spanning it covers it
			case isDash(r):
				vb.add([]byte{'-'}, from, to) // hyphens, dashes and minus signs
			case r == 0x3002 || r == 0xff61 || r == 0xfe12:
				vb.add([]byte{'.'}, from, to) // ideographic full stops (IDNA label separators)
			case latinLookalike(r) != 0:
				vb.add([]byte{latinLookalike(r)}, from, to)
			case r >= utf8.RuneSelf && unicode.Is(unicode.Nd, r):
				vb.add([]byte{'0' + ndValue(r)}, from, to) // ٤ ३ → 4 3
			default:
				vb.add(seg[:n], from, to)
			}
			seg = seg[n:]
		}
	}
	v := vb.view(len(s))
	v.cut, v.cutAt = cut, cutAt
	return v
}

// ignorable reports whether r is a default-ignorable code point (format
// characters, variation selectors, combining grapheme joiner, Hangul
// fillers...): invisible, so it may sit inside a value and hide it.
func ignorable(r rune) bool {
	return unicode.In(r, unicode.Cf, unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector)
}

// droppedInView reports a rune the detection view drops: invisible
// (default-ignorable), a control, the braille blank, a combining mark.
func droppedInView(r rune) bool {
	return ignorable(r) || dropControl(r) || r == '\u2800' || unicode.In(r, unicode.Mn, unicode.Me)
}

func isDash(r rune) bool {
	switch r {
	case 0x2212, 0xfe63, 0xff0d, 0x2043, 0x058a, 0x05be, 0x2e3a, 0x2e3b, 0x30fc, 0x2e17, 0x2027:
		return true
	}
	return r >= 0x2010 && r <= 0x2015
}

// lookalikes are the Cyrillic and Greek letters drawn like a Latin one
// (a country code, a domain): read as that letter.
var lookalikes = map[rune]byte{
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'У': 'Y', 'Ѕ': 'S', 'І': 'I', 'Ј': 'J',
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'ѕ': 's', 'і': 'i', 'ј': 'j', 'һ': 'h', 'ԁ': 'd',
	'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
	'ο': 'o', 'ν': 'v', 'ι': 'i', 'κ': 'k',
}

func latinLookalike(r rune) byte {
	if r < 0x370 {
		return 0
	}
	return lookalikes[r]
}

// dropControl reports a control character a value may hide behind: C0
// but tab, newline and carriage return, DEL, C1.
func dropControl(r rune) bool {
	return r < 0x20 && r != '\t' && r != '\n' && r != '\r' || r == 0x7f || r >= 0x80 && r < 0xa0
}

// ndValue is the value of a decimal digit (Unicode Nd): digits come in
// runs of ten (or of several tens, the mathematical ones) from 0.
func ndValue(r rune) byte {
	z := r
	for unicode.Is(unicode.Nd, z-1) && r-(z-1) < 50 {
		z--
	}
	return byte((r - z) % 10)
}

// maxViewBytes caps a view's text: NFKC can expand a text about tenfold.
// A view cut there makes the rest of the source one match (find).
const maxViewBytes = 2 * DetectLimit

// viewOverlap is how far a view goes on past maxViewBytes, so that a value
// written across that point is found whole.
const viewOverlap = 16 << 10

// DetectionViews returns the detection view of s, then the detection view
// of each decoding of s that changes it: percent-decoded once and twice,
// JSON string escapes, HTML character references, all of them chained (until
// nothing changes, at most 16 rounds, cleaned up between rounds), \\xHH escapes, and form encoding ("+" as a space) then percent. Texts are distinct.
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
	if a, ok := ansiView(s); ok && !seen[a.Text] {
		seen[a.Text] = true
		out = append(out, a)
	}
	if sep, ok := separateANSI(s); ok {
		if v := compose(View{Text: s}, cleanView(sep)); !seen[v.Text] {
			seen[v.Text] = true
			out = append(out, v)
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
	// Every decoding in turn, a few rounds: a value written with two
	// encodings ("jean%40example&#46;com", "jean&#37;40...") or three
	// percent rounds.
	chain, rounds := src, 0
	for round := 0; round < 16; round++ {
		changed := false
		// Clean up between decodings: an escape written with a look-alike
		// or broken by an invisible character ("jean％40", "%4\u200b0").
		if c := detectionView(chain.Text); c.Text != chain.Text {
			chain = compose(chain, c)
		}
		for _, dec := range []func(string) (View, bool){decodePercent, decodeJSONEscapes, decodeHTML, decodeHexEscapes} {
			if d, ok := dec(chain.Text); ok {
				chain, changed = compose(chain, d), true
			}
		}
		if !changed {
			break
		}
		rounds++
	}
	if rounds == 16 {
		chain.cut, chain.cutAt = true, 0 // still decoding: mask it all
	}
	addDecoded(chain, rounds > 0)
	// Form encoding: "+" for a space, then percent ("tel=%2B32+475+12").
	if f, ok := decodeForm(s); ok {
		fv := compose(src, f)
		if p, ok := decodePercent(fv.Text); ok {
			fv = compose(fv, p)
		}
		addDecoded(fv, true)
	}
	return out
}

// decodeHexEscapes decodes "\\xHH" (nginx, Python, Go %q logs).
func decodeHexEscapes(s string) (View, bool) {
	if !strings.Contains(s, `\x`) {
		return View{}, false
	}
	var vb viewBuilder
	vb.b = make([]byte, 0, len(s))
	changed := false
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			h, ok1 := unhex(s[i+2])
			l, ok2 := unhex(s[i+3])
			if ok1 && ok2 {
				vb.add([]byte{h<<4 | l}, i, i+4)
				i += 4
				changed = true
				continue
			}
		}
		vb.add([]byte{s[i]}, i, i+1)
		i++
	}
	return vb.view(len(s)), changed
}

// decodeForm reads "+" as a space (application/x-www-form-urlencoded).
func decodeForm(s string) (View, bool) {
	if !strings.Contains(s, "+") {
		return View{}, false
	}
	var vb viewBuilder
	vb.b = make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '+' {
			c = ' '
		}
		vb.add([]byte{c}, i, i+1)
	}
	return vb.view(len(s)), true
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

// decodeJSONEscapes decodes the escapes of a JSON string ("\u0040",
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

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
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
		for k < len(s) && s[k] == '0' && k < 4096 {
			k++ // leading zeros do not count toward the cap ("&#000064;")
		}
		from, limit := k, k+maxEntity
		if k > 2+boolInt(isHex) {
			from = 2 + boolInt(isHex) // zeros alone are a number too
		}
		for k < len(s) && k < limit {
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
