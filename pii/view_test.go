package pii

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestDetectionViewText(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain ascii", "plain ascii"},
		{"ｊｏｈｎ@ｅｘａｍｐｌｅ.ｃｏｍ", "john@example.com"}, // full-width letters
		{"ﬁle", "file"}, // ligature
		{"jo\u200bhn\u200d@exa\u2060mple.com", "john@example.com"},
		{"+32\u202e475 12\u2066 34 56", "+32475 12 34 56"}, // bidi controls
		{"\ufeffBOM", "BOM"},
		{"so\u00adft", "soft"}, // soft hyphen
		{"+32 475 12 34", "+32 475 12 34"},
		{"４１１１", "4111"},
		{"bad \xff byte", "bad \xff byte"},
		{"rené", "rené"}, // composed by NFKC
	}
	for _, c := range cases {
		if got := DetectionView(c.in).Text; got != c.want {
			t.Errorf("DetectionView(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A range of the view maps back to the source characters it was written
// with, covering what was dropped inside it.
func TestDetectionViewSource(t *testing.T) {
	s := "x jo\u200bhn@ｅｘ.com y"
	v := DetectionView(s)
	if v.Text != "x john@ex.com y" {
		t.Fatalf("Text = %q", v.Text)
	}
	i := strings.Index(v.Text, "john@ex.com")
	a, b := v.Source(i, i+len("john@ex.com"))
	if got := s[a:b]; got != "jo\u200bhn@ｅｘ.com" {
		t.Errorf("Source = %q", got)
	}
	// Clamping and empty ranges.
	if a, b := v.Source(-5, 1000); a != 0 || b != len(s) {
		t.Errorf("Source(-5, 1000) = %d, %d", a, b)
	}
	if a, b := v.Source(len(v.Text), len(v.Text)); a != len(s) || b != len(s) {
		t.Errorf("Source(end, end) = %d, %d", a, b)
	}
	id := DetectionView("abc")
	if a, b := id.Source(1, 2); a != 1 || b != 2 {
		t.Errorf("identity Source = %d, %d", a, b)
	}
}

func viewTexts(s string) []string {
	var out []string
	for _, v := range DetectionViews(s) {
		out = append(out, v.Text)
	}
	return out
}

func TestDetectionViewsDecode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"to=jean%40example.com", "to=jean@example.com"},
		{"to=jean%2540example.com", "to=jean@example.com"}, // double
		{`"to":"jean\u0040example.com"`, `"to":"jean@example.com"`},
		{`"e":"\ud83d\ude00 x\n"`, "\"e\":\"\U0001F600 x\n\""},
		{`lone \ud83d`, "lone \ufffd"},
		{"jean&#64;example.com", "jean@example.com"},
		{"jean&#x40;example.com", "jean@example.com"},
		{"jean&#64example.com", "jean@example.com"},
		{"jean&commat;example.com", "jean@example.com"},
		{"a&amp;b", "a&b"},
		{"%e2%80%8bjean", "jean"}, // a percent-encoded zero-width space, then dropped
	}
	for _, c := range cases {
		got := viewTexts(c.in)
		found := false
		for _, g := range got {
			found = found || g == c.want
		}
		if !found {
			t.Errorf("DetectionViews(%q) = %q, want one %q", c.in, got, c.want)
		}
	}
	if got := viewTexts("nothing to decode & 100% sure"); len(got) != 1 {
		t.Errorf("DetectionViews = %q, want the detection view only", got)
	}
}

// A value written behind an escape, a look-alike or a zero-width character
// is found, and its whole written form in the source is the match.
func TestFindInViewsCoversEncodedForm(t *testing.T) {
	cases := []struct{ in, value, kind string }{
		{"to=jean%40example.com&x=1", "jean%40example.com", "email"},
		{"to=jean%2540example.com&x=1", "jean%2540example.com", "email"},
		{`{"to":"jean\u0040example.com"}`, `jean\u0040example.com`, "email"},
		{"<a>jean&#64;example.com</a>", "jean&#64;example.com", "email"},
		{"<a>jean&#x40;example.com</a>", "jean&#x40;example.com", "email"},
		{"<a>jean&commat;example.com</a>", "jean&commat;example.com", "email"},
		{"mail jo\u200bhn@example.com now", "jo\u200bhn@example.com", "email"},
		{"mail ｊｏｈｎ@ｅｘａｍｐｌｅ.ｃｏｍ now", "ｊｏｈｎ@ｅｘａｍｐｌｅ.ｃｏｍ", "email"},
		{"iban BE68\u200b5390\u200b0754\u200b7034 ok", "BE68\u200b5390\u200b0754\u200b7034", "iban"},
		{"tel +32\u202e475123456 ok", "+32\u202e475123456", "phone"},
		{"tel=%2B32475123456 ok", "%2B32475123456", "phone"},
		{"card 4111%201111%201111%201111 ok", "4111%201111%201111%201111", "card"},
	}
	ds := AllDetectors()
	for _, c := range cases {
		ms := FindInViews(c.in, ds)
		var got []string
		ok := false
		for _, m := range ms {
			got = append(got, m.Kind+"="+c.in[m.Start:m.End])
			ok = ok || c.in[m.Start:m.End] == c.value && m.Kind == c.kind
		}
		if !ok {
			t.Errorf("FindInViews(%q) = %q, want %s=%q", c.in, got, c.kind, c.value)
		}
	}
	// No view finds anything in a text without values.
	if ms := FindInViews("GET /api/orders/4812 200 12ms", ds); ms != nil {
		t.Errorf("FindInViews = %v", ms)
	}
}

func FuzzDetectionView(f *testing.F) {
	for _, s := range []string{"jo\u200bhn@ｅｘ.com", "%2540&#x40;\\u0040&commat;", "\xff\xfe%", "&#;&#x;&;", `\ud800A`, "ﬁ́\u200d"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1024 {
			return
		}
		for _, v := range DetectionViews(s) {
			pa, pb := 0, 0
			for i := 0; i <= len(v.Text); i++ {
				a, b := v.Source(i, len(v.Text))
				if a < pa || a > b || b > len(s) {
					t.Fatalf("view %q of %q: Source(%d, end) = %d, %d", v.Text, s, i, a, b)
				}
				pa = a
				a, b = v.Source(0, i)
				if a > b || b < pb || b > len(s) {
					t.Fatalf("view %q of %q: Source(0, %d) = %d, %d", v.Text, s, i, a, b)
				}
				pb = b
				if utf8.ValidString(s) {
					a, b = v.Source(i, min(i+1, len(v.Text)))
					if a < len(s) && !utf8.RuneStart(s[a]) || b < len(s) && !utf8.RuneStart(s[b]) {
						t.Fatalf("view %q of %q: Source(%d, %d) = %d, %d off rune boundaries", v.Text, s, i, i+1, a, b)
					}
				}
			}
		}
	})
}

// Invisible characters that are not format characters (Cf) still do not
// hide a value: every default-ignorable code point is dropped.
func TestFindInViewsDefaultIgnorables(t *testing.T) {
	ds := AllDetectors()
	for _, x := range []string{"\u200b", "\u2061", "͏", "️", "\U000E0100", "᠋", "឴", "ᅟ", "ᅠ", "ㅤ", "ﾠ", "\u00ad"} {
		for _, c := range []struct{ value, kind string }{
			{"4111" + x + "1111" + x + "1111" + x + "1111", "card"},
			{"+32" + x + "475123456", "phone"},
			{"jo" + x + "hn@example.com", "email"},
		} {
			in := "v " + c.value + " ok"
			ms := FindInViews(in, ds)
			if len(ms) != 1 || in[ms[0].Start:ms[0].End] != c.value {
				t.Errorf("FindInViews(%q) = %v, want the whole %s", in, ms, c.kind)
			}
		}
	}
}

// Dropping an invisible character can join the neighbouring words to a
// value: that masks more, never less.
func TestFindInViewsJoinsAcrossDropped(t *testing.T) {
	in := "x\u200bjean@example.com\u200by"
	ms := FindInViews(in, AllDetectors())
	if len(ms) != 1 || ms[0].Start != 0 {
		t.Errorf("FindInViews = %v", ms)
	}
}

// Past DetectLimit, the unscanned rest of the text is one match of kind
// CutKind: matches are always safe to apply to the text itself.
func TestFindCoversUnscannedRest(t *testing.T) {
	s := strings.Repeat("x ", DetectLimit/2) + "jean@example.com and more"
	for name, f := range map[string]func(string, []Detector) []Match{"Find": Find, "FindInViews": FindInViews} {
		ms := f(s, AllDetectors())
		if len(ms) == 0 || ms[len(ms)-1].Kind != CutKind || ms[len(ms)-1].End != len(s) || ms[len(ms)-1].Start > DetectLimit {
			t.Errorf("%s: last match %v, want the rest as %s", name, ms, CutKind)
		}
	}
	// A view expanded past its cap (NFKC: U+FDFA is 3 bytes, about 33
	// after) masks what it could not scan.
	s = strings.Repeat("ﷺ", DetectLimit/3)
	ms := FindInViews(s, AllDetectors())
	if len(ms) != 1 || ms[0].Kind != CutKind || ms[0].End != len(s) {
		t.Errorf("FindInViews over an expanded view = %v", ms)
	}
}

// Planted values, each character encoded at random (percent, double
// percent, JSON, HTML, full-width, default-ignorables inserted), in
// JSON, HTML and query contexts: the written form is covered whole.
func TestFindInViewsPlantedEncodings(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 9))
	values := map[string]string{"email": "jean.dupont@example.com", "iban": "BE68539007547034", "card": "4111111111111111", "phone": "+32475123456", "be_niss": "85073003328", "us_ssn": "123-45-6789"}
	kinds := []string{"email", "iban", "card", "phone", "be_niss", "us_ssn"}
	ds := AllDetectors()
	for range 3000 {
		kind := kinds[r.IntN(len(kinds))]
		v := values[kind]
		scheme := r.IntN(6)
		var b strings.Builder
		for i, c := range v {
			switch {
			case scheme == 0 && r.IntN(2) == 0:
				fmt.Fprintf(&b, "%%%02X", c)
			case scheme == 1 && r.IntN(2) == 0:
				fmt.Fprintf(&b, "%%25%02X", c)
			case scheme == 2 && r.IntN(2) == 0:
				fmt.Fprintf(&b, `\u%04x`, c)
			case scheme == 3 && r.IntN(2) == 0:
				fmt.Fprintf(&b, "&#%d;", c)
			case scheme == 4 && c >= '0' && c <= '9' && r.IntN(2) == 0:
				b.WriteRune('０' + c - '0')
			default:
				b.WriteRune(c)
			}
			if scheme == 5 && i < len(v)-1 && r.IntN(3) == 0 {
				b.WriteString([]string{"\u200b", "͏", "️", "\u2060"}[r.IntN(4)])
			}
		}
		enc := b.String()
		ctx := []string{`{"v":"%s","n":1}`, "<td>%s</td>", "GET /?q=%s&x=1", "v=%s ok"}[r.IntN(4)]
		in := fmt.Sprintf(ctx, enc)
		start := strings.Index(in, enc)
		covered := false
		for _, m := range FindInViews(in, ds) {
			covered = covered || m.Start <= start && start+len(enc) <= m.End
		}
		if !covered {
			t.Fatalf("FindInViews(%q) does not cover %q (%s)", in, enc, kind)
		}
	}
}

// A value straddling the point where an expanded view stops is masked
// whole: the fail-closed match starts before it.
func TestFindInViewsValueAcrossViewCap(t *testing.T) {
	ds := AllDetectors()
	// Values only a view finds whole: in the source, an invisible
	// character cuts each.
	values := []string{"jean\u200b.dupont@example.com", "BE68\u200b5390\u200b0754\u200b7034", "+32\u200b475123456", "4111\u200b1111\u200b1111\u200b1111", fullwidthEmail, "jean.dupont&#64;example.com"}
	// U+FDFA expands to 33 bytes: after k of them the view is 33k bytes
	// long; padding moves the point where it stops across the value.
	k := maxViewBytes / 33
	for _, v := range values {
		for pad := 0; pad <= maxViewBytes-33*k+len(v); pad++ {
			s := strings.Repeat("\ufdfa", k) + strings.Repeat(",", pad) + " " + v + " " + strings.Repeat("\ufdfa", 100)
			start := strings.Index(s, v)
			covered := false
			for _, m := range FindInViews(s, ds) {
				covered = covered || m.Start <= start && start+len(v) <= m.End
			}
			if !covered {
				t.Fatalf("value %q after %d commas not covered whole: %v", v, pad, FindInViews(s, ds))
			}
		}
	}
}

// ｊｅａｎ．ｄｕｐｏｎｔ＠ｅｘａｍｐｌｅ．ｃｏｍ, built so that no tool rewrites it.
var fullwidthEmail = func() string {
	var b strings.Builder
	for _, c := range "jean.dupont@example.com" {
		b.WriteRune(c - 0x21 + 0xff01)
	}
	return b.String()
}()

// Values written across DetectLimit, in every encoding, are covered
// whole: the rest's match starts where they start.
func TestFindInViewsValueAcrossDetectLimit(t *testing.T) {
	ds := AllDetectors()
	values := []string{
		"jean.dupont\u200b@example.com", "jean.dupont&#64;example.com", "+32\u200b475123456", fullwidthEmail,
		strings.Repeat("j", 47) + ".dupont@example.com", "jean.dupont" + "\\" + "u0040example.com", "BE68 5390 0754 7034",
	}
	for _, v := range values {
		for off := -len(v) - 2; off <= 2; off++ {
			pad := DetectLimit + off
			if pad < 1 {
				continue
			}
			s := strings.Repeat("x", pad-1) + " " + v + " " + strings.Repeat("y", 100)
			start := pad
			covered := false
			ms := FindInViews(s, ds)
			for _, m := range ms {
				covered = covered || m.Start <= start && start+len(v) <= m.End
			}
			if !covered {
				t.Fatalf("%q at %d from DetectLimit not covered whole: %v", v, off, ms)
			}
			if fs := Find(s, ds); len(fs) == 0 || fs[len(fs)-1].End != len(s) {
				t.Fatalf("Find on a long text: %v", fs)
			}
		}
	}
}

// Look-alike digits, marks on digits, controls, form encoding and mixed
// encodings do not hide a value.
func TestFindInViewsMoreHidings(t *testing.T) {
	arabic := func(d string) string {
		var b strings.Builder
		for _, c := range d {
			if c >= '0' && c <= '9' {
				b.WriteRune(0x0660 + c - '0')
			} else {
				b.WriteRune(c)
			}
		}
		return b.String()
	}
	marked := func(d string, mark rune) string {
		var b strings.Builder
		for i, c := range d {
			b.WriteRune(c)
			if c >= '0' && c <= '9' && i < len(d)-1 {
				b.WriteRune(mark) // between digits: a trailing mark is not part of the value
			}
		}
		return b.String()
	}
	cases := []struct{ value, kind string }{
		{arabic("4111111111111111"), "card"},
		{"+" + string([]rune{0x0969, 0x0968}) + "475123456", "phone"},
		{marked("4111111111111111", 0x0303), "card"},
		{marked("4111111111111111", 0x20e3), "card"},
		{"4111\x001111\x7f1111\u28001111", "card"},
		{"%2B32+475+12+34+56", "phone"},
		{"jean%40example&#46;com", "email"},
		{"jean&#37;40example.com", "email"},
		{"jean%252540example.com", "email"},
		{"jean@example%2Ecom", "email"},
	}
	ds := AllDetectors()
	for _, c := range cases {
		in := "v=" + c.value + " ok"
		covered := false
		ms := FindInViews(in, ds)
		for _, m := range ms {
			covered = covered || m.Start <= 2 && 2+len(c.value) <= m.End
		}
		if !covered {
			t.Errorf("FindInViews(%q) = %v, want the whole %s", in, ms, c.kind)
		}
	}
}

// Long inputs: the fuzzer's text near DetectLimit.
func FuzzFindLongText(f *testing.F) {
	f.Add("jean.dupont@example.com", uint16(10))
	f.Add("jean&#64;example.com", uint16(3))
	f.Add("+32\u200b475123456", uint16(20))
	ds := AllDetectors()
	f.Fuzz(func(t *testing.T, tail string, back uint16) {
		if len(tail) > 2048 {
			return
		}
		pad := DetectLimit - int(back%2048)
		s := strings.Repeat("a ", pad/2) + tail
		ms := FindInViews(s, ds)
		checkMatches(t, s, ms)
		out := detectText(s, ds)
		if len(s) <= DetectLimit && !gapsPreserved(s, out, ms) {
			t.Fatalf("Detect changes text outside FindInViews")
		}
		if len(s) > DetectLimit && (len(ms) == 0 || ms[len(ms)-1].Kind != CutKind || ms[len(ms)-1].Start > DetectLimit) {
			t.Fatalf("long text without its rest: %v", ms)
		}
	})
}

// The round-3 review's inputs: padded values across the cut, escapes
// behind look-alikes or invisibles, zero-padded references, colour codes,
// deep encodings, \\xHH escapes, dashes.
func TestFindInViewsReviewRepros(t *testing.T) {
	ds := AllDetectors()
	zw := "\u200b"
	long := []string{
		"4111111111" + strings.Repeat(zw, 1400) + "111111",
		"jeanpierredupont" + strings.Repeat(zw, 1500) + "@example.com",
		"4111111111" + strings.Repeat("%E2%80%8B", 500) + "111111",
		"4111111111" + strings.Repeat("\u0336", 2500) + "111111",
	}
	for _, v := range long {
		s := strings.Repeat("x ", DetectLimit/2)[:DetectLimit-20] + v + " tail"
		start := DetectLimit - 20
		covered := false
		for _, m := range FindInViews(s, ds) {
			covered = covered || m.Start <= start && start+len(v) <= m.End
		}
		if !covered {
			t.Errorf("padded value across DetectLimit (%d bytes) not covered whole", len(v))
		}
	}
	cases := []struct{ in, value string }{
		{"mail jean\uff0540example.com x", "jean\uff0540example.com"},
		{"mail jean%4" + zw + "0example.com x", "jean%4" + zw + "0example.com"},
		{"mail jean&#6" + zw + "4;example.com x", "jean&#6" + zw + "4;example.com"},
		{"mail jean&#" + strings.Repeat("0", 40) + "64;example.com x", "jean&#" + strings.Repeat("0", 40) + "64;example.com"},
		{"user \x1b[1mjean\x1b[22m@example.com x", "jean\x1b[22m@example.com"},
		{"tel +32 475\x1b[0m 12 34 56 x", "+32 475\x1b[0m 12 34 56"},
		{"mail jean%2525252540example.com x", "jean%2525252540example.com"},
		{"mail jo\\xE2\\x80\\x8Bhn@example.com x", "jo\\xE2\\x80\\x8Bhn@example.com"},
		{"card 4111\u20101111\u20101111\u20101111 x", "4111\u20101111\u20101111\u20101111"},
	}
	for _, c := range cases {
		start := strings.Index(c.in, c.value)
		covered := false
		ms := FindInViews(c.in, ds)
		for _, m := range ms {
			covered = covered || m.Start <= start && start+len(c.value) <= m.End
		}
		if !covered {
			t.Errorf("FindInViews(%q) = %v, want %q covered", c.in, ms, c.value)
		}
	}
}

// The round-4 review's inputs.
func TestFindInViewsReviewRepros4(t *testing.T) {
	ds := AllDetectors()
	zw := "\u200b"
	pad := strings.Repeat("x ", (DetectLimit-100)/2)
	for _, c := range []struct{ prefix, value string }{
		{pad, "jean.dupont" + strings.Repeat("\x0b", 5001) + "@example.com"},
		{pad, "jean.dupont" + strings.Repeat("\x0c", 5001) + "@example.com"},
		{pad, "jean.dupont" + strings.Repeat("\u0085", 3000) + "@example.com"},
		{pad, "0475 " + strings.Repeat(zw, 2000) + "12 34 56"},
	} {
		s := c.prefix + c.value + " tail"
		start := len(c.prefix)
		covered := false
		for _, m := range FindInViews(s, ds) {
			covered = covered || m.Start <= start && start+len(c.value) <= m.End
		}
		if !covered {
			t.Errorf("padded value (%d bytes) across DetectLimit not covered whole", len(c.value))
		}
	}
	for _, c := range []struct{ in, value string }{
		{"mail jean\x1b(B\x1b[mmple@example.com x", "jean\x1b(B\x1b[mmple@example.com"},
		{"mail jean@exa\x1b(B\x1b[mmple.com x", "jean@exa\x1b(B\x1b[mmple.com"},
		{"mail jean@exa\x1bP;\x1b\\mple.com x", "jean@exa\x1bP;\x1b\\mple.com"},
		{"mail jean@exa\x1b_;\x1b\\mple.com x", "jean@exa\x1b_;\x1b\\mple.com"},
		{"mail jean@exa\u009b;31mmple.com x", "jean@exa\u009b;31mmple.com"},
		{"pay B\u0332E68539007547034 x", "B\u0332E68539007547034"},
		{"call +\u033232 475 12 34 56 x", "+\u033232 475 12 34 56"},
		{"mail jean@example.\u0301com x", "jean@example.\u0301com"},
		{"mail jean@example\u3002com x", "jean@example\u3002com"},
		{"mail jean@example\uff61com x", "jean@example\uff61com"},
		{"iban \u0412\u041568539007547034 x", "\u0412\u041568539007547034"},
		{"iban \u0392\u039568539007547034 x", "\u0392\u039568539007547034"},
		{"ssn 123\u204345\u20436789 x", "123\u204345\u20436789"},
	} {
		start := strings.Index(c.in, c.value)
		covered := false
		ms := FindInViews(c.in, ds)
		for _, m := range ms {
			covered = covered || m.Start <= start && start+len(c.value) <= m.End
		}
		if !covered {
			t.Errorf("FindInViews(%q) = %v, want %q covered", c.in, ms, c.value)
		}
	}
	// Still decoding after the last round: everything is masked.
	in := "jean&" + strings.Repeat("amp;", 16) + "#64;example.com"
	if ms := FindInViews(in, ds); len(ms) != 1 || ms[0].Start != 0 || ms[0].End != len(in) {
		t.Errorf("FindInViews(%q) = %v, want it all", in, ms)
	}
}

var ansiCanaries = []string{"jean.dupont@example.com", "+32 475 12 34 56", "BE68 5390 0754 7034", "4111 1111 1111 1111"}

// A value after, inside or across every terminal sequence form,
// terminated or not, is covered: stripping is an extra view, and only
// well-formed short sequences are stripped whole.
func TestFindInViewsTerminalSequences(t *testing.T) {
	ds := AllDetectors()
	esc := "\x1b"
	forms := []struct{ open, close string }{
		{esc + "]0;", "\x07"}, {esc + "]0;", esc + "\\"}, {esc + "]0;", ""},
		{esc + "P", esc + "\\"}, {esc + "P", ""}, {esc + "_", ""}, {esc + "X", ""}, {esc + "^", ""},
		{"\u009d", "\u009c"}, {"\u009d", ""}, {"\u0090", ""},
		{esc + "[", ""}, {"\u009b", ""}, {esc + "[1;", esc + "[0m"}, {esc + "(", ""}, {esc + "#", ""}, {esc + "7", ""},
	}
	for _, v := range ansiCanaries {
		for _, f := range forms {
			for _, in := range []string{
				"a " + f.open + f.close + " " + v + " z", // after
				"a " + f.open + v + f.close + " z",       // inside
				"a " + f.open + " " + v + " z",           // after an unterminated introducer
			} {
				start := strings.Index(in, v)
				covered := false
				for _, m := range FindInViews(in, ds) {
					covered = covered || m.Start <= start && start+len(v) <= m.End
				}
				if !covered {
					t.Errorf("FindInViews(%q) leaves %q", in, v)
				}
			}
		}
	}
}

// Differential: whatever terminal bytes surround a value written as its
// own word, the value is covered.
func FuzzFindAroundTerminalSequences(f *testing.F) {
	f.Add("\x1b]0;", "\x07", uint8(0))
	f.Add("\xc2\x9b12;", "m", uint8(1))
	f.Add("\x1b(", "\x1bP", uint8(2))
	ds := AllDetectors()
	covers := func(in, v string) bool {
		start := strings.Index(in, v)
		for _, m := range FindInViews(in, ds) {
			if m.Start <= start && start+len(v) <= m.End {
				return true
			}
		}
		return false
	}
	f.Fuzz(func(t *testing.T, before, after string, k uint8) {
		if len(before)+len(after) > 512 {
			return
		}
		v := ansiCanaries[int(k)%len(ansiCanaries)]
		// Differential: the detectors' own plain-text behaviour with these
		// neighbours (a card read inside a longer number...) is not this
		// test's subject; only what the terminal bytes add is.
		if !covers("x "+v+" "+after, v) || !covers(before+" "+v+" x", v) {
			return
		}
		if in := before + " " + v + " " + after; !covers(in, v) {
			t.Fatalf("FindInViews(%q) leaves %q", in, v)
		}
	})
}

// A terminal sequence written escaped (JSON, \xHH, percent, HTML), or an
// invalid UTF-8 byte, inside a value never hides it: the decoded views
// and the view without invalid bytes are stripped too.
func TestFindInViewsSplitByEscapedSequenceOrInvalidByte(t *testing.T) {
	ds := allDetectors(t)
	splitters := []string{
		`\u001b[31m`, `\u001b[1m`, `\u001B[0;1m`, `\x1b[31m`, `%1b[31m`, `%1B[1m`, `&#x1b;[31m`, `&#27;[1m`,
		"\xff", "\x9b", "\xc0\x80", "\x9b31m", "\x1b[1m\xff",
		// The introducer decoded one chain round before the rest.
		`%1b&amp;#91;31m`, `\u001b&amp;#91;31m`, `\x1b&amp;#91;31m`, `&#x1b;%255b31m`,
		// Shell spellings.
		`\033[31m`, `\e[1m`,
	}
	for _, v := range []string{"jean.dupont@example.com", "BE68539007547034", "4111111111111111", "+32475123456"} {
		for _, sp := range splitters {
			for _, p := range []int{4, len(v) / 2} {
				in := `{"log":"to ` + v[:p] + sp + v[p:] + ` now"}`
				start := strings.Index(in, v[:p])
				end := strings.Index(in, v[p:]) + len(v[p:])
				covered := false
				for _, m := range FindInViews(in, ds) {
					covered = covered || m.Start <= start && end <= m.End
				}
				if !covered {
					t.Errorf("FindInViews(%q) leaves %q", in, v)
				}
			}
		}
	}
	for _, in := range []string{
		`{"log":"card 4111 1111\u001b[1m 1111 1111\u001b[0m"}`,
		`{"log":"tel +32 475\u001b[1m 12 34 56\u001b[0m"}`,
		"pay BE68\x1b[1m5390%200754%207034",
		`card 4111 1111 \x1b]0;t\x071111 1111`,
		`card 4111 1111 \x9d0;t\x071111 1111`,
		`card 4111 1111 %1b]0;t&#7;1111 1111`,
		`card 4111 1111 %1b]0;t\x071111 1111`,
		"card 4111 1111 \x1b]0;t\\x071111 1111",
		"mail jean%4\xff0example.com",
		"mail jean\\x4\xff0example.com",
		"mail jean&#6\xff4;example.com",
		"mail jean\\u00\xff40example.com",
		"mail jean%4%ff0example.com",
		"x \x1b]0;4111 1111\x1b[1m 1111 1111\x07 y",
		"x \x1b]0;BE68 5390\x1b[1m 0754 7034\x07 y",
		"x \x1b_ 4111111111\x1b[m111111\x07 y",
		"title \x1b]2; started; log: card 4111 1111\x1b[0m 1111 1111 done \x1b\\",
		"x %1b]0;4111111111%1b[1m111111%07 y",
		`{"m":"\u001b]0;jean.dupont\u001b[1m@example.com\u0007"}`,
		"x 4111111111\x1b[1\x07m111111 y",
		"x BE68539007\x1b[0\x07m547034 y",
		"x jean.dupont\x1b[\x071m@example.com y",
		"x 4111111111\x1b[1\x18111111 y",
		"x 4111111111\x1b[1\nm111111 y",
		"card 4111 1111\x1b[3\u200b1m 1111 1111",
		"mail jean%4\x1b[m0example.com",
		"mail jean\\x4\x1b[m0example.com",
		"iban BE68 5390 \x1b]0;" + strings.Repeat("a", 260) + "\x07" + "0754 7034",
		"iban BE68 5390 \x1b[" + strings.Repeat("1", 260) + "m0754 7034",
	} {
		ms := FindInViews(in, ds)
		var b strings.Builder
		last := 0
		for _, m := range ms {
			b.WriteString(in[last:m.Start])
			b.WriteString("#")
			last = m.End
		}
		b.WriteString(in[last:])
		for _, piece := range []string{"4111", "1111", "+32", "BE68", "7034", "jean", "example"} {
			if strings.Contains(b.String(), piece) {
				t.Errorf("FindInViews(%q) leaves %q: %q", in, piece, b.String())
			}
		}
	}
}

// Differential: any run of invisible terminal units (sequences a terminal
// executes without showing anything), raw or escaped, inside a value
// never leaves it readable.
func FuzzFindValueSplitByTerminal(f *testing.F) {
	f.Add([]byte{0, 1, 2}, uint8(0), uint8(3), uint8(0))
	f.Add([]byte{5, 9}, uint8(2), uint8(8), uint8(1))
	units := []string{"\x1b[1m", "\x1b[0;31m", "\x1b[1\x07m", "\x1b]0;t\x07", "\x1b]0;t\x1b\\", "\x1b(B", "\x1b7", "​", "\u009b1m", "\x1b[1\x18", "\x9b1m", "\x1b[m", "\x1b[38;5;196m"}
	ds := AllDetectors()
	f.Fuzz(func(t *testing.T, picks []byte, k, at, enc uint8) {
		if len(picks) == 0 || len(picks) > 8 {
			return
		}
		v := []string{"jean.dupont@example.com", "BE68539007547034", "4111111111111111", "+32475123456"}[int(k)%4]
		p := 1 + int(at)%(len(v)-1)
		var mid strings.Builder
		for _, b := range picks {
			mid.WriteString(units[int(b)%len(units)])
		}
		m := mid.String()
		switch enc % 3 {
		case 1:
			if !utf8.ValidString(m) {
				return
			}
			m = strings.NewReplacer(`\`, `\\`, "\x1b", `\u001b`, "\x07", `\u0007`, "\x18", `\u0018`).Replace(m)
		case 2:
			m = strings.ReplaceAll(strings.ReplaceAll(m, "\x1b", "%1b"), "\x07", "%07")
		}
		in := `{"log":"to ` + v[:p] + m + v[p:] + ` now"}`
		start := strings.Index(in, v[:p])
		end := strings.LastIndex(in, v[p:]) + len(v[p:])
		for _, mt := range FindInViews(in, ds) {
			if mt.Start <= start && end <= mt.End {
				return
			}
		}
		t.Fatalf("FindInViews(%q) leaves %q", in, v)
	})
}
