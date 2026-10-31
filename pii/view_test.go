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
		{`"to":"jean@example.com"`, `"to":"jean@example.com"`},
		{`"e":"😀 x\n"`, "\"e\":\"\U0001F600 x\n\""},
		{`lone \ud83d`, "lone �"},
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
		{`{"to":"jean@example.com"}`, `jean@example.com`, "email"},
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
