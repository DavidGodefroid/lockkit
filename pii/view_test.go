package pii

import (
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
