package pii

import (
	"math/rand/v2"
	"strings"
	"testing"
	"unicode/utf8"
)

// findCorpus is the detectors' own test inputs plus mixed texts.
var findCorpus = []string{
	`{"to":"jean.dupont@example.com","status":"sent"}`,
	"to jöhn@example.com.", "rené.dupont@example.com", "john@exämple.com",
	"rené.dupont@example.com", "a@b.com-c@d.org", "foo@bar.com1@baz.org",
	"a@x.com_b@y.org", "a@x.com+b@y.org", "ÉLÈVE_42@école.fr",
	"ref 85073003328 ok", "ref 85.07.30-033.28 ok", "ref 85 07 30 033 28 ok", "id 12345678901",
	"pay BE68 5390 0754 7034 now", "BE68539007547034", "BE68 5390 0754 7035", "Be68539007547034",
	"card 4111 1111 1111 1111.", "4111-1111-1111-1111", "4111 1111 1111 1112",
	"call +32 475 12 34 56 now", "0475123456", "0475/12.34.56 and 02 123 45 67", "0032475123456",
	"tel 0475123456 2026", "+33 6 12 34 56 78",
	"order 12345678901, 2026-10-07, 0.123456789, v1.2.3, 10.0.0.1",
	"nir 1 84 03 76 451 089 96", "nir 184037645108996", "nir 2 69 05 2A 001 123 07",
	"bsn 111222333", "ssn 123-45-6789", "ssn 666-45-6789 000-12-3456",
	"+32 475 12 34 56 josé@exämple.de (415) 555-2671 ４１１１ ４１１１ ４１１１ ４１１１",
	"user=jean@example.com iban=BE68539007547034 card=4111111111111111 tel=+32475123456 niss=85073003328",
	"2026-10-30T14:02:11Z ERROR render pdf for jean.dupont@example.com failed: upstream timed out",
	"", "no values here at all", "a@b.c",
}

// maskWith replaces each match of s with MaskText of its text.
func maskWith(s string, ms []Match) string {
	var b strings.Builder
	last := 0
	for _, m := range ms {
		b.WriteString(s[last:m.Start])
		b.WriteString(MaskText(s[m.Start:m.End]))
		last = m.End
	}
	b.WriteString(s[last:])
	return b.String()
}

func allDetectors(t testing.TB) []Detector {
	ds, err := Detectors([]string{"email", "phone", "iban", "card", "be_niss", "fr_nir", "nl_bsn", "us_ssn", "phone_loose", "secret", "ip"})
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

func detectText(s string, ds []Detector) string {
	if out, ok := Detect(s, ds).(string); ok {
		return out
	}
	return s
}

func checkMatches(t *testing.T, s string, ms []Match) {
	t.Helper()
	last := 0
	for _, m := range ms {
		if m.Start < last || m.End <= m.Start || m.End > len(s) {
			t.Fatalf("Find(%q) = %v: out of order, empty or out of bounds", s, ms)
		}
		if utf8.ValidString(s) && (!utf8.RuneStart(s[m.Start]) || m.End < len(s) && !utf8.RuneStart(s[m.End])) {
			t.Fatalf("Find(%q): %v not on rune boundaries", s, m)
		}
		if m.Kind == "" {
			t.Fatalf("Find(%q): %v without a kind", s, m)
		}
		last = m.End
	}
}

// Replacing every match with MaskText gives exactly Detect's output.
func TestFindGoldenEqualsDetect(t *testing.T) {
	for _, dsName := range [][]string{nil, {"email"}, {"phone", "card"}} {
		ds := allDetectors(t)
		if dsName != nil {
			ds, _ = Detectors(dsName)
		}
		for _, s := range findCorpus {
			ms := Find(s, ds)
			checkMatches(t, s, ms)
			if got, want := maskWith(s, ms), detectText(s, ds); got != want {
				t.Errorf("%v: maskWith(Find(%q)) = %q, Detect = %q", dsName, s, got, want)
			}
		}
	}
	// Generated texts: values of every kind glued with fillers.
	values := []string{"jean.dupont@example.com", "+32 475 12 34 56", "0475/12.34.56", "BE68 5390 0754 7034",
		"4111 1111 1111 1111", "85.07.30-033.28", "1 84 03 76 451 089 96", "111222333", "123-45-6789",
		"(415) 555-2671", "rené@école.fr", "４１１１ ４１１１ ４１１１ ４１１１"}
	fillers := []string{" ", ", ", " id=", "\t", "=", "/", " order 4812 ", " ", "; ", "x"}
	r := rand.New(rand.NewPCG(1, 2))
	ds := allDetectors(t)
	for range 2000 {
		var b strings.Builder
		for range 1 + r.IntN(6) {
			b.WriteString(fillers[r.IntN(len(fillers))])
			b.WriteString(values[r.IntN(len(values))])
		}
		s := b.String()
		ms := Find(s, ds)
		checkMatches(t, s, ms)
		got, want := maskWith(s, ms), detectText(s, ds)
		if overlapping(find(s, ds, nil)) {
			// A later detector matched across an earlier mask: Find
			// masks the union, Detect the mask again.
			if !gapsPreserved(s, want, ms) {
				t.Fatalf("Detect(%q) = %q changes text outside Find = %v", s, want, ms)
			}
			continue
		}
		if got != want {
			t.Fatalf("maskWith(Find(%q)) = %q, Detect = %q", s, got, want)
		}
	}
}

func overlapping(ms []rankedMatch) bool {
	for i := range ms {
		for j := range ms {
			if i != j && ms[i].Start < ms[j].End && ms[j].Start < ms[i].End {
				return true
			}
		}
	}
	return false
}

func TestFindKinds(t *testing.T) {
	s := "mail jean@example.com iban BE68539007547034 tel +32 475 12 34 56 ssn 123-45-6789"
	ms := Find(s, AllDetectors())
	var kinds []string
	for _, m := range ms {
		kinds = append(kinds, m.Kind+"="+s[m.Start:m.End])
	}
	want := []string{"email=jean@example.com", "iban=BE68539007547034", "phone=+32 475 12 34 56", "us_ssn=123-45-6789"}
	if strings.Join(kinds, "|") != strings.Join(want, "|") {
		t.Errorf("Find kinds = %v, want %v", kinds, want)
	}
	if Find(s, nil) != nil || Find("", AllDetectors()) != nil {
		t.Error("Find without detectors or text found something")
	}
}

type foreignDetector struct{}

func (foreignDetector) Name() string { return "custom" }
func (foreignDetector) Mask(s string) string {
	return strings.ReplaceAll(s, "secret", "******")
}

// A detector that cannot give spans makes the whole text one match.
func TestFindForeignDetectorFailsClosed(t *testing.T) {
	s := "the secret is out, mail a@b.org"
	ms := Find(s, append(AllDetectors(), foreignDetector{}))
	if len(ms) != 1 || ms[0].Start != 0 || ms[0].End != len(s) || ms[0].Kind != "email" {
		t.Errorf("Find = %v, want one match of the whole text (kind email, the earliest)", ms)
	}
	ms = Find("nothing here", []Detector{foreignDetector{}})
	if ms != nil {
		t.Errorf("Find = %v, want none", ms)
	}
	ms = Find("a secret", []Detector{foreignDetector{}})
	if len(ms) != 1 || ms[0] != (Match{0, 8, "custom"}) {
		t.Errorf("Find = %v", ms)
	}
}

func TestFindCutsLongText(t *testing.T) {
	s := strings.Repeat("x ", DetectLimit/2) + "jean@example.com"
	ms := Find(s, AllDetectors())
	if len(ms) != 1 || ms[0].Kind != CutKind || ms[0].End != len(s) {
		t.Errorf("Find = %v, want the unscanned rest as one %s match", ms, CutKind)
	}
	s = "jean@example.com " + strings.Repeat("y", DetectLimit)
	ms = Find(s, AllDetectors())
	if len(ms) != 2 || ms[0] != (Match{0, 16, "email"}) || ms[1].Kind != CutKind || ms[1].End != len(s) {
		t.Errorf("Find = %v", ms)
	}
}

// gapsPreserved reports whether out is s with only the matched ranges
// changed: the text between matches appears in out, in order, with the
// same prefix and suffix.
func gapsPreserved(s, out string, ms []Match) bool {
	var gaps []string
	last := 0
	for _, m := range ms {
		gaps = append(gaps, s[last:m.Start])
		last = m.End
	}
	gaps = append(gaps, s[last:])
	if len(gaps) == 1 {
		return out == s
	}
	first, final := gaps[0], gaps[len(gaps)-1]
	if !strings.HasPrefix(out, first) || !strings.HasSuffix(out[len(first):], final) {
		return false
	}
	rest := out[len(first) : len(out)-len(final)]
	for _, g := range gaps[1 : len(gaps)-1] {
		k := strings.Index(rest, g)
		if k < 0 {
			return false
		}
		rest = rest[k+len(g):]
	}
	return true
}

// Every byte Detect changes lies inside a match of Find, and so of
// FindInViews.
func FuzzFindCoversDetect(f *testing.F) {
	for _, s := range findCorpus {
		f.Add(s)
	}
	f.Add("a***(12) 345 6789 jo\u200bhn@example.com jean%40example.com &#64;")
	ds := allDetectors(f)
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 512 {
			return
		}
		ms := Find(s, ds)
		checkMatches(t, s, ms)
		out := detectText(s, ds)
		if !gapsPreserved(s, out, ms) {
			t.Fatalf("Detect(%q) = %q changes text outside Find = %v", s, out, ms)
		}
		vs := FindInViews(s, ds)
		checkMatches(t, s, vs)
		if !gapsPreserved(s, out, vs) {
			t.Fatalf("Detect(%q) = %q changes text outside FindInViews = %v", s, out, vs)
		}
		// FindInViews covers every match of Find.
		for _, m := range ms {
			covered := false
			for _, v := range vs {
				if v.Start <= m.Start && m.End <= v.End {
					covered = true
				}
			}
			if !covered {
				t.Fatalf("FindInViews(%q) = %v misses %v", s, vs, m)
			}
		}
	})
}
