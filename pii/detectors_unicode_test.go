package pii

import (
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

const (
	nbsp  = " "
	nnbsp = " "
	thin  = " "
)

// locksql#17: Unicode addresses, typographic spaces, full-width digits and
// national phone numbers without a trunk 0.
func TestDetectorMasksIssue17(t *testing.T) {
	cases := []struct {
		det, in  string
		masked   []string
		kept     []string
		contains string
	}{
		{det: "email", in: "josé@example.com", masked: []string{"osé", "example"}, contains: "j***(16)"},
		{det: "email", in: "müller.hans@exämple.de", masked: []string{"üller", "hans", "exämple"}, contains: "m***(22)"},
		{det: "email", in: "to josé.dupont@example.com.", masked: []string{"josé", "dupont"}, kept: []string{"to ", "."}, contains: "to j***(23)."},
		{det: "email", in: "a@xn--exmple-cua.com b@例え.jp", masked: []string{"a@xn", "b@例え"}},
		{det: "email", in: "a@déja.fr", masked: []string{"ja.fr"}, contains: "a***(10)"}, // decomposed é in the domain
		{det: "phone", in: "call +32" + nbsp + "475" + nbsp + "12" + nbsp + "34" + nbsp + "56 now", masked: []string{"475", "34"}, kept: []string{"call ", " now"}, contains: "call +***(16) now"},
		{det: "phone", in: "0475" + nnbsp + "12" + nnbsp + "34" + nnbsp + "56", masked: []string{"0475", "34"}, contains: "0***(13)"},
		{det: "phone", in: "0475" + thin + "12" + thin + "34" + thin + "56", masked: []string{"0475", "34"}},
		{det: "phone", in: "(02) 123 45 67", masked: []string{"(02", "123 45"}, contains: "(***(14)"},
		{det: "card", in: "4111" + nbsp + "1111" + nbsp + "1111" + nbsp + "1111.", masked: []string{"4111", "1111"}, contains: "4***(19)."},
		{det: "iban", in: "BE68" + nbsp + "5390" + nbsp + "0754" + nbsp + "7034 ok", masked: []string{"5390", "7034"}, kept: []string{" ok"}, contains: "B***(19) ok"},
		{det: "iban", in: "BE68" + nnbsp + "5390" + nnbsp + "0754" + nnbsp + "7034", masked: []string{"5390"}},
		{det: "card", in: "４１１１ １１１１ １１１１ １１１１", masked: []string{"４１１１"}, contains: "４***(19)"},
		{det: "phone", in: "０４７５１２３４５６", masked: []string{"０４７５"}},
		{det: "be_niss", in: "85" + nbsp + "07" + nbsp + "30" + nbsp + "033" + nbsp + "28", masked: []string{"033"}},
		// Negatives: prose and short numbers stay.
		{det: "phone", in: "page" + nbsp + "12, 1.5 kg, 2026-01-02, 12" + nbsp + "€", kept: []string{"page" + nbsp + "12", "1.5", "2026-01-02", "12" + nbsp + "€"}},
		{det: "card", in: "total 1" + nbsp + "234" + nbsp + "567 €", kept: []string{"1" + nbsp + "234" + nbsp + "567"}},
		{det: "email", in: "écrire à josé ou @home.fr", kept: []string{"écrire à josé ou @home.fr"}},
		// The default phone detector does not change.
		{det: "phone", in: "(415) 555-2671 / 612 345 678 / 347 1234567", kept: []string{"555-2671", "612 345 678", "347 1234567"}},
		{det: "phone_loose", in: "(415) 555-2671", masked: []string{"415", "555", "2671"}, contains: "(***(14)"},
		{det: "phone_loose", in: "tel 415-555-2671.", masked: []string{"555"}, kept: []string{"tel ", "."}},
		{det: "phone_loose", in: "612 345 678", masked: []string{"345"}},
		{det: "phone_loose", in: "612" + nbsp + "345" + nbsp + "678", masked: []string{"345"}},
		{det: "phone_loose", in: "347 1234567", masked: []string{"1234567"}},
		{det: "phone_loose", in: "+32 475 12 34 56 et 0475 12 34 56", masked: []string{"475 12", "0475"}},
		// phone_loose negatives: ids, amounts, dates, versions, decimals.
		{det: "phone_loose", in: "id 4155552671, 123.456.789 €, 1 234 567 890, 2026-01-02 10:30, v1.2.3, 1.5, 10.0.0.1, 12 345", kept: []string{"4155552671", "123.456.789", "1 234 567 890", "2026-01-02", "1.5", "10.0.0.1", "12 345"}},
		{det: "phone_loose", in: "2026/01/02 1234, 2026.01.02 12:30, 1 612 345 678", kept: []string{"2026/01/02 1234", "2026.01.02", "1 612 345 678"}},
	}
	for _, c := range cases {
		got := detector(t, c.det).Mask(c.in)
		for _, m := range c.masked {
			if strings.Contains(got, m) {
				t.Errorf("%s.Mask(%q) = %q, still contains %q", c.det, c.in, got, m)
			}
		}
		for _, k := range c.kept {
			if !strings.Contains(got, k) {
				t.Errorf("%s.Mask(%q) = %q, lost %q", c.det, c.in, got, k)
			}
		}
		if c.contains != "" && !strings.Contains(got, c.contains) {
			t.Errorf("%s.Mask(%q) = %q, want it to contain %q", c.det, c.in, got, c.contains)
		}
	}
}

func TestFoldOffsets(t *testing.T) {
	in := "é" + nbsp + "1" + nnbsp + "２x"
	got, offs := fold(in)
	if got != "é 1 2x" {
		t.Fatalf("fold = %q", got)
	}
	want := []int{0, 1, 2, 4, 5, 8, 11, 12}
	if len(offs) != len(want) {
		t.Fatalf("offs = %v", offs)
	}
	for i := range want {
		if offs[i] != want[i] {
			t.Fatalf("offs = %v, want %v", offs, want)
		}
	}
	if s, o := fold("plain café"); s != "plain café" || o != nil {
		t.Errorf("fold without foldable runes = %q, %v", s, o)
	}
}

var defaultDetectors = []string{"email", "phone", "iban", "card"}

func TestDetectFloats(t *testing.T) {
	ds, err := Detectors(defaultDetectors)
	if err != nil {
		t.Fatal(err)
	}
	if got := Detect(float64(4111111111111111), ds); got != "4***(16)" {
		t.Errorf("Detect(float64 card) = %#v", got)
	}
	// An integral float goes the way the same integer goes.
	for _, n := range []int64{4111111111111111, 32475123456, 475123456, 42, -4111111111111111} {
		want := Detect(n, ds)
		if _, unchanged := want.(int64); unchanged {
			want = float64(n)
		}
		if got := Detect(float64(n), ds); got != want {
			t.Errorf("Detect(float64(%d)) = %#v, want %#v", n, got, want)
		}
	}
	nds, _ := Detectors([]string{"be_niss"})
	if got := Detect(float64(85073003328), nds); got != "8***(11)" {
		t.Errorf("Detect(float64 NISS) = %#v", got)
	}
	if got := Detect(float32(16777216), ds); got != float32(16777216) {
		t.Errorf("float32 changed: %#v", got)
	}
	// Non-integral or out-of-range floats pass, with their type.
	for _, f := range []float64{1.5, 4111111111111111.5e-1, 1e20, -1e19} {
		if got := Detect(f, ds); got != f {
			t.Errorf("Detect(%v) = %#v", f, got)
		}
	}
}

func TestCutAtUnicodeValue(t *testing.T) {
	// A cut inside a Unicode address or a NBSP-grouped number drops it whole.
	for _, v := range []string{"josé.dupont@exämple.de", "4111" + nbsp + "1111" + nbsp + "1111" + nbsp + "1111"} {
		s := strings.Repeat("x", 100) + "\n" + v
		for n := 102; n < len(s); n++ {
			got := CutAt(s, n)
			if len(got) > n+len(CutMark) || !strings.HasSuffix(got, "\n"+CutMark) {
				t.Errorf("CutAt(%q, %d) = %q", v, n, got)
			}
		}
	}
}

// Pathological inputs stay linear: each detector over DetectLimit bytes of
// worst-case text finishes well within a time bound.
func TestDetectorsPathologicalInputs(t *testing.T) {
	all := append([]string{}, detectorOrder...)
	ds, err := Detectors(all)
	if err != nil {
		t.Fatal(err)
	}
	inputs := map[string]string{
		"nbsp digits":  strings.Repeat("1"+nbsp, DetectLimit/3),
		"nnbsp digits": strings.Repeat("12"+nnbsp, DetectLimit/5),
		"full-width":   strings.Repeat("１", DetectLimit/3),
		"paren groups": strings.Repeat("(12) ", DetectLimit/5),
		"dash groups":  strings.Repeat("123-", DetectLimit/4),
		"unicode at":   strings.Repeat("é@", DetectLimit/3),
		"unicode dots": strings.Repeat("é.", DetectLimit/3) + "@x",
		"domain dots":  "a@" + strings.Repeat("é.", DetectLimit/3),
		"marks":        "a" + strings.Repeat("́", DetectLimit/2) + "@b.fr",
		"iban-like":    strings.Repeat("BE68"+nbsp, DetectLimit/7),
	}
	for name, in := range inputs {
		start := time.Now()
		Detect(in+" bob@example.org", ds)
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%s: %v over %d bytes", name, d, len(in))
		}
	}
}

// Folding never hides a value the unfolded text shows.
func TestFoldOnlyMasksMore(t *testing.T) {
	for det, in := range map[string]string{
		"phone": "１0475123456",
		"card":  "２4111111111111111",
		"iban":  "BE68539007547034１",
	} {
		got := detector(t, det).Mask(in)
		if strings.Contains(got, "0475123456") || strings.Contains(got, "4111111111111111") || strings.Contains(got, "539007547034") {
			t.Errorf("%s.Mask(%q) = %q", det, in, got)
		}
	}
	if got := mergeSpans([]span{{5, 9}, {0, 3}, {2, 6}, {10, 12}}); len(got) != 2 || got[0] != (span{0, 9}) || got[1] != (span{10, 12}) {
		t.Errorf("mergeSpans = %v", got)
	}
}

// legacyEmailRe is the e-mail pattern before locksql#17; the new one
// masks at least what it masked.
var legacyEmailRe = regexp.MustCompile(`[\p{L}\p{M}\p{N}._%+\-]+@[\p{L}0-9\-]+(?:\.[\p{L}0-9\-]+)*\.\p{L}{2,}`)

func FuzzEmailMasksAtLeastLegacy(f *testing.F) {
	for _, s := range []string{"josé.dupont@exämple.de", "a@b.com-c@d.org", "x é@é.fr a@déja.fr", "a@b.c1@d.ee"} {
		f.Add(s)
	}
	d, _ := Detectors([]string{"email"})
	f.Fuzz(func(t *testing.T, s string) {
		if !utf8.ValidString(s) || len(s) > 256 {
			return
		}
		got := d[0].Mask(s)
		last := -1
		for _, sp := range scan(s, legacyEmailRe, 0, func(s string, start, end int) (int, bool) {
			r, _ := utf8.DecodeLastRuneInString(s[:start])
			if start > 0 && start != last && emailLocalRune(r) {
				return 0, false
			}
			last = end
			return end, true
		}) {
			if v := s[sp.start:sp.end]; len(v) > 8 && strings.Contains(got, v) {
				t.Errorf("Mask(%q) = %q keeps %q", s, got, v)
			}
		}
	})
}
