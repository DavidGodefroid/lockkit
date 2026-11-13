package pii

import (
	"slices"
	"strings"
	"testing"
)

// changeDigit returns v with its middle digit changed (a Dutch VAT
// number's last two digits are a branch number, outside the check).
func changeDigit(v string) string {
	var at []int
	for i := 0; i < len(v); i++ {
		if isDigit(v[i]) {
			at = append(at, i)
		}
	}
	i := at[len(at)/2]
	return v[:i] + string('0'+(v[i]-'0'+1)%10) + v[i+1:]
}

func euDetectors(t *testing.T, names ...string) []Detector {
	t.Helper()
	ds, err := Detectors(names)
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

func TestEUVATAndBECompany(t *testing.T) {
	ds := euDetectors(t, "eu_vat", "be_company", "card", "be_niss", "nl_bsn", "phone")
	cases := []struct {
		v, kind string
		conf    Confidence
	}{
		{"BE0123.456.749", "eu_vat", ConfidenceHigh},
		{"BE 0123456749", "eu_vat", ConfidenceHigh},
		{"BE0123456749", "eu_vat", ConfidenceHigh},
		{"be 0123 456 749", "eu_vat", ConfidenceHigh},
		{"0123.456.749", "be_company", ConfidenceHigh},
		{"0123 456 749", "be_company", ConfidenceHigh},
		{"FR40303265045", "eu_vat", ConfidenceHigh},
		{"FR 40 303 265 045", "eu_vat", ConfidenceHigh},
		{"NL004495445B01", "eu_vat", ConfidenceHigh},
		{"nl004495445b01", "eu_vat", ConfidenceHigh},
		{"DE136695976", "eu_vat", ConfidenceHigh},
		{"DE 136 695 976", "eu_vat", ConfidenceHigh},
		{"LU26375245", "eu_vat", ConfidenceHigh},
		{"LU 26375245", "eu_vat", ConfidenceHigh},
	}
	for _, c := range cases {
		for _, frame := range []string{"%s", "VAT: %s.", `{"vat":"%s"}`, "TVA %s, merci"} {
			in := strings.Replace(frame, "%s", c.v, 1)
			start := strings.Index(in, c.v)
			want := []Match{{start, start + len(c.v), c.kind, c.conf}}
			if got := Find(in, ds); !slices.Equal(got, want) {
				t.Errorf("Find(%q) = %v, want %v", in, got, want)
			}
			bad := strings.Replace(frame, "%s", changeDigit(c.v), 1)
			for _, m := range Find(bad, ds) {
				if m.Kind == c.kind {
					t.Errorf("Find(%q) = %v: an invalid checksum matched", bad, m)
				}
			}
		}
	}
}

func TestEUVATConfidenceAndNegatives(t *testing.T) {
	ds := euDetectors(t, "eu_vat", "be_company", "phone")
	// A French key with a letter: no public check, pattern only.
	if got := Find("TVA FRA0303265045", ds); len(got) != 1 || got[0].Kind != "eu_vat" || got[0].Confidence != ConfidenceMedium {
		t.Errorf("FRA0303265045: %v, want one medium eu_vat", got)
	}
	for _, in := range []string{
		"0475 12 34 56",    // a Belgian mobile stays a phone
		"0123456749",       // ten bare digits: context only
		"0123.456 749",     // mixed separators
		"BE0123.456749",    // mixed separators after the prefix
		"XBE0123456749",    // inside a word
		"BE01234567490",    // one digit too many
		"0123.456.749.12",  // a longer dotted number
		"v10123.456.749",   // inside a token
		"DE1366959761",     // ten digits
		"LU263752451",      // nine digits
		"NL004495445B012",  // three after the B
		"2123.456.749",     // a company number starts with 0 or 1
		"FR40 303265045XY", // glued to letters
	} {
		for _, m := range Find(in, ds) {
			if m.Kind != "phone" {
				t.Errorf("Find(%q) = %v, want no VAT or company number", in, m)
			}
		}
	}
	if got := Find("0475 12 34 56", ds); len(got) != 1 || got[0].Kind != "phone" {
		t.Errorf("mobile: %v, want phone", got)
	}
}

func TestNewDetectorsOptIn(t *testing.T) {
	want := []string{"email", "iban", "fr_nir", "card", "be_niss", "nl_bsn", "us_ssn", "phone"}
	var got []string
	for _, d := range AllDetectors() {
		got = append(got, d.Name())
	}
	if !slices.Equal(got, want) {
		t.Errorf("AllDetectors = %v, want %v (new detectors are opt-in)", got, want)
	}
	for _, n := range []string{"eu_vat", "be_company", "be_eid", "passport", "birth_date", "plate", "postal_address"} {
		detector(t, n)
	}
}

func TestConfidenceOnEveryMatch(t *testing.T) {
	ds, err := Detectors(detectorOrder)
	if err != nil {
		t.Fatal(err)
	}
	in := "jean@example.com BE68 5390 0754 7034 BE0123456749 0123.456.749 4111 1111 1111 1111 " +
		"85.07.30-033.28 call +32 475 12 34 56 from 8.8.8.8 password=Hunter2Hunter2x Jean Dupont at 415-555-2671"
	ms := FindInViews(in, ds)
	if len(ms) < 10 {
		t.Fatalf("FindInViews = %v, want every kind", ms)
	}
	for _, m := range ms {
		if m.Confidence == 0 {
			t.Errorf("%v: no confidence", m)
		}
		if want := detectorConfidence[m.Kind]; m.Confidence != want {
			t.Errorf("%v: confidence %v, want %v", m, m.Confidence, want)
		}
	}
	long := strings.Repeat("x ", DetectLimit/2+1)
	if ms := Find(long, ds); len(ms) != 1 || ms[0].Kind != CutKind || ms[0].Confidence != ConfidenceLow {
		t.Errorf("cut: %v", ms)
	}
}

func TestNormaliseVAT(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenEpochStore(dir+"/e", true, t0)
	if err != nil {
		t.Fatal(err)
	}
	p := s.Current()
	for _, group := range [][]string{
		{"eu_vat", "BE0123456749", "BE 0123.456.749", "be0123456749", "be 0123 456 749"},
		{"eu_vat", "FR40303265045", "FR 40 303 265 045", "fr40303265045"},
		{"be_company", "0123456749", "0123.456.749", "0123 456 749"},
	} {
		want := mustID(t, p, group[0], group[1])
		for _, v := range group[2:] {
			if n := Normalise(group[0], v); n != group[1] {
				t.Errorf("Normalise(%s, %q) = %q, want %q", group[0], v, n, group[1])
			}
			if got := mustID(t, p, group[0], v); got != want {
				t.Errorf("ID(%s, %q) = %s, want %s", group[0], v, got, want)
			}
		}
	}
}
