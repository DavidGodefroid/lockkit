package pii

import (
	"slices"
	"strings"
	"testing"
)

func TestContextRaisesWeakCandidates(t *testing.T) {
	phone := euDetectors(t, "phone")
	cases := []struct {
		ds      []Detector
		in, v   string
		kind    string
		without bool // found without the context word too
	}{
		{phone, "tel 612 345 678", "612 345 678", "phone", false},
		{phone, "Tél. : 475 12 34 56", "475 12 34 56", "phone", false},
		{phone, "Telefoonnummer: 20 123 4567", "20 123 4567", "phone", false},
		{phone, "Handy 151 23456789", "151 23456789", "phone", false},
		{euDetectors(t, "be_niss"), "NISS 85-07-30-033-28", "85-07-30-033-28", "be_niss", false},
		{euDetectors(t, "be_niss"), "Rijksregisternummer 850730/033.28", "850730/033.28", "be_niss", false},
		{euDetectors(t, "be_company"), "KBO 0123456749", "0123456749", "be_company", false},
		{euDetectors(t, "be_company"), "n° d'entreprise : 0123456749.", "0123456749", "be_company", false},
		{euDetectors(t, "be_company"), `{"company_number":"0123456749"}`, "0123456749", "be_company", false},
	}
	for _, c := range cases {
		start := strings.Index(c.in, c.v)
		want := []Match{{start, start + len(c.v), c.kind, ConfidenceLow}}
		if got := FindInViews(c.in, c.ds); !slices.Equal(got, want) {
			t.Errorf("FindInViews(%q) = %v, want %v", c.in, got, want)
		}
		if got := FindInViews(c.v, c.ds); got != nil {
			t.Errorf("FindInViews(%q) = %v, want none without a context", c.v, got)
		}
	}
	for _, in := range []string{
		"hotel 612 345 678", // "tel" inside a word
		"tel\n612 345 678",  // not on the same line
		"tel: see the attached list further below, item 612 345 678", // too far
		"KBO 0123456748",       // wrong check
		"NISS 85-07-30-033-29", // wrong check
	} {
		ds := euDetectors(t, "phone", "be_niss", "be_company")
		if strings.HasPrefix(in, "KBO") {
			ds = euDetectors(t, "be_company") // ten digits with a trunk 0: a phone
		}
		if got := FindInViews(in, ds); got != nil {
			t.Errorf("FindInViews(%q) = %v, want none", in, got)
		}
	}
	// With phone_loose enabled, the loose number is its match.
	if got := FindInViews("tel 612 345 678", euDetectors(t, "phone", "phone_loose")); len(got) != 1 || got[0].Kind != "phone_loose" {
		t.Errorf("phone+phone_loose: %v", got)
	}
	// A context word does not lower a verified match.
	if got := FindInViews("NISS 85.07.30-033.28", euDetectors(t, "be_niss")); len(got) != 1 || got[0].Confidence != ConfidenceHigh {
		t.Errorf("verified NISS after a context word: %v", got)
	}
}

func TestFindField(t *testing.T) {
	ds := euDetectors(t, "email", "phone", "be_niss", "be_company")
	for _, c := range []struct{ field, v, kind string }{
		{"phone", "612 345 678", "phone"},
		{"mobileNumber", "612 345 678", "phone"},
		{"telefoonnummer", "475 12 34 56", "phone"},
		{"kbo_nr", "0123456749", "be_company"},
		{"CompanyNumber", "0123456749", "be_company"},
		{"rijksregisternummer", "85-07-30-033-28", "be_niss"},
	} {
		want := []Match{{0, len(c.v), c.kind, ConfidenceLow}}
		if got := FindField(c.field, c.v, ds); !slices.Equal(got, want) {
			t.Errorf("FindField(%q, %q) = %v, want %v", c.field, c.v, got, want)
		}
	}
	for _, field := range []string{"", "order_id", "hotel", "amount"} {
		if got := FindField(field, "612 345 678", ds); got != nil {
			t.Errorf("FindField(%q) = %v, want none", field, got)
		}
	}
	if got := FindField("phone", "mail jean@example.com", ds); len(got) != 1 || got[0].Kind != "email" {
		t.Errorf("FindField keeps the other matches: %v", got)
	}
}

// Context is additive: over the bench corpus, every match found without a
// context word is covered by one of the same kind with the context words
// of every kind before the text, or with a field name announcing them.
func TestContextOnlyAdds(t *testing.T) {
	var names []string
	for _, n := range detectorOrder {
		if n != "phone_loose" { // so that phone raises
			names = append(names, n)
		}
	}
	ds := euDetectors(t, names...)
	prefix := "tel rijksregister kbo: "
	for _, c := range benchTexts(t) {
		plain := FindInViews(c.Text, ds)
		withText := FindInViews(prefix+c.Text, ds)
		withField := FindField("phone_niss_kbo", c.Text, ds)
		for _, m := range plain {
			if m.Kind == CutKind {
				continue
			}
			shifted := Match{m.Start + len(prefix), m.End + len(prefix), m.Kind, m.Confidence}
			if !covers(withText, shifted) {
				t.Errorf("%s: %v lost with a context word before the text: %v", c.ID, m, withText)
			}
			if !covers(withField, m) {
				t.Errorf("%s: %v lost with a field name: %v", c.ID, m, withField)
			}
		}
	}
}

func covers(ms []Match, m Match) bool {
	return slices.ContainsFunc(ms, func(x Match) bool { return x.Start <= m.Start && x.End >= m.End })
}
