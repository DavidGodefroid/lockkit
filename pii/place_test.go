package pii

import (
	"slices"
	"strings"
	"testing"
)

func TestPlates(t *testing.T) {
	ds := euDetectors(t, "plate", "phone", "card")
	for _, v := range []string{
		"1-ABC-123", "ABC-123", // BE
		"AB-123-CD",                                                                                    // FR
		"XX-99-XX", "XX-XX-99", "99-XX-XX", "99-XXX-9", "9-XXX-99", "XX-999-X", "X-999-XX", "XXX-99-X", // NL 4-11
	} {
		v = strings.NewReplacer("X", "K", "9", "7").Replace(v)
		for _, frame := range []string{"%s", "Plaque %s.", "kenteken %s, wit", `{"plate":"%s"}`} {
			in := strings.Replace(frame, "%s", v, 1)
			start := strings.Index(in, v)
			want := []Match{{start, start + len(v), "plate", ConfidenceMedium}}
			if got := Find(in, ds); !slices.Equal(got, want) {
				t.Errorf("Find(%q) = %v, want %v", in, got, want)
			}
		}
	}
	for _, in := range []string{
		"Order AB-123-CD-45 shipped", // a longer reference
		"SKU-1234-XS",                // four digits
		"INV-123 paid",               // a known prefix
		"CVE-123",                    // ditto
		"see v2/AB-12-CD",            // glued
		"ab-123-cd",                  // lower case
		"AB123CD",                    // no dashes
		"1-ABC-1234",                 // too long
		"XAB-123-CD",                 // glued letter
	} {
		if got := Find(in, ds); slices.ContainsFunc(got, func(m Match) bool { return m.Kind == "plate" }) {
			t.Errorf("Find(%q) = %v, want no plate", in, got)
		}
	}
}

func TestPostalAddresses(t *testing.T) {
	ds := euDetectors(t, "postal_address", "phone", "person_name", "plate")
	for _, c := range []struct{ in, v string }{
		{"Siège : Rue de la Loi 16, 1000 Bruxelles.", "Rue de la Loi 16, 1000 Bruxelles"},
		{"Avenue Louise 54 bte 3, 1050 Ixelles", "Avenue Louise 54 bte 3, 1050 Ixelles"},
		{"livrer au 12 rue de la Paix, 75002 Paris", "12 rue de la Paix, 75002 Paris"},
		{"15 bis, boulevard Haussmann 75009 Paris", "15 bis, boulevard Haussmann 75009 Paris"},
		{"Chaussée de Waterloo 1200 - 1180 Uccle", "Chaussée de Waterloo 1200 - 1180 Uccle"},
		{"Adres: Kerkstraat 12, 9000 Gent", "Kerkstraat 12, 9000 Gent"},
		{"Hoofdweg 3a, 1234 AB Amsterdam", "Hoofdweg 3a, 1234 AB Amsterdam"},
		{"Grote Markt 7 in het centrum", "Grote Markt 7"},
		{"Grote Steenweg 88, 2600 Berchem", "Grote Steenweg 88, 2600 Berchem"},
		{"Ship to 221B Baker Street, today", "221B Baker Street"},
		{"Office: 10 Downing Street", "10 Downing Street"},
		{`{"address":"Place Flagey 18, 1050 Ixelles"}`, "Place Flagey 18, 1050 Ixelles"},
	} {
		start := strings.Index(c.in, c.v)
		want := []Match{{start, start + len(c.v), "postal_address", ConfidenceMedium}}
		if got := Find(c.in, ds); !slices.Equal(got, want) {
			t.Errorf("Find(%q) = %v, want %v", c.in, got, want)
		}
	}
	for _, in := range []string{
		"La rue est fermée jusqu'à lundi.",           // rue in prose, no number
		"rue de la Paix",                             // no number
		"The meeting will take place in 12 minutes.", // place in prose
		"Dat ligt in de weg 3 keer per dag.",         // no capitalised name
		"Rue du Commerce en ligne",                   // no number
		"Kerkstraat",                                 // no number
		"We sold 2 Road bikes",                       // a type without a name
	} {
		if got := Find(in, ds); slices.ContainsFunc(got, func(m Match) bool { return m.Kind == "postal_address" }) {
			t.Errorf("Find(%q) = %v, want no address", in, got)
		}
	}
}

func TestGapFixes(t *testing.T) {
	// A NIR whose digits also pass Luhn is a NIR, not a card.
	ds := euDetectors(t, "fr_nir", "card")
	for _, v := range []string{"1 85 05 78 006 223 49", "185057800622349"} {
		if got := Find("NIR "+v, ds); len(got) != 1 || got[0].Kind != "fr_nir" {
			t.Errorf("Find(NIR %s) = %v, want fr_nir", v, got)
		}
	}
	// German mobiles have 12 digits.
	phone := euDetectors(t, "phone")
	for _, v := range []string{"0151 23456789", "0171 23456789", "015123456789"} {
		if got := Find("Handy "+v, phone); len(got) != 1 || got[0].End-got[0].Start != len(v) {
			t.Errorf("Find(Handy %s) = %v", v, got)
		}
	}
	for _, v := range []string{"0123 45678901", "0301 23456789"} {
		if got := Find("ref "+v, phone); got != nil {
			t.Errorf("Find(ref %s) = %v, want none (12 digits, not a German mobile)", v, got)
		}
	}
	// An apostrophe inside an e-mail local part; quotes around it stay out.
	email := euDetectors(t, "email")
	for _, c := range []struct{ in, v string }{
		{"to renée.o'hara@example.com now", "renée.o'hara@example.com"},
		{"WHERE email = 'john@example.com'", "john@example.com"},
		{"d’arcy.o’neil@example.org", "d’arcy.o’neil@example.org"},
	} {
		start := strings.Index(c.in, c.v)
		want := []Match{{start, start + len(c.v), "email", ConfidenceMedium}}
		if got := Find(c.in, email); !slices.Equal(got, want) {
			t.Errorf("Find(%q) = %v, want %v", c.in, got, want)
		}
	}
}

func TestNormalisePlaceKinds(t *testing.T) {
	for _, c := range []struct{ kind, a, b string }{
		{"plate", "1-ABC-123", "1abc123"},
		{"postal_address", "Rue de la Loi 16, 1000 Bruxelles", "rue de la loi 16 1000  bruxelles"},
	} {
		if x, y := Normalise(c.kind, c.a), Normalise(c.kind, c.b); x != y {
			t.Errorf("Normalise(%s): %q → %q, %q → %q", c.kind, c.a, x, c.b, y)
		}
	}
}
