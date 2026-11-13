package pii

import (
	"slices"
	"strings"
	"testing"
)

func TestBEEID(t *testing.T) {
	ds := euDetectors(t, "be_eid", "card", "be_niss", "phone")
	for _, v := range []string{"591-2345678-29", "592-3456789-81", "012-3456789-39"} {
		for _, frame := range []string{"%s", "eID %s.", `{"card":"%s"}`, "carte d'identité n° %s, valide"} {
			in := strings.Replace(frame, "%s", v, 1)
			start := strings.Index(in, v)
			want := []Match{{start, start + len(v), "be_eid", ConfidenceHigh}}
			if got := Find(in, ds); !slices.Equal(got, want) {
				t.Errorf("Find(%q) = %v, want %v", in, got, want)
			}
			bad := strings.Replace(frame, "%s", changeDigit(v), 1)
			for _, m := range Find(bad, ds) {
				if m.Kind == "be_eid" {
					t.Errorf("Find(%q) = %v: an invalid checksum matched", bad, m)
				}
			}
		}
	}
	for _, in := range []string{"5912345678-29", "591-2345678-290", "A591-2345678-29", "591-2345678-29-1", "591 2345678 29"} {
		for _, m := range Find(in, ds) {
			if m.Kind == "be_eid" {
				t.Errorf("Find(%q) = %v, want no be_eid", in, m)
			}
		}
	}
}

func TestPassportContextOnly(t *testing.T) {
	ds := euDetectors(t, "passport")
	for _, in := range []string{"Passport EH123456", "N° de passeport : EH123456", "Paspoortnummer EH123456.", "Reisepass-Nr. EH123456", `{"passport_no":"EH123456"}`} {
		start := strings.Index(in, "EH123456")
		want := []Match{{start, start + 8, "passport", ConfidenceLow}}
		if got := FindInViews(in, ds); !slices.Equal(got, want) {
			t.Errorf("FindInViews(%q) = %v, want %v", in, got, want)
		}
	}
	for _, in := range []string{"EH123456", "Order EH123456 shipped", "passport EH1234567", "passport eh123456", "passport XEH123456"} {
		if got := FindInViews(in, ds); got != nil {
			t.Errorf("FindInViews(%q) = %v, want none", in, got)
		}
	}
	if got := FindField("passportNumber", "EH123456", ds); len(got) != 1 || got[0].Kind != "passport" {
		t.Errorf("FindField(passportNumber) = %v", got)
	}
}

func TestBirthDateContextOnly(t *testing.T) {
	ds := euDetectors(t, "birth_date", "phone", "card", "be_niss")
	cases := []struct{ in, v string }{
		{"Date de naissance : 12/03/1985", "12/03/1985"},
		{"né le 3 mars 1985 à Liège", "3 mars 1985"},
		{"née le 1er avril 1990", "1er avril 1990"},
		{"Geboortedatum: 12-03-1985", "12-03-1985"},
		{"geboren op 7 mei 1979", "7 mei 1979"},
		{"Date of birth: March 3, 1985", "March 3, 1985"},
		{"DOB 1985-03-12", "1985-03-12"},
		{"D.O.B.: 03/12/1985", "03/12/1985"},
		{"Geburtsdatum: 12.03.1985", "12.03.1985"},
		{"geb. 3. März 1985", "3. März 1985"},
		{`{"birth_date":"1985-03-12","city":"Gent"}`, "1985-03-12"},
	}
	for _, c := range cases {
		start := strings.Index(c.in, c.v)
		want := []Match{{start, start + len(c.v), "birth_date", ConfidenceLow}}
		if got := FindInViews(c.in, ds); !slices.Equal(got, want) {
			t.Errorf("FindInViews(%q) = %v, want %v", c.in, got, want)
		}
	}
	for _, in := range []string{
		"Delivery expected on 12/03/2026.", // a date without a birth word
		"Invoice dated 1985-03-12",
		"Born to run, the album, was first released on 12/03/1985", // too far
		"date de naissance : 32/13/1985",                           // no such day or month
		"birth 12/03/1785",                                         // out of range
		"geboren 2023-13-01",
	} {
		if got := FindInViews(in, ds); slices.ContainsFunc(got, func(m Match) bool { return m.Kind == "birth_date" }) {
			t.Errorf("FindInViews(%q) = %v, want no birth_date", in, got)
		}
	}
	for _, field := range []string{"birth_date", "dateOfBirth", "date_naissance", "geboortedatum", "dob", "Geburtsdatum"} {
		if got := FindField(field, "12/03/1985", ds); len(got) != 1 || got[0].Kind != "birth_date" {
			t.Errorf("FindField(%q) = %v, want birth_date", field, got)
		}
	}
	if got := FindField("created_at", "12/03/1985", ds); got != nil {
		t.Errorf("FindField(created_at) = %v, want none", got)
	}
}

func TestNormaliseIdentity(t *testing.T) {
	for _, c := range []struct{ kind, a, b string }{
		{"be_eid", "591-2345678-29", "591234567829"},
		{"passport", "EH123456", " EH123456 "},
		{"birth_date", "12/03/1985", "1985-03-12"},
		{"birth_date", "12.03.1985", "12 March 1985"},
		{"birth_date", "3 mars 1985", "1985-03-03"},
	} {
		if x, y := Normalise(c.kind, c.a), Normalise(c.kind, c.b); x != y {
			t.Errorf("Normalise(%s): %q → %q, %q → %q", c.kind, c.a, x, c.b, y)
		}
	}
}
