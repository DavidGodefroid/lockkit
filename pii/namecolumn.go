package pii

import (
	"strings"
)

// --- person-name columns
//
// A column called "name" holds a person's name in "customers" and a
// product's in "products": the column name alone never decides. The
// sampled values do, and the table name moves the bar.

// personTables are table name tokens of rows that are people: their
// "name" column is likely a person's.
var personTables = set(
	"customer", "user", "employee", "contact", "client", "person", "people", "member", "patient",
	"student", "subscriber", "author", "owner", "staff", "guest", "recipient", "beneficiary", "debtor",
	"profile", "applicant", "candidate", "teacher", "tenant", "visitor", "volunteer",
	"klant", "gebruiker", "medewerker", "werknemer", "persoon", "lid", "leerling",
	"utilisateur", "employe", "personne", "membre", "eleve", "abonne", "locataire",
	"kunde", "benutzer", "mitarbeiter", "mitglied", "cliente", "usuario", "empleado",
)

// thingTables are table name tokens of rows that are things, places or
// labels: their "name" column is likely not a person's.
var thingTables = set(
	"product", "item", "article", "sku", "role", "permission", "group", "category", "tag", "label",
	"city", "country", "region", "province", "town", "place", "location", "street", "brand",
	"company", "organisation", "organization", "department", "team", "project", "file", "document",
	"template", "setting", "plan", "status", "type", "service", "feature", "module", "page", "menu",
	"produit", "categorie", "ville", "pays", "rue", "societe", "entreprise", "fichier",
	"stad", "gemeente", "land", "straat", "bedrijf", "bestand", "groep",
	"produkt", "kategorie", "stadt", "staedte", "städte", "firma", "producto", "ciudad",
)

// Shares of the sampled values that must be person names, by table hint.
const (
	nameShareDefault = 0.5
	nameSharePerson  = 0.3
	nameShareThing   = 0.8
)

// LooksPersonNameColumn reports a column that holds person names: its
// name means "name" ("name", "full_name", "nom", "naam", "customer_name",
// "display_name") and a significant share of its sampled values are
// person names as person_name finds them, each value one name ("Alice
// Dupont", "Chloé Lambert"). The column name alone is never enough. The
// table name moves the share: half the values in general, 30 % in a table
// of people ("customers", "users", "employees", "contacts", "clients"),
// 80 % in a table of things ("products", "roles", "categories", "tags",
// "cities"). Empty and blank samples do not count; a table of people
// needs one name, any other table two.
//
// A column that LooksPersonalColumn already reports needs no samples.
func LooksPersonNameColumn(table, column string, samples []string) bool {
	if !nameColumn(column) {
		return false
	}
	share, min := nameShareDefault, 2
	switch tableHint(table) {
	case +1:
		share, min = nameSharePerson, 1
	case -1:
		share = nameShareThing
	}
	n, names := 0, 0
	for _, s := range samples {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		n++
		if wholePersonName(s) {
			names++
		}
	}
	return names >= min && float64(names) >= share*float64(n)
}

// nameColumn reports a column name that means "name", alone or with any
// other token ("name", "full_name", "product_name", "nom_client",
// "fullname").
func nameColumn(column string) bool {
	toks := Tokens(column)
	if len(toks) == 0 || neutralLast[toks[len(toks)-1]] && len(toks) > 1 {
		return false // "name_id", "name_length"
	}
	for _, t := range toks {
		if nameWords[t] || t == "names" || t == "noms" || t == "namen" {
			return true
		}
	}
	return len(toks) == 1 && (strings.HasSuffix(toks[0], "name") || strings.HasSuffix(toks[0], "naam"))
}

// tableHint is +1 for a table of people, -1 for a table of things, 0
// otherwise, from the last token of its name, plural or not.
func tableHint(table string) int {
	if i := strings.LastIndexByte(table, '.'); i >= 0 {
		table = table[i+1:] // "public.customers"
	}
	toks := Tokens(table)
	if len(toks) == 0 {
		return 0
	}
	t := toks[len(toks)-1]
	for _, f := range singulars(t) {
		switch {
		case personTables[f]:
			return +1
		case thingTables[f]:
			return -1
		}
	}
	return 0
}

// singulars are a token and its singular candidates in en/fr/nl/de/es
// ("customers", "cities", "klanten", "leden", "mitglieder").
func singulars(t string) []string {
	out := []string{t}
	for _, suf := range []struct{ plural, single string }{
		{"ies", "y"}, {"es", ""}, {"s", ""}, {"x", ""}, {"en", ""}, {"eden", "id"}, {"ten", "t"}, {"n", ""}, {"er", ""},
	} {
		if strings.HasSuffix(t, suf.plural) && len(t) > len(suf.plural) {
			out = append(out, strings.TrimSuffix(t, suf.plural)+suf.single)
		}
	}
	return out
}

// wholePersonName reports a value that is one person's name, nothing
// more: person_name finds a name covering it from its first letter to
// its last, a leading title aside.
func wholePersonName(s string) bool {
	if len(s) > 120 {
		return false
	}
	spans := findPersonNames(s)
	if len(spans) != 1 {
		return false
	}
	ws := words(s)
	if len(ws) == 0 {
		return false
	}
	first := ws[0]
	if spans[0].start != first.start && len(ws) > 1 && honorifics[first.key] {
		first = ws[1] // "Dr. Alice Dupont": person_name leaves the title out
	}
	return spans[0].start == first.start && spans[0].end == ws[len(ws)-1].end &&
		strings.TrimSpace(s[:ws[0].start]) == "" && strings.TrimSpace(s[ws[len(ws)-1].end:]) == ""
}
