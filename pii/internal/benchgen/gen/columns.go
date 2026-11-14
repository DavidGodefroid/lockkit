package gen

import (
	"fmt"
	"math/rand/v2"
	"strings"
)

// Name columns: a table, a column whose name means "name" and a few
// sampled values, labelled person names or not. Positives are tables of
// people, or neutral tables, whose name column holds person names;
// negatives are tables of things, places and labels ("products.name",
// "roles.name", "cities.name", "tags.name") and tables of people whose
// name column holds no person names (companies, logins).

// ColumnCase is one sampled column, labelled.
type ColumnCase struct {
	ID          string   `json:"id"`
	Lang        string   `json:"lang"`
	Table       string   `json:"table"`
	Column      string   `json:"column"`
	Samples     []string `json:"samples"`
	PersonNames bool     `json:"person_names"`
}

// Sizes of the column blocks, per language.
const (
	columnPositivesPerLang = 40
	columnNegativesPerLang = 40
	columnSamplesMin       = 3
	columnSamplesMax       = 8
)

var nameColumns = map[string][]string{
	"en": {"name", "full_name", "fullName", "customer_name", "display_name", "contact_name"},
	"fr": {"nom", "nom_complet", "name", "nom_client", "full_name"},
	"nl": {"naam", "volledige_naam", "name", "klant_naam", "naam_klant"},
	"de": {"name", "vollstaendiger_name", "kunde_name", "full_name"},
}

var personTablesByLang = map[string][]string{
	"en": {"customers", "users", "employees", "contacts", "clients", "public.customers", "crm.contacts"},
	"fr": {"clients", "utilisateurs", "employes", "contacts", "personnes", "membres"},
	"nl": {"klanten", "gebruikers", "medewerkers", "contacten", "leden", "personen"},
	"de": {"kunden", "benutzer", "mitarbeiter", "kontakte", "mitglieder"},
}

var neutralTablesByLang = map[string][]string{
	"en": {"orders", "invoices", "bookings", "registrations"},
	"fr": {"commandes", "factures", "reservations", "inscriptions"},
	"nl": {"bestellingen", "facturen", "reservaties", "inschrijvingen"},
	"de": {"bestellungen", "rechnungen", "buchungen", "anmeldungen"},
}

// thingColumns are tables of things with the values of their name
// column.
var thingColumns = map[string][]struct {
	table  string
	values []string
}{
	"en": {
		{"products", []string{"Laptop Pro 14", "USB-C Hub", "Wireless Mouse", "Standing Desk", "Office Chair", "Monitor 27 inch", "Paper A4"}},
		{"roles", []string{"admin", "editor", "viewer", "owner", "billing", "support"}},
		{"cities", []string{"London", "Manchester", "Leeds", "Bristol", "Namur", "Liège"}},
		{"tags", []string{"urgent", "billing", "later", "follow-up", "vip", "spam"}},
		{"categories", []string{"Fiction", "Comics", "Children", "Travel", "Cooking", "History"}},
		{"companies", []string{"Acme Ltd", "Globex Corporation", "Initech", "Umbrella plc", "Stark Industries"}},
	},
	"fr": {
		{"produits", []string{"Ordinateur portable 14", "Clé USB 32 Go", "Souris sans fil", "Bureau assis-debout", "Chaise de bureau"}},
		{"roles", []string{"admin", "éditeur", "lecteur", "propriétaire", "comptabilité"}},
		{"villes", []string{"Namur", "Liège", "Bruxelles", "Charleroi", "Mons", "Arlon"}},
		{"tags", []string{"urgent", "facturation", "plus tard", "relance", "important"}},
		{"categories", []string{"Romans", "Bandes dessinées", "Jeunesse", "Voyage", "Cuisine", "Histoire"}},
		{"societes", []string{"Acme SA", "Durand et Fils SPRL", "Boulangerie du Centre", "Garage Moderne SRL"}},
	},
	"nl": {
		{"producten", []string{"Laptop Pro 14", "USB-stick 32 GB", "Draadloze muis", "Zit-sta bureau", "Bureaustoel"}},
		{"rollen", []string{"beheerder", "redacteur", "lezer", "eigenaar", "boekhouding"}},
		{"steden", []string{"Gent", "Antwerpen", "Brugge", "Leuven", "Hasselt", "Mechelen"}},
		{"tags", []string{"dringend", "facturatie", "later", "opvolgen", "belangrijk"}},
		{"categorieen", []string{"Romans", "Strips", "Jeugd", "Reizen", "Koken", "Geschiedenis"}},
		{"bedrijven", []string{"Acme NV", "Bakkerij De Molen BV", "Garage Centrum", "Drukkerij Vanhove"}},
	},
	"de": {
		{"produkte", []string{"Laptop Pro 14", "USB-Stick 32 GB", "Kabellose Maus", "Stehschreibtisch", "Bürostuhl"}},
		{"rollen", []string{"admin", "redakteur", "leser", "eigentümer", "buchhaltung"}},
		{"staedte", []string{"Berlin", "Hamburg", "München", "Köln", "Aachen", "Eupen"}},
		{"tags", []string{"dringend", "rechnung", "später", "nachfassen", "wichtig"}},
		{"kategorien", []string{"Romane", "Comics", "Kinderbuch", "Reisen", "Kochen", "Geschichte"}},
		{"firmen", []string{"Acme GmbH", "Bäckerei Müller KG", "Autohaus Zentrum", "Druckerei Weber AG"}},
	},
}

// nonNames are name column values of a table of people that are no
// person's name: companies, logins, placeholders.
var nonNames = map[string][]string{
	"en": {"Acme Ltd", "Globex Corporation", "admin", "jdoe42", "n/a", "unknown", "test account", "Support Team"},
	"fr": {"Acme SA", "Garage Moderne SRL", "admin", "jdupont", "n/a", "inconnu", "compte test", "Service client"},
	"nl": {"Acme NV", "Bakkerij De Molen BV", "admin", "jjanssens", "n.v.t.", "onbekend", "testaccount", "Klantendienst"},
	"de": {"Acme GmbH", "Bäckerei Müller KG", "admin", "hmueller", "k. A.", "unbekannt", "Testkonto", "Kundendienst"},
}

// Columns returns the column cases of every language.
func Columns() []ColumnCase {
	var out []ColumnCase
	for _, lang := range Langs {
		r := rng(lang + "/columns")
		for i := range columnPositivesPerLang {
			out = append(out, columnPositive(r, lang, fmt.Sprintf("c-%s-pos-%04d", lang, i+1)))
		}
		for i := range columnNegativesPerLang {
			out = append(out, columnNegative(r, lang, fmt.Sprintf("c-%s-neg-%04d", lang, i+1)))
		}
	}
	return out
}

func sampleCount(r *rand.Rand) int {
	return columnSamplesMin + r.IntN(columnSamplesMax-columnSamplesMin+1)
}

// columnPositive is a name column of person names: in a table of people,
// a few values may be blank or no person's name; in a neutral table, all
// of them are names.
func columnPositive(r *rand.Rand, lang, id string) ColumnCase {
	people := r.IntN(4) != 0
	table := pick(r, neutralTablesByLang[lang])
	if people {
		table = pick(r, personTablesByLang[lang])
	}
	n := sampleCount(r)
	samples := make([]string, n)
	for i := range samples {
		switch {
		case people && i > 0 && r.IntN(6) == 0:
			samples[i] = pick(r, append(nonNames[lang], ""))
		case r.IntN(2) == 0:
			samples[i] = knownName(r, lang)
		default:
			v, _ := personName(r, lang)
			samples[i] = strings.Replace(v, unspanned, "", 1) // "Mme Dubois": a whole value
		}
	}
	return ColumnCase{ID: id, Lang: lang, Table: table, Column: pick(r, nameColumns[lang]), Samples: samples, PersonNames: true}
}

// columnNegative is a name column of a table of things, or of a table of
// people holding no person's name.
func columnNegative(r *rand.Rand, lang, id string) ColumnCase {
	n := sampleCount(r)
	samples := make([]string, n)
	if r.IntN(5) == 0 {
		for i := range samples {
			samples[i] = pick(r, nonNames[lang])
		}
		return ColumnCase{ID: id, Lang: lang, Table: pick(r, personTablesByLang[lang]), Column: pick(r, nameColumns[lang]),
			Samples: samples}
	}
	t := thingColumns[lang][r.IntN(len(thingColumns[lang]))]
	for i := range samples {
		samples[i] = pick(r, t.values)
	}
	column := pick(r, []string{"name", "name", nameColumns[lang][0], "label_name"})
	return ColumnCase{ID: id, Lang: lang, Table: t.table, Column: column, Samples: samples}
}
