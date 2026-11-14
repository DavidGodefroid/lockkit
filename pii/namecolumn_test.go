package pii

import "testing"

// Synthetic names only: common given and family names, no real person.

func TestLooksPersonNameColumn(t *testing.T) {
	en := []string{"John Smith", "Sarah Johnson", "Emily Taylor", "Michael Brown"}
	fr := []string{"Alice Dupont", "Bob Martin", "Chloé Lambert", "Hélène Dubois"}
	nl := []string{"Jan Janssens", "Sanne de Vries", "Emma Wouters", "Zoë Peeters"}
	for _, c := range []struct {
		table, column string
		samples       []string
	}{
		// lockkit#163's fixture
		{"public.customers", "name", []string{"Alice Dupont", "Bob Martin", "Chloé Lambert"}},
		{"customers", "name", en},
		{"users", "full_name", fr},
		{"klanten", "naam", nl},
		{"clients", "nom", fr},
		{"contacts", "displayName", en},
		{"employees", "name", append([]string{"", "  "}, nl...)},
		{"leden", "naam", nl},
		// a neutral table needs half the values
		{"orders", "customer_name", []string{"Alice Dupont", "Jan Janssens", "n/a", "unknown"}},
		{"invoices", "name", fr},
		// a table of people needs one name in three
		{"customers", "name", []string{"Alice Dupont", "ACME SA", "Foo BV"}},
		// a leading title
		{"patients", "name", []string{"Dr. Alice Dupont", "Mme Hélène Dubois"}},
	} {
		if !LooksPersonNameColumn(c.table, c.column, c.samples) {
			t.Errorf("%s.%s %q: not a person-name column", c.table, c.column, c.samples)
		}
	}
	for _, c := range []struct {
		table, column string
		samples       []string
	}{
		{"products", "name", []string{"Laptop Pro 14", "USB-C Hub", "Wireless Mouse"}},
		{"roles", "name", []string{"admin", "editor", "viewer"}},
		{"cities", "name", []string{"Namur", "Liège", "Bruxelles", "Gent"}},
		{"tags", "name", []string{"urgent", "billing", "later"}},
		{"categories", "name", []string{"Romans", "Bandes dessinées", "Jeunesse"}},
		// the column name alone is never enough
		{"customers", "name", nil},
		{"customers", "name", []string{"", " "}},
		// names in a column that does not mean "name"
		{"customers", "notes_ref", fr},
		{"customers", "name_id", fr},
		// a table of things needs 80 %
		{"products", "name", []string{"Alice Dupont", "Laptop Pro 14", "USB-C Hub"}},
		// a neutral table needs two names
		{"orders", "name", []string{"Alice Dupont"}},
		// a value holding more than a name
		{"customers", "name", []string{"Alice Dupont, Bob Martin and others", "#12 Alice Dupont"}},
	} {
		if LooksPersonNameColumn(c.table, c.column, c.samples) {
			t.Errorf("%s.%s %q: a person-name column", c.table, c.column, c.samples)
		}
	}
}

func TestPersonNameAccents(t *testing.T) {
	for _, s := range []string{"Chloé Lambert", "Hélène Dubois", "Zoë Peeters", "Noël Martin", "Anaïs Leroy"} {
		if !wholePersonName(s) {
			t.Errorf("%q: not a person name", s)
		}
	}
	for _, s := range []string{"Chloé", "Hélène", "Zoë", "Liège", "Laptop Pro 14"} {
		if wholePersonName(s) {
			t.Errorf("%q: a person name", s)
		}
	}
}

func TestTableHint(t *testing.T) {
	for table, want := range map[string]int{
		"customers": 1, "public.users": 1, "klanten": 1, "leden": 1, "people": 1, "Employees": 1,
		"mitglieder": 1, "kunden": 1, "benutzer": 1, "staedte": -1, "kategorien": -1, "producten": -1,
		"products": -1, "roles": -1, "categories": -1, "tags": -1, "cities": -1, "product_categories": -1,
		"orders": 0, "": 0,
	} {
		if got := tableHint(table); got != want {
			t.Errorf("%q: %d, want %d", table, got, want)
		}
	}
}
