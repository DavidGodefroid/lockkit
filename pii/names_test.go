package pii

import (
	"reflect"
	"testing"
)

func TestLooksPersonal(t *testing.T) {
	for _, n := range []string{"email", "customer_email", "firstName", "nom_de_famille", "prénom", "voornaam",
		"telefoonnummer", "mail_address", "phone_no", "iban", "customeremail", "x-customer-ref-email",
		"sender.name", "password"} {
		if !LooksPersonal(n) {
			t.Errorf("%s: not personal", n)
		}
	}
	for _, n := range []string{"", "id", "email_id", "email_verified_at", "template_name", "file_name", "sku",
		"order_total", "created_at", "status"} {
		if LooksPersonal(n) {
			t.Errorf("%s: personal", n)
		}
	}
	// A type alone makes a column personal: network addresses; a document
	// name on a binary column.
	if !LooksPersonalColumn("last_seen_from", "inet") || !LooksPersonalColumn("scan", "bytea") || LooksPersonalColumn("scan", "text") {
		t.Error("type rules")
	}
}

func TestLooksQuasi(t *testing.T) {
	for _, n := range []string{"birth_date", "zip", "postal_code", "gender", "date_naissance"} {
		if !LooksQuasi(n) {
			t.Errorf("%s: not quasi", n)
		}
	}
	for _, n := range []string{"zip_id", "created_at", "amount"} {
		if LooksQuasi(n) {
			t.Errorf("%s: quasi", n)
		}
	}
}

func TestTokens(t *testing.T) {
	if got := Tokens("customerEmailAddress"); !reflect.DeepEqual(got, []string{"customer", "email", "address"}) {
		t.Errorf("camel: %v", got)
	}
	if got := Tokens("Prénom-HTTPServer_2"); !reflect.DeepEqual(got, []string{"prenom", "http", "server", "2"}) {
		t.Errorf("mixed: %v", got)
	}
}
