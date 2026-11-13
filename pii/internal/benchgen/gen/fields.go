package gen

import (
	"fmt"
	"strings"
)

// Field names, labelled as a human reviewer would: personal (the field
// holds personal data), quasi (a quasi-identifier: birth date, postal
// code, gender, coordinates, free text) or neither (metadata about
// personal data counts as neither: "email_verified_at"). Each is written
// in snake case and rendered in the case style its random source picks.

const (
	isPersonal = 1 << iota
	isQuasi
)

var fieldLists = map[string][]struct {
	name  string
	label int
}{
	"en": {
		{"email", isPersonal}, {"email_address", isPersonal}, {"phone_number", isPersonal}, {"mobile", isPersonal}, {"first_name", isPersonal}, {"last_name", isPersonal},
		{"full_name", isPersonal}, {"customer_name", isPersonal}, {"recipient_name", isPersonal}, {"street", isPersonal}, {"city", isPersonal}, {"home_address", isPersonal},
		{"iban", isPersonal}, {"card_number", isPersonal}, {"ssn", isPersonal}, {"passport_number", isPersonal}, {"ip_address", isPersonal}, {"password", isPersonal},
		{"username", isPersonal}, {"api_key", isPersonal}, {"tax_id", isPersonal}, {"bank_account", isPersonal}, {"nickname", isPersonal}, {"contact_name", isPersonal},
		{"date_of_birth", isQuasi}, {"birthdate", isQuasi}, {"zip_code", isQuasi}, {"postal_code", isQuasi}, {"gender", isQuasi}, {"notes", isQuasi},
		{"comment", isQuasi}, {"latitude", isQuasi}, {"longitude", isQuasi}, {"bio", isQuasi}, {"dob", isQuasi},
		{"order_id", 0}, {"created_at", 0}, {"total_amount", 0}, {"status", 0}, {"product_name", 0},
		{"file_name", 0}, {"template_name", 0}, {"email_count", 0}, {"email_verified_at", 0}, {"sku", 0},
		{"quantity", 0}, {"currency", 0}, {"phone_type", 0}, {"invoice_number", 0}, {"updated_at", 0},
		{"warehouse_code", 0}, {"country_code", 0},
	},
	"fr": {
		{"courriel", isPersonal}, {"adresse_mail", isPersonal}, {"telephone", isPersonal}, {"portable", isPersonal}, {"prenom", isPersonal}, {"nom_client", isPersonal},
		{"nom_de_famille", isPersonal}, {"nom_destinataire", isPersonal}, {"adresse", isPersonal}, {"rue", isPersonal}, {"ville", isPersonal}, {"iban", isPersonal},
		{"numero_carte", isPersonal}, {"nir", isPersonal}, {"numero_securite_sociale", isPersonal}, {"passeport", isPersonal}, {"adresse_ip", isPersonal},
		{"mot_de_passe", isPersonal}, {"identifiant", isPersonal}, {"pseudo", isPersonal}, {"nom_complet", isPersonal}, {"tel_portable", isPersonal},
		{"date_naissance", isQuasi}, {"date_de_naissance", isQuasi}, {"code_postal", isQuasi}, {"sexe", isQuasi}, {"genre", isQuasi},
		{"commentaire", isQuasi}, {"remarques", isQuasi}, {"latitude", isQuasi}, {"lieu_naissance", isQuasi},
		{"observations", isQuasi}, {"coordonnees_gps", isQuasi}, {"date_anniversaire", isQuasi},
		{"numero_commande", 0}, {"date_creation", 0}, {"montant_total", 0}, {"statut", 0}, {"nom_produit", 0},
		{"nom_fichier", 0}, {"nom_modele", 0}, {"quantite", 0}, {"devise", 0}, {"reference", 0},
		{"numero_facture", 0}, {"date_maj", 0}, {"code_magasin", 0}, {"taux_tva", 0}, {"nombre_emails", 0},
	},
	"nl": {
		{"emailadres", isPersonal}, {"e_mail", isPersonal}, {"telefoon", isPersonal}, {"gsm", isPersonal}, {"voornaam", isPersonal}, {"achternaam", isPersonal},
		{"familienaam", isPersonal}, {"naam_klant", isPersonal}, {"klant_naam", isPersonal}, {"adres", isPersonal}, {"straat", isPersonal}, {"woonplaats", isPersonal},
		{"huisnummer", isPersonal}, {"iban", isPersonal}, {"kaartnummer", isPersonal}, {"bsn", isPersonal}, {"rijksregisternummer", isPersonal}, {"insz", isPersonal},
		{"paspoort", isPersonal}, {"ip_adres", isPersonal}, {"wachtwoord", isPersonal}, {"gebruikersnaam", isPersonal}, {"telefoonnummer", isPersonal},
		{"geboortedatum", isQuasi}, {"postcode", isQuasi}, {"geslacht", isQuasi}, {"opmerking", isQuasi}, {"opmerkingen", isQuasi},
		{"notities", isQuasi}, {"lengtegraad", isQuasi}, {"geboorteplaats", isQuasi},
		{"breedtegraad", isQuasi}, {"notitie", isQuasi}, {"geboortejaar", isQuasi},
		{"bestelnummer", 0}, {"aangemaakt_op", 0}, {"totaal_bedrag", 0}, {"status", 0}, {"productnaam", 0},
		{"bestandsnaam", 0}, {"sjabloon_naam", 0}, {"aantal", 0}, {"munt", 0}, {"factuurnummer", 0},
		{"bijgewerkt_op", 0}, {"winkel_code", 0}, {"btw_tarief", 0}, {"email_id", 0}, {"artikelcode", 0},
	},
	"de": {
		{"email", isPersonal}, {"emailadresse", isPersonal}, {"telefon", isPersonal}, {"handy", isPersonal}, {"vorname", isPersonal}, {"nachname", isPersonal},
		{"familienname", isPersonal}, {"kunde_name", isPersonal}, {"anschrift", isPersonal}, {"strasse", isPersonal}, {"hausnummer", isPersonal}, {"stadt", isPersonal},
		{"iban", isPersonal}, {"kartennummer", isPersonal}, {"reisepass", isPersonal}, {"ip_adresse", isPersonal}, {"passwort", isPersonal}, {"benutzername", isPersonal},
		{"telefonnummer", isPersonal}, {"steuer_id", isPersonal}, {"wohnort", isPersonal}, {"personalausweis", isPersonal},
		{"geburtsdatum", isQuasi}, {"geburtstag", isQuasi}, {"postleitzahl", isQuasi}, {"plz", isQuasi}, {"geschlecht", isQuasi},
		{"kommentar", isQuasi}, {"bemerkung", isQuasi}, {"notizen", isQuasi}, {"breitengrad", isQuasi},
		{"anmerkungen", isQuasi}, {"laengengrad", isQuasi}, {"geburtsort", isQuasi},
		{"bestellnummer", 0}, {"erstellt_am", 0}, {"gesamtbetrag", 0}, {"status", 0}, {"produktname", 0},
		{"dateiname", 0}, {"vorlagen_name", 0}, {"menge", 0}, {"waehrung", 0}, {"rechnungsnummer", 0},
		{"aktualisiert_am", 0}, {"lager_code", 0}, {"mwst_satz", 0}, {"email_count", 0}, {"artikelnummer", 0},
	},
}

// Fields returns the field cases of every language.
func Fields() []FieldCase {
	var out []FieldCase
	for _, lang := range Langs {
		r := rng(lang + "/fields")
		for i, f := range fieldLists[lang] {
			out = append(out, FieldCase{
				ID:       fmt.Sprintf("f-%s-%04d", lang, i+1),
				Lang:     lang,
				Field:    style(pick(r, []string{"snake", "snake", "camel", "pascal", "upper"}), f.name),
				Personal: f.label&isPersonal != 0,
				Quasi:    f.label&isQuasi != 0,
			})
		}
	}
	return out
}

func style(s, name string) string {
	parts := strings.Split(name, "_")
	switch s {
	case "camel", "pascal":
		for i, p := range parts {
			if i > 0 || s == "pascal" {
				parts[i] = title(p)
			}
		}
		return strings.Join(parts, "")
	case "upper":
		return strings.ToUpper(name)
	}
	return name
}
