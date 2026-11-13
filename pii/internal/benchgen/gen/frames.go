package gen

import "strings"

// Frames are the texts a value is written in: {v} is the value. A frame
// starting with "!" is a context the detectors are known to miss (a hard
// positive). Prose frames are per language; structured frames (JSON, a
// key=value log line, YAML) are shared, with a key per kind.

var prose = map[string]map[string][]string{
	"en": {
		"secret": {"password={v}", "Authorization: Bearer {v}", "export DB_PASSWORD={v}", "mysql -u app -p{v} shop",
			"https://deploy:{v}@git.example.com/app.git", "--password {v}", "!The new password is {v}, please change it after login."},
		"email": {"Please reply to {v} before Friday.", "Invoice sent to {v} this morning.", "Contact: {v}", "<{v}> wrote:"},
		"iban":  {"Please transfer the refund to {v} by Monday.", "Bank account: {v}", "IBAN {v} (current account)"},
		"card":  {"Card used: {v}, expires next year.", "The customer paid with {v}.", "card {v} declined"},
		"us_ssn": {"SSN: {v}", "Social Security number {v} on file.", "Her SSN is {v}.",
			"Form W-4 lists {v} as the employee's number."},
		"person_name": {"Meeting with {v} tomorrow morning.", "Ticket assigned to {v}.", "Signed by {v}, branch manager.",
			"Please call {v} about the delivery."},
		"ip":             {"Login from {v} at dawn.", "Request blocked: client {v}.", "Connection from {v} refused."},
		"phone":          {"Call me on {v} after six.", "Phone: {v}", "Mobile {v} (evenings only)."},
		"phone_loose":    {"Call me on {v} after six.", "Phone: {v}", "Reach the front desk at {v}."},
		"be_company":     {"Belgian company number {v}", "Registered with the KBO under {v}.", "Company no. {v}"},
		"be_eid":         {"Belgian ID card no. {v}", "eID card {v} expired.", "Identity card number: {v}"},
		"passport":       {"Passport number: {v}", "Passport {v} issued in Brussels.", "Passport no. {v}"},
		"plate":          {"Licence plate {v}", "Vehicle {v} parked in bay 4.", "Speeding ticket for {v}."},
		"postal_address": {"Ship to {v}.", "Billing address: {v}", "Delivered to {v} this morning."},
		"birth_date":     {"Date of birth: {v}", "DOB {v}", "Born on {v} in Leeds."},
		"eu_vat":         {"VAT number: {v}", "Please add our VAT ID {v} to the invoice.", "Supplier VAT {v} (reverse charge)."},
	},
	"fr": {
		"secret": {"password={v}", "Authorization: Bearer {v}", "export DB_PASSWORD={v}", "mysql -u app -p{v} boutique",
			"https://deploy:{v}@git.example.com/app.git", "--password {v}", "!Le mot de passe du compte est {v}, à changer à la première connexion."},
		"email":   {"Merci de répondre à {v} avant vendredi.", "Facture envoyée à {v} ce matin.", "Contact : {v}", "Écrivez-nous à {v}."},
		"iban":    {"Merci de rembourser sur le compte {v} avant lundi.", "Compte bancaire : {v}", "IBAN {v} (compte courant)"},
		"card":    {"Carte utilisée : {v}, expire l'an prochain.", "Le client a payé avec la carte {v}.", "carte {v} refusée"},
		"be_niss": {"Numéro de registre national : {v}", "NISS {v} du patient.", "Le numéro national {v} est enregistré."},
		"fr_nir": {"Numéro de sécurité sociale : {v}", "NIR {v} de l'assuré.", "Le salarié a fourni le numéro {v}.",
			"Carte Vitale n° {v}"},
		"person_name": {"Rendez-vous avec {v} demain matin.", "Dossier suivi par {v}.", "Signé par {v}, directrice d'agence.",
			"Merci d'appeler {v} pour la livraison."},
		"ip":             {"Connexion depuis {v} ce matin.", "Requête bloquée : client {v}.", "Accès refusé pour {v}."},
		"phone":          {"Appelez-moi au {v} après dix-huit heures.", "Tél. : {v}", "Portable {v} (le soir uniquement)."},
		"phone_loose":    {"Appelez-moi au {v} après dix-huit heures.", "Tél. : {v}", "Joignable au {v} en semaine."},
		"plate":          {"Plaque d'immatriculation : {v}", "Véhicule {v} stationné au niveau -1.", "Amende pour {v}."},
		"postal_address": {"Adresse : {v}", "Livraison : {v}.", "Domicile : {v}"},
		"be_eid":         {"Carte d'identité n° {v}", "Numéro de carte eID : {v}", "eID {v} expirée."},
		"passport":       {"Numéro de passeport : {v}", "Passeport {v} délivré à Bruxelles.", "Passeport n° {v}"},
		"birth_date":     {"Date de naissance : {v}", "Né le {v} à Namur.", "Née le {v}"},
		"eu_vat":         {"N° TVA : {v}", "Merci d'indiquer notre numéro de TVA {v} sur la facture.", "TVA intracommunautaire {v} (autoliquidation)."},
		"be_company":     {"Numéro d'entreprise : {v}", "BCE {v}", "Inscrite à la BCE sous le numéro {v}."},
	},
	"nl": {
		"secret": {"password={v}", "Authorization: Bearer {v}", "export DB_PASSWORD={v}", "mysql -u app -p{v} winkel",
			"https://deploy:{v}@git.example.com/app.git", "--password {v}", "!Het nieuwe wachtwoord is {v}, wijzig het na het aanmelden."},
		"email":   {"Graag antwoorden aan {v} voor vrijdag.", "Factuur vanochtend verstuurd naar {v}.", "Contact: {v}", "Mail ons op {v}."},
		"iban":    {"Graag de terugbetaling op rekening {v} storten voor maandag.", "Bankrekening: {v}", "IBAN {v} (zichtrekening)"},
		"card":    {"Gebruikte kaart: {v}, vervalt volgend jaar.", "De klant betaalde met {v}.", "kaart {v} geweigerd"},
		"be_niss": {"Rijksregisternummer: {v}", "INSZ {v} van de patiënt.", "Het rijksregisternummer {v} is geregistreerd."},
		"nl_bsn": {"BSN: {v}", "Burgerservicenummer {v} van de klant.", "De werknemer gaf nummer {v} op.",
			"Uw BSN is {v}."},
		"person_name": {"Afspraak met {v} morgenvroeg.", "Dossier opgevolgd door {v}.", "Ondertekend door {v}, kantoordirecteur.",
			"Bel {v} even over de levering."},
		"ip":             {"Aanmelding vanaf {v} vanochtend.", "Verzoek geblokkeerd: client {v}.", "Toegang geweigerd voor {v}."},
		"phone":          {"Bel me op {v} na zes uur.", "Tel.: {v}", "Gsm {v} (enkel 's avonds)."},
		"phone_loose":    {"Bel me op {v} na zes uur.", "Tel.: {v}", "Bereikbaar op {v} tijdens de week."},
		"plate":          {"Kenteken: {v}", "Nummerplaat {v} geflitst.", "Wagen {v} staat op niveau -1."},
		"postal_address": {"Adres: {v}", "Leveren op {v}.", "Woonachtig: {v}"},
		"be_eid":         {"Identiteitskaartnummer: {v}", "eID-kaart {v}", "Kaartnummer eID {v} vervallen."},
		"passport":       {"Paspoortnummer: {v}", "Paspoort {v} geldig tot 2030.", "Paspoort nr. {v}"},
		"birth_date":     {"Geboortedatum: {v}", "Geboren op {v} in Gent.", "geboren {v}"},
		"eu_vat":         {"Btw-nummer: {v}", "Gelieve ons btw-nummer {v} op de factuur te vermelden.", "Btw {v} (verlegd)."},
		"be_company":     {"Ondernemingsnummer: {v}", "KBO {v}", "Ingeschreven in de KBO onder nummer {v}."},
	},
	"de": {
		"secret": {"password={v}", "Authorization: Bearer {v}", "export DB_PASSWORD={v}", "mysql -u app -p{v} laden",
			"https://deploy:{v}@git.example.com/app.git", "--password {v}", "!Das neue Passwort lautet {v}, bitte nach der Anmeldung ändern."},
		"email":   {"Bitte bis Freitag an {v} antworten.", "Rechnung heute früh an {v} gesendet.", "Kontakt: {v}", "Schreiben Sie uns an {v}."},
		"iban":    {"Bitte die Erstattung bis Montag auf {v} überweisen.", "Bankverbindung: {v}", "IBAN {v} (Girokonto)"},
		"card":    {"Verwendete Karte: {v}, läuft nächstes Jahr ab.", "Der Kunde zahlte mit {v}.", "Karte {v} abgelehnt"},
		"be_niss": {"Nationalregisternummer: {v}", "INSZ {v} des Patienten.", "Die Nationalnummer {v} ist erfasst."},
		"person_name": {"Termin mit {v} morgen früh.", "Vorgang bearbeitet von {v}.", "Unterschrieben von {v}, Filialleiterin.",
			"Bitte {v} wegen der Lieferung anrufen."},
		"ip":          {"Anmeldung von {v} heute früh.", "Anfrage blockiert: Client {v}.", "Zugriff verweigert für {v}."},
		"phone":       {"Rufen Sie mich unter {v} nach achtzehn Uhr an.", "Tel.: {v}", "Handy {v} (nur abends)."},
		"phone_loose": {"Rufen Sie mich unter {v} nach achtzehn Uhr an.", "Tel.: {v}", "Erreichbar unter {v} werktags."},
		"be_eid":      {"Personalausweisnummer: {v}", "eID-Karte {v}", "Kartennummer eID {v} abgelaufen."},
		"passport":    {"Reisepassnummer: {v}", "Reisepass {v} gültig bis 2030.", "Pass Nr. {v}"},
		"birth_date":  {"Geburtsdatum: {v}", "Geboren am {v} in Eupen.", "geb. {v}"},
		"eu_vat":      {"USt-IdNr.: {v}", "Bitte unsere USt-IdNr. {v} auf der Rechnung angeben.", "Umsatzsteuer-ID {v} (Reverse Charge)."},
		"be_company":  {"Unternehmensnummer: {v}", "ZDU {v}", "Eingetragen unter der Unternehmensnummer {v}."},
	},
}

// structuredKeys are the field names a kind is logged under.
var structuredKeys = map[string]string{
	"email": "email", "iban": "iban", "card": "card_number", "be_niss": "niss", "fr_nir": "nir",
	"nl_bsn": "bsn", "us_ssn": "ssn", "person_name": "customer", "ip": "client_ip", "phone": "phone",
	"phone_loose": "phone", "eu_vat": "vat_number", "be_company": "company_number",
	"be_eid": "id_card_number", "passport": "passport_number", "birth_date": "birth_date",
	"plate": "license_plate", "postal_address": "address",
}

var structuredFrames = []string{
	`{"type":"user","{k}":"{v}","active":true}`,
	`level=info msg="profile updated" {k}={v}`,
	`{k}: {v}`,
}

func framesFor(lang, kind string) []string {
	out := append([]string(nil), prose[lang][kind]...)
	if k, ok := structuredKeys[kind]; ok {
		for _, f := range structuredFrames {
			out = append(out, strings.ReplaceAll(f, "{k}", k))
		}
	}
	return out
}

// mixedFrames hold several values: [[kind]] is a value of that kind.
var mixedFrames = map[string][]string{
	"en": {"[[person_name]] <[[email]]>, mobile [[phone]]", "Contact [[person_name]] on [[phone]] or at [[email]].",
		`{"name":"[[person_name]]","email":"[[email]]","phone":"[[phone]]"}`},
	"fr": {"[[person_name]] <[[email]]>, portable [[phone]]", "Contacter [[person_name]] au [[phone]] ou à [[email]].",
		`{"nom":"[[person_name]]","courriel":"[[email]]","tel":"[[phone]]"}`},
	"nl": {"[[person_name]] <[[email]]>, gsm [[phone]]", "Contacteer [[person_name]] op [[phone]] of via [[email]].",
		`{"naam":"[[person_name]]","email":"[[email]]","telefoon":"[[phone]]"}`},
	"de": {"[[person_name]] <[[email]]>, Handy [[phone]]", "Kontakt: [[person_name]] unter [[phone]] oder [[email]].",
		`{"name":"[[person_name]]","email":"[[email]]","telefon":"[[phone]]"}`},
}
