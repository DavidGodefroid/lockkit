package gen

import (
	"fmt"
	"math/rand/v2"
	"strings"
)

// Hard negatives: texts that look like personal data and hold none.
// Order numbers, dates, amounts, product codes, invoice ids, versions,
// timestamps, hashes, checksummed numbers with a wrong checksum, private
// IP addresses and capitalised words that are no names.

type negFrame struct{ kind, frame string }

var negFrames = map[string][]negFrame{
	"en": {
		{"order", "Order {v} shipped this morning."}, {"order", "Your order #{v} is ready for pickup."},
		{"date", "Delivery expected on {v}."}, {"amount", "Total due: {v}."}, {"grouped", "Stock count: {v} units."},
		{"product", "Item {v} is back in stock."}, {"ean", "Barcode {v} scanned at till three."},
		{"invoice", "Invoice {v} was paid in full."}, {"version", "Upgraded the agent to {v}."},
		{"timestamp", "Job finished at {v}."}, {"hash", "Deployed commit {v} to staging."},
		{"bad_iban", "Rejected account {v}: checksum error."}, {"bad_card", "Test number {v} failed validation."},
		{"bad_ssn", "Placeholder {v} used in the form template."}, {"private_ip", "Health check from {v} passed."},
		{"words", "Started Network Manager Wait Online."}, {"words", "Grace Period Expired for Mark Price Update."},
		{"words", "Thank You Page Updated by Marketing Team."},
	},
	"fr": {
		{"order", "Commande {v} expédiée ce matin."}, {"order", "Votre commande n° {v} est prête."},
		{"date", "Livraison prévue le {v}."}, {"amount", "Montant dû : {v}."}, {"grouped", "Stock : {v} unités."},
		{"product", "L'article {v} est de nouveau disponible."}, {"ean", "Code-barres {v} scanné en caisse."},
		{"invoice", "La facture {v} est réglée."}, {"version", "Agent mis à jour en {v}."},
		{"timestamp", "Tâche terminée à {v}."}, {"hash", "Commit {v} déployé en recette."},
		{"bad_iban", "Compte {v} refusé : clé invalide."}, {"bad_card", "Le numéro de test {v} est invalide."},
		{"bad_niss", "Numéro {v} refusé par le registre."}, {"bad_nir", "Le NIR {v} a une clé erronée."},
		{"private_ip", "Sonde depuis {v} : OK."},
		{"words", "Service Client Belgique : ouverture lundi."}, {"words", "Mise à Jour Grande Braderie Annuelle."},
		{"words", "Bon de Commande Validé par la Direction."},
	},
	"nl": {
		{"order", "Bestelling {v} is vanochtend verzonden."}, {"order", "Uw bestelling nr. {v} ligt klaar."},
		{"date", "Levering verwacht op {v}."}, {"amount", "Te betalen: {v}."}, {"grouped", "Voorraad: {v} stuks."},
		{"product", "Artikel {v} is terug op voorraad."}, {"ean", "Barcode {v} gescand aan kassa drie."},
		{"invoice", "Factuur {v} is betaald."}, {"version", "Agent bijgewerkt naar {v}."},
		{"timestamp", "Taak klaar om {v}."}, {"hash", "Commit {v} uitgerold op staging."},
		{"bad_iban", "Rekening {v} geweigerd: controlegetal fout."}, {"bad_card", "Testnummer {v} is ongeldig."},
		{"bad_niss", "Nummer {v} geweigerd door het register."}, {"bad_bsn", "BSN-controle mislukt voor {v}."},
		{"private_ip", "Health check vanaf {v} geslaagd."},
		{"words", "Klantendienst Gent Gesloten Wegens Inventaris."}, {"words", "Nieuwe Collectie Herfst Winter."},
		{"words", "Bestelbon Goedgekeurd door Directie."},
	},
	"de": {
		{"order", "Bestellung {v} wurde heute verschickt."}, {"order", "Ihre Bestellung Nr. {v} liegt bereit."},
		{"date", "Lieferung voraussichtlich am {v}."}, {"amount", "Zu zahlen: {v}."}, {"grouped", "Bestand: {v} Stück."},
		{"product", "Artikel {v} ist wieder verfügbar."}, {"ean", "Barcode {v} an Kasse drei gescannt."},
		{"invoice", "Rechnung {v} ist bezahlt."}, {"version", "Agent auf {v} aktualisiert."},
		{"timestamp", "Auftrag beendet um {v}."}, {"hash", "Commit {v} auf Staging ausgerollt."},
		{"bad_iban", "Konto {v} abgelehnt: Prüfziffer falsch."}, {"bad_card", "Testnummer {v} ist ungültig."},
		{"bad_niss", "Nummer {v} vom Register abgelehnt."}, {"private_ip", "Health-Check von {v} erfolgreich."},
		{"words", "Kundendienst Berlin Wegen Inventur Geschlossen."}, {"words", "Neue Kollektion Herbst Winter."},
		{"words", "Bestellschein Freigegeben durch Geschäftsleitung."},
	},
}

var negValues = map[string]func(r *rand.Rand, lang string) string{
	"order": func(r *rand.Rand, _ string) string { return fmt.Sprint(1+r.IntN(9)) + digits(r, 5+r.IntN(5)) },
	"date": func(r *rand.Rand, lang string) string {
		d, m, y := 1+r.IntN(28), 1+r.IntN(12), 2019+r.IntN(9)
		switch r.IntN(3) {
		case 0:
			return fmt.Sprintf("%04d-%02d-%02d", y, m, d)
		case 1:
			if lang == "de" {
				return fmt.Sprintf("%02d.%02d.%04d", d, m, y)
			}
			if lang == "en" {
				return fmt.Sprintf("%02d/%02d/%04d", m, d, y)
			}
			return fmt.Sprintf("%02d/%02d/%04d", d, m, y)
		}
		return fmt.Sprintf("%02d-%02d-%04d", d, m, y)
	},
	"amount": func(r *rand.Rand, lang string) string {
		whole, cents := 1000+r.IntN(98000), r.IntN(100)
		th, rest := whole/1000, whole%1000
		switch lang {
		case "en":
			return fmt.Sprintf("€%d,%03d.%02d", th, rest, cents)
		case "fr":
			return fmt.Sprintf("%d%s%03d,%02d €", th, pick(r, []string{" ", "\u00a0", "\u202f"}), rest, cents)
		case "nl":
			return fmt.Sprintf("€ %d.%03d,%02d", th, rest, cents)
		}
		return fmt.Sprintf("%d.%03d,%02d EUR", th, rest, cents)
	},
	"grouped": func(r *rand.Rand, _ string) string {
		return fmt.Sprintf("%d %03d %03d", 1+r.IntN(999), r.IntN(1000), r.IntN(1000))
	},
	"product": func(r *rand.Rand, _ string) string {
		switch r.IntN(3) {
		case 0:
			return "SKU-" + digits(r, 4) + "-" + pick(r, []string{"XS", "M", "XL"})
		case 1:
			return "REF " + digits(r, 2) + "-" + digits(r, 3) + "-" + digits(r, 3)
		}
		return letters(r, 3) + digits(r, 5)
	},
	"ean": func(r *rand.Rand, _ string) string {
		// A real EAN-13 check digit: some pass Luhn too.
		d := "54" + digits(r, 10)
		sum := 0
		for i := range 12 {
			n := int(d[i] - '0')
			if i%2 == 1 {
				n *= 3
			}
			sum += n
		}
		return d + fmt.Sprint((10-sum%10)%10)
	},
	"invoice": func(r *rand.Rand, _ string) string {
		y := 2020 + r.IntN(7)
		switch r.IntN(3) {
		case 0:
			return fmt.Sprintf("INV-%d-%06d", y, r.IntN(1000000))
		case 1:
			return fmt.Sprintf("FAC/%d/%04d", y, r.IntN(10000))
		}
		return fmt.Sprintf("F%d-%05d", y, r.IntN(100000))
	},
	"version": func(r *rand.Rand, _ string) string {
		switch r.IntN(4) {
		case 0:
			return fmt.Sprintf("v%d.%d.%d", r.IntN(10), r.IntN(30), r.IntN(20))
		case 1:
			return fmt.Sprintf("version %d.%d.%d.%d", 1+r.IntN(9), r.IntN(10), r.IntN(10), r.IntN(400))
		case 2:
			return fmt.Sprintf("Chrome/%d.0.%d.%d", 100+r.IntN(40), 5000+r.IntN(2000), r.IntN(200))
		}
		return fmt.Sprintf("build %d.%d.%d.%d", 10, 0, 19000+r.IntN(1000), r.IntN(5000))
	},
	"timestamp": func(r *rand.Rand, _ string) string {
		h, m, s := r.IntN(24), r.IntN(60), r.IntN(60)
		switch r.IntN(3) {
		case 0:
			return fmt.Sprintf("2026-%02d-%02dT%02d:%02d:%02dZ", 1+r.IntN(12), 1+r.IntN(28), h, m, s)
		case 1:
			return fmt.Sprintf("2026-%02d-%02d %02d:%02d:%02d.%03d", 1+r.IntN(12), 1+r.IntN(28), h, m, s, r.IntN(1000))
		}
		return fmt.Sprint(1700000000 + r.IntN(90000000))
	},
	"hash": func(r *rand.Rand, _ string) string {
		const hex = "0123456789abcdef"
		var b strings.Builder
		for range []int{7, 40, 64}[r.IntN(3)] {
			b.WriteByte(hex[r.IntN(16)])
		}
		return b.String()
	},
	"bad_iban": func(r *rand.Rand, lang string) string {
		v := validIBAN(r, lang)
		for IBANValid(v) {
			v = v[:len(v)-1] + digits(r, 1)
		}
		return group(v, 4, " ")
	},
	"bad_card": func(r *rand.Rand, _ string) string {
		v := validCard(r)
		for Luhn(v) {
			v = v[:len(v)-1] + digits(r, 1)
		}
		return group(v, 4, " ")
	},
	"bad_niss": func(r *rand.Rand, _ string) string {
		v := validNISS(r)
		for NISSValid(v) {
			v = v[:9] + digits(r, 2)
		}
		return formatNISS(r, v)
	},
	"bad_nir": func(r *rand.Rand, _ string) string {
		v := validNIR(r)
		for NIRValid(v) {
			v = v[:13] + digits(r, 2)
		}
		return formatNIR(r, v)
	},
	"bad_bsn": func(r *rand.Rand, _ string) string {
		v := validBSN(r)
		for BSNValid(v) {
			v = v[:8] + digits(r, 1)
		}
		return v
	},
	"bad_ssn": func(r *rand.Rand, _ string) string {
		// Area numbers never issued: 000, 666, 9xx.
		return pick(r, []string{"000", "666", "9" + digits(r, 2)}) + "-" + digits(r, 2) + "-" + digits(r, 4)
	},
	"private_ip": func(r *rand.Rand, _ string) string {
		switch r.IntN(5) {
		case 0:
			return fmt.Sprintf("10.%d.%d.%d", r.IntN(256), r.IntN(256), 1+r.IntN(254))
		case 1:
			return fmt.Sprintf("192.168.%d.%d", r.IntN(256), 1+r.IntN(254))
		case 2:
			return fmt.Sprintf("172.%d.%d.%d", 16+r.IntN(16), r.IntN(256), 1+r.IntN(254))
		case 3:
			return "127.0.0.1"
		}
		return fmt.Sprintf("fd00::%x", 1+r.IntN(0xfff))
	},
	"words": func(*rand.Rand, string) string { return "" },
	// A wrong check, the number glued to its prefix: with a space, its
	// digits alone are a fair phone or BSN candidate, and so are nine
	// digits that pass the Dutch 11-proof.
	"bad_vat": func(r *rand.Rand, lang string) string {
		v := vatNumber(r, pick(r, vatCountries[lang]), false)
		for strings.HasPrefix(v, "DE") && BSNValid(v[2:]) {
			v = vatNumber(r, "DE", false)
		}
		if r.IntN(4) == 0 {
			return strings.ToLower(v)
		}
		return v
	},
	// A wrong check on a number starting with 1: one starting with 0 is
	// also a fair national phone number.
	"bad_company": func(r *rand.Rand, _ string) string {
		d := "1" + beCompany(r, false)[1:]
		for BECompanyValid(d) {
			d = "1" + beCompany(r, false)[1:]
		}
		return d[:4] + "." + d[4:7] + "." + d[7:]
	},
	"bad_eid": func(r *rand.Rand, _ string) string { return formatEID(beEID(r, false)) },
	// Two capitals and six digits: a passport only after a passport word.
	"code": func(r *rand.Rand, _ string) string { return passportNumber(r) },
	// A date that is no birth date.
	"any_date": func(r *rand.Rand, lang string) string { v, _ := birthDate(r, lang); return v },
}

// laterNegatives are the hard negatives of the kinds written after the
// first corpus, per kind and language.
var laterNegatives = map[string]map[string][]negFrame{
	"eu_vat": {
		// The value ends the sentence: words after it could make an IBAN.
		"en": {{"bad_vat", "VIES rejected the VAT number {v}."}, {"bad_vat", "Wrong check digits: {v}"}},
		"fr": {{"bad_vat", "VIES a refusé le numéro de TVA {v}."}, {"bad_vat", "Clé erronée : {v}"}},
		"nl": {{"bad_vat", "VIES weigerde het btw-nummer {v}."}, {"bad_vat", "Foutief controlecijfer: {v}"}},
		"de": {{"bad_vat", "VIES lehnte die USt-IdNr. {v} ab."}, {"bad_vat", "Falsche Prüfziffer: {v}"}},
	},
	"be_company": {
		"fr": {{"bad_company", "Numéro {v} inconnu à la BCE."}, {"bad_company", "Colis {v} remis au transporteur."}},
		"nl": {{"bad_company", "Nummer {v} onbekend in de KBO."}, {"bad_company", "Pakket {v} afgegeven aan de koerier."}},
		"de": {{"bad_company", "Nummer {v} unbekannt in der ZDU."}, {"bad_company", "Paket {v} an den Kurier übergeben."}},
	},
	"be_eid": {
		"fr": {{"bad_eid", "Carte {v} refusée : chiffres de contrôle faux."}, {"bad_eid", "Référence {v} inconnue."}},
		"nl": {{"bad_eid", "Kaart {v} geweigerd: controlecijfers fout."}, {"bad_eid", "Referentie {v} onbekend."}},
		"de": {{"bad_eid", "Karte {v} abgelehnt: Prüfziffern falsch."}, {"bad_eid", "Referenz {v} unbekannt."}},
	},
	"passport": {
		"fr": {{"code", "Colis {v} expédié ce matin."}, {"code", "Lot {v} contrôlé."}},
		"nl": {{"code", "Pakket {v} vanochtend verzonden."}, {"code", "Partij {v} gecontroleerd."}},
		"de": {{"code", "Paket {v} heute verschickt."}, {"code", "Charge {v} geprüft."}},
	},
	"birth_date": {
		"en": {{"any_date", "Contract signed on {v}."}, {"any_date", "Invoice date: {v}"}, {"any_date", "Warranty until {v}."}},
		"fr": {{"any_date", "Contrat signé le {v}."}, {"any_date", "Date de facture : {v}"}, {"any_date", "Garantie jusqu'au {v}."}},
		"nl": {{"any_date", "Contract getekend op {v}."}, {"any_date", "Factuurdatum: {v}"}, {"any_date", "Garantie tot {v}."}},
		"de": {{"any_date", "Vertrag unterzeichnet am {v}."}, {"any_date", "Rechnungsdatum: {v}"}, {"any_date", "Garantie bis {v}."}},
	},
}
