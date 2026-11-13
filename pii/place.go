package pii

import (
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// --- licence plates (BE, FR, NL; pattern only)

// plateRe is, in upper case with dashes: Belgian 1-ABC-123 and ABC-123,
// French AB-123-CD, and the Dutch sidecodes 4 to 11 (XX-99-XX, XX-XX-99,
// 99-XX-XX, 99-XXX-9, 9-XXX-99, XX-999-X, X-999-XX, XXX-99-X).
var plateRe = regexp.MustCompile(`[1-9]-[A-Z]{3}-[0-9]{3}` +
	`|[A-Z]{3}-[0-9]{3}` +
	`|[A-Z]{2}-[0-9]{3}-[A-Z]{2}` +
	`|[A-Z]{2}-[0-9]{2}-[A-Z]{2}` +
	`|[A-Z]{2}-[A-Z]{2}-[0-9]{2}` +
	`|[0-9]{2}-[A-Z]{2}-[A-Z]{2}` +
	`|[0-9]{2}-[A-Z]{3}-[0-9]` +
	`|[0-9]-[A-Z]{3}-[0-9]{2}` +
	`|[A-Z]{2}-[0-9]{3}-[A-Z]` +
	`|[A-Z]-[0-9]{3}-[A-Z]{2}` +
	`|[A-Z]{3}-[0-9]{2}-[A-Z]`)

// plateStop are the three-letter prefixes of references shaped like an
// old Belgian plate (ABC-123): standards, tickets, document numbers.
var plateStop = set("CVE", "ISO", "RFC", "REF", "INV", "SKU", "ORD", "TKT", "BUG", "API", "ERR", "VAT", "FAC", "DOC", "NEN", "DIN", "SEC", "OPS", "DEV", "PRJ", "TSK", "REQ", "INC", "CHG", "PRB", "UTF", "WIN")

func findPlates(s string) []span {
	return scan(s, plateRe, 9, func(s string, start, end int) (int, bool) {
		// A plate is a token of its own: no letter, digit, dash, dot or
		// slash glued to it ("SKU-1234-XS", "AB-123-CD-45", "v2/AB-12-CD").
		if b := before(s, start); isAlnum(b) || b == '-' || b == '.' || b == '/' {
			return 0, false
		}
		if a := after(s, end); isAlnum(a) || a == '-' || a == '/' || a == '.' && isAlnum(after(s, end+1)) {
			return 0, false
		}
		v := s[start:end]
		if len(v) == 7 && v[3] == '-' && plateStop[v[:3]] {
			return 0, false
		}
		return end, true
	})
}

// --- postal addresses (BE, FR, NL; pattern only)

const (
	// addrCap is a capitalised one.
	addrCap = `[\p{Lu}][\p{L}\p{M}'’\-]*`
	// addrPart are the small words inside a street name.
	addrPart = `(?:de|du|des|la|le|les|l'|l’|d'|d’|aux|au|sur|sous|en|van|der|den|het|ten|ter|of|the)`
	// addrName is a street name: particles, then a capitalised word, then
	// particles or capitalised words, at most 6 words.
	addrName = `(?:` + addrPart + `\s?){0,3}` + addrCap + `(?:\s(?:` + addrPart + `|` + addrCap + `)){0,4}`
	// addrNum is a house number, with a letter, bis/ter or a box.
	addrNum = `[0-9]{1,4}(?:\s?[A-Za-z]\b|\s(?:bis|ter)\b)?(?:,?\s(?:bte|bus|boîte|box)\.?\s?[0-9A-Za-z]{1,4})?`
	// addrTail is a postcode (BE/FR 4/5 digits, NL 1234 AB) and a
	// locality after the street, on the same line.
	addrTail = `(?:[ \t]*[,;\-–]?[ \t]*(?:[0-9]{4} ?[A-Z]{2}|[0-9]{4,5})[ \t]` + addrCap + `(?:[ \-](?:sur|sous|en|aan|den|le|la|lez|` + addrCap + `)){0,3})?`
	// addrTypes are street types written as a word of their own.
	addrTypes = `(?i:rue|avenue|av\.|boulevard|bd\.?|chaussée|chaussee|place|allée|allee|impasse|quai|chemin|square|drève|dreve|steenweg|straat|laan|plein|weg|street|road)`
	// addrSuffixes end a Dutch compound street name ("Kerkstraat").
	addrSuffixes = `(?:straat|laan|weg|plein|steenweg|dreef|lei|kaai|singel|gracht|markt|kade|pad|dijk|baan)`
)

// addressRe is, with its postcode and locality when they follow:
//   - a type, a name, a number: "Rue de la Loi 16", "Avenue Louise 54
//     bte 3", "Grote Steenweg 12";
//   - a Dutch compound or a name and a capitalised type: "Kerkstraat 12",
//     "Grote Markt 7";
//   - a number first: "12 rue de la Paix", "221B Baker Street",
//     "10 Downing Street".
var addressRe = regexp.MustCompile(
	addrTypes + `\s` + addrName + `,?\s` + addrNum + addrTail +
		`|(?:(?:` + addrCap + `\s)?\p{Lu}\p{Ll}+` + addrSuffixes + `|` + addrCap + `\s(?:Straat|Laan|Weg|Plein|Steenweg|Dreef|Lei|Kaai|Singel|Gracht|Markt|Kade|Dijk|Baan))\s` + addrNum + addrTail +
		`|` + addrNum + `,?\s` + addrTypes + `\s` + addrName + addrTail +
		`|` + addrNum + `\s` + addrCap + `(?:\s` + addrCap + `){0,2}\s(?:Street|Road|Lane|Avenue|Drive|St\.|Rd\.)` + addrTail)

// addressMaxLen bounds a match of addressRe (6 name words, a box, a
// 4-word locality), so that the regexp only sees short windows.
const addressMaxLen = 256

// addressKeys are the lower-case street words one of which every address
// holds: a text without any is not scanned.
var addressKeys = []string{"rue", "av", "bd", "boulevard", "chauss", "place", "all", "impasse", "quai", "chemin", "square", "dr",
	"straat", "laan", "weg", "plein", "lei", "kaai", "singel", "gracht", "markt", "kade", "pad", "dijk", "baan", "street", "road", "lane", "st.", "rd."}

func findAddresses(s string) []span {
	lower := strings.ToLower(s)
	if !slices.ContainsFunc(addressKeys, func(k string) bool { return strings.Contains(lower, k) }) {
		return nil
	}
	return scan(s, addressRe, addressMaxLen, func(s string, start, end int) (int, bool) {
		// Never inside a word or a number, at either end.
		r, _ := utf8.DecodeLastRuneInString(s[:start])
		if start > 0 && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '/') {
			return 0, false
		}
		r, _ = utf8.DecodeRuneInString(s[end:])
		if end < len(s) && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
			return 0, false
		}
		return end, true
	})
}
