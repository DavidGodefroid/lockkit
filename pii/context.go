package pii

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Context words: a word or field name that says what the next value is
// raises a candidate too weak to be a match on its own (a phone number
// without its trunk 0, ten bare digits of a company number) to a match of
// ConfidenceLow. Context is additive only: it never removes a match.

// contextWindow is how far before a candidate a context word may start
// (on the same line).
const contextWindow = 32

// contextWords are the words, in lower case, that announce a value of a
// detector's kind, in en/fr/nl/de. A word matches at the start of a word
// of the text, so a compound counts ("rijksregisternummer",
// "telefoonnummer"); "_" and "-" read as spaces ("company_number").
var contextWords = map[string][]string{
	"phone": {
		"tel", "tél", "phone", "mobile", "cell", "call", "fax", "whatsapp", // en
		"téléphone", "telephone", "portable", "appelez", "joignable", // fr
		"telefoon", "gsm", "mobiel", "bel me", "bereikbaar", // nl
		"telefon", "handy", "mobilnummer", "rufnummer", "erreichbar", // de
	},
	"be_niss": {
		"national number", "national register", "niss", "insz", "rrn", // en, abbreviations
		"numéro national", "numero national", "registre national", "n° national", // fr
		"rijksregister",                      // nl
		"nationalregister", "nationalnummer", // de
	},
	"be_company": {
		"company number", "company no", "enterprise number", "vat", "kbo", "bce", // en, abbreviations
		"numéro d'entreprise", "numero d'entreprise", "n° d'entreprise", "n° entreprise", "tva", "entreprise", // fr
		"ondernemingsnummer", "onderneming", "btw", // nl
		"unternehmensnummer", "zdu", "ust", "mwst", // de
	},
	"passport": {
		"passport", "travel document", // en
		"passeport",           // fr
		"paspoort", "reispas", // nl
		"reisepass", "pass nr", "passnummer", // de
	},
	"birth_date": {
		"date of birth", "birth", "born", "dob", "d o b", // en ("D.O.B.": dots read as spaces)
		"date de naissance", "naissance", "né le", "née le", "né(e) le", // fr
		"geboortedatum", "geboorte", "geboren", // nl
		"geburtsdatum", "geburt", "geb", // de
	},
}

// contextFinders find the candidates of a detector that only a context
// raises; near reports a context for a candidate starting at an offset.
var contextFinders = map[string]func(s string, near func(int) bool) []gspan{
	"phone":      raisePhones,
	"be_niss":    raiseNISS,
	"be_company": raiseBECompany,
	"passport":   raisePassport,
	"birth_date": raiseBirthDates,
}

// contextBefore reports a context word of kind in the contextWindow bytes
// before s[i], on the same line.
func contextBefore(kind string, s string, i int) bool {
	w := s[max(0, i-contextWindow):i]
	if k := strings.LastIndexAny(w, "\n\r"); k >= 0 {
		w = w[k+1:]
	}
	return hasContextWord(kind, w)
}

// fieldContext reports a field name that announces a value of kind:
// "phone", "kbo_nr", "companyNumber", "RijksregisterNummer".
func fieldContext(kind, field string) bool {
	var b strings.Builder
	prev := rune(0)
	for _, r := range field {
		if unicode.IsUpper(r) && unicode.IsLower(prev) {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
		prev = r
	}
	return hasContextWord(kind, b.String())
}

func hasContextWord(kind, w string) bool {
	if w == "" {
		return false
	}
	w = strings.Map(func(r rune) rune {
		if r == '_' || r == '-' || r == '.' || r == '/' {
			return ' '
		}
		return unicode.ToLower(r)
	}, w)
	for _, word := range contextWords[kind] {
		for k := 0; ; {
			j := strings.Index(w[k:], word)
			if j < 0 {
				break
			}
			j += k
			if r, _ := utf8.DecodeLastRuneInString(w[:j]); j == 0 || !unicode.IsLetter(r) && !unicode.IsDigit(r) {
				return true
			}
			k = j + 1
		}
	}
	return false
}

func raised(spans []span, near func(int) bool) []gspan {
	var out []gspan
	for _, sp := range spans {
		if near(sp.start) {
			out = append(out, gspan{sp, ConfidenceLow})
		}
	}
	return out
}

// raisePhones: the phone_loose candidates after a phone word, for phone
// alone (with phone_loose enabled, they are phone_loose matches).
func raisePhones(s string, near func(int) bool) []gspan {
	return raised(findLoosePhones(s), near)
}

// nissAnyRe is a Belgian national number with any of the separators
// " .-/" between its groups, or none.
var nissAnyRe = regexp.MustCompile(`[0-9]{2}[-./ ]?[0-9]{2}[-./ ]?[0-9]{2}[-./ ]?[0-9]{3}[-./ ]?[0-9]{2}`)

// raiseNISS: a national number whose separators break the written rule
// ("85-07-30-033-28", "850730/033.28"), after a context word.
func raiseNISS(s string, near func(int) bool) []gspan {
	return raised(scan(s, nissAnyRe, 15, func(s string, start, end int) (int, bool) {
		if isDigit(before(s, start)) || !numberEnds(s, end) || !near(start) {
			return 0, false
		}
		d := digitsOf(s[start:end])
		check := int(d[9]-'0')*10 + int(d[10]-'0')
		return end, 97-mod97(d[:9]) == check || 97-mod97("2"+d[:9]) == check
	}), near)
}

var bareCompanyRe = regexp.MustCompile(`[01][0-9]{9}`)

// raiseBECompany: ten bare digits of a company number after a context
// word ("KBO 0123456749").
func raiseBECompany(s string, near func(int) bool) []gspan {
	return raised(scan(s, bareCompanyRe, 10, func(s string, start, end int) (int, bool) {
		if b := before(s, start); isAlnum(b) || b == '.' || b == '-' || b == '+' {
			return 0, false
		}
		if !numberEnds(s, end) || !near(start) {
			return 0, false
		}
		return end, beCompanyValid(s[start:end])
	}), near)
}

// FindField is FindInViews for the value of a field: the field name is a
// context for every candidate of the value, as a context word before it
// would be ("phone" raises "612 345 678"). A name that announces nothing
// gives FindInViews' matches.
func FindField(field, s string, ds []Detector) []Match {
	if field == "" {
		return FindInViews(s, ds)
	}
	with := make([]Detector, len(ds))
	for i, d := range ds {
		if fd, ok := d.(finderDetector); ok && fd.ctx != nil && fieldContext(fd.name, field) {
			fd.field = true
			d = fd
		}
		with[i] = d
	}
	return FindInViews(s, with)
}
