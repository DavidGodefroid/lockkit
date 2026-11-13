package gen

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"unicode/utf8"
)

// unspanned separates, in a generated value, a prefix written in the text
// but outside the gold span ("Mme " before a surname: person_name finds
// the name, not the title).
const unspanned = "\x00"

// values generate a personal value of each kind for a language, and
// report a hard positive: a form the detectors are known to find hard or
// not to find at all.
var values = map[string]func(r *rand.Rand, lang string) (string, bool){
	"secret":      secretValue,
	"email":       emailValue,
	"iban":        func(r *rand.Rand, lang string) (string, bool) { return formatIBAN(r, validIBAN(r, lang)), false },
	"card":        func(r *rand.Rand, _ string) (string, bool) { return formatCard(r, validCard(r)), false },
	"be_niss":     func(r *rand.Rand, _ string) (string, bool) { return formatNISS(r, validNISS(r)), false },
	"fr_nir":      func(r *rand.Rand, _ string) (string, bool) { return formatNIR(r, validNIR(r)), false },
	"nl_bsn":      func(r *rand.Rand, _ string) (string, bool) { return formatBSN(r, validBSN(r)), false },
	"us_ssn":      func(r *rand.Rand, _ string) (string, bool) { return formatSSN(r, validSSN(r)), false },
	"person_name": personName,
	"ip":          ipValue,
	"phone":       func(r *rand.Rand, lang string) (string, bool) { return digitsIn(r, pick(r, phoneShapes[lang])), false },
	// Every national number without its trunk 0 is a hard positive:
	// only phone_loose finds them.
	"phone_loose": func(r *rand.Rand, lang string) (string, bool) {
		return digitsIn(r, pick(r, loosePhoneShapes[lang])), true
	},
	"eu_vat": func(r *rand.Rand, lang string) (string, bool) {
		return formatVAT(r, vatNumber(r, pick(r, vatCountries[lang]), true)), false
	},
	"be_company": companyValue,
	"be_eid":     func(r *rand.Rand, _ string) (string, bool) { return formatEID(beEID(r, true)), false },
	"passport":   func(r *rand.Rand, _ string) (string, bool) { return passportNumber(r), false },
	"birth_date": birthDate,
}

// digitKinds are the kinds whose values have digits a disguise can
// rewrite.
var digitKinds = map[string]bool{"iban": true, "card": true, "be_niss": true, "fr_nir": true,
	"nl_bsn": true, "us_ssn": true, "ip": true, "phone": true, "eu_vat": true, "be_company": true,
	"be_eid": true, "passport": true}

// disguise rewrites one value in five: full-width digits, a zero-width
// space inside, or no-break spaces between digit groups.
func disguise(r *rand.Rand, kind, v string) (string, bool) {
	if r.IntN(5) != 0 {
		return v, false
	}
	prefix, body, ok := strings.Cut(v, unspanned)
	if !ok {
		prefix, body = "", v
	} else {
		prefix += unspanned
	}
	ways := []string{"zw"}
	if digitKinds[kind] {
		ways = append(ways, "fw")
		if strings.Contains(body, " ") {
			ways = append(ways, "nbsp")
		}
	}
	switch pick(r, ways) {
	case "fw":
		var b strings.Builder
		for _, c := range body {
			if c >= '0' && c <= '9' {
				c = '\uff10' + c - '0'
			}
			b.WriteRune(c)
		}
		body = b.String()
	case "nbsp":
		body = strings.ReplaceAll(body, " ", pick(r, []string{"\u00a0", "\u202f"}))
	default:
		i := len(body) / 2
		for i > 0 && !utf8.RuneStart(body[i]) {
			i--
		}
		body = body[:i] + "\u200b" + body[i:]
	}
	return prefix + body, true
}

func digits(r *rand.Rand, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('0' + r.IntN(10))
	}
	return string(b)
}

func letters(r *rand.Rand, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('A' + r.IntN(26))
	}
	return string(b)
}

// digitsIn replaces each 'd' of shape with a random digit.
func digitsIn(r *rand.Rand, shape string) string {
	var b strings.Builder
	for i := 0; i < len(shape); i++ {
		if shape[i] == 'd' {
			b.WriteByte(byte('0' + r.IntN(10)))
		} else {
			b.WriteByte(shape[i])
		}
	}
	return b.String()
}

// group writes s in groups of n separated by sep.
func group(s string, n int, sep string) string {
	var parts []string
	for len(s) > n {
		parts = append(parts, s[:n])
		s = s[n:]
	}
	return strings.Join(append(parts, s), sep)
}

// --- checksummed numbers

// Mod97 returns the number written in s modulo 97, letters counting as
// 10..35 (the IBAN rule).
func Mod97(s string) int {
	m := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			m = (m*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			m = (m*100 + int(c-'A') + 10) % 97
		}
	}
	return m
}

// IBANValid checks an IBAN written without blanks.
func IBANValid(v string) bool { return len(v) >= 15 && Mod97(v[4:]+v[:4]) == 1 }

var ibanCountries = map[string][]string{"en": {"GB", "IE"}, "fr": {"FR", "BE"}, "nl": {"NL", "BE"}, "de": {"DE", "AT"}}

func validIBAN(r *rand.Rand, lang string) string {
	cc := pick(r, ibanCountries[lang])
	var bban string
	switch cc {
	case "GB", "IE":
		bban = letters(r, 4) + digits(r, 14)
	case "FR":
		bban = digits(r, 23)
	case "BE":
		bban = digits(r, 12)
	case "NL":
		bban = letters(r, 4) + digits(r, 10)
	case "DE":
		bban = digits(r, 18)
	case "AT":
		bban = digits(r, 16)
	}
	check := 98 - Mod97(bban+cc+"00")
	return fmt.Sprintf("%s%02d%s", cc, check, bban)
}

func formatIBAN(r *rand.Rand, v string) string {
	switch n := r.IntN(20); {
	case n < 14:
		return group(v, 4, " ")
	case n < 19:
		return v
	default:
		return strings.ToLower(v)
	}
}

// Luhn reports a number whose digits pass the Luhn check.
func Luhn(d string) bool {
	sum := 0
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if (len(d)-1-i)%2 == 1 {
			if n *= 2; n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return sum%10 == 0
}

// cardPrefixes are test-card issuer prefixes; the rest is random.
var cardPrefixes = []string{"411111", "400000", "424242", "555555", "222300", "378282"}

func validCard(r *rand.Rand) string {
	p := pick(r, cardPrefixes)
	n := 16
	if p[0] == '3' {
		n = 15
	}
	body := p + digits(r, n-len(p)-1)
	for c := '0'; c <= '9'; c++ {
		if Luhn(body + string(c)) {
			return body + string(c)
		}
	}
	panic("unreachable")
}

func formatCard(r *rand.Rand, v string) string {
	sep := pick(r, []string{" ", " ", "-", ""})
	if len(v) == 15 {
		return v[:4] + sep + v[4:10] + sep + v[10:]
	}
	return group(v, 4, sep)
}

// NISSValid checks the 11 digits of a Belgian national number, born
// before or from 2000.
func NISSValid(d string) bool {
	check := int(d[9]-'0')*10 + int(d[10]-'0')
	return 97-Mod97(d[:9]) == check || 97-Mod97("2"+d[:9]) == check
}

func validNISS(r *rand.Rand) string {
	yy := r.IntN(100)
	body := fmt.Sprintf("%02d%02d%02d%03d", yy, 1+r.IntN(12), 1+r.IntN(28), 1+r.IntN(997))
	key := body
	if yy < 20 {
		key = "2" + body
	}
	return fmt.Sprintf("%s%02d", body, 97-Mod97(key))
}

func formatNISS(r *rand.Rand, d string) string {
	switch r.IntN(4) {
	case 0, 1:
		return d[0:2] + "." + d[2:4] + "." + d[4:6] + "-" + d[6:9] + "." + d[9:]
	case 2:
		return d
	}
	return d[0:6] + " " + d[6:9] + " " + d[9:]
}

// NIRValid checks the 15 characters of a French NIR (Corsica as 2A/2B).
func NIRValid(c string) bool {
	body := c[:13]
	switch body[5:7] {
	case "2A":
		body = body[:5] + "19" + body[7:]
	case "2B":
		body = body[:5] + "18" + body[7:]
	}
	return 97-Mod97(body) == int(c[13]-'0')*10+int(c[14]-'0')
}

func validNIR(r *rand.Rand) string {
	dept := 1 + r.IntN(95)
	if dept == 20 {
		dept = 21
	}
	body := fmt.Sprintf("%d%02d%02d%02d%03d%03d", 1+r.IntN(2), r.IntN(100), 1+r.IntN(12), dept, 1+r.IntN(990), 1+r.IntN(999))
	return fmt.Sprintf("%s%02d", body, 97-Mod97(body))
}

func formatNIR(r *rand.Rand, c string) string {
	if r.IntN(3) == 0 {
		return c
	}
	return c[0:1] + " " + c[1:3] + " " + c[3:5] + " " + c[5:7] + " " + c[7:10] + " " + c[10:13] + " " + c[13:]
}

// BSNValid applies the Dutch 11-proof to 9 digits.
func BSNValid(d string) bool {
	sum := 0
	for i := 0; i < 8; i++ {
		sum += int(d[i]-'0') * (9 - i)
	}
	sum -= int(d[8] - '0')
	return sum != 0 && sum%11 == 0
}

func validBSN(r *rand.Rand) string {
	for {
		d := fmt.Sprintf("%d", 1+r.IntN(9)) + digits(r, 7)
		sum := 0
		for i := 0; i < 8; i++ {
			sum += int(d[i]-'0') * (9 - i)
		}
		if last := sum % 11; last < 10 && BSNValid(d+string(byte('0'+last))) {
			return d + string(byte('0'+last))
		}
	}
}

func formatBSN(r *rand.Rand, d string) string {
	if r.IntN(3) == 0 {
		return d[:4] + "." + d[4:6] + "." + d[6:]
	}
	return d
}

func validSSN(r *rand.Rand) string {
	area := 1 + r.IntN(899)
	if area == 666 {
		area = 667
	}
	return fmt.Sprintf("%03d%02d%04d", area, 1+r.IntN(99), 1+r.IntN(9999))
}

func formatSSN(r *rand.Rand, d string) string {
	sep := pick(r, []string{"-", "-", " "})
	return d[:3] + sep + d[3:5] + sep + d[5:]
}

// --- VAT and company numbers

// BECompanyValid checks the 10 digits of a Belgian company number.
func BECompanyValid(d string) bool {
	return len(d) == 10 && (d[0] == '0' || d[0] == '1') && 97-Mod97(d[:8]) == int(d[8]-'0')*10+int(d[9]-'0')
}

// beCompany returns 10 digits of a Belgian company number, its check
// valid or not.
func beCompany(r *rand.Rand, valid bool) string {
	for {
		body := pick(r, []string{"0", "0", "0", "1"}) + digits(r, 7)
		check := 97 - Mod97(body)
		if !valid {
			check = (check + 1 + r.IntN(90)) % 100
		}
		if d := fmt.Sprintf("%s%02d", body, check); BECompanyValid(d) == valid {
			return d
		}
	}
}

// formatCompany writes 10 digits as 0xxx.xxx.xxx, 0xxx xxx xxx or bare.
func formatCompany(r *rand.Rand, d string) string {
	switch r.IntN(6) {
	case 0, 1, 2:
		return d[:4] + "." + d[4:7] + "." + d[7:]
	case 3, 4:
		return d[:4] + " " + d[4:7] + " " + d[7:]
	}
	return d
}

// companyValue is a Belgian company number; ten bare digits are a hard
// positive (found only with a context word).
func companyValue(r *rand.Rand, _ string) (string, bool) {
	v := formatCompany(r, beCompany(r, true))
	return v, !strings.ContainsAny(v, ". ")
}

var vatCountries = map[string][]string{"en": {"BE", "FR", "NL", "DE", "LU"}, "fr": {"FR", "BE", "BE", "LU"}, "nl": {"NL", "BE", "BE"}, "de": {"DE", "BE", "LU", "DE"}}

// vatNumber returns a VAT number of a country without blanks, its check
// valid or not.
func vatNumber(r *rand.Rand, cc string, valid bool) string {
	off := 0
	if !valid {
		off = 1 + r.IntN(8)
	}
	switch cc {
	case "BE":
		return "BE" + beCompany(r, valid)
	case "FR":
		siren := fmt.Sprint(1+r.IntN(9)) + digits(r, 8)
		return fmt.Sprintf("FR%02d%s", ((12+3*Mod97(siren))%97+off)%100, siren)
	case "NL":
		for {
			d := fmt.Sprint(1+r.IntN(9)) + digits(r, 7)
			sum := 0
			for i := range 8 {
				sum += int(d[i]-'0') * (9 - i)
			}
			if last := (sum%11 + off) % 11; last < 10 {
				return fmt.Sprintf("NL%s%dB%02d", d, last, 1+r.IntN(20))
			}
		}
	case "DE":
		d := fmt.Sprint(1+r.IntN(9)) + digits(r, 7)
		return fmt.Sprintf("DE%s%d", d, (deCheck(d)+off)%10)
	}
	n := 100000 + r.IntN(900000)
	return fmt.Sprintf("LU%d%02d", n, (n%89+off)%100)
}

// deCheck is the ISO 7064 MOD 11,10 check digit of 8 digits.
func deCheck(d string) int {
	p := 10
	for i := range 8 {
		s := (int(d[i]-'0') + p) % 10
		if s == 0 {
			s = 10
		}
		p = 2 * s % 11
	}
	if c := 11 - p; c != 10 {
		return c
	}
	return 0
}

// formatVAT writes a VAT number bare, with a space after the prefix,
// grouped as it is printed on invoices, or in lower case.
func formatVAT(r *rand.Rand, v string) string {
	cc, n := v[:2], v[2:]
	switch r.IntN(10) {
	case 0, 1, 2, 3:
		return v
	case 4, 5:
		return cc + " " + n
	case 6, 7, 8:
		switch cc {
		case "BE":
			return cc + pick(r, []string{"", " "}) + n[:4] + "." + n[4:7] + "." + n[7:]
		case "FR":
			return cc + " " + n[:2] + " " + n[2:5] + " " + n[5:8] + " " + n[8:]
		case "DE":
			return cc + " " + n[:3] + " " + n[3:6] + " " + n[6:]
		}
		return cc + " " + n
	}
	return strings.ToLower(v)
}

// --- identity documents and birth dates

// EIDValid checks the 12 digits of a Belgian identity card number: the
// last 2 are the first 10 mod 97 (97 for 0).
func EIDValid(d string) bool {
	c := Mod97(d[:10])
	if c == 0 {
		c = 97
	}
	return c == int(d[10]-'0')*10+int(d[11]-'0')
}

func beEID(r *rand.Rand, valid bool) string {
	for {
		body := fmt.Sprintf("59%d", r.IntN(10)) + digits(r, 7)
		c := Mod97(body)
		if c == 0 {
			c = 97
		}
		if !valid {
			c = (c + 1 + r.IntN(90)) % 100
		}
		if d := fmt.Sprintf("%s%02d", body, c); EIDValid(d) == valid {
			return d
		}
	}
}

func formatEID(d string) string { return d[:3] + "-" + d[3:10] + "-" + d[10:] }

func passportNumber(r *rand.Rand) string {
	return pick(r, []string{"EH", "EJ", "EK", "EL", "EM", "EN", "EP"}) + digits(r, 6)
}

var monthsByLang = map[string][]string{
	"en": {"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"},
	"fr": {"janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"},
	"nl": {"januari", "februari", "maart", "april", "mei", "juni", "juli", "augustus", "september", "oktober", "november", "december"},
	"de": {"Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober", "November", "Dezember"},
}

// birthDate writes a date between 1930 and 2009 as people of lang write
// it: numeric (day first, but month first in en one time in three), ISO,
// or with the month name.
func birthDate(r *rand.Rand, lang string) (string, bool) {
	d, m, y := 1+r.IntN(28), 1+r.IntN(12), 1930+r.IntN(80)
	month := monthsByLang[lang][m-1]
	switch r.IntN(4) {
	case 0:
		return fmt.Sprintf("%04d-%02d-%02d", y, m, d), false
	case 1:
		switch lang {
		case "en":
			if r.IntN(3) == 0 {
				return fmt.Sprintf("%s %d, %d", month, d, y), false
			}
			return fmt.Sprintf("%d %s %d", d, month, y), false
		case "fr":
			if d == 1 {
				return fmt.Sprintf("1er %s %d", month, y), false
			}
		case "de":
			return fmt.Sprintf("%d. %s %d", d, month, y), false
		}
		return fmt.Sprintf("%d %s %d", d, month, y), false
	}
	sep := map[string]string{"en": "/", "fr": "/", "nl": "-", "de": "."}[lang]
	if lang == "en" && r.IntN(3) == 0 {
		return fmt.Sprintf("%02d/%02d/%04d", m, d, y), false
	}
	return fmt.Sprintf("%02d%s%02d%s%04d", d, sep, m, sep, y), false
}

// --- phones: 'd' is a random digit. The shapes keep to the ranges set
// aside for fiction where a country has one (UK 020 7946 0xxx and
// 07700 900xxx, US 555-01xx, France 01 99 00 and 06 39 98).

var phoneShapes = map[string][]string{
	"en": {"+44 20 7946 0ddd", "020 7946 0ddd", "07700 900ddd", "+44 7700 900ddd", "0044 20 7946 0ddd", "+1 415 555 01dd", "+1-212-555-01dd"},
	"fr": {"01 99 00 dd dd", "+33 1 99 00 dd dd", "06 39 98 dd dd", "06.39.98.dd.dd", "0033 6 39 98 dd dd", "02 ddd dd dd", "+32 2 ddd dd dd", "0475 dd dd dd"},
	"nl": {"06 dd dd dd dd", "06-dddddddd", "+31 6 dddddddd", "020-ddd dddd", "0031 20 ddd dddd", "0475 dd dd dd", "+32 475 dd dd dd", "09 ddd dd dd"},
	"de": {"030 ddddddd", "+49 30 ddddddd", "0151 dddddddd", "+49 151 dddddddd", "0049 89 dddddd", "089/dddddd", "(030) dddd ddd"},
}

var loosePhoneShapes = map[string][]string{
	"en": {"(415) 555-01dd", "415-555-01dd", "415 555 01dd", "(212) 555-01dd", "20 7946 0ddd", "7700 900ddd"},
	"fr": {"33 6 39 98 dd dd", "475 dd dd dd", "6 39 98 dd dd", "1 99 00 dd dd", "2 ddd dd dd"},
	"nl": {"20 ddd dddd", "475 dd dd dd", "6 dddddddd", "31 6 dddddddd", "10 ddd dddd"},
	"de": {"30 ddddddd", "151 dddddddd", "49 30 ddddddd", "89 dddddd", "171 ddddddd"},
}

// --- e-mail addresses

var emailDomains = []string{"example.com", "example.org", "example.net", "mail.example.com", "shop.example.org", "example.co.uk"}

func emailValue(r *rand.Rand, lang string) (string, bool) {
	g, s := asciiFold(pick(r, givenNames[lang])), asciiFold(pick(r, surnames[lang]))
	hard := false
	var local string
	switch r.IntN(8) {
	case 0:
		local = g[:1] + s
	case 1:
		local = g + "." + s + digits(r, 2)
	case 2:
		local = g + "+" + pick(r, []string{"news", "shop", "billing"})
	case 3:
		local = s + "_" + g
	case 4:
		// A local part with its accents (RFC 6531).
		local, hard = pick(r, accented[lang]), true
	default:
		local = g + "." + s
	}
	v := local + "@" + pick(r, emailDomains)
	if r.IntN(10) == 0 {
		v = strings.ToUpper(v[:1]) + v[1:]
	}
	return v, hard
}

var accented = map[string][]string{
	"en": {"zoë.brontë", "renée.o'hara", "chloë.ashby"},
	"fr": {"rené.lefèvre", "éloïse.béranger", "françois.mérieux"},
	"nl": {"daniël.öztürk", "anaïs.vanderbeek", "noël.verhaegen"},
	"de": {"jürgen.müller", "björn.groß", "käthe.schäfer"},
}

func asciiFold(s string) string {
	r := strings.NewReplacer("é", "e", "è", "e", "ë", "e", "ï", "i", "ö", "o", "ü", "u", "ä", "a", "ç", "c", "ß", "ss")
	return strings.ToLower(r.Replace(s))
}

// --- person names

// givenNames and surnames are in the detector's gazetteer; synthetic
// names are built from syllables, mostly outside it.
var givenNames = map[string][]string{
	"en": {"john", "emma", "oliver", "sarah", "james", "olivia", "michael", "laura", "thomas", "rachel", "george", "hannah", "peter", "alice"},
	"fr": {"jean", "marie", "nicolas", "isabelle", "thierry", "céline", "chloé", "mathieu", "sophie", "laurent", "camille", "julien", "nathalie", "pascale"},
	"nl": {"wout", "lotte", "pieter", "sanne", "joris", "femke", "bram", "lien", "maarten", "eline", "katrien", "geert", "hanne", "dries"},
	"de": {"wolfgang", "sabine", "katharina", "stefan", "ulrike", "tobias", "birgit", "dieter", "heike", "klaus", "petra", "jens", "monika", "lukas"},
}

var surnames = map[string][]string{
	"en": {"anderson", "bennett", "campbell", "bailey", "armstrong", "butler", "carpenter", "barker", "bishop", "burke"},
	"fr": {"bernard", "bertrand", "bonnet", "boyer", "brunet", "blanc", "benoit", "lefebvre", "dubois", "lambert"},
	"nl": {"wouters", "claessens", "lemmens", "goossens", "desmet", "peeters", "jacobs", "hermans", "aerts", "wuyts"},
	"de": {"bauer", "baumann", "becker", "berger", "schneider", "fischer", "weber", "hoffmann", "schulz", "koch"},
}

var (
	syllOnsets = []string{"ta", "mo", "ve", "li", "ka", "ro", "se", "du", "fa", "ni", "be", "zo", "qui", "ar", "ely"}
	syllMids   = []string{"", "ra", "le", "vi", "no", "sa", "ri"}
	syllEnds   = []string{"n", "ric", "mir", "del", "via", "lo", "th", "ane", "ys"}
	surnameEnd = map[string][]string{
		"en": {"wick", "thorpe", "ley", "combe", "hurst"},
		"fr": {"ac", "ville", "ière", "court", "mont"},
		"nl": {"aert", "mans", "hoven", "ens", "inckx"},
		"de": {"mann", "berg", "hauser", "inger", "stedt"},
	}
)

func title(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	return strings.ToUpper(string(r)) + s[n:]
}

func syntheticGiven(r *rand.Rand) string {
	return title(pick(r, syllOnsets) + pick(r, syllMids) + pick(r, syllEnds))
}

func syntheticSurname(r *rand.Rand, lang string) string {
	return title(pick(r, syllOnsets) + pick(r, syllMids) + pick(r, surnameEnd[lang]))
}

func knownName(r *rand.Rand, lang string) string {
	return title(pick(r, givenNames[lang])) + " " + title(pick(r, surnames[lang]))
}

var honorificsByLang = map[string][]string{
	"en": {"Mr. ", "Mrs. ", "Ms ", "Dr. "},
	"fr": {"M. ", "Mme ", "Mlle ", "Dr "},
	"nl": {"Dhr. ", "Mevr. ", "Mevrouw ", "Dr. "},
	"de": {"Herr ", "Frau ", "Dr. ", "Prof. "},
}

func personName(r *rand.Rand, lang string) (string, bool) {
	surname := func() string {
		if r.IntN(3) == 0 {
			return syntheticSurname(r, lang)
		}
		return title(pick(r, surnames[lang]))
	}
	switch n := r.IntN(20); {
	case n < 7:
		// A given name outside the gazetteer.
		return syntheticGiven(r) + " " + surname(), true
	case n < 9:
		// "Smith, John": surname first.
		return title(pick(r, surnames[lang])) + ", " + title(pick(r, givenNames[lang])), true
	case n < 12:
		return pick(r, honorificsByLang[lang]) + unspanned + surname(), false
	case n < 14:
		return strings.ToUpper(knownName(r, lang)), false
	case n < 16:
		return strings.ToLower(knownName(r, lang)), false
	case n < 17:
		return title(pick(r, givenNames[lang])) + " " + letters(r, 1) + ". " + title(pick(r, surnames[lang])), false
	}
	return title(pick(r, givenNames[lang])) + " " + surname(), false
}

// --- IP addresses: documentation ranges and public resolvers only

func ipValue(r *rand.Rand, _ string) (string, bool) {
	switch n := r.IntN(10); {
	case n < 5:
		return fmt.Sprintf("%s.%d", pick(r, []string{"192.0.2", "198.51.100", "203.0.113"}), 1+r.IntN(254)), false
	case n < 6:
		return pick(r, []string{"1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "208.67.222.222"}), false
	case n < 8:
		return fmt.Sprintf("2001:db8:%x::%x", r.IntN(0xffff), 1+r.IntN(0xfff)), false
	case n < 9:
		return pick(r, []string{"2606:4700:4700::1111", "2001:4860:4860::8888", "2620:fe::fe"}), false
	}
	return fmt.Sprintf("::ffff:203.0.113.%d", 1+r.IntN(254)), true
}

// --- secrets

// passwordChars are those a password can hold unescaped in every frame
// (a URL's userinfo has no "#" or "%").
const passwordChars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!*-_"

func secretValue(r *rand.Rand, _ string) (string, bool) {
	if r.IntN(4) == 0 {
		// A JSON Web Token shape: header {"alg":"HS256"}, random rest.
		return "eyJhbGciOiJIUzI1NiJ9." + b64url(r, 30) + "." + b64url(r, 43), false
	}
	n := 14 + r.IntN(14)
	b := make([]byte, n)
	for i := range b {
		b[i] = passwordChars[r.IntN(len(passwordChars))]
	}
	return string(b), false
}

func b64url(r *rand.Rand, n int) string {
	const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	b := make([]byte, n)
	for i := range b {
		b[i] = a[r.IntN(len(a))]
	}
	return string(b)
}
