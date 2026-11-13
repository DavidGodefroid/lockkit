package pii

import (
	"regexp"
	"strings"
)

// --- Belgian company number (KBO/BCE, mod 97)

// beCompanyRe is the written forms: 0xxx.xxx.xxx or 0xxx xxx xxx (one
// separator throughout). Ten bare digits collide with phone numbers: they
// are not found here.
var beCompanyRe = regexp.MustCompile(`[01][0-9]{3}[. ][0-9]{3}[. ][0-9]{3}`)

func findBECompany(s string) []gspan {
	var out []gspan
	for _, sp := range scan(s, beCompanyRe, 12, func(s string, start, end int) (int, bool) {
		if b := before(s, start); isAlnum(b) || b == '.' || b == '-' || b == '+' || b == '/' {
			return 0, false
		}
		if !numberEnds(s, end) || s[start+4] != s[start+8] {
			return 0, false
		}
		return end, beCompanyValid(digitsOf(s[start:end]))
	}) {
		out = append(out, gspan{sp, ConfidenceHigh})
	}
	return out
}

// numberEnds reports that a number ends at s[i]: no letter or digit
// follows, nor a separator and a digit ("0123.456.749.1").
func numberEnds(s string, i int) bool {
	a := after(s, i)
	if isAlnum(a) {
		return false
	}
	return !(a == '.' || a == '-' || a == '/' || a == ',') || !isDigit(after(s, i+1))
}

// beCompanyValid checks 10 digits of a Belgian company number: a leading
// 0 or 1, and 97 - (the first 8 mod 97) as the last 2.
func beCompanyValid(d string) bool {
	if len(d) != 10 || d[0] != '0' && d[0] != '1' {
		return false
	}
	return 97-mod97(d[:8]) == int(d[8]-'0')*10+int(d[9]-'0')
}

// --- EU VAT numbers (BE, FR, NL, DE, LU)

// euVATRe is a country prefix in either case, an optional space, and the
// national number in its usual written forms.
var euVATRe = regexp.MustCompile(`(?i)(?:` +
	`BE ?[01][0-9]{3}[. ]?[0-9]{3}[. ]?[0-9]{3}` +
	`|FR ?[0-9A-Z]{2} ?[0-9]{3} ?[0-9]{3} ?[0-9]{3}` +
	`|NL ?[0-9]{9}B[0-9]{2}` +
	`|DE ?[0-9]{3} ?[0-9]{3} ?[0-9]{3}` +
	`|LU ?[0-9]{8})`)

func findEUVAT(s string) []gspan {
	var out []gspan
	scan(s, euVATRe, 18, func(s string, start, end int) (int, bool) {
		if isAlnum(before(s, start)) || !numberEnds(s, end) {
			return 0, false
		}
		ok, conf := euVATValid(s[start:end])
		if ok {
			out = append(out, gspan{span{start, end}, conf})
		}
		return end, ok
	})
	return out
}

// euVATValid checks a VAT number as euVATRe matched it, and grades it: a
// French number with a letter in its key has no public check (medium).
func euVATValid(v string) (bool, Confidence) {
	cc := strings.ToUpper(v[:2])
	body := strings.ToUpper(strings.Map(func(r rune) rune {
		if r == ' ' || r == '.' {
			return -1
		}
		return r
	}, v[2:]))
	switch cc {
	case "BE":
		// After the prefix: one separator throughout, or none.
		n := strings.TrimPrefix(v[2:], " ")
		if a, b := n[4], n[len(n)-4]; (a == ' ' || a == '.' || b == ' ' || b == '.') && a != b {
			return false, 0
		}
		return beCompanyValid(body), ConfidenceHigh
	case "FR":
		key, siren := body[:2], body[2:]
		if !isDigit(key[0]) || !isDigit(key[1]) {
			return true, ConfidenceMedium
		}
		return (12+3*mod97(siren))%97 == int(key[0]-'0')*10+int(key[1]-'0'), ConfidenceHigh
	case "NL":
		return elevenProof(body[:9]) || mod97("NL"+body) == 1, ConfidenceHigh
	case "DE":
		return deVATValid(body), ConfidenceHigh
	case "LU":
		return atoi(body[:6])%89 == atoi(body[6:]), ConfidenceHigh
	}
	return false, 0
}

// elevenProof is the Dutch 11-proof on 9 digits, the last weighted -1.
func elevenProof(d string) bool {
	sum := 0
	for i := 0; i < 8; i++ {
		sum += int(d[i]-'0') * (9 - i)
	}
	sum -= int(d[8] - '0')
	return sum%11 == 0 && d != "000000000"
}

// deVATValid checks 9 digits with ISO 7064 MOD 11,10.
func deVATValid(d string) bool {
	p := 10
	for i := 0; i < 8; i++ {
		s := (int(d[i]-'0') + p) % 10
		if s == 0 {
			s = 10
		}
		p = 2 * s % 11
	}
	check := 11 - p
	if check == 10 {
		check = 0
	}
	return check == int(d[8]-'0')
}

func atoi(d string) int {
	n := 0
	for i := 0; i < len(d); i++ {
		n = n*10 + int(d[i]-'0')
	}
	return n
}
