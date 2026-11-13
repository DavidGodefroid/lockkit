package pii

import "strings"

// --- value prefilters
//
// On a short text (the common log message: "order confirmed in 123ms"),
// starting a regexp costs more than the text is worth. Each finder below
// first checks a byte-level condition that every one of its matches
// fulfils, and returns nothing when the text fails it. A prefilter never
// changes a result: a text that passes runs the same scan as before
// (TestValuePrefiltersAreExact, FuzzValuePrefiltersAreExact). The finder
// is handed the text or one of its detection views, so the prefilter sees
// what the regexp would see.

// Least ASCII digits a match holds: the digits of each regexp, its
// shortest alternative (the French NIR's Corsican "2A" form drops one).
const (
	cardMinDigits = 13 // [0-9](?:[ \-]?[0-9]){12,18}
	nissMinDigits = 11 // 2+2+2+3+2
	nirMinDigits  = 14 // 1+2+2+1+3+3+2, "2A" for the department
	bsnMinDigits  = 9  // [0-9]{9} or 4.2.3
	ssnMinDigits  = 9  // 3-2-4
)

// hasDigits reports whether s holds at least n ASCII digits.
func hasDigits(s string, n int) bool {
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			if n--; n == 0 {
				return true
			}
		}
	}
	return false
}

func findEmails(s string) []span {
	if strings.IndexByte(s, '@') < 0 {
		return nil
	}
	return scanEmails(s)
}

func findCards(s string) []span {
	if !hasDigits(s, cardMinDigits) {
		return nil
	}
	return scanCards(s)
}

func findNISS(s string) []span {
	if !hasDigits(s, nissMinDigits) {
		return nil
	}
	return scanNISS(s)
}

func findNIR(s string) []span {
	if !hasDigits(s, nirMinDigits) {
		return nil
	}
	return scanNIR(s)
}

func findBSN(s string) []span {
	if !hasDigits(s, bsnMinDigits) {
		return nil
	}
	return scanBSN(s)
}

func findSSN(s string) []span {
	if !hasDigits(s, ssnMinDigits) {
		return nil
	}
	return scanSSN(s)
}

func findIBANs(s string) []span {
	if !hasIBANPrefix(s) {
		return nil
	}
	return scanIBANs(s)
}

// hasIBANPrefix reports whether s may hold ibanRe's mandatory prefix,
// (?i)[A-Z]{2}[0-9]{2}: two ASCII digits after two letters. The (?i) also
// folds "k" to the Kelvin sign and "s" to the long s, so any byte outside
// ASCII stands for a letter: the regexp decides.
func hasIBANPrefix(s string) bool {
	for i := 2; i+1 < len(s); i++ {
		if isDigit(s[i]) && isDigit(s[i+1]) && ibanLetterByte(s[i-1]) && ibanLetterByte(s[i-2]) {
			return true
		}
	}
	return false
}

func ibanLetterByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= 0x80
}

// findIPs needs two colons for an IPv6 address or three dots for an IPv4
// one; jsonEscapeView, which it reads through, adds neither.
func findIPs(s string) []span {
	if strings.Count(s, ":") < 2 && strings.Count(s, ".") < 3 {
		return nil
	}
	return scanIPs(s)
}
