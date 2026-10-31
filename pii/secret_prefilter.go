package pii

import "strings"

// --- literal prefilters
//
// Go's regexp has no fast path for an alternation without a literal
// prefix: it runs its automaton from every position of the text. Each
// finder below first checks for a literal that every one of its matches
// must contain, and returns nothing when the text has none. A prefilter
// never changes a result: a text that passes runs the same regexp as
// before (TestSecretPrefiltersAreExact, FuzzSecretPrefiltersAreExact).

// tokenShapeLits holds, for each alternative of tokenShapeRe in order, the
// literals one of which every match of that alternative contains.
var tokenShapeLits = []string{
	"eyJ",
	"AKIA", "ASIA", "ABIA", "ACCA", "AGPA", "AIDA", "AROA", "ANPA", "ANVA", "AIPA",
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_",
	"github_pat_",
	"glpat-", "gldt-", "glrt-", "glptt-", "glsoat-", "glft-", "glimt-", "glagent-", "glcbt-", "gloas-",
	"xox",
	"hooks.slack.com/",
	"_live_", "_test_",
	"whsec_",
	"AIza",
	"GOCSPX-",
	"1//0",
	"ya29.",
	"sk-",
	"npm_",
	"pypi-",
	"rubygems_",
	"dckr_pat_",
	"hf_",
	"_v1_",
	"shpat_", "shpca_", "shppa_", "shpss_",
	"glc_", "glsa_",
	"PMAK-",
	"dp.",
	"lin_api_", "lin_oauth_",
	"ATATT3",
	"hvs.", "hvb.", "hvr.",
	"SG.",
	"key-",
	":AA",
	"AccountKey=",
}

// authSchemeWords are the words of authSchemeRe, matched ignoring ASCII case.
var authSchemeWords = []string{"bearer", "basic", "token", "apikey", "api-key", "negotiate", "ntlm", "aws4-hmac-sha256"}

func containsAny(s string, lits []string) bool {
	for _, l := range lits {
		if strings.Contains(s, l) {
			return true
		}
	}
	return false
}

// containsAnyFold reports whether s contains one of words, ignoring ASCII
// case; words are lower case. The (?i) of authSchemeRe also folds "K" to
// the Kelvin sign U+212A, which no word contains, and "s" to the long s
// U+017F, which "basic" and "aws4-hmac-sha256" contain: a text with
// U+017F passes, so that the regexp decides.
func containsAnyFold(s string, words []string) bool {
	if strings.Contains(s, "ſ") {
		return true
	}
	for i := 0; i < len(s); i++ {
		c := lowerASCII(s[i])
		for _, w := range words {
			if c != w[0] || len(s)-i < len(w) {
				continue
			}
			j := 1
			for j < len(w) && lowerASCII(s[i+j]) == w[j] {
				j++
			}
			if j == len(w) {
				return true
			}
		}
	}
	return false
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

func findTokenShapes(s string) []span {
	if !containsAny(s, tokenShapeLits) {
		return nil
	}
	return scanTokenShapes(s)
}

func findAuthSchemes(s string) []span {
	if !containsAnyFold(s, authSchemeWords) {
		return nil
	}
	return scanAuthSchemes(s)
}

func findUserinfo(s string) []span {
	if !strings.Contains(s, "://") {
		return nil
	}
	return scanUserinfo(s)
}

func findMySQLPasswords(s string) []span {
	if !strings.Contains(s, "-p") && !strings.Contains(s, "-u") {
		return nil
	}
	return scanMySQLPasswords(s)
}
