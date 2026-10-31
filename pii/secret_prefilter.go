package pii

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

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
// case; words are lower case ASCII. The (?i) of authSchemeRe also folds
// some ASCII letters to runes outside ASCII ("k" to the Kelvin sign
// U+212A, "s" to the long s U+017F): a text that holds one of those runes
// passes, so that the regexp decides; folds holds them
// (nonASCIIFolds(words)).
func containsAnyFold(s string, words []string, folds string) bool {
	if strings.ContainsAny(s, folds) {
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

var authSchemeFold = nonASCIIFolds(authSchemeWords)

// nonASCIIFolds returns every rune outside ASCII that unicode.SimpleFold
// relates to a letter of words.
func nonASCIIFolds(words []string) string {
	var b strings.Builder
	seen := map[rune]bool{}
	for _, w := range words {
		for _, r := range w {
			for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
				if f > unicode.MaxASCII && !seen[f] {
					seen[f] = true
					b.WriteRune(f)
				}
			}
		}
	}
	return b.String()
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
	if !containsAnyFold(s, authSchemeWords, authSchemeFold) {
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

// pairKeyBytes bounds what pairRe matches before the blanks ahead of its
// separator: a 2-byte opening quote, "--", four "_", a 64-rune key of at
// most 4 bytes a rune, a 2-byte closing quote.
const pairKeyBytes = 2 + 2 + 4 + 64*utf8.UTFMax + 2

// pairWindow returns where a pairRe search from pos may start without
// missing its leftmost match, or false when none can follow. Every match
// holds a separator ("=", ":" or "=>"), and the bytes before the first one
// it holds are an opening quote (which may itself be ":"), a key, a
// closing quote and blanks, none of them "=" or ":" but that quote: the
// leftmost match starts at most pairKeyBytes before the blanks ahead of
// the first separator after pos. Go's regexp otherwise runs its automaton
// over every byte of a text without one.
func pairWindow(s string, pos int) (int, bool) {
	k := strings.IndexAny(s[pos:], "=:")
	if k < 0 {
		return 0, false
	}
	k += pos
	for k > pos && (s[k-1] == ' ' || s[k-1] == '\t') {
		k--
	}
	return max(pos, k-pairKeyBytes), true
}
