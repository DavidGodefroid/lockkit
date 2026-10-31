package pii

import (
	"encoding/base64"
	"math"
	"regexp"
	"strings"
	"unicode/utf8"
)

// --- secrets: credentials, tokens and keys written in a text
//
// The secret detector finds the value of a credential, never its label:
// "Authorization: Bearer <value>", "password=<value>", "-----BEGIN
// PRIVATE KEY-----...", a token whose shape names its issuer. Its spans
// are masked whole as Redacted (never a first character or a length).
// What it cannot see is documented in GUIDE §8: secrets without a known
// shape or label (short tokens, passwords in prose, session ids in URL
// paths, connection strings without userinfo, base64 or hex content).

// maxCandidate bounds the value of a key with no credential name that
// the detector reads to judge its shape: a longer one is content (a
// payload, a blob), not a credential. A secret-named value is read whole,
// and a later pair that starts inside it is skipped, so that no byte is
// read twice.
const maxCandidate = 1 << 10

// findSecrets returns the spans of every secret value of s, merged.
func findSecrets(s string) []span {
	var out []span
	out = append(out, findPEM(s)...)
	out = append(out, findTokenShapes(s)...)
	out = append(out, findAuthSchemes(s)...)
	out = append(out, findUserinfo(s)...)
	out = append(out, findSecretPairs(s)...)
	out = append(out, findSecretFlags(s)...)
	out = append(out, findMySQLPasswords(s)...)
	out = append(out, findNameValuePairs(s)...)
	if len(out) == 0 {
		return nil
	}
	return mergeSpans(out)
}

// --- PEM private keys

var pemBeginRe = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----`)
var pemEndRe = regexp.MustCompile(`-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----`)

// findPEM masks a private key block from its BEGIN line to its END line,
// or to the end of the text when it has none (a key cut by a line limit).
func findPEM(s string) []span {
	var out []span
	for _, m := range pemBeginRe.FindAllStringIndex(s, -1) {
		if n := len(out); n > 0 && m[0] < out[n-1].end {
			continue
		}
		end := len(s)
		if e := pemEndRe.FindStringIndex(s[m[1]:]); e != nil {
			end = m[1] + e[1]
		}
		out = append(out, span{m[0], end})
	}
	return out
}

// --- tokens whose shape names their issuer

// tokenShapeRe lists the shapes of well-known credentials. Each must stand
// alone: tokenShapes checks that no token character touches a match.
var tokenShapeRe = regexp.MustCompile(strings.Join([]string{
	// JSON Web Token (and JWS/JWE compact forms): base64url "{" header.
	`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`,
	// AWS access key ids.
	`(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}`,
	// GitHub tokens (classic and fine-grained).
	`gh[pousr]_[A-Za-z0-9]{36,255}`,
	`github_pat_[A-Za-z0-9_]{22,255}`,
	// GitLab.
	`gl(?:pat|dt|rt|ptt|soat|ft|imt|agent|cbt|oas)-[A-Za-z0-9_-]{20,}`,
	// Slack tokens and webhooks.
	`xox[abposre]-[A-Za-z0-9-]{10,}`,
	`hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]{16,}`,
	// Stripe.
	`(?:sk|rk|pk|whsec)_(?:live|test)_[A-Za-z0-9]{10,}`,
	`whsec_[A-Za-z0-9]{24,}`,
	// Google API keys and OAuth client secrets, refresh tokens.
	`AIza[0-9A-Za-z_-]{35}`,
	`GOCSPX-[0-9A-Za-z_-]{20,}`,
	`1//0[0-9A-Za-z_-]{30,}`,
	`ya29\.[0-9A-Za-z_-]{20,}`,
	// OpenAI, Anthropic and other "sk-" keys.
	`sk-(?:proj-|ant-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}`,
	// npm, PyPI, RubyGems, Docker Hub, Hugging Face, DigitalOcean,
	// Shopify, Grafana, Postman, Doppler, Linear, Atlassian, Vault.
	`npm_[A-Za-z0-9]{36}`,
	`pypi-[A-Za-z0-9_-]{50,}`,
	`rubygems_[a-f0-9]{48}`,
	`dckr_pat_[A-Za-z0-9_-]{20,}`,
	`hf_[A-Za-z0-9]{30,}`,
	`do[por]_v1_[a-f0-9]{64}`,
	`shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}`,
	`gl(?:c|sa)_[A-Za-z0-9_+/=-]{32,}`,
	`PMAK-[a-f0-9]{24}-[a-f0-9]{34}`,
	`dp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,}`,
	`lin_(?:api|oauth)_[A-Za-z0-9]{40}`,
	`ATATT3[A-Za-z0-9_=-]{100,}`,
	`hv[sbr]\.[A-Za-z0-9_-]{24,}`,
	// SendGrid, Mailgun, Twilio API key secrets, Telegram bot tokens.
	`SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}`,
	`key-[0-9a-zA-Z]{32}`,
	`[0-9]{8,10}:AA[A-Za-z0-9_-]{33}`,
	// Azure storage account keys and SAS signatures in a connection string.
	`AccountKey=[A-Za-z0-9+/]{40,}={0,2}`,
}, "|"))

func scanTokenShapes(s string) []span {
	var out []span
	eachMatch(s, tokenShapeRe, func(start int) bool {
		// Only a letter or a digit continues a token: "key=<token>",
		// "a:<token>" and "/<token>" start one.
		return !isLetterDigit(before(s, start)) || strings.HasPrefix(s[start:], "hooks.")
	}, func(m []int) int {
		start, end := m[0], m[1]
		// A longer token than the shape allows is still one token.
		for end < len(s) && isTokenByte(s[end]) {
			end++
		}
		if strings.HasPrefix(s[start:end], "AccountKey=") {
			start += len("AccountKey=")
		} else if strings.HasPrefix(s[start:end], "hooks.") {
			start += strings.IndexByte(s[start:end], '/') + 1 // the host stays in clear
		}
		out = append(out, span{start, end})
		return end
	})
	return out
}

func hasLetter(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80 {
			return true
		}
	}
	return false
}

func isLetterDigit(c byte) bool { return isDigit(c) || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// eachMatch calls f with every match of re in s whose start passes ok
// (the boundary RE2 cannot look behind for), then searches again from
// the offset f returns; a refused match is retried one rune on.
func eachMatch(s string, re *regexp.Regexp, ok func(start int) bool, f func(m []int) int) {
	eachMatchGlue(s, re, isAlnum, nil, ok, f)
}

// eachMatchGlue is eachMatch where a refused match skips the rest of the
// run of glue bytes it starts in (any match starting there is refused too).
//
// window, when set, moves a search start forward to where a match can
// begin (see pairWindow), or reports that none can.
func eachMatchGlue(s string, re *regexp.Regexp, glue func(byte) bool, window func(s string, pos int) (int, bool), ok func(start int) bool, f func(m []int) int) {
	for pos := 0; pos <= len(s); {
		if window != nil {
			w, more := window(s, pos)
			if !more {
				return
			}
			pos = w
		}
		m := re.FindStringSubmatchIndex(s[pos:])
		if m == nil {
			return
		}
		for k := range m {
			if m[k] >= 0 {
				m[k] += pos
			}
		}
		next := m[0] + 1
		if !ok(m[0]) {
			// Refused: any match starting inside the same word is too.
			for next < len(s) && glue(s[next]) && glue(s[next-1]) && !escapeBoundary(s, next) {
				next++
			}
		} else {
			if n := f(m); n > m[0] {
				next = n
			}
		}
		for next < len(s) && !utf8.RuneStart(s[next]) {
			next++
		}
		pos = next
	}
}

// isTokenByte reports a byte that may continue a token: base64, base64url
// and the separators token shapes use.
func isTokenByte(c byte) bool {
	return isAlnum(c) || c == '-' || c == '+' || c == '/' || c == '='
}

// --- Authorization schemes: "Bearer <token>", "Basic <base64>"

var authSchemeRe = regexp.MustCompile(`(?i)(bearer|basic|token|apikey|api-key|negotiate|ntlm|aws4-hmac-sha256)[ \t]+`)

// findAuthSchemes masks the credential after an authorization scheme
// word. A credential must look like one, so that prose ("basic
// authentication", "bearer token required") stays in clear: a Basic
// credential is base64 of "user:password"; another is at least 8 token
// characters with a digit or a token separator, or at least 20.
func scanAuthSchemes(s string) []span {
	var out []span
	eachMatch(s, authSchemeRe, func(start int) bool {
		b := before(s, start)
		return !isAlnum(b)
	}, func(m []int) int {
		scheme := strings.ToLower(s[m[2]:m[3]])
		start := m[1]
		if scheme == "aws4-hmac-sha256" {
			// "AWS4-HMAC-SHA256 Credential=…, SignedHeaders=…, Signature=…"
			end := lineEnd(s, start, true)
			out = append(out, span{start, end})
			return end
		}
		end := start
		for end < len(s) && isCredentialByte(s[end]) {
			end++
		}
		v := s[start:end]
		switch {
		case scheme == "basic":
			if !basicCredential(v) {
				return start
			}
		case scheme == "token" && !strings.ContainsAny(v, "0123456789"):
			return start // "token expired"
		case strings.Contains(strings.TrimRight(v, "="), "="):
			return start // "token count=42", "token_type=Bearer expires_in=3600": the next pair
		case (scheme == "negotiate" || scheme == "ntlm") && (len(v) < 16 || strings.ContainsAny(v, "-._~")):
			return start // "negotiate cipher-suite": SPNEGO and NTLM are base64
		case !looksCredential(v):
			return start // "Bearer Bearer <token>": the next word may be the scheme
		}
		out = append(out, span{start, end})
		return end
	})
	return out
}

func isCredentialByte(c byte) bool {
	return isAlnum(c) || strings.IndexByte("-._~+/=", c) >= 0
}

func basicCredential(v string) bool {
	if len(v) < 4 {
		return false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(v); err == nil && strings.IndexByte(string(b), ':') > 0 {
			return true
		}
	}
	return false
}

func looksCredential(v string) bool {
	if len(v) < 8 {
		return false
	}
	return len(v) >= 20 || strings.ContainsAny(v, "0123456789-._~+/=")
}

// --- URL userinfo: scheme://user:password@host

// The password runs to the last "@" before a blank: it may hold "@" or "/".
// The user may be an e-mail address (smtp://bob@example.com:pw@host).
var userinfoRe = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]{0,31}://([^\s/?#"'<>:]*:[^\s?#"'<>]*)@`)

// portPath is "5173/…": a port and a path, not a password
// (http://localhost:5173/@vite/client).
var portPath = regexp.MustCompile(`^[0-9]{1,5}/`)

func scanUserinfo(s string) []span {
	var out []span
	for _, m := range userinfoRe.FindAllStringSubmatchIndex(s, -1) {
		if _, pw, _ := strings.Cut(s[m[2]:m[3]], ":"); portPath.MatchString(pw) {
			continue
		}
		if m[3] > m[2] {
			out = append(out, span{m[2], m[3]})
		}
	}
	return out
}

// --- key=value and "key": "value" pairs

// pairRe finds a key followed by "=" or ":" in logfmt, JSON, headers,
// query strings, connection strings and command lines ("--password=x").
// A JSON key may be quoted, and escaped when the JSON is logged inside a
// string (\"password\":\"x\").
var pairRe = regexp.MustCompile(`(\\?["'\[:]?)(-{0,2}_{0,4}[A-Za-z0-9][\pL0-9_.-]{0,63})(\\?["'\]]?)[ \t]*(=>|[:=]|\\u003[dD])[ \t]*`)

func findSecretPairs(s string) []span { return secretPairs(s, pairWindow) }

// secretPairs is findSecretPairs; a nil window searches from every
// position (the reference the window is tested against).
func secretPairs(s string, window func(string, int) (int, bool)) []span {
	s = jsonEscapeView(s) // same offsets
	var out []span
	eachMatchGlue(s, pairRe, func(c byte) bool { return isAlnum(c) || c == '.' || c == '-' }, window, func(start int) bool {
		if escapeLen(s, start) > 0 {
			return false // "\r\nauth=": the key starts after the escape
		}
		b := before(s, start)
		return !isAlnum(b) && b != '.' && b != '-' && b != '\\'
	}, func(m []int) int {
		key := s[m[4]:m[5]]
		start := m[1]
		if !hasLetter(key) {
			return start // "12:30", "8080=": a number, not a key ("2fa_secret" is one)
		}
		if s[m[8]] == ':' && strings.HasPrefix(s[start:], "//") {
			return start // a URL: "https://"
		}
		if (key == "--user" || key == "--proxy-user") && s[m[8]] != ':' {
			v, vs, ve := pairValue(s, start, false, 0)
			if strings.Contains(v, ":") {
				out = append(out, span{vs, ve})
			}
			return max(ve, start) // read once: "--user=--user=…"
		}
		if !isSecretHeader(key) && !LooksSecret(key) && !((s[m[8]] != ':' || m[3] > m[2] || m[7] > m[6]) && odbcPwd(key, s[start:])) || key == "PASS" && s[m[8]] == ':' || passCount(s, key, start) {
			// Search again from the value: a pair may sit inside it
			// ("msg=password=x", "x: password=y").
			if hashName(key) {
				return start // "SHA256:…" fingerprints, checksums, digests
			}
			if v, vs, ve := pairValue(s, start, false, maxCandidate+1); ve > vs && highEntropy(v) {
				out = append(out, span{vs, ve})
				return ve
			}
			return start
		}
		if start >= len(s) {
			return start // "password=" ends the text
		}
		if s[start] == '[' || s[start] == '{' {
			// A JSON array (Go's http.Header: "X-Api-Key":["v"]) or
			// object ("credentials":{"user":"bob","pw":"x"}): the whole
			// value, to its closing bracket.
			end := arrayEnd(s, start)
			if end > start+1 {
				out = append(out, span{start + 1, end})
			}
			return end
		}
		var v string
		var vs int
		if c := s[start]; headerLike(key) && m[6] == m[7] && c != '"' && c != '\'' && c != '\\' {
			// A raw header line (the key is not a quoted JSON key): its
			// value runs to the end of the line, quotes included
			// (`Cookie: a="b"; session=…`, Digest parameters).
			vs = start
			var end int
			if open := s[m[2]:m[3]]; m[6] == m[7] && (strings.HasSuffix(open, `"`) || strings.HasSuffix(open, "'")) {
				// `-H "Authorization: Bearer x" next`: the header sits in
				// a quoted argument, which its closing quote (or the end
				// of the line) ends; one scan, so the text is read once.
				end = closingQuote(s, vs, open)
			} else {
				end = lineEnd(s, vs, true)
			}
			v = strings.TrimRight(s[vs:end], " \t")
		} else {
			v, vs, _ = pairValue(s, start, false, 0)
		}
		scheme := 0
		if isAuthorization(key) {
			scheme = authSchemePrefix(v)
		}
		ve := vs + len(v)
		vs += scheme // keep "Bearer " in clear
		if ve > vs {
			out = append(out, span{vs, ve})
			return ve
		}
		return start
	})
	return out
}

// arrayEnd returns the offset of the "]" or "}" that closes the JSON
// array or object opened at s[i]: nested ones and quoted strings (plain,
// or escaped as \" in a logged JSON string) are skipped, and the value
// may span lines (json.MarshalIndent). A value that never closes (cut, or
// not JSON) runs to the end of the text, so no later element is left in
// clear; the caller skips what it masked, so the text is read once. A
// single quote opens a string only where a value starts ("['a']"), not
// inside a word ("Bob's").
func arrayEnd(s string, i int) int {
	var q byte     // the open quote, 0 outside a string
	esc := false   // the open quote is an escaped \" (JSON logged in a string)
	inner := false // in an escaped string: the last inner character was an unpaired backslash
	open, closing := s[i], byte(']')
	if open == '{' {
		closing = '}'
	}
	depth := 0
	for j := i + 1; j < len(s); j++ {
		c := s[j]
		switch {
		case esc:
			// The text is escaped once: "\\" is one inner backslash,
			// "\"" one inner quote. The inner string closes on an inner
			// quote that no inner backslash escapes.
			quote := false
			if c == '\\' && j+1 < len(s) {
				j++
				c = s[j]
				quote = c == '"'
			}
			switch {
			case inner:
				inner = false
			case c == '\\':
				inner = true
			case quote:
				q, esc = 0, false
			}
		case q != 0 && c == '\\':
			j++
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '\\' && j+1 < len(s) && s[j+1] == '"':
			q, esc, inner = '"', true, false
			j++
		case c == '"' || c == '\'' && !isLetterDigit(s[j-1]):
			q = c
		case c == open:
			depth++
		case c == closing:
			if depth == 0 {
				return j
			}
			depth--
		}
	}
	return len(s)
}

// odbcPwd reports the ODBC and ADO "Pwd=" keyword (the caller checks "="
// or a quoted key: "bash: pwd: command not found" is no password) (a password), told
// from the shell's PWD by its value: a working directory is an absolute
// path ("/home/bob", "~", "C:\\Users").
func odbcPwd(key, v string) bool {
	if !strings.EqualFold(key, "pwd") {
		return false
	}
	v = strings.TrimLeft(v, `"'\`)
	if v == "" {
		return false
	}
	switch c := v[0]; {
	case c == '/' || c == '~' || c == '$' || c == ' ' || c == '\t' || c == '\n' || c == '\r':
		return false
	case len(v) > 2 && isLetterDigit(c) && v[1] == ':' && (v[2] == '\\' || v[2] == '/'):
		return false
	}
	return true
}

// closingQuote returns the offset of the quote that closes open (", ' or
// an escaped \") from s[i], an escaped quote of the plain kind skipped, or
// of the end of the line when there is none.
func closingQuote(s string, i int, open string) int {
	q := open[len(open)-1]
	if strings.HasPrefix(open, "\\") {
		return escapedEnd(s, i, q, len(s))
	}
	for j := i; j < len(s); j++ {
		switch {
		case s[j] == '\n' || s[j] == '\r':
			return j
		case s[j] == '\\':
			j++
		case s[j] == q:
			return j
		}
	}
	return len(s)
}

// escapedEnd returns the offset of the escaped quote (\" or \') that
// closes a string of JSON logged inside a string, from s[i], or of the
// end of the line, or stop. The text is escaped once: `\\` is one inner
// backslash, and an inner quote it escapes (`\\\"`) does not close.
func escapedEnd(s string, i int, q byte, stop int) int {
	inner := false // the last inner character was an unpaired backslash
	for j := i; j < stop; j++ {
		c := s[j]
		if c == '\n' || c == '\r' {
			return j
		}
		if c != '\\' || j+1 >= len(s) {
			inner = false
			continue
		}
		switch n := s[j+1]; {
		case inner:
			inner = false
		case n == '\\':
			inner = true
		case n == q:
			return j
		}
		j++
	}
	return stop
}

// passCount reports a test runner's "pass=10": a count, not a password.
func passCount(s, key string, i int) bool {
	if !strings.EqualFold(key, "pass") {
		return false
	}
	j := i
	for j < len(s) && isDigit(s[j]) {
		j++
	}
	if j == i || isAlnum(after(s, j)) || before(s, i-1) != '=' && before(s, i) != '=' {
		return false
	}
	// A count only right beside a sibling count pair, within 64 bytes
	// ("pass=10 fail=0 skip=2"), never a failed-login line.
	win := strings.ToLower(s[max(0, i-64):min(len(s), j+64)])
	for _, w := range []string{"user", "login", "auth"} {
		if strings.Contains(win, w) {
			return false // a login line: the digits are a password
		}
	}
	return siblingCount.MatchString(s[j:min(len(s), j+64)]) || siblingCount.MatchString(s[max(0, i-64):i])
}

var siblingCount = regexp.MustCompile(`(?:^|[\s,;])(?:fail|failed|skip|skipped|error|errors)=[0-9]+(?:$|[\s,;])`)

// hashName reports a key that names a digest, whose value is high-entropy
// by nature and no credential.
func hashName(key string) bool {
	for _, t := range Tokens(key) {
		switch t {
		case "md5", "sha", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3", "blake2b", "blake3",
			"hash", "checksum", "digest", "etag", "integrity", "fingerprint", "crc32", "h1":
			return true
		}
	}
	return false
}

// pairValue reads the value that starts at s[i]: quoted (to its closing
// quote, escaped quotes skipped, or the end of the line), or unquoted (to
// a blank or a delimiter; with toLineEnd, to the end of the line). It
// reads at most limit bytes when limit > 0.
func pairValue(s string, i int, toLineEnd bool, limit int) (string, int, int) {
	if i >= len(s) {
		return "", i, i
	}
	escaped := false
	q := s[i]
	if q == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\'') {
		escaped, q = true, s[i+1]
		i++
	}
	if q == '"' || q == '\'' {
		start := i + 1
		stop := len(s)
		if limit > 0 {
			stop = min(stop, start+limit)
		}
		if escaped {
			j := escapedEnd(s, start, q, stop)
			return s[start:j], start, j
		}
		for j := start; j < stop; j++ {
			switch {
			case s[j] == '\\':
				j++ // an escaped character, maybe the quote
			case s[j] == q:
				return s[start:j], start, j
			case s[j] == '\n':
				return s[start:j], start, j
			}
		}
		return s[start:stop], start, stop
	}
	stop := len(s)
	if limit > 0 {
		stop = min(stop, i+limit)
	}
	end := i
	if toLineEnd {
		end = min(stop, lineEnd(s, i, true))
	} else {
		for end < stop && strings.IndexByte(" \t\r\n,;&\"'<>|)}]", s[end]) < 0 {
			end++
		}
	}
	for end > i && strings.IndexByte(" \t,;.", s[end-1]) >= 0 {
		end--
	}
	return s[i:end], i, end
}

// lineEnd is the end of the line that holds s[i], or of the JSON string
// it sits in: at a newline, an escaped newline or quote (\n, \"), and,
// unless quotes is set, at a plain quote.
func lineEnd(s string, i int, quotes bool) int {
	end := i
	for end < len(s) && s[end] != '\n' && s[end] != '\r' && (quotes || s[end] != '"') {
		if s[end] == '\\' && end+1 < len(s) && (s[end+1] == 'n' || s[end+1] == 'r' || s[end+1] == '"') {
			break // \n or \" in a logged JSON string
		}
		end++
	}
	return end
}

// headerLike reports a key whose value runs to the end of its line: the
// HTTP headers whose values hold blanks.
func headerLike(key string) bool {
	k := strings.ToLower(strings.TrimLeft(key, "-"))
	return k == "cookie" || k == "set-cookie" || isAuthorization(key)
}

func isAuthorization(key string) bool {
	k := strings.ToLower(strings.TrimLeft(key, "-"))
	return k == "authorization" || k == "proxy-authorization"
}

// isSecretHeader reports the "*-Token" and "*-Key" header names
// (X-Api-Key, X-Auth-Token, Ocp-Apim-Subscription-Key, X-Goog-Api-Key).
func isSecretHeader(key string) bool {
	if !strings.Contains(key, "-") || strings.HasPrefix(key, "-") {
		return false
	}
	toks := Tokens(key)
	if len(toks) < 2 {
		return false
	}
	last := toks[len(toks)-1]
	return last == "token" || last == "key" && secretKeyOwners[toks[len(toks)-2]]
}

// authSchemePrefix returns the length of an authorization scheme word and
// its blanks at the start of v ("Bearer "), or 0.
func authSchemePrefix(v string) int {
	word, rest, ok := strings.Cut(v, " ")
	if !ok {
		return 0
	}
	switch strings.ToLower(word) {
	case "bearer", "basic", "token", "digest", "negotiate", "ntlm", "hoba", "mutual", "apikey", "dpop":
		return len(v) - len(strings.TrimLeft(rest, " "))
	}
	return 0
}

// highEntropy reports a value that looks like a random credential in a
// key or header position: at least 32 base64 or base64url characters with
// upper- and lower-case letters and digits, at least 4 bits of entropy
// per character. Hex (hashes, trace and request ids, kept for tracing),
// UUIDs, paths and URLs are not secrets by shape.
func highEntropy(v string) bool {
	if len(v) < 32 || len(v) > maxCandidate || v[0] == '/' || strings.Contains(v, "://") {
		return false
	}
	var upper, lower, digit bool
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case isDigit(c):
			digit = true
		case strings.IndexByte("+/=_-.~", c) >= 0:
		default:
			return false
		}
	}
	if strings.IndexByte(v, '/') >= 0 && fileExt.MatchString(v) {
		return false // a relative path: src/main/java/…/Abc.java
	}
	return upper && lower && digit && !qualifiedName.MatchString(v) && entropy(v) >= 4.0
}

var fileExt = regexp.MustCompile(`\.[A-Za-z][A-Za-z0-9]{0,4}$`)

// qualifiedName is a dotted identifier: a Java class or a package, a
// logger name, a module path.
var qualifiedName = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$`)

// entropy is the Shannon entropy of the bytes of v, in bits per byte.
func entropy(v string) float64 {
	var n [256]int
	for i := 0; i < len(v); i++ {
		n[v[i]]++
	}
	h := 0.0
	for _, c := range n {
		if c > 0 {
			p := float64(c) / float64(len(v))
			h -= p * math.Log2(p)
		}
	}
	return h
}

// --- command-line flags: "--password hunter2", "curl -u user:pass"

var flagRe = regexp.MustCompile(`(--?[A-Za-z][A-Za-z0-9_-]{0,63})[ \t]+`)

func findSecretFlags(s string) []span {
	s = blankEscapes(s) // "a\\n--password\\tx" in a JSON string; same offsets
	var out []span
	eachMatch(s, flagRe, func(start int) bool {
		b := before(s, start)
		return b == 0 || b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '"' || b == '\''
	}, func(m []int) int {
		flag, start := s[m[2]:m[3]], m[1]
		if start >= len(s) {
			return start
		}
		var v string
		vs, ve := start, start
		if c := s[start]; c == '"' || c == '\'' || c == '\\' {
			v, vs, ve = pairValue(s, start, false, 0)
		} else {
			if c == '-' {
				return start // another flag
			}
			for ve < len(s) && strings.IndexByte(" \t\r\n\"'", s[ve]) < 0 {
				ve++
			}
			v = s[vs:ve]
		}
		secret := false
		switch {
		case flag == "-u" || flag == "--user" || flag == "--proxy-user":
			// curl: user:password. "-u 1000:1000" (a uid) and "-u root"
			// are not credentials.
			u, p, ok := strings.Cut(v, ":")
			secret = ok && p != "" && !allDigits(u+p)
		case (len(flag) > 2 && flag[1] == '-' || len(flag) > 3) && LooksSecret(flag):
			// "--password x", and single-dash Java-style "-storepass x".
			secret = true
		}
		if !secret || ve <= vs {
			return start
		}
		out = append(out, span{vs, ve})
		return ve
	})
	return out
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return s != ""
}

// --- name/value pairs: Kubernetes env, AWS tags, form fields

var nameValueRe = regexp.MustCompile(`(?i)"(?:name|key)"[ \t]*:[ \t]*"([^"\\]{1,64})"[ \t]*,[ \t]*"value"[ \t]*:[ \t]*"`)

// findNameValuePairs masks the value of {"name":"DB_PASSWORD","value":"x"}.
func findNameValuePairs(s string) []span {
	var out []span
	for _, m := range nameValueRe.FindAllStringSubmatchIndex(s, -1) {
		if !LooksSecret(s[m[2]:m[3]]) {
			continue
		}
		if _, vs, ve := pairValue(s, m[1]-1, false, 0); ve > vs {
			out = append(out, span{vs, ve})
		}
	}
	return out
}

// --- MySQL and MariaDB clients: "mysql -uroot -phunter2"

var mysqlRe = regexp.MustCompile(`\b(?:docker|podman|nerdctl|buildah|mongo|mongosh|mongodump|mongorestore|curl|mysql|mysqldump|mysqladmin|mysqlimport|mysqlshow|mysqlcheck|mysqlpump|mysqlsh|mariadb|mariadb-dump|mariadb-admin)\b`)
var mysqlPassRe = regexp.MustCompile(`(?:^|\s)-p(?:"([^"\n]*)"|'([^'\n]*)'|([^\s"'|;&]+))`)

// spacePassRe is "-p value" (docker login, mongosh), also glued or "=".
var spacePassRe = regexp.MustCompile(`(?:^|\s)-p(?:[ \t]+|=)?(?:"([^"\n]*)"|'([^'\n]*)'|([^\s"'|;&-][^\s"'|;&]*))`)

// curlUserRe is curl's -u with the credentials glued on: "-ubob:pw".
var curlUserRe = regexp.MustCompile(`(?:^|\s)-u([^\s"':-][^\s"':]*:[^\s"']+)`)

func scanMySQLPasswords(s string) []span {
	s = blankEscapes(s) // "\\nmysql -p…" in a JSON string; same offsets
	var out []span
	done := 0
	for _, m := range mysqlRe.FindAllStringIndex(s, -1) {
		if m[0] < done {
			continue // inside the command already read
		}
		end := commandEnd(s, m[1])
		done = end
		seg := s[m[1]:end]
		re := mysqlPassRe
		switch cmd := s[m[0]:m[1]]; cmd {
		case "curl":
			re = curlUserRe
		case "docker", "podman", "nerdctl", "buildah":
			if !strings.Contains(seg, " login") {
				continue // "docker run -p 8080:80": a port
			}
			re = spacePassRe
		case "mongo", "mongosh", "mongodump", "mongorestore":
			re = spacePassRe
		}
		for _, p := range re.FindAllStringSubmatchIndex(seg, -1) {
			for g := 2; g+1 < len(p); g += 2 {
				if p[g] >= 0 && p[g+1] > p[g] {
					out = append(out, span{m[1] + p[g], m[1] + p[g+1]})
				}
			}
		}
	}
	return out
}

// continued reports a line break at s[j] that a shell line continuation
// ("\\" at the end of the line, maybe before blanks or a CR) carries on.
func continued(s string, i, j int) bool {
	k := j
	for k > i && (s[k-1] == ' ' || s[k-1] == '\t' || s[k-1] == '\r') {
		k--
	}
	return k > i && s[k-1] == '\\'
}

// commandEnd is where the shell command that starts at s[i] ends: a
// newline, a pipe, ";" or "&&" outside quotes.
func commandEnd(s string, i int) int {
	var q byte
	for j := i; j < len(s); j++ {
		c := s[j]
		switch {
		case c == '\n' || c == '\r':
			if !continued(s, i, j) {
				return j
			}
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '|' || c == ';' || c == '&' && j+1 < len(s) && s[j+1] == '&':
			return j
		}
	}
	return len(s)
}

// blankEscapes returns s with each \n, \r and \t escape (an odd run of
// backslashes, then the letter) replaced by a space and the character it
// stands for: the same length, so offsets stay valid, and commands and
// flags written in a JSON string read as on a terminal.
func blankEscapes(s string) string {
	i := strings.IndexByte(s, '\\')
	if i < 0 {
		return s
	}
	b := []byte(s)
	for ; i+1 < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		if escapeLen(s, i) == 2 {
			b[i], b[i+1] = ' ', map[byte]byte{'n': '\n', 'r': '\r', 't': '\t'}[b[i+1]]
		}
		i++ // an escape pair, or a backslash and the byte it escapes
	}
	return string(b)
}

// jsonEscapeView returns s with the \u00XX escapes of quotes, "=", "&",
// "<" and ">" (System.Text.Json, Gson, Go's encoding/json) written as
// the character, a quote as the \" escape the pair finder reads, padded
// with blanks to the same length: offsets stay valid.
func jsonEscapeView(s string) string {
	i := strings.Index(s, `\u00`)
	if i < 0 {
		return s
	}
	b := []byte(s)
	for ; i+5 < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		if escapeLen(s, i) == 6 {
			var rep string
			switch strings.ToLower(s[i+2 : i+6]) {
			case "0022":
				rep = `\"    `
			case "0027":
				rep = `\'    `
			case "003d":
				rep = "=     "
			case "0026":
				rep = "&     "
			case "003c":
				rep = "<     "
			case "003e":
				rep = ">     "
			}
			copy(b[i:i+6], rep)
			i += 5
			continue
		}
		i++ // a backslash and the byte it escapes
	}
	return string(b)
}
