package pii

import (
	"slices"
	"strings"
)

// secretTokens are name tokens that make a field a credential on their
// own (in English, French, Dutch, German and Spanish).
var secretTokens = set(
	"password", "passwords", "passwd", "pass", "passphrase", "passcode", "motdepasse", "mdp",
	"wachtwoord", "passwort", "kennwort", "contrasena", "contrasenas",
	"secret", "secrets", "clientsecret",
	"token", "apitoken", "accesstoken", "refreshtoken", "idtoken", "authtoken", "sessiontoken",
	"bearertoken", "csrftoken", "xsrftoken",
	"apikey", "accesskey", "secretkey", "privatekey", "authkey", "sshkey", "masterkey", "signingkey",
	"authorization", "auth", "credential", "credentials", "creds",
	"cookie", "cookies", "sessionid", "sessid", "phpsessid", "jsessionid", "aspsessionid", "sid",
	"otp", "totp", "sig", "signature",
)

// secretKeyOwners make "key" a credential when they precede it ("api_key",
// "X-Goog-Api-Key", "client_key"): alone, a key is a cache or a sort key.
var secretKeyOwners = set(
	"api", "access", "secret", "private", "auth", "subscription", "signing", "encryption", "master",
	"account", "shared", "client", "license", "licence", "session", "app", "service", "ssh", "gpg", "pgp",
	"aes", "hmac", "jwt", "webhook", "consumer", "storage", "functions", "host", "admin", "root",
)

// secretNeutralLast are last tokens that make a field metadata about a
// credential rather than the credential: "token_type", "password_changed_at",
// "access_token_ttl", "secret_name", "token_endpoint", "api_key_id".
var secretNeutralLast = set(
	"id", "ids", "uuid", "fk", "count", "nb", "num", "type", "types", "status", "kind", "flag", "enabled",
	"verified", "validated", "valid", "format", "length", "len", "at", "on", "sent", "consent",
	"used", "usage", "expires", "expiry", "expiration", "exp", "ttl", "in", "limit", "max", "min", "total",
	"name", "names", "hint", "policy", "rotation", "rotated", "version", "scope", "scopes", "issuer",
	"audience", "required", "present", "missing", "changed", "updated", "created", "file", "path",
	"dir", "env", "url", "uri", "endpoint", "header", "field", "param", "label", "source", "provider",
	"method", "mode", "authentication", "error", "errors", "result", "ok", "failed", "strength", "score", "age", "date",
	"time", "ms", "manager", "store", "ref", "arn",
)

// LooksSecret reports a field, label, header or flag name that holds a
// credential: a password, a token, an API or private key, a cookie, an
// authorization. Its value is a secret whatever it looks like. Metadata
// about a credential ("token_type", "password_changed_at") does not count,
// nor do token counts ("max_tokens", "prompt_tokens"), nor the shell's
// working directory ("PWD").
func LooksSecret(name string) bool {
	toks := Tokens(name)
	if len(toks) == 0 {
		return false
	}
	if len(toks) == 1 && (toks[0] == "pwd" || toks[0] == "oldpwd") {
		return false
	}
	last := toks[len(toks)-1]
	if len(toks) > 1 && secretNeutralLast[last] {
		return false
	}
	for i := 1; i < len(toks); i++ {
		if toks[i] == "key" && secretKeyOwners[toks[i-1]] {
			return true
		}
	}
	if len(toks) > 1 && slices.Contains(toks, "pwd") {
		return true // "db_pwd", "pwd_db"
	}
	if strings.Contains(strings.Join(toks, ""), "motdepasse") {
		return true // "mot_de_passe", "motDePasse"
	}
	if last == "session" {
		return true // a session cookie: "session", "laravel_session"
	}
	if slices.ContainsFunc(toks, func(t string) bool { return secretTokens[t] }) {
		return true
	}
	// Unsplit environment names: PGPASSWORD, DBSECRET, GITHUBTOKEN.
	for _, t := range toks {
		for _, suffix := range []string{"password", "passwd", "secret", "token"} {
			if strings.HasSuffix(t, suffix) && len(t) > len(suffix) {
				return true
			}
		}
	}
	return false
}
