// Package config is the product-neutral half of a product's configuration:
// where the project and user config files are, how a TOML file is decoded
// without ever reading a secret, the profile base every product shares
// (credentials, Vault, TLS, SSH bastion, production, session limits), the
// policy fingerprint, the diff helpers that mark loosenings, and the store
// of the policies the human approved.
//
// The rule every product follows: the AI may tighten a policy (the change
// applies at once); only the human loosens it (the console shows the diff
// and applies it after a typed confirmation).
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/BurntSushi/toml"

	"github.com/DavidGodefroid/lockkit/kit"
)

// ConfigFile is the name of a project or user config file.
const ConfigFile = "config.toml"

// UserConfigPath is <user config dir>/<p.Name>/config.toml.
func UserConfigPath(p kit.Product) (string, error) {
	dir, err := p.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ConfigFile), nil
}

// ProjectConfigPath is <root>/.<p.Name>/config.toml.
func ProjectConfigPath(p kit.Product, root string) string {
	return filepath.Join(root, p.ProjectDir(), ConfigFile)
}

// FindProjectRoot walks up from cwd to the first directory holding
// .<p.Name>/config.toml.
func FindProjectRoot(p kit.Product, cwd string) (string, bool) {
	dir, err := filepath.Abs(cwd)
	if err != nil {
		return "", false
	}
	for {
		st, err := os.Stat(ProjectConfigPath(p, dir))
		if err == nil && st.Mode().IsRegular() {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// ProjectKey names the project of cwd in socket paths: ProjectHash of the
// project root, or "user" when cwd is outside any project (profiles from
// the user config only). The console and its clients must agree on it.
func ProjectKey(p kit.Product, cwd string) string {
	if root, ok := FindProjectRoot(p, cwd); ok {
		return ProjectHash(root)
	}
	return "user"
}

// ProjectKeyOf is ProjectKey for a known project root ("" for none).
func ProjectKeyOf(root string) string {
	if root == "" {
		return "user"
	}
	return ProjectHash(root)
}

// ProjectHash returns the first 8 hex digits of sha256 of the absolute,
// cleaned project root.
func ProjectHash(root string) string {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = filepath.Clean(root)
	}
	sum := sha256.Sum256([]byte(abs))
	return hex.EncodeToString(sum[:])[:8]
}

// secretWords are refused as config key names, or as a "_"/"-" separated
// part of one, at any depth.
var secretWords = map[string]bool{"password": true, "passwd": true, "pwd": true, "secret": true, "token": true}

// Decode decodes TOML data into into. name labels errors. It refuses a key
// that looks like a secret (password, token, ...) at any depth and any key
// into does not declare, and never quotes a value in an error.
func Decode(p kit.Product, data []byte, name string, into any) (toml.MetaData, error) {
	md, err := toml.Decode(string(data), into)
	if err != nil {
		return md, sanitizeDecodeError(name, err)
	}
	for _, key := range md.Keys() {
		if SecretKey(key) {
			return md, fmt.Errorf("config: %s: key %q looks like a secret; %s never reads secrets from config files (the console asks for them)", name, key.String(), p.Name)
		}
	}
	if und := md.Undecoded(); len(und) > 0 {
		return md, fmt.Errorf("config: %s: unknown key %q", name, und[0].String())
	}
	return md, nil
}

func sanitizeDecodeError(path string, err error) error {
	var pe toml.ParseError
	if errors.As(err, &pe) {
		if pe.LastKey != "" && !SecretKey(strings.Split(pe.LastKey, ".")) {
			return fmt.Errorf("config: %s: invalid TOML at line %d (key %q)", path, pe.Position.Line, pe.LastKey)
		}
		return fmt.Errorf("config: %s: invalid TOML at line %d", path, pe.Position.Line)
	}
	// Type errors from decoding into known keys name the key and the types,
	// never the value. Secret-looking keys are never decoded.
	return fmt.Errorf("config: %s: invalid TOML: %s", path, strings.TrimPrefix(err.Error(), "toml: "))
}

// SecretKey reports a key with a part that names a secret.
func SecretKey(key toml.Key) bool {
	for _, part := range key {
		for _, word := range strings.FieldsFunc(strings.ToLower(part), func(r rune) bool { return r == '_' || r == '-' || r == '.' }) {
			if secretWords[word] {
				return true
			}
		}
	}
	return false
}

// EmbedsPassword reports whether s looks like a DSN carrying a password:
// user:pw@host, scheme://user:pw@host, or a keyword DSN with password=.
func EmbedsPassword(s string) bool {
	lower := strings.ToLower(s)
	if strings.Contains(lower, "password=") || strings.Contains(lower, "pwd=") {
		return true
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	at := strings.LastIndex(s, "@")
	if at < 0 {
		return false
	}
	return strings.Contains(s[:at], ":")
}

// UnsafeRune reports a character that could alter or hide text on a
// terminal: a control character (C0, DEL, C1), an invalid byte or a format
// character such as a bidi override.
func UnsafeRune(r rune) bool {
	return r == utf8.RuneError || unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}

// CheckValue refuses a config value that embeds a password or holds a
// character that could hide text on the approval screen, where config
// values are shown to the human.
func CheckValue(p kit.Product, key, val string) error {
	if EmbedsPassword(val) {
		return fmt.Errorf("%s looks like a DSN with an embedded password; %s never reads secrets from config files", key, p.Name)
	}
	if strings.IndexFunc(val, UnsafeRune) >= 0 {
		return fmt.Errorf("%s holds a control or formatting character", key)
	}
	return nil
}

// MaxProfileName bounds a profile name, in bytes.
const MaxProfileName = 64

var profileNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// approvalWords are answers too common to serve as the name typed to approve
// a production request.
var approvalWords = map[string]bool{"y": true, "yes": true, "n": true, "no": true, "ok": true}

// CheckProfileName refuses a name unusable in file and socket names, and,
// for a production profile, a name too short or too common to be typed as
// an approval.
func CheckProfileName(name string, production bool) error {
	if len(name) > MaxProfileName || !profileNameRe.MatchString(name) {
		return fmt.Errorf("invalid profile name %q: use letters, digits, '_', '-' or '.', starting with a letter or digit", name)
	}
	if production && (len(name) < 2 || approvalWords[strings.ToLower(name)]) {
		// Production requests are approved by typing the profile name,
		// which must not be an everyday answer such as "y".
		return errors.New("a production profile needs a name of 2 characters or more that is not y, yes, n, no or ok")
	}
	return nil
}
