// Package verbs is the shared half of the launcher verbs every lock
// accepts, so that `lox init` drives every lock the same way (GUIDE.md
// §14):
//
//	<lock> init <agent>
//	<lock> profile add [--non-interactive] [--json] [--project DIR] [--profile NAME] [--production] [--credentials ask|vault [--vault-path P]] <target flags>
//	<lock> doctor [--fix [--yes]] [--json]
//
// The verbs themselves are the product's: verbs gives the checks of the
// non-interactive form (no secret value, ever, and a credential source
// that is the console asking at start or Vault) and the JSON shapes
// `lox init` reads.
package verbs

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/secrets"
)

// The flags of the contract that every lock spells the same way.
const (
	FlagNonInteractive = "non-interactive"
	FlagJSON           = "json"
	FlagProject        = "project"
	FlagProfile        = "profile"
	FlagProduction     = "production"
	FlagCredentials    = "credentials"
	FlagVaultPath      = "vault-path"
	FlagFix            = "fix"
	FlagYes            = "yes"
)

// ErrSecret is the refusal of a secret given on the command line: a flag
// named like a secret (--password, --token, ...), a value that embeds a
// password (user:pw@host, password=...), or a credential source other
// than the console asking at start or Vault. errors.Is finds it in the
// errors of RefuseSecrets and Credentials.
var ErrSecret = errors.New("a secret is never given on the command line")

// RefuseSecrets checks every flag set on fs, the parsed flags of a
// non-interactive `profile add` (call it after fs.Parse, before writing
// anything). It refuses a flag whose name has a part that names a secret
// (password, passwd, pwd, secret, token: --password, --vault-token,
// --api-secret), whatever its value, and a value that embeds a password
// or holds a control or formatting character. Positional arguments are
// checked too. The error names the flag, never its value (it may be the
// secret), and wraps ErrSecret for a secret.
func RefuseSecrets(p kit.Product, fs *flag.FlagSet) error {
	var err error
	fs.Visit(func(f *flag.Flag) {
		if err != nil {
			return
		}
		err = checkArg(p, "--"+f.Name, f.Name, f.Value.String())
	})
	if err != nil {
		return err
	}
	for i, a := range fs.Args() {
		if err := checkArg(p, fmt.Sprintf("argument %d", i+1), "", a); err != nil {
			return err
		}
	}
	return nil
}

func checkArg(p kit.Product, label, name, val string) error {
	if name != "" && config.SecretKey(strings.Split(name, "-")) {
		return fmt.Errorf("%s: %w: %s asks for it at start or reads it from Vault (--%s %s|%s)",
			label, ErrSecret, consoleName(p), FlagCredentials, config.CredentialsAsk, config.CredentialsVault)
	}
	if config.EmbedsPassword(val) {
		return fmt.Errorf("%s: %w: the value looks like it embeds a password; give the target without it", label, ErrSecret)
	}
	if strings.IndexFunc(val, config.UnsafeRune) >= 0 {
		return fmt.Errorf("%s holds a control or formatting character", label)
	}
	return nil
}

func consoleName(p kit.Product) string {
	if p.Name == "" {
		return "the console"
	}
	return "the " + p.Name + " console"
}

// Credentials checks the credential source of a non-interactive
// `profile add`: "" (the default) or "ask", the console asks for the
// secret at start, or "vault", the console reads it from Vault at
// vaultPath. It returns the source to write ("ask" or "vault"). Any other
// source, the keychain included, is refused with ErrSecret: under
// `lox up` the console reads its secret at start or from Vault only. A
// vault path is checked as secrets.CheckVaultPath does, and refused
// without "vault". The source is never quoted (a secret pasted in the
// wrong place).
func Credentials(source, vaultPath string) (string, error) {
	switch source {
	case "", config.CredentialsAsk:
		if vaultPath != "" {
			return "", fmt.Errorf("--%s is for --%s %s", FlagVaultPath, FlagCredentials, config.CredentialsVault)
		}
		return config.CredentialsAsk, nil
	case config.CredentialsVault:
		if vaultPath == "" {
			return "", fmt.Errorf("--%s %s needs --%s, such as database/creds/<role>", FlagCredentials, config.CredentialsVault, FlagVaultPath)
		}
		if err := secrets.CheckVaultPath(vaultPath); err != nil {
			return "", fmt.Errorf("--%s: %s", FlagVaultPath, strings.TrimPrefix(err.Error(), "secrets: "))
		}
		return config.CredentialsVault, nil
	}
	return "", fmt.Errorf("--%s: %w: want %s (the console asks at start) or %s (with --%s)",
		FlagCredentials, ErrSecret, config.CredentialsAsk, config.CredentialsVault, FlagVaultPath)
}

// The codes of an Error, which `lox init` acts on.
const (
	// CodeUsage: a flag is missing, unknown or invalid.
	CodeUsage = "usage"
	// CodeSecret: a secret was given (ErrSecret).
	CodeSecret = "secret"
	// CodeExists: the profile is already in the project's config; nothing
	// was written.
	CodeExists = "exists"
	// CodeFailed: anything else (a file could not be written, a check
	// failed).
	CodeFailed = "failed"
)

// ErrorCode is the code of err: CodeSecret for an error that wraps
// ErrSecret, else fallback.
func ErrorCode(err error, fallback string) string {
	if errors.Is(err, ErrSecret) {
		return CodeSecret
	}
	return fallback
}

// Error is the JSON a verb run with --json prints on stdout when it fails
// (its exit status is not 0).
type Error struct {
	Lock  string `json:"lock"`
	Code  string `json:"code"`
	Error string `json:"error"`
}

// Profile is the JSON `profile add --json` prints on stdout when it wrote
// the profile (exit status 0).
type Profile struct {
	Lock    string `json:"lock"`
	Profile string `json:"profile"`
	// Config is the file the profile was written to.
	Config     string `json:"config"`
	Production bool   `json:"production"`
	// Credentials is "ask" or "vault"; empty for a target that has no
	// secret.
	Credentials string `json:"credentials,omitempty"`
}

// The statuses of a Check.
const (
	StatusOK   = "ok"
	StatusWarn = "warn"
	StatusFail = "fail"
)

// Check is one line of a doctor.
type Check struct {
	Check  string `json:"check"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	// Fix is what --fix would do, or the command the human runs; empty
	// when nothing does.
	Fix string `json:"fix,omitempty"`
}

// Doctor is the JSON `doctor --json` prints on stdout. Its exit status is
// 0 exactly when OK.
type Doctor struct {
	Lock string `json:"lock"`
	// OK: no check failed (after the repairs, with --fix).
	OK bool `json:"ok"`
	// Fixed are the repairs --fix made, one line each.
	Fixed  []string `json:"fixed"`
	Checks []Check  `json:"checks"`
}

// NewDoctor is the report of checks: OK unless one failed, and never nil
// slices (JSON [] rather than null).
func NewDoctor(p kit.Product, checks []Check, fixed []string) Doctor {
	d := Doctor{Lock: p.Name, OK: true, Fixed: fixed, Checks: checks}
	if d.Fixed == nil {
		d.Fixed = []string{}
	}
	if d.Checks == nil {
		d.Checks = []Check{}
	}
	for _, c := range checks {
		if c.Status != StatusOK && c.Status != StatusWarn {
			d.OK = false
		}
	}
	return d
}

// WriteJSON writes v as one line of JSON, the only thing a verb run with
// --json prints on stdout.
func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
