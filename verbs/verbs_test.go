package verbs

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/kit"
)

var testProduct = kit.Product{Name: "lockmq", Account: "lockmq", ClientsGroup: "lockmq-clients", KeychainService: "lockmq", EnvPrefix: "LOCKMQ_"}

// profileFlags is a profile add's flag set, with a few target flags.
func profileFlags() *flag.FlagSet {
	fs := flag.NewFlagSet("profile add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Bool(FlagNonInteractive, false, "")
	fs.Bool(FlagJSON, false, "")
	fs.String(FlagProfile, "", "")
	fs.Bool(FlagProduction, false, "")
	fs.String(FlagCredentials, "", "")
	fs.String(FlagVaultPath, "", "")
	fs.String("url", "", "")
	fs.String("user", "", "")
	fs.String("password", "", "")
	fs.String("vault-token", "", "")
	fs.String("api_secret", "", "")
	fs.String("pwd", "", "")
	fs.String("auth", "", "")
	fs.String("key", "", "")
	return fs
}

func TestRefuseSecrets(t *testing.T) {
	const secret = "s3cr3t-Value"
	for _, tc := range []struct {
		name   string
		args   []string
		secret bool // wraps ErrSecret
		ok     bool
	}{
		{"plain target", []string{"--non-interactive", "--json", "--profile", "dev", "--url", "https://mq.example.com:15672", "--user", "app", "--credentials", "vault", "--vault-path", "rabbitmq/creds/app"}, false, true},
		{"auth method named password", []string{"--auth", "password", "--key", "/home/u/.ssh/id_ed25519"}, false, true},
		{"empty password flag still refused", []string{"--password", ""}, true, false},
		{"password flag", []string{"--password", secret}, true, false},
		{"token part", []string{"--vault-token", secret}, true, false},
		{"secret part with underscore", []string{"--api_secret", secret}, true, false},
		{"pwd", []string{"--pwd=" + secret}, true, false},
		{"url with password", []string{"--url", "amqp://app:" + secret + "@mq:5672/"}, true, false},
		{"keyword dsn", []string{"--user", "host=db password=" + secret}, true, false},
		{"swallowed api-key flag", []string{"--url", "--api-key=" + secret}, true, false},
		{"bearer token", []string{"--auth", "Bearer " + secret}, true, false},
		{"authorization header", []string{"--key", "Authorization: " + secret}, true, false},
		{"url with a token", []string{"--url", "https://" + secret + "@mq"}, true, false},
		{"url with @ in the path", []string{"--url", "https://mq:15672/x@y"}, false, true},
		{"path with :@", []string{"--key", "/data/v1:2@x.db"}, false, true},
		{"positional bearer", []string{"--profile", "dev", "bearer " + secret}, true, false},
		{"positional with password", []string{"--profile", "dev", "https://app:" + secret + "@mq"}, true, false},
		{"flag after a positional", []string{"--profile", "dev", "stray", "--password", secret}, true, false},
		{"bare positional", []string{"--profile", "dev", secret}, false, false},
		{"control character", []string{"--user", "app\x1b[2J"}, false, false},
		{"bidi override", []string{"--profile", "dev\u202e"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := profileFlags()
			if err := fs.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			err := RefuseSecrets(testProduct, fs)
			if tc.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("accepted")
			}
			if errors.Is(err, ErrSecret) != tc.secret {
				t.Fatalf("errors.Is(ErrSecret) = %v, want %v: %v", !tc.secret, tc.secret, err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("the error quotes the secret: %v", err)
			}
		})
	}
}

func TestRefuseSecretsNamesTheFlag(t *testing.T) {
	fs := profileFlags()
	if err := fs.Parse([]string{"--vault-token", "x"}); err != nil {
		t.Fatal(err)
	}
	err := RefuseSecrets(testProduct, fs)
	if err == nil || !strings.Contains(err.Error(), "--vault-token") || !strings.Contains(err.Error(), "lockmq console") {
		t.Fatalf("got %v", err)
	}
}

func TestCredentials(t *testing.T) {
	for _, tc := range []struct {
		source, vault, want string
		secret, ok          bool
	}{
		{"", "", "ask", false, true},
		{"ask", "", "ask", false, true},
		{"vault", "database/creds/app", "vault", false, true},
		{"ask", "database/creds/app", "", false, false},
		{"", "database/creds/app", "", false, false},
		{"vault", "", "", false, false},
		{"vault", "/abs/path", "", false, false},
		{"vault", "-flag", "", false, false},
		{"vault", "a path", "", false, false},
		{"keychain", "", "", true, false},
		{"none", "", "", true, false},
		{"hunter2", "", "", true, false},
		{"ASK", "", "", true, false},
	} {
		got, err := Credentials(tc.source, tc.vault)
		if tc.ok {
			if err != nil || got != tc.want {
				t.Errorf("Credentials(%q, %q) = %q, %v; want %q", tc.source, tc.vault, got, err, tc.want)
			}
			continue
		}
		if err == nil {
			t.Errorf("Credentials(%q, %q) accepted: %q", tc.source, tc.vault, got)
			continue
		}
		if errors.Is(err, ErrSecret) != tc.secret {
			t.Errorf("Credentials(%q, %q): errors.Is(ErrSecret) wrong: %v", tc.source, tc.vault, err)
		}
		if tc.source != "" && tc.source != "ask" && tc.source != "vault" && strings.Contains(err.Error(), tc.source) {
			t.Errorf("Credentials(%q): the error quotes the source: %v", tc.source, err)
		}
	}
}

func TestErrorCode(t *testing.T) {
	_, err := Credentials("keychain", "")
	if got := ErrorCode(err, CodeUsage); got != CodeSecret {
		t.Fatalf("got %q", got)
	}
	if got := ErrorCode(errors.New("x"), CodeUsage); got != CodeUsage {
		t.Fatalf("got %q", got)
	}
}

func TestNewDoctor(t *testing.T) {
	d := NewDoctor(testProduct, nil, nil)
	if !d.OK || d.Lock != "lockmq" {
		t.Fatalf("%+v", d)
	}
	var b bytes.Buffer
	if err := WriteJSON(&b, d); err != nil {
		t.Fatal(err)
	}
	if got := b.String(); got != `{"lock":"lockmq","ok":true,"fixed":[],"checks":[]}`+"\n" {
		t.Fatalf("got %s", got)
	}
	if d := NewDoctor(testProduct, []Check{{Check: "a", Status: StatusOK}, {Check: "b", Status: StatusWarn}}, []string{"wired claude"}); !d.OK {
		t.Fatal("warn fails the doctor")
	}
	if d := NewDoctor(testProduct, []Check{{Check: "a", Status: StatusOK}, {Check: "b", Status: StatusFail}}, nil); d.OK {
		t.Fatal("fail passes the doctor")
	}
	if d := NewDoctor(testProduct, []Check{{Check: "a", Status: "skipped"}}, nil); d.OK {
		t.Fatal("an unknown status passes the doctor")
	}
}

func TestWriteJSONShapes(t *testing.T) {
	var b bytes.Buffer
	if err := WriteJSON(&b, Profile{Lock: "locksql", Profile: "dev", Config: "/p/.locksql/config.toml", Credentials: "ask"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&b, Error{Lock: "locksql", Code: CodeExists, Error: "profile dev is already in /p/.locksql/config.toml <here>"}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want one line each: %q", b.String())
	}
	if lines[0] != `{"lock":"locksql","profile":"dev","config":"/p/.locksql/config.toml","production":false,"credentials":"ask"}` {
		t.Fatalf("profile: %s", lines[0])
	}
	var e Error
	if err := json.Unmarshal([]byte(lines[1]), &e); err != nil || e.Code != "exists" || !strings.Contains(lines[1], "<here>") {
		t.Fatalf("error: %s %v", lines[1], err)
	}
}

func TestParseNeverQuotes(t *testing.T) {
	const secret = "s3cr3t-Value"
	for _, tc := range []struct {
		name   string
		args   []string
		want   string // in the error
		secret bool
	}{
		{"int flag", []string{"--port", secret}, "--port: invalid value", false},
		{"bool flag", []string{"--production=" + secret}, "--production: invalid value", false},
		{"missing value", []string{"--user"}, "--user needs a value", false},
		{"unknown flag", []string{"--" + secret, "x"}, "unknown flag", false},
		{"unknown secret flag", []string{"--db-password=" + secret}, "unknown flag", true},
		{"unknown api-key flag", []string{"--api-key", secret}, "unknown flag", true},
		{"unknown camelCase flag", []string{"--authToken=" + secret}, "unknown flag", true},
		{"bad syntax", []string{"---" + secret}, "bad flag syntax", false},
		{"secret flag defined", []string{"--password", secret}, "--password", true},
		{"positional", []string{secret}, "positional", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := profileFlags()
			fs.Int("port", 0, "")
			var out bytes.Buffer
			fs.SetOutput(&out)
			err := Parse(testProduct, fs, tc.args)
			if err == nil {
				t.Fatal("accepted")
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(out.String(), secret) {
				t.Fatalf("quotes the value: %v / %q", err, out.String())
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if errors.Is(err, ErrSecret) != tc.secret {
				t.Fatalf("errors.Is(ErrSecret) wrong: %v", err)
			}
		})
	}
	fs := profileFlags()
	if err := Parse(testProduct, fs, []string{"--non-interactive", "--json", "--user", "app"}); err != nil {
		t.Fatal(err)
	}
}

func TestWantsJSON(t *testing.T) {
	for args, want := range map[string]bool{
		"--bogus --json":         true,
		"-json --x":              true,
		"--json=true":            true,
		"--json=false":           false,
		"--user json":            false,
		"-- --json":              false,
		"--non-interactive":      false,
		"--json=1":               true,
		"-json=t":                true,
		"--json=TRUE":            true,
		"--json --json=false":    false,
		"--json=0 -json":         true,
		"--json=maybe":           false,
		"--json -- --json=false": true,
	} {
		if got := WantsJSON(strings.Fields(args)); got != want {
			t.Errorf("WantsJSON(%q) = %v", args, got)
		}
	}
}

// setErrValue is a Value whose Set error names another flag.
type setErrValue struct{}

func (setErrValue) String() string { return "" }
func (setErrValue) Set(string) error {
	return errors.New("want a number, like -port 5672 or -name x: y")
}

func TestParseErrorNamesItsOwnFlag(t *testing.T) {
	fs := profileFlags()
	fs.Int("port", 0, "")
	fs.Var(setErrValue{}, "vhost", "")
	err := Parse(testProduct, fs, []string{"--vhost", "x"})
	if err == nil || err.Error() != "--vhost: invalid value" {
		t.Fatalf("got %v", err)
	}
	for msg, want := range map[string]string{
		"flag provided but not defined: -db-password":                "db-password",
		"flag needs an argument: -user":                              "user",
		`invalid value "a\" for flag -port: x" for flag -vhost: y`:   "vhost",
		`invalid boolean value "x for -port: " for -production: bad`: "production",
		"bad flag syntax: ---x -port":                                "",
		"something -port: else":                                      "",
	} {
		if got := flagName(msg); got != want {
			t.Errorf("flagName(%q) = %q, want %q", msg, got, want)
		}
	}
}

func TestRefuseSecretsSwallowedSecretFlag(t *testing.T) {
	const secret = "s3cr3t-Value"
	for _, args := range [][]string{
		{"--user", "--password", secret},
		{"--user", "-password=" + secret},
		{"--user", "--db-token"},
	} {
		err := Parse(testProduct, profileFlags(), args)
		if !errors.Is(err, ErrSecret) || !strings.Contains(err.Error(), "--user") || strings.Contains(err.Error(), secret) {
			t.Errorf("%q: got %v", args, err)
		}
	}
	if err := Parse(testProduct, profileFlags(), []string{"--user", "-x"}); err != nil {
		t.Fatalf("--user -x: %v", err)
	}
}

func TestParseHelp(t *testing.T) {
	for _, h := range []string{"-h", "-help", "--help"} {
		if err := Parse(testProduct, profileFlags(), []string{"--json", h}); !errors.Is(err, flag.ErrHelp) {
			t.Errorf("%s: got %v", h, err)
		}
	}
}

// TestLauncherEndToEnd builds testdata/launcher, a `profile add` written
// as GUIDE §14 shows, and runs it as a subprocess.
func TestLauncherEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain")
	}
	bin := filepath.Join(t.TempDir(), "launcher")
	if out, err := exec.Command(goBin, "build", "-o", bin, "./testdata/launcher").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	run := func(args ...string) (stdout, stderr string, code int) {
		t.Helper()
		var o, e bytes.Buffer
		cmd := exec.Command(bin, args...)
		cmd.Stdout, cmd.Stderr = &o, &e
		err := cmd.Run()
		var exit *exec.ExitError
		switch {
		case errors.As(err, &exit):
			code = exit.ExitCode()
		case err != nil:
			t.Fatal(err)
		}
		return o.String(), e.String(), code
	}

	const secret = "s3cr3t-Value"
	for _, args := range [][]string{
		{"--non-interactive", "--json", "--user", "--password", secret},
		{"--non-interactive", "--json", "--url", "https://" + secret + "@mq"},
		{"--non-interactive", "--json=1", "--url", "--api-key=" + secret},
	} {
		stdout, stderr, code := run(args...)
		if code == 0 || strings.Contains(stdout+stderr, secret) {
			t.Errorf("%q: exit %d, leaks the secret: %q / %q", args, code, stdout, stderr)
		}
		var e Error
		if strings.Count(stdout, "\n") != 1 || json.Unmarshal([]byte(stdout), &e) != nil || e.Code != CodeSecret || e.Lock != "lockmq" {
			t.Errorf("%q: want one verbs.Error line with code secret, got %q", args, stdout)
		}
	}
	if stdout, _, code := run("--non-interactive", "--json", "--user", "--password", secret); !strings.Contains(stdout, "--user") || code == 0 {
		t.Errorf("does not name --user: %q", stdout)
	}

	for _, h := range []string{"-h", "-help"} {
		stdout, stderr, code := run("--non-interactive", h)
		if code != 0 || stdout != "" || !strings.Contains(stderr, "Usage of profile add") || !strings.Contains(stderr, "-"+FlagVaultPath) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", h, code, stdout, stderr)
		}
	}

	stdout, _, code := run("--non-interactive", "--json", "--profile", "uat", "--url", "https://mq:15672/x@y", "--user", "app")
	var p Profile
	if code != 0 || json.Unmarshal([]byte(stdout), &p) != nil || p.Profile != "uat" || p.Credentials != "ask" {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
}
