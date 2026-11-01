package verbs

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
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
		{"positional with password", []string{"--profile", "dev", "https://app:" + secret + "@mq"}, true, false},
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
