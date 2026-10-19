package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/kit"
)

var testProduct = kit.Product{Name: "lockmq", Account: "lockmq", ClientsGroup: "lockmq-clients",
	KeychainService: "lockmq", EnvPrefix: "LOCKMQ_"}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFindProjectRootWalksUp(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".lockmq", "config.toml"), "")
	deep := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	got, ok := FindProjectRoot(testProduct, deep)
	if !ok || got != root {
		t.Fatalf("FindProjectRoot = %q, %v; want %q", got, ok, root)
	}
	if got := ProjectConfigPath(testProduct, root); got != filepath.Join(root, ".lockmq", "config.toml") {
		t.Errorf("ProjectConfigPath = %q", got)
	}
	if ProjectKey(testProduct, deep) != ProjectHash(root) {
		t.Error("ProjectKey is not the hash of the root")
	}
	// Another product's project directory is not this product's project.
	other := t.TempDir()
	writeFile(t, filepath.Join(other, ".locksql", "config.toml"), "")
	if _, ok := FindProjectRoot(testProduct, other); ok {
		t.Error("found a project under another product's directory")
	}
	if ProjectKey(testProduct, other) != "user" {
		t.Error("ProjectKey outside a project is not user")
	}
	if ProjectKeyOf(root) != ProjectHash(root) || ProjectKeyOf("") != "user" {
		t.Error("ProjectKeyOf")
	}
}

func TestProjectHash(t *testing.T) {
	h := ProjectHash("/srv/app")
	if len(h) != 8 || h != ProjectHash("/srv/app/") || h == ProjectHash("/srv/other") {
		t.Fatalf("ProjectHash = %q", h)
	}
}

func TestUserConfigPath(t *testing.T) {
	p, err := UserConfigPath(testProduct)
	if err != nil || !strings.HasSuffix(p, filepath.Join("lockmq", "config.toml")) {
		t.Fatalf("UserConfigPath = %q, %v", p, err)
	}
}

type rawProfiles struct {
	Profiles map[string]struct {
		URL  string `toml:"url"`
		User string `toml:"user"`
	} `toml:"profiles"`
}

func TestDecodeRefusesSecretKeys(t *testing.T) {
	for _, key := range []string{"password", "db_password", "api-token", "secret", "pwd", "nested.passwd"} {
		data := "[profiles.p]\n" + strings.Replace(key, ".", "]\n[profiles.p.", 1) + " = \"hunter2\"\n"
		if strings.Contains(key, ".") {
			data = "[profiles.p." + strings.Split(key, ".")[0] + "]\n" + strings.Split(key, ".")[1] + " = \"hunter2\"\n"
		}
		var raw rawProfiles
		_, err := Decode(testProduct, []byte(data), "c.toml", &raw)
		if err == nil || !strings.Contains(err.Error(), "looks like a secret; lockmq never reads secrets from config files") {
			t.Errorf("%s: %v", key, err)
		}
		if err != nil && strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: the value leaked: %v", key, err)
		}
	}
}

func TestDecodeRefusesUnknownKeys(t *testing.T) {
	var raw rawProfiles
	_, err := Decode(testProduct, []byte("[profiles.p]\nurl = \"x\"\nflavour = 1\n"), "c.toml", &raw)
	if err == nil || !strings.Contains(err.Error(), `unknown key "profiles.p.flavour"`) {
		t.Fatalf("err = %v", err)
	}
}

// A TOML syntax error names the line and a non-secret key, never a value.
func TestDecodeErrorsAreSanitised(t *testing.T) {
	var raw rawProfiles
	_, err := Decode(testProduct, []byte("[profiles.p]\nurl = \"never-shown\n"), "c.toml", &raw)
	if err == nil || strings.Contains(err.Error(), "never-shown") || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("err = %v", err)
	}
	_, err = Decode(testProduct, []byte("[profiles.p]\nuser = 3\n"), "c.toml", &raw)
	if err == nil || !strings.Contains(err.Error(), "c.toml: invalid TOML") {
		t.Fatalf("type err = %v", err)
	}
}

func TestCheckValue(t *testing.T) {
	for _, bad := range []string{"amqps://u:pw@h", "u:pw@h", "host=h password=x", "a\x1b[2Jb", "a" + string(rune(0x202e)) + "b"} {
		if err := CheckValue(testProduct, "url", bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := CheckValue(testProduct, "url", "amqps://u:pw@h"); err == nil || !strings.Contains(err.Error(), "url looks like a DSN with an embedded password; lockmq never reads secrets from config files") {
		t.Errorf("message: %v", err)
	}
	for _, ok := range []string{"", "https://rabbitmq.example.com:15671", "u@h", "database/creds/ro"} {
		if err := CheckValue(testProduct, "url", ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
}

func TestProfileName(t *testing.T) {
	for _, ok := range []string{"prod", "uat-2", "a.b_c"} {
		if err := CheckProfileName(ok, false); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-x", "a b", strings.Repeat("a", 65)} {
		if CheckProfileName(bad, false) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// A production profile is approved by typing its name: never an everyday answer.
	for _, bad := range []string{"y", "Yes", "ok", "n", "p"} {
		if CheckProfileName(bad, true) == nil {
			t.Errorf("production %q accepted", bad)
		}
	}
}
