package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func TestSetDiff(t *testing.T) {
	got := SetDiff("detectors", []string{"email", "iban"}, []string{"card", "email"}, true)
	want := []Change{{Field: "detectors", Old: "iban", Loosens: true}, {Field: "detectors", New: "card"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("removal loosens: %+v", got)
	}
	got = SetDiff("allow", []string{"a"}, []string{"a", "b"}, false)
	if want := []Change{{Field: "allow", New: "b", Loosens: true}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("addition loosens: %+v", got)
	}
}

func TestLooserLimit(t *testing.T) {
	for _, c := range []struct {
		o, n int64
		want bool
	}{{10, 20, true}, {20, 10, false}, {10, 0, true}, {0, 10, false}, {0, 0, false}, {5, 5, false}} {
		if got := LooserLimit(c.o, c.n); got != c.want {
			t.Errorf("LooserLimit(%d, %d) = %v", c.o, c.n, got)
		}
	}
}

type fpValue struct {
	A string   `json:"a"`
	B []string `json:"b"`
}

func TestFingerprint(t *testing.T) {
	a := Fingerprint(fpValue{A: "x", B: []string{"1"}})
	if len(a) != 64 || a != Fingerprint(fpValue{A: "x", B: []string{"1"}}) || a == Fingerprint(fpValue{A: "y"}) {
		t.Fatalf("fingerprint %q", a)
	}
	// A value JSON cannot encode still gets a fingerprint, unlike any valid one.
	bad := Fingerprint(map[string]any{"f": func() {}})
	if len(bad) != 64 || bad == Fingerprint(map[string]any{}) {
		t.Fatalf("unencodable value: %q", bad)
	}
}

func TestApprovedRoundTrip(t *testing.T) {
	state := t.TempDir()
	key := ApprovedKey("/srv/app", "prod")
	if key != ProjectHash("/srv/app")+"-prod" || ApprovedKey("", "prod") != "user-prod" {
		t.Fatalf("key %q", key)
	}
	var v fpValue
	if ok, err := LoadApproved(testProduct, state, key, &v); ok || err != nil {
		t.Fatalf("missing: ok=%v err=%v", ok, err)
	}
	want := fpValue{A: "approved", B: []string{"x"}}
	if err := SaveApproved(testProduct, state, key, want); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, "lockmq", "approved", key+".json")
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode: %v %v", fi, err)
		}
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "{\n  \"a\": \"approved\",\n  \"b\": [\n    \"x\"\n  ]\n}\n" {
		t.Fatalf("file:\n%s", raw)
	}
	var got fpValue
	if ok, err := LoadApproved(testProduct, state, key, &got); !ok || err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("load: %+v ok=%v err=%v", got, ok, err)
	}
	if err := SaveApproved(testProduct, state, "../evil", want); err == nil {
		t.Fatal("a path-like key was accepted")
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, err := LoadApproved(testProduct, state, key, &got); err == nil || errors.Is(err, fs.ErrNotExist) || ok {
		t.Fatalf("corrupt file: ok=%v err=%v", ok, err)
	}
}

func TestDiffBase(t *testing.T) {
	a := Base{User: "ro", Credentials: CredentialsAsk, TLS: TLSVerifyFull, Production: true,
		IdleTimeout: 20 * time.Minute, MaxSession: 4 * time.Hour}
	if got := DiffBase(a, a); len(got) != 0 {
		t.Fatalf("no change: %+v", got)
	}
	c := a
	c.Credentials, c.VaultPath = CredentialsVault, "rabbitmq/creds/ro"
	c.TLS, c.TLSCA = TLSRequire, "/ca.pem"
	c.Production = false
	c.IdleTimeout, c.MaxSession = 30*time.Minute, 2*time.Hour
	c.SSH = &SSHProfile{Host: "b", Port: 22, User: "u", Auth: SSHAuthAgent, Credentials: CredentialsAsk}
	c.CredentialsTTL = time.Hour
	got := map[string]bool{}
	for _, ch := range DiffBase(a, c) {
		got[ch.Field] = ch.Loosens
	}
	want := map[string]bool{"credentials": true, "vault_path": true, "tls": true, "tls_ca": true, "production": true,
		"ssh": true, "limits.idle_timeout": true, "limits.max_session": false, "credentials_ttl": false, "user": false}
	delete(want, "user")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("changes = %v\nwant      %v", got, want)
	}
	// Keychain to ask tightens; a TLS upgrade tightens.
	b := a
	b.Credentials, b.TLS = CredentialsKeychain, TLSRequire
	for _, ch := range DiffBase(b, a) {
		if ch.Loosens {
			t.Errorf("%s loosens", ch.Field)
		}
	}
	// Any change of the user is another login.
	u := a
	u.User = "admin"
	if ch := DiffBase(a, u); len(ch) != 1 || ch[0].Field != "user" || !ch[0].Loosens {
		t.Fatalf("user: %+v", ch)
	}
}
