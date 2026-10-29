package hubclient_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/hubclient"
)

func TestValidInstance(t *testing.T) {
	for _, ok := range []string{"crm-prod", "a", "0db", strings.Repeat("a", 63)} {
		if !hubclient.ValidInstance(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "-a", "Crm", "a_b", "../x", "a/b", "a.key", strings.Repeat("a", 64), "a\n"} {
		if hubclient.ValidInstance(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestInstanceKeyCreatedOnceAndPrivate(t *testing.T) {
	home := t.TempDir()
	k1, err := hubclient.InstanceKey(home, "crm-prod")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := hubclient.InstanceKey(home, "crm-prod")
	if err != nil || !k1.Equal(k2) {
		t.Fatalf("second call: %v, same key %v", err, k1.Equal(k2))
	}
	if _, err := hubclient.InstanceKey(home, "../evil"); err == nil {
		t.Error("invalid instance accepted")
	}
	if runtime.GOOS == "windows" {
		return
	}
	path := filepath.Join(home, "hub", "crm-prod.key")
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi, err)
	}
	if di, _ := os.Stat(filepath.Dir(path)); di.Mode().Perm() != 0o700 {
		t.Errorf("key dir mode %v", di.Mode().Perm())
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := hubclient.InstanceKey(home, "crm-prod"); err == nil {
		t.Error("a key file readable by others was used")
	}
}

func TestHubKeyCommand(t *testing.T) {
	home := t.TempDir()
	var out bytes.Buffer
	if err := hubclient.HubKeyCommand(&out, home, []string{"--instance", "crm-prod"}); err != nil {
		t.Fatal(err)
	}
	line := out.String()
	if !strings.HasSuffix(line, "\n") || strings.Count(line, "\n") != 1 {
		t.Fatalf("not one line: %q", line)
	}
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("not a base64 std key: %q %v", line, err)
	}
	k, _ := hubclient.InstanceKey(home, "crm-prod")
	if !k.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(pub)) {
		t.Error("printed key is not the instance key")
	}
	out.Reset()
	_ = hubclient.HubKeyCommand(&out, home, []string{"--instance", "crm-prod"})
	if out.String() != line {
		t.Error("second call printed another key")
	}
	for _, args := range [][]string{nil, {"--instance", ""}, {"--instance", "Bad"}, {"--instance", "a", "extra"}} {
		if err := hubclient.HubKeyCommand(&out, home, args); err == nil {
			t.Errorf("%q accepted", args)
		}
	}
}

func TestReadHubKey(t *testing.T) {
	dir := t.TempDir()
	pub, _, _ := ed25519.GenerateKey(nil)
	good := filepath.Join(dir, "hub.pub")
	os.WriteFile(good, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644)
	got, err := hubclient.ReadHubKey(good)
	if err != nil || !got.Equal(pub) {
		t.Fatalf("read: %v", err)
	}
	for name, body := range map[string]string{"short": base64.StdEncoding.EncodeToString(pub[:16]), "junk": "not base64!", "empty": "",
		"two lines": base64.StdEncoding.EncodeToString(pub) + "\n" + base64.StdEncoding.EncodeToString(pub) + "\n"} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "_"))
		os.WriteFile(p, []byte(body), 0o644)
		if _, err := hubclient.ReadHubKey(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := hubclient.ReadHubKey(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file accepted")
	}
}
