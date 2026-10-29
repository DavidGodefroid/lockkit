package hubclient_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DavidGodefroid/lockkit/hubclient"
)

func transportCfg(t *testing.T, url string, plain bool) hubclient.Config {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return hubclient.Config{URL: url, Instance: inst, Key: priv, HubKey: pub, PlainHTTP: plain,
		StateFile: filepath.Join(t.TempDir(), "state.json")}
}

// Plain http only to a loopback address, or with --hub-plain-http to a
// service name without a dot or a private address; https always.
func TestPlainHTTPRefused(t *testing.T) {
	for url, ok := range map[string]bool{
		"http://127.0.0.1:8443": true, "http://[::1]:8443": true, "http://localhost:8443": true,
		"https://hub.example.com": true, "https://lockhub:8443": true,
		"http://lockhub:8443": false, "http://hub.example.com": false, "http://10.0.0.5:8443": false,
	} {
		_, err := hubclient.New(transportCfg(t, url, false))
		if (err == nil) != ok {
			t.Errorf("%s: err %v", url, err)
		}
		if err != nil && !strings.Contains(err.Error(), "--hub-plain-http") {
			t.Errorf("%s: the error does not name the flag: %v", url, err)
		}
	}
	for url, ok := range map[string]bool{
		"http://lockhub:8443": true, "http://10.0.0.5:8443": true, "http://[fd00::1]:8443": true,
		"http://hub.example.com": false, "http://8.8.8.8": false, "http://lockhub.": false,
	} {
		if _, err := hubclient.New(transportCfg(t, url, true)); (err == nil) != ok {
			t.Errorf("--hub-plain-http %s: err %v", url, err)
		}
	}
}

// A redirect from the hub is an error, and nothing is sent to its target.
func TestRedirectRefused(t *testing.T) {
	var elsewhere atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		_, _ = w.Write([]byte(`{"name":"x","api":1}`))
	}))
	defer target.Close()
	var hub atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hub.Add(1)
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	c, err := hubclient.New(transportCfg(t, srv.URL, false))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Poll(context.Background(), 0); err == nil {
		t.Fatal("a redirect was followed")
	}
	if hub.Load() != 1 || elsewhere.Load() != 0 {
		t.Fatalf("hub %d requests, redirect target %d", hub.Load(), elsewhere.Load())
	}
}

// A state file others may read, or a link, is refused.
func TestStateFileChecked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix modes")
	}
	cfg := transportCfg(t, "http://127.0.0.1:1", false)
	if err := os.WriteFile(cfg.StateFile, []byte(`{"cursor":0}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := hubclient.New(cfg); err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("0644 state file: %v", err)
	}
	real := filepath.Join(t.TempDir(), "real.json")
	if err := os.WriteFile(real, []byte(`{"cursor":0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg = transportCfg(t, "http://127.0.0.1:1", false)
	if err := os.Symlink(real, cfg.StateFile); err != nil {
		t.Fatal(err)
	}
	if _, err := hubclient.New(cfg); err == nil || !strings.Contains(err.Error(), "not a plain file") {
		t.Fatalf("symlinked state file: %v", err)
	}
	cfg = transportCfg(t, "http://127.0.0.1:1", false)
	if err := os.WriteFile(cfg.StateFile, []byte(`{"cursor":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := hubclient.New(cfg); err != nil {
		t.Fatalf("0600 state file: %v", err)
	}
}
