package hubclient_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// Hub URL errors name the scheme and host, never a user or token in the
// URL.
func TestHubURLErrorsDoNotEchoUserinfo(t *testing.T) {
	const canary = "glsa_CanarySecretToken123"
	for _, u := range []string{
		"http://" + canary + "@hub.example.com", "http://u:" + canary + "@hub.example.com",
		"ftp://u:" + canary + "@hub.example.com", "https://u:" + canary + "@hub.example.com:bad",
	} {
		_, err := hubclient.New(transportCfg(t, u, false))
		if err == nil || strings.Contains(err.Error(), canary) {
			t.Errorf("%s: err %v (want an error without the userinfo)", u, err)
		}
	}
	// Otherwise valid URLs carrying a user or token are refused.
	for _, u := range []string{
		"https://" + canary + "@hub.example.com", "https://u:" + canary + "@hub.example.com",
		"http://" + canary + "@127.0.0.1:8443",
	} {
		_, err := hubclient.New(transportCfg(t, u, false))
		if err == nil || strings.Contains(err.Error(), canary) || !strings.Contains(err.Error(), "user or password") {
			t.Errorf("%s: err %v (want refused, without the userinfo)", u, err)
		}
	}
	if _, err := hubclient.New(transportCfg(t, "http://lockhub.example.com:8443", true)); err == nil ||
		!strings.Contains(err.Error(), "hub URL http://lockhub.example.com:8443:") {
		t.Errorf("--hub-plain-http: err %v (want the scheme and host)", err)
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

// The hub URL is scheme://host[:port]: a path, query or fragment (where a
// token would sit) is refused, without the value.
func TestHubURLRefusesPathQueryFragment(t *testing.T) {
	const canary = "glsa_Canary"
	for _, u := range []string{
		"https://user:" + canary + "@h/path?token=" + canary, "https://h/path?token=" + canary,
		"https://h?token=" + canary, "https://h/?" + canary, "https://h?", "https://h#" + canary, "https://h/#x",
		"https://h/" + canary, "https://h/lockhub/", "https://h//", "https://h/%2F", "http://127.0.0.1:8443/v1",
		"http://[fe80::1%25" + canary + "]:80", "https://h:99999", "https://h:0", "https://h:",
		"https://h;" + canary, "https://h&token=" + canary, "https://h!$&'()*+,;=" + canary, "https://h%41" + canary,
		"https://\u2603.com", "https://[" + canary + "]", "https://[10.0.0.1]", "https://-h",
	} {
		if _, err := hubclient.New(transportCfg(t, u, false)); err == nil || strings.Contains(err.Error(), canary) ||
			!strings.Contains(err.Error(), "want http(s)://host[:port]") {
			t.Errorf("New(%s): %v (want refused, naming the allowed form only)", u, err)
		}
		if got, err := hubclient.CanonicalURL(u); err == nil || got != "" || strings.Contains(err.Error(), canary) {
			t.Errorf("CanonicalURL(%s) = %q, %v", u, got, err)
		}
	}
	for in, want := range map[string]string{
		"https://hub.example.com": "https://hub.example.com", "https://hub.example.com/": "https://hub.example.com",
		"http://127.0.0.1:8443/": "http://127.0.0.1:8443", "HTTPS://lockhub:8443": "https://lockhub:8443",
		"https://h:00443": "https://h:443", "http://[::1]:8443/": "http://[::1]:8443", "https://lock_hub:8443": "https://lock_hub:8443",
		"https://hub.example.com.": "https://hub.example.com.", "https://xn--n3h.example": "https://xn--n3h.example",
	} {
		if got, err := hubclient.CanonicalURL(in); err != nil || got != want {
			t.Errorf("CanonicalURL(%s) = %q, %v, want %s", in, got, err, want)
		}
		c, err := hubclient.New(transportCfg(t, in, false))
		if err != nil || c.URL() != want {
			t.Errorf("New(%s): URL %v, %v, want %s", in, c, err, want)
		}
	}
}

// A hub that cannot be reached is an ErrUnreachable naming the hub by
// scheme and host, not net/http's *url.Error with the request URL.
func TestTransportErrorsDropTheURL(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	srv.Close()
	c, err := hubclient.New(transportCfg(t, base+"/", false))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Hello(context.Background())
	var ue *url.Error
	if !errors.Is(err, hubclient.ErrUnreachable) || errors.As(err, &ue) || strings.Contains(err.Error(), "/v1/") ||
		!strings.Contains(err.Error(), base) {
		t.Fatalf("Hello: %v (want unreachable, naming %s, without the request URL)", err, base)
	}
	// A transport whose error quotes the URL it was given, query and all.
	c, err = hubclient.New(hubclient.Config{URL: "https://hub.example.com", Instance: inst, Key: transportCfg(t, "", false).Key,
		HubKey: transportCfg(t, "", false).HubKey, StateFile: filepath.Join(t.TempDir(), "s.json"),
		HTTP: &http.Client{Transport: failRT{}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Hello(context.Background())
	if !errors.Is(err, hubclient.ErrUnreachable) || strings.Contains(err.Error(), "/v1/hello") ||
		!strings.Contains(err.Error(), "Get https://hub.example.com: refused") {
		t.Fatalf("Hello: %v", err)
	}
}

type failRT struct{}

func (failRT) RoundTrip(*http.Request) (*http.Response, error) { return nil, errors.New("refused") }
