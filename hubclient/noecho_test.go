package hubclient_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/ticket"
	"github.com/DavidGodefroid/lockkit/ticket/devicetest"
)

// Errors name the flag or field and the allowed form, never the value: it
// may be a token pasted in the wrong place.
const (
	echoCanary    = "glsa_CanarySecretToken123"
	echoCanaryURL = "https://user:glsa_Canary@h/path?token=glsa_Canary"
)

func TestErrorsNeverEchoValues(t *testing.T) {
	home := t.TempDir()
	check := func(what string, err error, want string) {
		t.Helper()
		if err == nil || strings.Contains(err.Error(), "glsa_Canary") || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v (want an error with %q, without the value)", what, err, want)
		}
	}
	for _, v := range []string{echoCanary, echoCanaryURL} {
		_, err := hubclient.InstanceKey(home, v)
		check("InstanceKey", err, "lowercase letters")
		check("hub-key --instance", hubclient.HubKeyCommand(&bytes.Buffer{}, home, []string{"--instance", v}), "lowercase letters")
		check("hub-key --instance=", hubclient.HubKeyCommand(&bytes.Buffer{}, home, []string{"--instance=" + v}), "lowercase letters")
		check("hub-key unknown flag", hubclient.HubKeyCommand(&bytes.Buffer{}, home, []string{"--" + v}), "usage: hub-key")
		check("hub-key extra", hubclient.HubKeyCommand(&bytes.Buffer{}, home, []string{"--instance", "a", v}), "usage: hub-key")
		_, err = hubclient.ParseRisks("write, " + v)
		check("ParseRisks", err, "want one of read")
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		_, err = hubclient.New(hubclient.Config{URL: "https://h", Instance: v, Key: priv, HubKey: pub, StateFile: filepath.Join(t.TempDir(), "s")})
		check("New Instance", err, "lowercase letters")
		_, err = hubclient.New(hubclient.Config{URL: v, Instance: inst, Key: priv, HubKey: pub, StateFile: filepath.Join(t.TempDir(), "s")})
		check("New URL", err, "want http(s)://host[:port]")
		_, err = hubclient.New(hubclient.Config{URL: "https://h", Instance: inst, Key: priv, HubKey: pub, StateFile: filepath.Join(t.TempDir(), "s"),
			Devices: []ticket.Device{devicetest.New(rpID, origin, "phone").Device()}, RequireDevice: []ticket.Risk{ticket.Risk(v)}})
		check("New RequireDevice", err, "unknown risk class")
	}
}
