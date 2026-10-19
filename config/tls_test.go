package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestTLSRank(t *testing.T) {
	if TLSRank("") != TLSRank(TLSPrefer) || TLSRank("bogus") != -1 {
		t.Fatal("empty or unknown mode")
	}
	for i, m := range []string{TLSDisable, TLSPrefer, TLSRequire, TLSVerifyCA, TLSVerifyFull} {
		if TLSRank(m) != i {
			t.Errorf("%s ranks %d", m, TLSRank(m))
		}
	}
}

func TestTLSVerifiesChain(t *testing.T) {
	for _, c := range []struct {
		mode, ca string
		want     bool
	}{{TLSVerifyFull, "", true}, {TLSVerifyCA, "", true}, {TLSRequire, "/ca.pem", true}, {TLSRequire, "", false}, {TLSPrefer, "/ca.pem", false}} {
		if got := TLSVerifiesChain(c.mode, c.ca); got != c.want {
			t.Errorf("%s ca=%q: %v", c.mode, c.ca, got)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	for _, h := range []string{"localhost", "LOCALHOST", "127.0.0.1", "127.8.9.1", "::1"} {
		if !IsLoopback(h) {
			t.Errorf("%s: not loopback", h)
		}
	}
	for _, h := range []string{"db.example.com", "10.0.0.1", "localhost.example.com", ""} {
		if IsLoopback(h) {
			t.Errorf("%s: loopback", h)
		}
	}
}

func TestValidServerName(t *testing.T) {
	for _, ok := range []string{"db.example.com", "10.0.0.1", "::1", "a"} {
		if !ValidServerName(ok) {
			t.Errorf("%s refused", ok)
		}
	}
	for _, bad := range []string{"", "-a.com", "a..b", "a b", strings.Repeat("a", 254)} {
		if ValidServerName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func errf(format string, a ...any) error { return fmt.Errorf("profile \"p\": "+format, a...) }

func TestParseSSH(t *testing.T) {
	s, err := ParseSSH(testProduct, RawSSH{Host: "bastion.example.com", User: "u", Auth: SSHAuthAgent}, CredentialsVault, errf)
	if err != nil {
		t.Fatal(err)
	}
	// The default port; Vault holds the backend login, the bastion's secret is asked.
	if s.Port != DefaultSSHPort || s.Credentials != CredentialsAsk {
		t.Fatalf("%+v", s)
	}
	if s, _ := ParseSSH(testProduct, RawSSH{Host: "b", User: "u", Auth: SSHAuthKey, Key: "~/.ssh/id"}, CredentialsKeychain, errf); s.Credentials != CredentialsKeychain {
		t.Fatalf("credentials follow the profile: %+v", s)
	}
	for name, r := range map[string]RawSSH{
		"no host":       {User: "u", Auth: SSHAuthAgent},
		"no user":       {Host: "b", Auth: SSHAuthAgent},
		"bad port":      {Host: "b", User: "u", Auth: SSHAuthAgent, Port: 70000},
		"key no file":   {Host: "b", User: "u", Auth: SSHAuthKey},
		"agent key":     {Host: "b", User: "u", Auth: SSHAuthAgent, Key: "k"},
		"bad auth":      {Host: "b", User: "u", Auth: "magic"},
		"vault creds":   {Host: "b", User: "u", Auth: SSHAuthAgent, Credentials: CredentialsVault},
		"dsn password":  {Host: "u:pw@b", User: "u", Auth: SSHAuthAgent},
		"control chars": {Host: "b\x1b", User: "u", Auth: SSHAuthAgent},
	} {
		_, err := ParseSSH(testProduct, r, CredentialsAsk, errf)
		if err == nil || !strings.HasPrefix(err.Error(), `profile "p": `) {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, err = ParseSSH(testProduct, RawSSH{Host: "u:pw@b", User: "u", Auth: SSHAuthAgent}, CredentialsAsk, errf)
	if !strings.Contains(err.Error(), "ssh.host looks like a DSN with an embedded password; lockmq never reads secrets") {
		t.Fatalf("message: %v", err)
	}
}

func TestSSHString(t *testing.T) {
	if SSHString(nil) != "none" {
		t.Fatal(SSHString(nil))
	}
	if got := SSHString(&SSHProfile{Host: "b", Port: 22, User: "u", Auth: SSHAuthAgent}); got != "u@b:22 (agent)" {
		t.Fatal(got)
	}
}
