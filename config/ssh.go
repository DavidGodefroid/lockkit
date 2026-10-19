package config

import (
	"strconv"

	"github.com/DavidGodefroid/lockkit/kit"
)

// Credentials modes: where the console gets a secret.
const (
	CredentialsAsk      = "ask"
	CredentialsKeychain = "keychain"
	CredentialsVault    = "vault"
)

// DefaultSSHPort is the bastion port when ssh.port is unset.
const DefaultSSHPort = 22

// SSH authentication methods.
const (
	SSHAuthKey      = "key"
	SSHAuthAgent    = "agent"
	SSHAuthPassword = "password"
)

// SSHProfile is the bastion a network profile is reached through. Host and
// Port of the profile are then seen from the bastion. It never holds a
// secret: a key passphrase or an SSH password follows Credentials.
type SSHProfile struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	User        string `json:"user"`
	Auth        string `json:"auth"`
	Key         string `json:"key,omitempty"`
	Credentials string `json:"credentials"`
}

// RawSSH is the [profiles.<name>.ssh] table as written.
type RawSSH struct {
	Host        string `toml:"host"`
	Port        int    `toml:"port"`
	User        string `toml:"user"`
	Auth        string `toml:"auth"`
	Key         string `toml:"key"`
	Credentials string `toml:"credentials"`
}

// ParseSSH validates the ssh table of a profile whose own credentials mode
// is credentials. errf prefixes errors with the profile. A product checks
// first that its backend can be reached through a TCP forward.
func ParseSSH(p kit.Product, r RawSSH, credentials string, errf func(string, ...any) error) (*SSHProfile, error) {
	for _, f := range []struct{ key, val string }{{"ssh.host", r.Host}, {"ssh.user", r.User}, {"ssh.key", r.Key}} {
		if err := CheckValue(p, f.key, f.val); err != nil {
			return nil, errf("%v", err)
		}
	}
	switch {
	case r.Host == "":
		return nil, errf("ssh.host is required")
	case r.User == "":
		return nil, errf("ssh.user is required")
	case r.Port < 0 || r.Port > 65535:
		return nil, errf("ssh.port %d out of range", r.Port)
	}
	switch r.Auth {
	case SSHAuthKey:
		if r.Key == "" {
			return nil, errf("ssh.key is required with ssh.auth = \"key\"")
		}
	case SSHAuthAgent, SSHAuthPassword:
		if r.Key != "" {
			return nil, errf("ssh.key is only used with ssh.auth = \"key\"")
		}
	default:
		return nil, errf("ssh.auth must be key, agent or password")
	}
	switch r.Credentials {
	case "", CredentialsAsk, CredentialsKeychain:
	default:
		return nil, errf("unknown ssh.credentials mode %q (want ask or keychain)", r.Credentials)
	}
	s := &SSHProfile{Host: r.Host, Port: r.Port, User: r.User, Auth: r.Auth, Key: r.Key, Credentials: r.Credentials}
	if s.Port == 0 {
		s.Port = DefaultSSHPort
	}
	if s.Credentials == "" {
		s.Credentials = credentials
		// Vault holds the backend login; the bastion's secret is asked.
		if s.Credentials == "" || s.Credentials == CredentialsVault {
			s.Credentials = CredentialsAsk
		}
	}
	return s, nil
}

// SSHString shows a bastion in a policy change.
func SSHString(s *SSHProfile) string {
	if s == nil {
		return "none"
	}
	return s.User + "@" + s.Host + ":" + strconv.Itoa(s.Port) + " (" + s.Auth + ")"
}
