package config

import (
	"net"
	"regexp"
	"slices"
	"strings"
)

// TLS modes of a network profile, as libpq's sslmode, in increasing
// strength.
const (
	TLSDisable    = "disable"
	TLSPrefer     = "prefer"
	TLSRequire    = "require"
	TLSVerifyCA   = "verify-ca"
	TLSVerifyFull = "verify-full"
)

var tlsModes = []string{TLSDisable, TLSPrefer, TLSRequire, TLSVerifyCA, TLSVerifyFull}

// TLSRank orders TLS modes by strength. "" is prefer, the mode of profiles
// approved before the setting existed; an unknown mode ranks -1.
func TLSRank(mode string) int {
	if mode == "" {
		mode = TLSPrefer
	}
	return slices.Index(tlsModes, mode)
}

// serverNameRe is a DNS name: dot-separated labels of letters, digits and
// inner hyphens.
var serverNameRe = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$`)

// ValidServerName reports a DNS name or an IP literal.
func ValidServerName(s string) bool {
	return len(s) <= 253 && (serverNameRe.MatchString(s) || net.ParseIP(s) != nil)
}

// TLSVerifiesChain reports a tls mode that verifies the server's certificate
// chain: verify-ca and verify-full, and require with tls_ca, as libpq.
func TLSVerifiesChain(mode, ca string) bool {
	return TLSRank(mode) >= TLSRank(TLSVerifyCA) || (mode == TLSRequire && ca != "")
}

// IsLoopback reports a host that names this machine: "localhost" or a
// loopback IP literal. Any other name, even one that resolves to loopback,
// is remote.
func IsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
