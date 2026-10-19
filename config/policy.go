package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"time"
)

// Change is one difference between two policies. For list fields each
// added or removed element is its own Change, with Old empty for an
// addition and New empty for a removal. Loosens marks a change the human
// must confirm in the console before it applies.
type Change struct {
	Field    string
	Old, New string
	Loosens  bool
}

// Policy is the security-relevant view of one profile of a product. The
// console fingerprints it, compares the current policy with the last
// approved one and asks the human before applying any loosening. A
// product's own loosening rules live in its Diff: lockkit never decides
// what loosens a product's fields.
type Policy interface {
	// Diff lists the changes from approved (a value of the same type) to
	// this policy, each marked Loosens or not.
	Diff(approved Policy) []Change
	// Describe is the policy as lines for the console's status screen.
	Describe() []string
}

// Fingerprint returns the hex sha256 of v's JSON encoding. The caller
// passes a canonical form (sorted lists, defaults applied) so that list
// order does not change it. A value JSON cannot encode is fingerprinted
// from its Go syntax, which still differs from every valid policy.
func Fingerprint(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		b = fmt.Appendf(nil, "invalid:%#v", v)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// LooserLimit reports whether moving a limit from o to n loosens it.
// Zero means unlimited.
func LooserLimit(o, n int64) bool {
	switch {
	case n == 0:
		return o != 0
	case o == 0:
		return false
	default:
		return n > o
	}
}

// SetDiff reports removed and added elements of two sorted sets. When
// removalLoosens, a removal loosens the policy (a mask rule, a detector);
// otherwise an addition does (an allow rule, a served name).
func SetDiff(field string, old, cur []string, removalLoosens bool) []Change {
	var out []Change
	for _, v := range old {
		if _, found := slices.BinarySearch(cur, v); !found {
			out = append(out, Change{Field: field, Old: v, Loosens: removalLoosens})
		}
	}
	for _, v := range cur {
		if _, found := slices.BinarySearch(old, v); !found {
			out = append(out, Change{Field: field, New: v, Loosens: !removalLoosens})
		}
	}
	return out
}

// SortedSet returns a sorted, de-duplicated, non-nil copy of s: the
// canonical form of a list field.
func SortedSet(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	out = slices.Compact(out)
	if out == nil {
		out = []string{}
	}
	return out
}

// Base is the profile part every product shares. A product embeds it in
// its profile (or keeps its own fields with the same meaning) and calls
// DiffBase from its Policy.Diff.
type Base struct {
	User        string `json:"user"`
	Credentials string `json:"credentials"`
	// VaultPath is the Vault path read for the login when Credentials is
	// "vault".
	VaultPath string `json:"vault_path,omitempty"`
	// CredentialsTTL makes the console ask for the secret again (and
	// reconnect) once the connection is that old; 0 keeps it for the
	// session.
	CredentialsTTL time.Duration `json:"credentials_ttl,omitempty"`
	TLS            string        `json:"tls,omitempty"`
	TLSCA          string        `json:"tls_ca,omitempty"`
	TLSCert        string        `json:"tls_cert,omitempty"`
	TLSKey         string        `json:"tls_key,omitempty"`
	Production     bool          `json:"production"`
	SSH            *SSHProfile   `json:"ssh,omitempty"`
	// IdleTimeout ends the console session after that long without
	// activity, MaxSession after that long in all.
	IdleTimeout time.Duration `json:"idle_timeout"`
	MaxSession  time.Duration `json:"max_session"`
}

// DiffBase lists the changes of the shared profile part and marks each
// loosening: any change of user (another login), a credentials mode other
// than ask, another Vault path, a weaker tls mode, any change of tls_ca,
// tls_cert or tls_key, production true→false, any change of the ssh table
// (a credentials mode other than ask for the bastion), a longer session
// limit, a longer or removed credentials_ttl.
func DiffBase(a, c Base) []Change {
	var out []Change
	same := func(field, o, n string) {
		if o != n {
			out = append(out, Change{Field: field, Old: o, New: n, Loosens: true})
		}
	}
	same("user", a.User, c.User)
	if a.Production != c.Production {
		out = append(out, Change{Field: "production", Old: strconv.FormatBool(a.Production), New: strconv.FormatBool(c.Production), Loosens: a.Production})
	}
	if a.Credentials != c.Credentials {
		out = append(out, Change{Field: "credentials", Old: a.Credentials, New: c.Credentials, Loosens: c.Credentials != CredentialsAsk})
	}
	// Another Vault path is another login, possibly with more grants.
	same("vault_path", a.VaultPath, c.VaultPath)
	if a.TLS != c.TLS {
		out = append(out, Change{Field: "tls", Old: a.TLS, New: c.TLS, Loosens: TLSRank(c.TLS) < TLSRank(a.TLS)})
	}
	// A new CA can vouch for any certificate; another client certificate
	// is another identity: every change loosens.
	same("tls_ca", a.TLSCA, c.TLSCA)
	same("tls_cert", a.TLSCert, c.TLSCert)
	same("tls_key", a.TLSKey, c.TLSKey)
	switch as, cs := a.SSH, c.SSH; {
	case as == nil && cs == nil:
	case as == nil || cs == nil:
		// Added or removed: the backend is reached another way.
		out = append(out, Change{Field: "ssh", Old: SSHString(as), New: SSHString(cs), Loosens: true})
	default:
		same("ssh.host", as.Host, cs.Host)
		same("ssh.port", strconv.Itoa(as.Port), strconv.Itoa(cs.Port))
		same("ssh.user", as.User, cs.User)
		same("ssh.auth", as.Auth, cs.Auth)
		same("ssh.key", as.Key, cs.Key)
		if as.Credentials != cs.Credentials {
			out = append(out, Change{Field: "ssh.credentials", Old: as.Credentials, New: cs.Credentials, Loosens: cs.Credentials != CredentialsAsk})
		}
	}
	for _, f := range []struct {
		field string
		o, n  time.Duration
	}{{"idle_timeout", a.IdleTimeout, c.IdleTimeout}, {"max_session", a.MaxSession, c.MaxSession}} {
		if f.o != f.n {
			out = append(out, Change{Field: "limits." + f.field, Old: f.o.String(), New: f.n.String(), Loosens: f.n > f.o})
		}
	}
	if a.CredentialsTTL != c.CredentialsTTL {
		out = append(out, Change{Field: "credentials_ttl", Old: a.CredentialsTTL.String(), New: c.CredentialsTTL.String(),
			Loosens: LooserLimit(int64(a.CredentialsTTL), int64(c.CredentialsTTL))})
	}
	return out
}
