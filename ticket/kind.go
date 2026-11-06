package ticket

import (
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// VersionKinds is the schema version of tickets that name what they ask
// for (Kind, Subject) and of decisions that name what decided them (Rule)
// and may carry a sealed secret (Secret). A version-1 value has none of
// these members and keeps verifying as it did: Version stays the version
// of every other signed value, and of the tickets NewTicket makes.
//
// A lock pinned to a lockkit that knows VersionKinds reads both versions;
// a hub or a lock that does not refuses a version-2 value (fail closed).
const VersionKinds = 2

// Kind is the closed set of what a version-2 ticket asks for, so that a
// decider (`lox run`'s rules, a facade) rules on a structured request,
// not on the screen's text alone. Each kind goes with the risk classes
// KindRisks allows.
type Kind string

const (
	// KindConnect: open the lock's backend connection for one profile
	// (Subject.Profile, Endpoint, Credential). A lock asks once per
	// connection: the connection lives until it is idle (lazyconn).
	KindConnect Kind = "connect"
	// KindRead: read through an open connection (a query, a grant's scope).
	KindRead Kind = "read"
	// KindWrite: change data.
	KindWrite Kind = "write"
	// KindDDL: change the schema.
	KindDDL Kind = "ddl"
	// KindAction: a verb that is neither a read nor a write of rows: an MQ
	// publish or purge, a file move, an HTTP method (Subject.Verb, Target).
	KindAction Kind = "action"
	// KindEndpoint: reach a new host or route (lockhttp; Subject.Endpoint,
	// Verb, Target).
	KindEndpoint Kind = "endpoint"
	// KindPolicy: loosen the policy in force.
	KindPolicy Kind = "policy"
)

// Kinds lists every kind.
var Kinds = []Kind{KindConnect, KindRead, KindWrite, KindDDL, KindAction, KindEndpoint, KindPolicy}

// kindRisks are the risk classes each kind may carry: the hub routes and
// expires by risk, the decider rules by kind, and neither can be made to
// contradict the other.
var kindRisks = map[Kind][]Risk{
	KindConnect:  {RiskRead, RiskReadPII, RiskWrite, RiskProdWrite, RiskUnlock},
	KindRead:     {RiskRead, RiskReadPII, RiskGrant},
	KindWrite:    {RiskWrite, RiskProdWrite},
	KindDDL:      {RiskWrite, RiskProdWrite},
	KindAction:   {RiskRead, RiskReadPII, RiskWrite, RiskProdWrite},
	KindEndpoint: {RiskRead, RiskReadPII, RiskWrite, RiskProdWrite},
	KindPolicy:   {RiskPolicyLoosen},
}

// KindRisks lists the risk classes a ticket of kind k may carry (nil for
// an unknown kind).
func KindRisks(k Kind) []Risk { return append([]Risk(nil), kindRisks[k]...) }

// ParseKind returns the kind named s; any other name is an error that
// does not quote s.
func ParseKind(s string) (Kind, error) {
	for _, k := range Kinds {
		if string(k) == s {
			return k, nil
		}
	}
	names := make([]string, len(Kinds))
	for i, k := range Kinds {
		names[i] = string(k)
	}
	return "", fmt.Errorf("ticket: unknown ticket kind: want one of %s", strings.Join(names, ", "))
}

// Valid reports whether k is one of Kinds.
func (k Kind) Valid() bool { _, err := ParseKind(string(k)); return err == nil }

// UnmarshalJSON refuses a kind outside Kinds.
func (k *Kind) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseKind(s)
	if err != nil {
		return err
	}
	*k = v
	return nil
}

// Credential sources a connect ticket names (Subject.Credential): where
// the lock gets the backend's secret. They mirror the policy's
// credentials modes, plus CredentialNone for a backend without one.
const (
	CredentialAsk      = "ask"
	CredentialKeychain = "keychain"
	CredentialVault    = "vault"
	CredentialNone     = "none"
)

func validCredential(s string) bool {
	switch s {
	case CredentialAsk, CredentialKeychain, CredentialVault, CredentialNone:
		return true
	}
	return false
}

// Subject is the structured request of a version-2 ticket, what a
// decider's rules match on. Like the screen, it leaves the lock and the
// hub reads it: the lock puts in it only names from its own configuration
// (a profile, an endpoint without userinfo, a credential source) and
// names it masks as it masks the screen (a queue, a route), never a
// secret, a value or a row.
type Subject struct {
	// Profile is the lock profile the request runs under.
	Profile string `json:"profile,omitempty"`
	// Endpoint is the backend (connect: "db.internal:5432/shop") or the
	// new host (endpoint: "api.example.com"): host[:port][/path] only,
	// without userinfo, query, options or whitespace (validEndpoint).
	Endpoint string `json:"endpoint,omitempty"`
	// Credential is where the lock gets the secret (connect only): one of
	// the Credential* sources.
	Credential string `json:"credential,omitempty"`
	// SecretTo, on a connect ticket, asks the decider for the secret: it
	// is the lock's one-use X25519 public key (32 bytes, base64url) for
	// this ticket, signed with the ticket. The decision carries the
	// secret sealed to it (Decision.Secret): the hub relays a box it
	// cannot open. Set when the profile is "ask", or its Vault token has
	// expired.
	SecretTo string `json:"secret_to,omitempty"`
	// Verb is an action's verb ("publish", "purge", "GET") or an
	// endpoint's method.
	Verb string `json:"verb,omitempty"`
	// Target is what the verb acts on (a queue, a path, a route, a table),
	// without query string, fragment or whitespace (validTarget).
	Target string `json:"target,omitempty"`
}

// maxVerb bounds Subject.Verb.
const maxVerb = 64

func validVerb(s string) bool {
	if s == "" || len(s) > maxVerb {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' || c == ':') {
			return false
		}
	}
	return true
}

// validEndpoint reports whether s is an endpoint the hub may read:
// host[:port][/path] (an optional scheme:// prefix, a bracketed IPv6
// host), in ASCII letters, digits and . - _ : / [ ]. Everything else —
// whitespace, ? # = & ; @, percent-escapes — is how a DSN, a URL query or
// userinfo carries a secret ("host=db password=…", "db:5432/x?sslpassword=…"),
// and the subject is not masked: the lock never sends one.
func validEndpoint(s string) bool {
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '-' || c == '_' || c == ':' || c == '/' || c == '[' || c == ']') {
			return false
		}
	}
	return true
}

// validTarget reports whether s is a target the hub may read: a name or a
// path, never a query string or a fragment ("/users?email=…&token=…") nor
// anything with whitespace or control characters. A lock that needs the
// rest shows it on the screen, which render masks.
func validTarget(s string) bool {
	for _, r := range s {
		if r == '?' || r == '#' || unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Validate checks s for a ticket of kind k, as Sign and VerifyTicket do:
// a lock calls it before it builds a screen from the subject.
func (s *Subject) Validate(k Kind) error {
	if !k.Valid() {
		return invalid("kind: unknown")
	}
	return s.validate(k)
}

// validate checks s for a ticket of kind k.
func (s *Subject) validate(k Kind) error {
	for _, f := range []struct{ n, v string }{
		{"subject.profile", s.Profile}, {"subject.endpoint", s.Endpoint}, {"subject.target", s.Target},
	} {
		if err := checkStr(f.n, f.v, maxField); err != nil {
			return err
		}
	}
	if strings.Contains(s.Endpoint, "@") {
		return invalid("subject.endpoint: userinfo never leaves the lock")
	}
	if !validEndpoint(s.Endpoint) {
		return invalid("subject.endpoint: want host[:port][/path], no query, option or space")
	}
	if !validTarget(s.Target) {
		return invalid("subject.target: no space, query or fragment (mask it through render)")
	}
	if s.Verb != "" && !validVerb(s.Verb) {
		return invalid("subject.verb: not a verb token")
	}
	if s.SecretTo != "" {
		if b, err := enc.DecodeString(s.SecretTo); err != nil || len(b) != 32 {
			return invalid("subject.secret_to: not an X25519 key")
		}
	}
	only := func(allowed ...string) error {
		set := map[string]string{"profile": s.Profile, "endpoint": s.Endpoint, "credential": s.Credential,
			"secret_to": s.SecretTo, "verb": s.Verb, "target": s.Target}
		for _, a := range allowed {
			delete(set, a)
		}
		for _, name := range []string{"profile", "endpoint", "credential", "secret_to", "verb", "target"} {
			if v, ok := set[name]; ok && v != "" {
				return invalid("subject.%s: not part of a %s ticket", name, k)
			}
		}
		return nil
	}
	switch k {
	case KindConnect:
		switch {
		case s.Profile == "":
			return invalid("subject.profile: required on a connect ticket")
		case s.Endpoint == "":
			return invalid("subject.endpoint: required on a connect ticket")
		case !validCredential(s.Credential):
			return invalid("subject.credential: want ask, keychain, vault or none")
		case s.Credential == CredentialNone && s.SecretTo != "":
			return invalid("subject.secret_to: a secret asked for a backend without one")
		}
		return only("profile", "endpoint", "credential", "secret_to")
	case KindAction:
		if s.Verb == "" {
			return invalid("subject.verb: required on an action ticket")
		}
		return only("profile", "verb", "target")
	case KindEndpoint:
		if s.Endpoint == "" {
			return invalid("subject.endpoint: required on an endpoint ticket")
		}
		return only("profile", "endpoint", "verb", "target")
	default:
		return only("profile", "target")
	}
}

// secretKey is the X25519 key of SecretTo.
func (s *Subject) secretKey() (*ecdh.PublicKey, error) {
	raw, err := enc.DecodeString(s.SecretTo)
	if err != nil {
		return nil, invalid("subject.secret_to")
	}
	return ecdh.X25519().NewPublicKey(raw)
}

// validateKind checks the members of a version-2 ticket.
func (t *Ticket) validateKind() error {
	if t.V == Version {
		if t.Kind != "" || t.Subject != nil {
			return invalid("kind and subject: version %d tickets have none (use version %d)", Version, VersionKinds)
		}
		return nil
	}
	if !t.Kind.Valid() {
		return invalid("kind %q", t.Kind)
	}
	allowed := false
	for _, r := range kindRisks[t.Kind] {
		allowed = allowed || r == t.Risk
	}
	if !allowed {
		return invalid("risk %s: not a risk of a %s ticket", t.Risk, t.Kind)
	}
	if t.Subject == nil {
		switch t.Kind {
		case KindConnect, KindAction, KindEndpoint:
			return invalid("subject: required on a %s ticket", t.Kind)
		}
		return nil
	}
	return t.Subject.validate(t.Kind)
}

// NewKindTicket is NewTicket for a version-2 ticket of kind k, asking for
// subj (nil only for read, write, ddl and policy). Sign validates the
// pair: a kind with a risk it does not allow, or a subject that is not
// the kind's, is refused.
func NewKindTicket(src Source, k Kind, risk Risk, subj *Subject, planHash, policyFP string, now time.Time, ttl time.Duration) *Ticket {
	t := NewTicket(src, risk, planHash, policyFP, now, ttl)
	t.V, t.Kind = VersionKinds, k
	if subj != nil {
		s := *subj
		t.Subject = &s
	}
	return t
}

// ConnectPlanHash is the plan hash of a connect ticket: the hash of its
// subject. A decision on it binds exactly that profile, endpoint,
// credential source and secret key.
func ConnectPlanHash(subj Subject) (string, error) { return HashOf(subj) }

// NewConnectTicket is the connect ticket for subj, whose plan is subj
// itself (ConnectPlanHash).
func NewConnectTicket(src Source, risk Risk, subj Subject, policyFP string, now time.Time, ttl time.Duration) (*Ticket, error) {
	if err := subj.Validate(KindConnect); err != nil {
		return nil, err
	}
	plan, err := ConnectPlanHash(subj)
	if err != nil {
		return nil, err
	}
	return NewKindTicket(src, KindConnect, risk, &subj, plan, policyFP, now, ttl), nil
}

// EffectiveKind is t's kind; for a version-1 ticket, the kind its risk
// implies (read for the read classes and grants, write for writes,
// policy for policy loosening, connect for unlock).
func (t *Ticket) EffectiveKind() Kind {
	if t.Kind != "" {
		return t.Kind
	}
	switch t.Risk {
	case RiskRead, RiskReadPII, RiskGrant:
		return KindRead
	case RiskPolicyLoosen:
		return KindPolicy
	case RiskUnlock:
		return KindConnect
	default:
		return KindWrite
	}
}

// EncodeX25519 is pub as a Subject.SecretTo carries it.
func EncodeX25519(pub *ecdh.PublicKey) string { return enc.EncodeToString(pub.Bytes()) }
