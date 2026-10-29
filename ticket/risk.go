package ticket

import (
	"encoding/json"
	"fmt"
	"time"
)

// Risk is the closed set of risk classes. Each product maps its operations
// onto one of them; the hub routes and expires tickets by risk alone, so a
// product cannot invent a class a facade does not know.
type Risk string

const (
	RiskRead         Risk = "read"
	RiskReadPII      Risk = "read-pii"
	RiskWrite        Risk = "write"
	RiskProdWrite    Risk = "prod-write"
	RiskPolicyLoosen Risk = "policy-loosen"
	RiskUnlock       Risk = "unlock"
)

// Risks lists every risk class, from the least to the most sensitive.
var Risks = []Risk{RiskRead, RiskReadPII, RiskWrite, RiskProdWrite, RiskPolicyLoosen, RiskUnlock}

// ParseRisk returns the risk class named s; any other name is an error.
func ParseRisk(s string) (Risk, error) {
	for _, r := range Risks {
		if string(r) == s {
			return r, nil
		}
	}
	return "", fmt.Errorf("ticket: unknown risk class %q", s)
}

// Valid reports whether r is one of Risks.
func (r Risk) Valid() bool {
	_, err := ParseRisk(string(r))
	return err == nil
}

// UnmarshalJSON refuses a risk class outside Risks.
func (r *Risk) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseRisk(s)
	if err != nil {
		return err
	}
	*r = v
	return nil
}

// TTL is how long a ticket of class r waits for a decision, and how long
// an approval stays usable once given; 0 means no expiry. Reads never
// expire; writes and policy loosening last 24 h; production writes and
// unlock (a secret typed for the lock) 4 h.
func (r Risk) TTL() time.Duration {
	switch r {
	case RiskRead, RiskReadPII:
		return 0
	case RiskWrite, RiskPolicyLoosen:
		return 24 * time.Hour
	default: // prod-write, unlock, and the shortest for anything else
		return 4 * time.Hour
	}
}

// ClampTTL is the TTL of class r for an instance configured with
// configured: an instance may only shorten it. configured <= 0 keeps
// r.TTL().
func ClampTTL(r Risk, configured time.Duration) time.Duration {
	def := r.TTL()
	if configured <= 0 {
		return def
	}
	if def == 0 || configured < def {
		return configured
	}
	return def
}
