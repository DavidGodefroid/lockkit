package ticket

import (
	"crypto/ecdh"
	"errors"
	"fmt"
)

// Rule is what decided a version-2 decision, for the lock's audit: one of
// the decider's auto rules (By RuleAuto, ID the rule's id, as `lox run`
// names it), or a human on Decision.Facade (By RuleHuman, no ID).
type Rule struct {
	By string `json:"by"`
	ID string `json:"id,omitempty"`
}

// Who decided.
const (
	RuleAuto  = "auto"
	RuleHuman = "human"
)

func (r *Rule) validate() error {
	switch r.By {
	case RuleAuto:
		if r.ID == "" {
			return invalid("rule.id: an auto decision names its rule")
		}
	case RuleHuman:
		if r.ID != "" {
			return invalid("rule.id: a human decision names no rule")
		}
	default:
		return invalid("rule.by %q", r.By)
	}
	return checkStr("rule.id", r.ID, maxField)
}

// Auto reports whether an auto rule, not a human, decided d.
func (d *Decision) Auto() bool { return d.Rule != nil && d.Rule.By == RuleAuto }

// validateKind checks the members of a version-2 decision.
func (d *Decision) validateKind() error {
	if d.V == Version {
		if d.Rule != nil || d.Secret != nil {
			return invalid("rule and secret: version %d decisions have none (use version %d)", Version, VersionKinds)
		}
		return nil
	}
	if d.Rule == nil {
		return invalid("rule: required on a version %d decision", VersionKinds)
	}
	if err := d.Rule.validate(); err != nil {
		return err
	}
	if d.Rule.By == RuleAuto && d.Device != nil {
		return invalid("rule: an auto decision signed by a device")
	}
	if d.Secret != nil {
		if d.Decision != Approved {
			return invalid("secret: on a %s decision", d.Decision)
		}
		if err := d.Secret.validate(); err != nil {
			return err
		}
	}
	return nil
}

// ErrAuto: an auto rule decided a ticket that only a human may decide.
var ErrAuto = errors.New("ticket: auto decision on a never-auto ticket")

// ErrNoSecret: a connect decision carries no secret where the lock asked
// for one, or one where it did not.
var ErrNoSecret = errors.New("ticket: no secret for the lock")

// ContextSecret is the associated data of a connect decision's secret.
const ContextSecret Context = "lockkit/connect-secret/v1"

// SecretAAD binds a sealed secret to the connect ticket it answers: its
// id, instance, lock key and plan hash. A box sealed for one ticket does
// not open as another's.
func SecretAAD(t *Ticket) []byte {
	return ContextSecret.message([]byte(t.ID + "\n" + t.Source.Instance + "\n" + t.Source.KeyID + "\n" + t.PlanHash))
}

// SealSecret seals secret for connect ticket t, to the key the lock put
// in t.Subject.SecretTo: what a decider (`lox run`) puts in
// Decision.Secret. The caller verified t first (VerifyTicket, under the
// lock key it pins): the signature is what binds SecretTo to the lock, so
// a hub cannot slip in a key of its own.
func SealSecret(t *Ticket, secret []byte) (*Sealed, error) {
	if t.Kind != KindConnect || t.Subject == nil || t.Subject.SecretTo == "" {
		return nil, fmt.Errorf("%w: ticket %s asks for no secret", ErrNoSecret, t.ID)
	}
	pub, err := t.Subject.secretKey()
	if err != nil {
		return nil, err
	}
	return Seal(pub, secret, SecretAAD(t))
}

// OpenSecret opens the secret of d, a decision that Match and Usable
// accepted for the lock's own connect ticket t, with priv, the one-use
// key whose public half is t.Subject.SecretTo. A ticket that asked for a
// secret and an approval without one (or the reverse) is ErrNoSecret; a
// box that does not open is ErrOpen. The caller wipes the secret after
// use (secrets.Wipe).
func (d *Decision) OpenSecret(t *Ticket, priv *ecdh.PrivateKey) ([]byte, error) {
	asked := t.Kind == KindConnect && t.Subject != nil && t.Subject.SecretTo != ""
	switch {
	case d.Secret == nil && asked:
		return nil, fmt.Errorf("%w: ticket %s asked for one", ErrNoSecret, t.ID)
	case d.Secret != nil && !asked:
		return nil, fmt.Errorf("%w: ticket %s asked for none", ErrNoSecret, t.ID)
	case d.Secret == nil:
		return nil, nil
	}
	if pub, err := t.Subject.secretKey(); err != nil || priv == nil || !priv.PublicKey().Equal(pub) {
		return nil, ErrOpen
	}
	return Open(priv, d.Secret, SecretAAD(t))
}
