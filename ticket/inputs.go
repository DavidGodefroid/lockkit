package ticket

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Typed inputs bounds.
const (
	// MaxInputs bounds Subject.Inputs.
	MaxInputs = 16
	// maxInputName bounds an input's name.
	maxInputName = 32
	// MaxInputValue bounds a typed value, in bytes.
	MaxInputValue = 1024
)

// ErrInputs: the typed values are not those the ticket asked for (a name
// missing or extra), or one is not a value a human types.
var ErrInputs = errors.New("ticket: typed inputs do not answer the ticket")

// ContextInputs is the associated data of the typed values of a plan
// ticket's decision: a connect secret never opens as inputs, nor inputs
// as a connect secret.
const ContextInputs Context = "lockkit/plan-inputs/v1"

// InputsAAD binds sealed inputs to the ticket they answer: its id,
// instance, lock key and plan hash.
func InputsAAD(t *Ticket) []byte {
	return ContextInputs.message([]byte(t.ID + "\n" + t.Source.Instance + "\n" + t.Source.KeyID + "\n" + t.PlanHash))
}

func validInputName(s string) bool {
	if s == "" || len(s) > maxInputName {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// validInputs checks Subject.Inputs: at most MaxInputs valid names,
// sorted and distinct.
func validInputs(names []string) error {
	if len(names) > MaxInputs {
		return invalid("subject.inputs: more than %d names", MaxInputs)
	}
	for i, n := range names {
		if !validInputName(n) {
			// Not quoted: it may be a value pasted where a name goes.
			return invalid("subject.inputs: a name is not [a-z0-9_]{1,%d}", maxInputName)
		}
		if i > 0 {
			switch {
			case n == names[i-1]:
				return invalid("subject.inputs: %s twice", n)
			case n < names[i-1]:
				return invalid("subject.inputs: not sorted")
			}
		}
	}
	return nil
}

// SortInputs is names sorted, as Subject.Inputs carries them.
func SortInputs(names []string) []string {
	out := append([]string(nil), names...)
	sort.Strings(out)
	return out
}

// checkInputValue checks one typed value, without quoting it.
func checkInputValue(name string, v []byte) error {
	switch {
	case len(v) == 0:
		return fmt.Errorf("%w: input %s is empty", ErrInputs, name)
	case len(v) > MaxInputValue:
		return fmt.Errorf("%w: input %s is longer than %d bytes", ErrInputs, name, MaxInputValue)
	case !utf8.Valid(v):
		return fmt.Errorf("%w: input %s is not valid UTF-8", ErrInputs, name)
	case strings.IndexFunc(string(v), unicode.IsControl) >= 0:
		return fmt.Errorf("%w: input %s holds a control character", ErrInputs, name)
	}
	return nil
}

// checkInputs checks that values answers exactly names, each value one a
// human types.
func checkInputs(names []string, values map[string][]byte) error {
	if len(values) != len(names) {
		return fmt.Errorf("%w: %d values for %d names", ErrInputs, len(values), len(names))
	}
	for _, n := range names {
		v, ok := values[n]
		if !ok {
			return fmt.Errorf("%w: no value for %s", ErrInputs, n)
		}
		if err := checkInputValue(n, v); err != nil {
			return err
		}
	}
	return nil
}

// AsksInputs reports whether t asks the human for typed values
// (Subject.Inputs).
func (t *Ticket) AsksInputs() bool { return t.Subject != nil && len(t.Subject.Inputs) > 0 }

// SealInputs seals values, the human's typed values for ticket t (exactly
// the names of t.Subject.Inputs, each 1..MaxInputValue bytes of UTF-8
// without control characters), to the key the lock put in
// t.Subject.SecretTo: what a decider (`lox run`) puts in Decision.Secret.
// The caller verified t first (VerifyTicket, under the lock key it pins):
// the signature is what binds SecretTo to the lock.
func SealInputs(t *Ticket, values map[string][]byte) (*Sealed, error) {
	if !t.AsksInputs() || t.Subject.SecretTo == "" {
		return nil, fmt.Errorf("%w: ticket %s asks for no inputs", ErrNoSecret, t.ID)
	}
	if err := checkInputs(t.Subject.Inputs, values); err != nil {
		return nil, err
	}
	pub, err := t.Subject.secretKey()
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, len(values))
	for k, v := range values {
		m[k] = string(v)
	}
	pt, err := Canonical(m)
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	return Seal(pub, pt, InputsAAD(t))
}

// OpenInputs opens the typed values of d, a decision that Match and
// Usable accepted for the lock's own ticket t, with priv, the one-use key
// whose public half is t.Subject.SecretTo. A ticket that asked for inputs
// and an approval without them (or the reverse) is ErrNoSecret; a box
// that does not open (another ticket's, a connect secret) is ErrOpen;
// values that are not exactly t's names, or not values a human types,
// are ErrInputs. The caller wipes the values after use (secrets.Wipe).
func (d *Decision) OpenInputs(t *Ticket, priv *ecdh.PrivateKey) (map[string][]byte, error) {
	asked := t.AsksInputs()
	switch {
	case d.Secret == nil && asked:
		return nil, fmt.Errorf("%w: ticket %s asked for inputs", ErrNoSecret, t.ID)
	case d.Secret != nil && !asked:
		return nil, fmt.Errorf("%w: ticket %s asked for no inputs", ErrNoSecret, t.ID)
	case d.Secret == nil:
		return nil, nil
	}
	if pub, err := t.Subject.secretKey(); err != nil || priv == nil || !priv.PublicKey().Equal(pub) {
		return nil, ErrOpen
	}
	pt, err := Open(priv, d.Secret, InputsAAD(t))
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	var m map[string]string
	if err := decodeStrict(pt, &m); err != nil {
		return nil, fmt.Errorf("%w: not a map of values", ErrInputs)
	}
	out := make(map[string][]byte, len(m))
	for k, v := range m {
		out[k] = []byte(v)
	}
	if err := checkInputs(t.Subject.Inputs, out); err != nil {
		for _, v := range out {
			clear(v)
		}
		return nil, err
	}
	return out, nil
}
