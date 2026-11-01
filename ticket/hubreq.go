package ticket

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Hub requests: what a human asks of a lock through the hub besides a
// decision, delivered over the lock's signed long poll. A reveal shows the
// clear screen of a ticket on a local facade; a renewal asks again for an
// expired ticket. Neither runs anything: only a decision does.

const (
	// ContextHubRequest signs a HubRequest with the hub's key.
	ContextHubRequest Context = "lockkit/hub-request/v1"
	// ContextRevealKey signs a RevealKey with a facade's key.
	ContextRevealKey Context = "lockkit/reveal-key/v1"
	// ContextRevealBox is the associated data of a reveal's box.
	ContextRevealBox Context = "lockkit/reveal-box/v1"
	// ContextRevealAnswer signs a RevealAnswer with the lock's key.
	ContextRevealAnswer Context = "lockkit/reveal-answer/v1"
)

// Local facades: they run on the host, at the human's own terminal.
const (
	FacadeTTY  = "tty"
	FacadeDeck = "deck"
)

// CanReveal reports whether facade may show a ticket's clear values on
// demand (Ctrl-O): only local facades. A device has its own path
// (PII.SealedFor); a chat facade never shows clear values.
func CanReveal(facade string) bool { return facade == FacadeTTY || facade == FacadeDeck }

// FacadeKey is a facade's Ed25519 key, as a lock pins it: `lox up`
// writes the facades the human reviewed at the host's terminal.
type FacadeKey struct {
	Facade string `json:"facade"`
	// Key is the raw 32-byte public key, standard base64.
	Key string `json:"key"`
}

// FacadeSet is the file of the facade keys a lock pins.
type FacadeSet struct {
	V       int         `json:"v"`
	Facades []FacadeKey `json:"facades"`
}

// PinnedFacade is a parsed FacadeKey.
type PinnedFacade struct {
	Facade string
	Key    ed25519.PublicKey
}

// MaxFacades bounds a FacadeSet.
const MaxFacades = 16

// ParseFacades reads a FacadeSet: version, facade names (CanReveal only:
// a key of any other facade is refused, not ignored), keys, no key twice.
func ParseFacades(data []byte) ([]PinnedFacade, error) {
	var fs FacadeSet
	if err := json.Unmarshal(data, &fs); err != nil {
		return nil, invalid("facades: %v", err)
	}
	if fs.V != Version {
		return nil, invalid("facades: unsupported version %d", fs.V)
	}
	if len(fs.Facades) > MaxFacades {
		return nil, invalid("facades: more than %d keys", MaxFacades)
	}
	out := make([]PinnedFacade, 0, len(fs.Facades))
	seen := map[string]bool{}
	for _, f := range fs.Facades {
		if !CanReveal(f.Facade) {
			return nil, invalid("facades: facade %q cannot reveal", f.Facade)
		}
		k, err := base64.StdEncoding.DecodeString(f.Key)
		if err != nil || len(k) != ed25519.PublicKeySize {
			return nil, invalid("facades: key of %s is not a base64 Ed25519 key", f.Facade)
		}
		if seen[string(k)] {
			return nil, invalid("facades: a key twice")
		}
		seen[string(k)] = true
		out = append(out, PinnedFacade{Facade: f.Facade, Key: ed25519.PublicKey(k)})
	}
	return out, nil
}

// RevealKey is a facade's ephemeral X25519 key for one reveal of one
// ticket, signed by the facade's Ed25519 key (ContextRevealKey). The lock
// seals the clear screen to EPK only if the signature verifies under a
// facade key it pins for Facade: a hub cannot put its own key in.
type RevealKey struct {
	V int `json:"v"`
	// ID names this reveal (NewID); the box is bound to it.
	ID       string `json:"id"`
	Ticket   string `json:"ticket"`
	Instance string `json:"instance"`
	KeyID    string `json:"key_id"` // the lock's key
	Facade   string `json:"facade"`
	// EPK is the ephemeral X25519 public key.
	EPK         string    `json:"epk"`
	At          time.Time `json:"at"`
	FacadeKeyID string    `json:"facade_key_id"`
	Sig         string    `json:"sig,omitempty"`
}

// RevealTTL is how long a RevealKey and the request carrying it can be
// acted on.
const RevealTTL = 2 * time.Minute

func (r *RevealKey) validate() error {
	switch {
	case r.V != Version:
		return invalid("reveal: unsupported version %d", r.V)
	case !ValidID(r.ID) || !ValidID(r.Ticket):
		return invalid("reveal: id")
	case !validKeyID(r.KeyID) || !validKeyID(r.FacadeKeyID):
		return invalid("reveal: key id")
	case !CanReveal(r.Facade):
		return invalid("reveal: facade %q cannot reveal", r.Facade)
	case r.At.IsZero() || !normalized(r.At):
		return invalid("reveal: at")
	}
	if err := checkSet("reveal: instance", r.Instance); err != nil {
		return err
	}
	if b, err := enc.DecodeString(r.EPK); err != nil || len(b) != 32 {
		return invalid("reveal: epk")
	}
	return nil
}

// NewRevealKey makes the reveal key of facade (signed by key) for ticket
// t, and returns it with the ephemeral private key, which the facade keeps
// in memory only and drops once the screen is shown.
func NewRevealKey(key ed25519.PrivateKey, facade string, t *Ticket, now time.Time) (*RevealKey, *ecdh.PrivateKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now = normTime(now)
	r := &RevealKey{V: Version, ID: NewID(now), Ticket: t.ID, Instance: t.Source.Instance, KeyID: t.Source.KeyID,
		Facade: facade, EPK: enc.EncodeToString(priv.PublicKey().Bytes()), At: now,
		FacadeKeyID: KeyID(key.Public().(ed25519.PublicKey))}
	if err := r.validate(); err != nil {
		return nil, nil, err
	}
	b, err := Canonical(r)
	if err != nil {
		return nil, nil, err
	}
	r.Sig = SignBytes(key, ContextRevealKey, b)
	return r, priv, nil
}

// ErrFacade: a reveal key does not verify under a facade the lock pins.
var ErrFacade = errors.New("ticket: facade key refused")

// Verify checks r against the facade keys a lock pins: the key it names
// is pinned for r.Facade, and signs r. It returns r's ephemeral key.
func (r *RevealKey) Verify(pinned []PinnedFacade) (*ecdh.PublicKey, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	i := slices.IndexFunc(pinned, func(p PinnedFacade) bool { return KeyID(p.Key) == r.FacadeKeyID })
	if i < 0 {
		return nil, fmt.Errorf("%w: key %s is not pinned", ErrFacade, r.FacadeKeyID)
	}
	if pinned[i].Facade != r.Facade {
		return nil, fmt.Errorf("%w: key %s is pinned for %s, not %s", ErrFacade, r.FacadeKeyID, pinned[i].Facade, r.Facade)
	}
	u := *r
	u.Sig = ""
	b, err := Canonical(&u)
	if err != nil {
		return nil, err
	}
	if err := VerifyBytes(pinned[i].Key, ContextRevealKey, b, r.Sig); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFacade, err)
	}
	raw, _ := enc.DecodeString(r.EPK)
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, invalid("reveal: epk")
	}
	return pub, nil
}

// RequestKind is the closed set of hub requests.
type RequestKind string

const (
	// RequestReveal: seal the clear screen of a ticket to a facade's
	// RevealKey.
	RequestReveal RequestKind = "reveal"
	// RequestRenew: ask again for an expired ticket (Ticket.Renews).
	RequestRenew RequestKind = "renew"
)

// HubRequest is a human's request to a lock about one of its tickets,
// signed by the hub. Approver and Facade are the hub's word: for a reveal
// the facade's own signature (Reveal) is what the lock checks. The lock checks it like a decision (pinned hub key,
// its own instance and key, fresh) and, for a reveal, the facade's own
// signature on Reveal.
type HubRequest struct {
	V        int         `json:"v"`
	ID       string      `json:"id"` // NewID, made by the hub
	Kind     RequestKind `json:"kind"`
	Ticket   string      `json:"ticket"`
	Instance string      `json:"instance"`
	KeyID    string      `json:"key_id"` // the lock's key
	Approver Approver    `json:"approver"`
	Facade   string      `json:"facade"`
	At       time.Time   `json:"at"`
	// Reveal is the facade's key, for RequestReveal only.
	Reveal   *RevealKey `json:"reveal,omitempty"`
	HubKeyID string     `json:"hub_key_id"`
	Sig      string     `json:"sig,omitempty"`
}

// Validate checks q's schema. It does not check the signatures.
func (q *HubRequest) Validate() error {
	switch {
	case q.V != Version:
		return invalid("request: unsupported version %d", q.V)
	case !ValidID(q.ID) || !ValidID(q.Ticket):
		return invalid("request: id")
	case !validKeyID(q.KeyID) || !validKeyID(q.HubKeyID):
		return invalid("request: key id")
	case q.At.IsZero() || !normalized(q.At):
		return invalid("request: at")
	}
	for _, f := range []struct{ n, v string }{
		{"request: instance", q.Instance}, {"request: facade", q.Facade},
	} {
		if err := checkSet(f.n, f.v); err != nil {
			return err
		}
	}
	for _, f := range []struct{ n, v string }{
		{"request: approver.id", q.Approver.ID}, {"request: approver.display", q.Approver.Display},
	} {
		if err := checkStr(f.n, f.v, maxField); err != nil {
			return err
		}
	}
	switch q.Kind {
	case RequestReveal:
		if q.Reveal == nil {
			return invalid("request: a reveal without its key")
		}
		if err := q.Reveal.validate(); err != nil {
			return err
		}
		if q.Reveal.Ticket != q.Ticket || q.Reveal.Instance != q.Instance || q.Reveal.KeyID != q.KeyID || q.Reveal.Facade != q.Facade {
			return invalid("request: the reveal key is for another ticket or facade")
		}
	case RequestRenew:
		if q.Reveal != nil {
			return invalid("request: a renewal with a reveal key")
		}
	default:
		return invalid("request: kind %q", q.Kind)
	}
	return nil
}

// Sign validates q, sets q.HubKeyID to the key's id when empty (a
// different one is an error), and signs it.
func (q *HubRequest) Sign(key ed25519.PrivateKey) error {
	pub := key.Public().(ed25519.PublicKey)
	if q.HubKeyID == "" {
		q.HubKeyID = KeyID(pub)
	} else if q.HubKeyID != KeyID(pub) {
		return invalid("hub_key_id %s is not the signing key %s", q.HubKeyID, KeyID(pub))
	}
	if err := q.Validate(); err != nil {
		return err
	}
	u := *q
	u.Sig = ""
	b, err := Canonical(&u)
	if err != nil {
		return err
	}
	q.Sig = SignBytes(key, ContextHubRequest, b)
	return nil
}

// Marshal is the canonical JSON of a signed request.
func (q *HubRequest) Marshal() ([]byte, error) { return Canonical(q) }

// VerifyHubRequest decodes a request and checks its schema and the hub's
// signature under pub, the hub key the lock pinned. The lock then checks
// that it is for its own instance and key, fresh (Fresh) and, for a
// reveal, Reveal.Verify under its pinned facades.
func VerifyHubRequest(pub ed25519.PublicKey, data []byte) (*HubRequest, error) {
	var q HubRequest
	if err := decodeStrict(data, &q); err != nil {
		return nil, err
	}
	if err := q.Validate(); err != nil {
		return nil, err
	}
	if q.HubKeyID != KeyID(pub) {
		return nil, fmt.Errorf("%w: request names hub key %s, pinned key is %s", ErrBadSignature, q.HubKeyID, KeyID(pub))
	}
	sig := q.Sig
	q.Sig = ""
	b, err := Canonical(&q)
	if err != nil {
		return nil, err
	}
	if err := VerifyBytes(pub, ContextHubRequest, b, sig); err != nil {
		return nil, err
	}
	q.Sig = sig
	return &q, nil
}

// Fresh reports whether q (and its reveal key) can be acted on at now:
// made less than RevealTTL ago, not more than a minute ahead.
func (q *HubRequest) Fresh(now time.Time) bool {
	ok := func(at time.Time) bool { return !at.After(now.Add(time.Minute)) && now.Sub(at) < RevealTTL }
	return ok(q.At) && (q.Reveal == nil || ok(q.Reveal.At))
}

// RevealAnswer is a lock's answer to a reveal: the clear screen sealed to
// the facade's ephemeral key, signed by the lock (ContextRevealAnswer), so
// that a hub can neither read it nor replace it.
type RevealAnswer struct {
	V        int     `json:"v"`
	Request  string  `json:"request"` // HubRequest.ID
	Reveal   string  `json:"reveal"`  // RevealKey.ID
	Ticket   string  `json:"ticket"`
	Instance string  `json:"instance"`
	KeyID    string  `json:"key_id"` // the lock's key
	Box      *Sealed `json:"box"`
	Sig      string  `json:"sig,omitempty"`
}

// RevealAAD is the associated data of a reveal's box: the reveal, its
// ticket, instance and lock key.
func RevealAAD(r *RevealKey) []byte {
	return ContextRevealBox.message([]byte(r.ID + "\x00" + r.Ticket + "\x00" + r.Instance + "\x00" + r.KeyID))
}

// SealReveal seals clear to the facade key of q (verified by the caller,
// epk) and signs the answer with the lock's key.
func SealReveal(key ed25519.PrivateKey, q *HubRequest, epk *ecdh.PublicKey, clear Screen) (*RevealAnswer, error) {
	if q.Kind != RequestReveal || q.Reveal == nil {
		return nil, invalid("reveal: not a reveal request")
	}
	if q.KeyID != KeyID(key.Public().(ed25519.PublicKey)) {
		return nil, invalid("reveal: request for key %s, not this lock's", q.KeyID)
	}
	pt, err := Canonical(&clear)
	if err != nil {
		return nil, err
	}
	box, err := Seal(epk, pt, RevealAAD(q.Reveal))
	if err != nil {
		return nil, err
	}
	a := &RevealAnswer{V: Version, Request: q.ID, Reveal: q.Reveal.ID, Ticket: q.Ticket, Instance: q.Instance, KeyID: q.KeyID, Box: box}
	b, err := Canonical(a)
	if err != nil {
		return nil, err
	}
	a.Sig = SignBytes(key, ContextRevealAnswer, b)
	return a, nil
}

// Marshal is the canonical JSON of a signed answer.
func (a *RevealAnswer) Marshal() ([]byte, error) { return Canonical(a) }

// OpenReveal checks a lock's answer to the facade's reveal r (signed by
// lockPub, the lock key the facade pinned; for r's reveal, ticket,
// instance and key) and opens it with the ephemeral key priv. The clear
// screen is the lock's own words and the agent's: a facade shows it
// through its own escaping, like the masked one.
func OpenReveal(lockPub ed25519.PublicKey, priv *ecdh.PrivateKey, r *RevealKey, data []byte) (Screen, error) {
	var a RevealAnswer
	if err := decodeStrict(data, &a); err != nil {
		return Screen{}, err
	}
	switch {
	case a.V != Version:
		return Screen{}, invalid("reveal answer: unsupported version %d", a.V)
	case a.Box == nil:
		return Screen{}, invalid("reveal answer: no box")
	case a.KeyID != KeyID(lockPub):
		return Screen{}, fmt.Errorf("%w: answer names key %s, pinned key is %s", ErrBadSignature, a.KeyID, KeyID(lockPub))
	case a.Reveal != r.ID || a.Ticket != r.Ticket || a.Instance != r.Instance || a.KeyID != r.KeyID:
		return Screen{}, fmt.Errorf("%w: the answer is for another reveal", ErrMismatch)
	}
	sig := a.Sig
	a.Sig = ""
	b, err := Canonical(&a)
	if err != nil {
		return Screen{}, err
	}
	if err := VerifyBytes(lockPub, ContextRevealAnswer, b, sig); err != nil {
		return Screen{}, err
	}
	pt, err := Open(priv, a.Box, RevealAAD(r))
	if err != nil {
		return Screen{}, err
	}
	var s Screen
	if err := decodeStrict(pt, &s); err != nil {
		return Screen{}, err
	}
	return s, nil
}
