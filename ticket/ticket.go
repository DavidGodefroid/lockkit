// Package ticket is the contract between a lock and lockhub: the ticket a
// lock pushes when a request needs a human, the decision the hub signs
// back, their canonical JSON (RFC 8785), Ed25519 signatures and the X25519
// sealed boxes that carry what the hub must not read.
//
// Signatures are computed over the canonical form of the value without its
// "sig" member, prefixed by a Context. Verification decodes strictly (no
// unknown member, no trailing data), validates, re-canonicalizes what it
// decoded and checks the signature over that: what verifies is exactly
// what the caller then reads.
package ticket

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

// Version is the schema version of tickets and decisions this package
// writes and reads. A value of any other version is refused (fail closed).
const Version = 1

// ErrInvalid is wrapped by every validation error.
var ErrInvalid = errors.New("ticket: invalid")

// Source is the lock that issued a ticket.
type Source struct {
	// Lock is the product: "locksql", "lockfile", ...
	Lock string `json:"lock"`
	// Instance names the lock instance ("crm-prod"); decisions are bound
	// to it.
	Instance string `json:"instance"`
	// KeyID is KeyID of the Ed25519 key that signs the ticket.
	KeyID string `json:"key_id"`
}

// Requester is the agent that asked, as the agent says: a label for
// display, never authenticated.
type Requester struct {
	Agent   string `json:"agent"`
	Session string `json:"session"`
}

// Flags change how a facade asks.
type Flags struct {
	// Production: the target is production; the facade asks for the
	// typed instance name.
	Production bool `json:"production"`
	// NeverAuto: never approved by an auto mode.
	NeverAuto bool `json:"never_auto"`
	// Retype, when set, is the answer that asks the lock to retype values.
	Retype string `json:"retype"`
}

// Screen is the approval screen, masked by the lock before it leaves the
// lock (the render package builds it). It mirrors the console's screen.
type Screen struct {
	// Header names the request ("db / shop · tier read").
	Header string `json:"header"`
	// Note is the agent's one-line reason (untrusted).
	Note string `json:"note"`
	// Body are the lines of the request; Warnings are shown in red.
	Body     []string `json:"body"`
	Warnings []string `json:"warnings"`
	// Red frames the screen in red outside production too.
	Red bool `json:"red"`
}

// PII says what personal data the request touches.
type PII struct {
	// Touched names the kinds of personal data involved ("email").
	Touched []string `json:"touched"`
	// ClearSealed is the unmasked screen sealed to one facade's device
	// key, for a facade able to show it; nil otherwise.
	ClearSealed *Sealed `json:"clear_sealed"`
}

// Ticket is a request for a human decision, signed by the lock.
type Ticket struct {
	V         int       `json:"v"`
	ID        string    `json:"id"` // NewID
	Source    Source    `json:"source"`
	Workspace string    `json:"workspace"`
	Requester Requester `json:"requester"`
	Risk      Risk      `json:"risk"`
	Flags     Flags     `json:"flags"`
	Screen    Screen    `json:"screen"`
	PII       PII       `json:"pii"`
	// PlanHash binds the ticket to the plan it asks for (HashOf).
	PlanHash string `json:"plan_hash"`
	// PolicyFP is the fingerprint of the policy the plan was made under.
	PolicyFP string    `json:"policy_fp"`
	Created  time.Time `json:"created"`
	// Expires is when a pending ticket expires; nil never.
	Expires *time.Time `json:"expires"`
	Sig     string     `json:"sig,omitempty"`
}

// Outcome is the closed set of decisions.
type Outcome string

const (
	Approved Outcome = "approved"
	Denied   Outcome = "denied"
)

// UnmarshalJSON refuses an outcome other than Approved and Denied.
func (o *Outcome) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if v := Outcome(s); v == Approved || v == Denied {
		*o = v
		return nil
	}
	return fmt.Errorf("ticket: unknown decision %q", s)
}

// Approver is who decided, as the hub identified them.
type Approver struct {
	ID      string `json:"id"`
	Display string `json:"display"`
}

// Decision is the hub's answer to one ticket, signed by the hub. It repeats
// the ticket's instance, lock key and plan hash: a lock refuses a decision
// that does not match its own ticket (Match), so a decision cannot be
// replayed to another instance or plan.
type Decision struct {
	V        int     `json:"v"`
	Ticket   string  `json:"ticket"`
	Instance string  `json:"instance"`
	KeyID    string  `json:"key_id"` // the lock's key
	PlanHash string  `json:"plan_hash"`
	Decision Outcome `json:"decision"`
	// Reason is the human's reason (a denial's, mostly); untrusted.
	Reason   string   `json:"reason"`
	Approver Approver `json:"approver"`
	// Facade is the facade the human answered on ("tty", "deck", ...).
	Facade string    `json:"facade"`
	At     time.Time `json:"at"`
	// Nonce is single use: a lock consumes it with the decision.
	Nonce    string `json:"nonce"`
	HubKeyID string `json:"hub_key_id"` // KeyID of the hub's key
	Sig      string `json:"sig,omitempty"`
}

// NewTicket is a ticket of the current Version with a fresh ID, created
// now, expiring after ttl (0: never; see ClampTTL).
func NewTicket(src Source, risk Risk, planHash, policyFP string, now time.Time, ttl time.Duration) *Ticket {
	now = normTime(now)
	t := &Ticket{V: Version, ID: NewID(now), Source: src, Risk: risk, PlanHash: planHash, PolicyFP: policyFP, Created: now}
	if ttl > 0 {
		e := now.Add(ttl)
		t.Expires = &e
	}
	return t
}

// normTime is t as signed values carry it: UTC, millisecond precision.
func normTime(t time.Time) time.Time { return t.UTC().Truncate(time.Millisecond) }

func normalized(t time.Time) bool { return t.Equal(normTime(t)) && t.Location() == time.UTC }

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// maxField bounds every string field but the screen's lines.
const maxField = 1024

func checkStr(name, s string, max int) error {
	if !utf8.ValidString(s) {
		return invalid("%s: invalid UTF-8", name)
	}
	if len(s) > max {
		return invalid("%s: longer than %d bytes", name, max)
	}
	return nil
}

func checkSet(name, s string) error {
	if s == "" {
		return invalid("%s: empty", name)
	}
	return checkStr(name, s, maxField)
}

// Screen bounds.
const (
	maxLines   = 512
	maxLine    = 4096
	maxTouched = 64
)

// Validate checks t's schema: version, id, source, risk, hashes, times,
// sizes. It does not check the signature.
func (t *Ticket) Validate() error {
	if t.V != Version {
		return invalid("unsupported version %d", t.V)
	}
	if !ValidID(t.ID) {
		return invalid("id %q is not a ULID", t.ID)
	}
	for _, f := range []struct{ n, v string }{
		{"source.lock", t.Source.Lock}, {"source.instance", t.Source.Instance},
	} {
		if err := checkSet(f.n, f.v); err != nil {
			return err
		}
	}
	if !validKeyID(t.Source.KeyID) {
		return invalid("source.key_id %q", t.Source.KeyID)
	}
	for _, f := range []struct{ n, v string }{
		{"workspace", t.Workspace}, {"requester.agent", t.Requester.Agent},
		{"requester.session", t.Requester.Session}, {"flags.retype", t.Flags.Retype},
		{"screen.header", t.Screen.Header}, {"screen.note", t.Screen.Note},
	} {
		if err := checkStr(f.n, f.v, maxField); err != nil {
			return err
		}
	}
	if !t.Risk.Valid() {
		return invalid("risk %q", t.Risk)
	}
	if len(t.Screen.Body)+len(t.Screen.Warnings) > maxLines {
		return invalid("screen: more than %d lines", maxLines)
	}
	for _, l := range append(append([]string(nil), t.Screen.Body...), t.Screen.Warnings...) {
		if err := checkStr("screen line", l, maxLine); err != nil {
			return err
		}
	}
	if len(t.PII.Touched) > maxTouched {
		return invalid("pii.touched: more than %d kinds", maxTouched)
	}
	for _, k := range t.PII.Touched {
		if err := checkSet("pii.touched", k); err != nil {
			return err
		}
	}
	if t.PII.ClearSealed != nil {
		if err := t.PII.ClearSealed.validate(); err != nil {
			return err
		}
	}
	if !validHash(t.PlanHash) {
		return invalid("plan_hash %q", t.PlanHash)
	}
	if !validHash(t.PolicyFP) {
		return invalid("policy_fp %q", t.PolicyFP)
	}
	if t.Created.IsZero() || !normalized(t.Created) {
		return invalid("created: not a UTC millisecond time")
	}
	if t.Expires != nil && (!normalized(*t.Expires) || !t.Expires.After(t.Created)) {
		return invalid("expires: not a UTC millisecond time after created")
	}
	return nil
}

// Validate checks d's schema. It does not check the signature.
func (d *Decision) Validate() error {
	if d.V != Version {
		return invalid("unsupported version %d", d.V)
	}
	if !ValidID(d.Ticket) {
		return invalid("ticket %q is not a ULID", d.Ticket)
	}
	if err := checkSet("instance", d.Instance); err != nil {
		return err
	}
	if !validKeyID(d.KeyID) {
		return invalid("key_id %q", d.KeyID)
	}
	if !validKeyID(d.HubKeyID) {
		return invalid("hub_key_id %q", d.HubKeyID)
	}
	if !validHash(d.PlanHash) {
		return invalid("plan_hash %q", d.PlanHash)
	}
	if d.Decision != Approved && d.Decision != Denied {
		return invalid("decision %q", d.Decision)
	}
	for _, f := range []struct{ n, v string }{
		{"reason", d.Reason}, {"approver.id", d.Approver.ID}, {"approver.display", d.Approver.Display},
	} {
		if err := checkStr(f.n, f.v, maxField); err != nil {
			return err
		}
	}
	if err := checkSet("facade", d.Facade); err != nil {
		return err
	}
	if d.At.IsZero() || !normalized(d.At) {
		return invalid("at: not a UTC millisecond time")
	}
	if !validNonce(d.Nonce) {
		return invalid("nonce")
	}
	return nil
}

// signedBytes is the canonical form of v with its Sig emptied by the
// caller (Sig is omitempty).
func signedBytes(v any) ([]byte, error) { return Canonical(v) }

// Sign validates t, sets t.Source.KeyID to the key's id when empty (a
// different one is an error), and signs it.
func (t *Ticket) Sign(key ed25519.PrivateKey) error {
	pub := key.Public().(ed25519.PublicKey)
	if t.Source.KeyID == "" {
		t.Source.KeyID = KeyID(pub)
	} else if t.Source.KeyID != KeyID(pub) {
		return invalid("source.key_id %s is not the signing key %s", t.Source.KeyID, KeyID(pub))
	}
	if err := t.Validate(); err != nil {
		return err
	}
	u := *t
	u.Sig = ""
	b, err := signedBytes(&u)
	if err != nil {
		return err
	}
	t.Sig = SignBytes(key, ContextTicket, b)
	return nil
}

// Sign validates d, sets d.HubKeyID to the key's id when empty (a
// different one is an error), and signs it.
func (d *Decision) Sign(key ed25519.PrivateKey) error {
	pub := key.Public().(ed25519.PublicKey)
	if d.HubKeyID == "" {
		d.HubKeyID = KeyID(pub)
	} else if d.HubKeyID != KeyID(pub) {
		return invalid("hub_key_id %s is not the signing key %s", d.HubKeyID, KeyID(pub))
	}
	if err := d.Validate(); err != nil {
		return err
	}
	u := *d
	u.Sig = ""
	b, err := signedBytes(&u)
	if err != nil {
		return err
	}
	d.Sig = SignBytes(key, ContextDecision, b)
	return nil
}

// Marshal is the canonical JSON of a signed ticket, as it is sent.
func (t *Ticket) Marshal() ([]byte, error) { return Canonical(t) }

// Marshal is the canonical JSON of a signed decision, as it is sent.
func (d *Decision) Marshal() ([]byte, error) { return Canonical(d) }

// decodeStrict decodes exactly one JSON value into v, refusing unknown
// members and trailing data, and anything but the canonical form of what
// it decoded: encoding/json matches member names without case and would
// take {"RISK":…} for "risk", so one value would have many encodings.
func decodeStrict(data []byte, v any) error {
	if !utf8.Valid(data) {
		return invalid("invalid UTF-8")
	}
	// Duplicate members and lone surrogates are refused here, before
	// encoding/json would silently pick one or replace them.
	if _, err := CanonicalizeJSON(data); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if dec.More() {
		return invalid("trailing data")
	}
	c, err := Canonical(v)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if !bytes.Equal(c, data) {
		return invalid("not in canonical form")
	}
	return nil
}

// VerifyTicket decodes a ticket and checks it: schema, then the signature
// under pub, the lock key the caller pinned for t.Source.Instance. A
// ticket naming another key id is refused.
func VerifyTicket(pub ed25519.PublicKey, data []byte) (*Ticket, error) {
	var t Ticket
	if err := decodeStrict(data, &t); err != nil {
		return nil, err
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	if t.Source.KeyID != KeyID(pub) {
		return nil, fmt.Errorf("%w: ticket names key %s, pinned key is %s", ErrBadSignature, t.Source.KeyID, KeyID(pub))
	}
	sig := t.Sig
	t.Sig = ""
	b, err := signedBytes(&t)
	if err != nil {
		return nil, err
	}
	if err := VerifyBytes(pub, ContextTicket, b, sig); err != nil {
		return nil, err
	}
	t.Sig = sig
	return &t, nil
}

// VerifyDecision decodes a decision and checks it: schema, then the
// signature under pub, the hub key the caller pinned. A decision naming
// another hub key id is refused. The caller then checks Match against its
// ticket and consumes the nonce.
func VerifyDecision(pub ed25519.PublicKey, data []byte) (*Decision, error) {
	var d Decision
	if err := decodeStrict(data, &d); err != nil {
		return nil, err
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	if d.HubKeyID != KeyID(pub) {
		return nil, fmt.Errorf("%w: decision names hub key %s, pinned key is %s", ErrBadSignature, d.HubKeyID, KeyID(pub))
	}
	sig := d.Sig
	d.Sig = ""
	b, err := signedBytes(&d)
	if err != nil {
		return nil, err
	}
	if err := VerifyBytes(pub, ContextDecision, b, sig); err != nil {
		return nil, err
	}
	d.Sig = sig
	return &d, nil
}

// Expired reports whether pending ticket t has expired at now.
func (t *Ticket) Expired(now time.Time) bool { return t.Expires != nil && !now.Before(*t.Expires) }

// ErrMismatch: a verified decision is not for this ticket.
var ErrMismatch = errors.New("ticket: decision does not match the ticket")

// ErrDenied: the decision is not an approval.
var ErrDenied = errors.New("ticket: not approved")

// ErrExpired: the ticket or the approval is past its TTL.
var ErrExpired = errors.New("ticket: expired")

// Match checks that d answers t: same ticket id, instance, lock key and
// plan hash. A lock calls it with its own ticket (never one rebuilt from
// the decision) before acting on d.
func (d *Decision) Match(t *Ticket) error {
	switch {
	case d.Ticket != t.ID:
		return fmt.Errorf("%w: ticket %s, expected %s", ErrMismatch, d.Ticket, t.ID)
	case d.Instance != t.Source.Instance:
		return fmt.Errorf("%w: instance %q, expected %q", ErrMismatch, d.Instance, t.Source.Instance)
	case d.KeyID != t.Source.KeyID:
		return fmt.Errorf("%w: key %s, expected %s", ErrMismatch, d.KeyID, t.Source.KeyID)
	case d.PlanHash != t.PlanHash:
		return fmt.Errorf("%w: plan hash differs", ErrMismatch)
	}
	return nil
}

// Usable checks that an approval of t can still be acted on at now: it
// came before the ticket expired, and it is younger than ttl (the
// instance's ClampTTL for t.Risk; 0 never ages). A decision dated in the
// future by more than a minute is refused too, and anything but an
// approval is ErrDenied.
func (d *Decision) Usable(t *Ticket, now time.Time, ttl time.Duration) error {
	const skew = time.Minute
	switch {
	case d.Decision != Approved:
		return fmt.Errorf("%w: %s", ErrDenied, d.Decision)
	case d.At.After(now.Add(skew)):
		return fmt.Errorf("%w: decision dated %s, in the future", ErrExpired, d.At.Format(time.RFC3339))
	case d.At.Before(t.Created.Add(-skew)):
		return fmt.Errorf("%w: decision dated before the ticket", ErrMismatch)
	case t.Expires != nil && d.At.After(*t.Expires):
		return fmt.Errorf("%w: decided after the ticket expired", ErrExpired)
	case ttl > 0 && now.Sub(d.At) > ttl:
		return fmt.Errorf("%w: approval older than %s", ErrExpired, ttl)
	}
	return nil
}
