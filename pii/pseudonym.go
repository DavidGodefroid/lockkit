package pii

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// PseudonymLen is the length of a pseudonym ID: 12 characters of
// Crockford base32, 60 bits.
const PseudonymLen = 12

// EpochLen is the length of an epoch id: 8 characters of Crockford
// base32, 40 random bits.
const EpochLen = 8

// KeyLen is the length of an epoch key.
const KeyLen = 32

// crockford is Crockford's base32 alphabet (no I, L, O, U).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Pseudonymizer gives each personal value a stable, keyed pseudonym for
// the duration of one epoch: the same value, however it is spelt
// (Normalise), gets the same ID; without the key, an ID says nothing about
// the value beyond what guessing a value and asking for its pseudonym
// would. The key never leaves the value: there is no accessor, and the fmt
// and JSON forms show the epoch only. It is safe for concurrent use.
type Pseudonymizer struct {
	epoch   string
	created time.Time
	seq     uint64 // order in an EpochStore
	// store keeps the EpochStore (and so its directory lock) alive while a
	// handle on one of its epochs is: a store dropped without Close must
	// not release the lock under a live key.
	store *EpochStore
	// key is shared by every copy of the value, so forgetting it reaches
	// them all; fmt prints a nested pointer as an address.
	key *epochKey
}

// epochKey is an epoch's key; b is nil once forgotten.
type epochKey struct {
	mu sync.RWMutex
	b  []byte
}

// ErrInvalidKind is the error of ID on a kind that is not 1 to 32 of
// [a-z0-9_].
var ErrInvalidKind = errors.New("pii: invalid pseudonym kind")

// idLabel separates this scheme's input from any other use of a key.
const idLabel = "lockkit-pseudonym-v1\x00"

// ValidKind reports whether kind may name a pseudonym's kind: 1 to 32
// characters of [a-z0-9_].
func ValidKind(kind string) bool {
	if kind == "" || len(kind) > 32 {
		return false
	}
	for i := 0; i < len(kind); i++ {
		if c := kind[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// ErrForgottenEpoch is the error of ID on an epoch whose key was deleted
// (EpochStore.Prune): the caller must redact the value, never show it.
var ErrForgottenEpoch = errors.New("pii: pseudonym epoch key deleted")

// NewEpoch returns a Pseudonymizer for a new epoch, with a random id and
// key, kept in memory only (a session epoch). EpochStore keeps them on
// disk.
func NewEpoch(now time.Time) (*Pseudonymizer, error) {
	key := make([]byte, KeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	id, err := randomEpochID()
	if err != nil {
		return nil, err
	}
	return &Pseudonymizer{epoch: id, created: now.UTC().Truncate(time.Second), key: &epochKey{b: key}}, nil
}

// NewPseudonymizer returns the Pseudonymizer of an existing epoch: its id
// (EpochLen characters of Crockford base32) and its KeyLen-byte key, which
// it copies.
func NewPseudonymizer(epoch string, created time.Time, key []byte) (*Pseudonymizer, error) {
	if !validEpochID(epoch) {
		return nil, errors.New("pii: invalid epoch id")
	}
	if len(key) != KeyLen {
		return nil, errors.New("pii: an epoch key is 32 bytes")
	}
	if subtle.ConstantTimeCompare(key, make([]byte, KeyLen)) == 1 {
		return nil, errors.New("pii: an all-zero epoch key")
	}
	return &Pseudonymizer{epoch: epoch, created: created.UTC(), key: &epochKey{b: append([]byte(nil), key...)}}, nil
}

func randomEpochID() (string, error) {
	var b [EpochLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = crockford[b[i]&31]
	}
	return string(b[:]), nil
}

func validEpochID(s string) bool { return len(s) == EpochLen && crockfordOnly(s) }

// Epoch returns the epoch id: random, it says nothing about the key.
func (p *Pseudonymizer) Epoch() string { return p.epoch }

// Created returns when the epoch began (to the second).
func (p *Pseudonymizer) Created() time.Time { return p.created }

// ID returns the pseudonym of value as a value of kind (a detector name:
// "email", "phone", ...): the first PseudonymLen characters of the
// Crockford base32 of HMAC-SHA256(key, "lockkit-pseudonym-v1" || 0x00 ||
// kind || 0x00 || Normalise(kind, value)); kind is 1 to 32 of [a-z0-9_]
// (ErrInvalidKind otherwise). Different kinds give different IDs for the same text. Once the
// epoch's key was deleted (EpochStore.Prune), ID fails with
// ErrForgottenEpoch and never computes an ID: the caller redacts the value.
func (p *Pseudonymizer) ID(kind, value string) (string, error) {
	if !ValidKind(kind) {
		return "", ErrInvalidKind
	}
	norm := Normalise(kind, value)
	if p == nil || p.key == nil {
		return "", ErrForgottenEpoch
	}
	p.key.mu.RLock()
	defer p.key.mu.RUnlock()
	if len(p.key.b) != KeyLen {
		return "", ErrForgottenEpoch
	}
	m := hmac.New(sha256.New, p.key.b)
	m.Write([]byte(idLabel))
	m.Write([]byte(kind))
	m.Write([]byte{0})
	m.Write([]byte(norm))
	return encodeID(m.Sum(nil)), nil
}

// Forgotten reports whether the epoch's key was deleted.
func (p *Pseudonymizer) Forgotten() bool {
	if p == nil || p.key == nil {
		return true
	}
	p.key.mu.RLock()
	defer p.key.mu.RUnlock()
	return len(p.key.b) != KeyLen
}

// encodeID writes the first 60 bits of sum in Crockford base32.
func encodeID(sum []byte) string {
	v := binary.BigEndian.Uint64(sum[:8]) >> 4
	var b [PseudonymLen]byte
	for i := PseudonymLen - 1; i >= 0; i-- {
		b[i] = crockford[v&31]
		v >>= 5
	}
	return string(b[:])
}

// ValidID reports whether s has the form of a pseudonym ID.
func ValidID(s string) bool { return len(s) == PseudonymLen && crockfordOnly(s) }

func crockfordOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(crockford, s[i]) < 0 {
			return false
		}
	}
	return true
}

// String shows the epoch, never the key.
func (p *Pseudonymizer) String() string {
	if p == nil {
		return "pii.Pseudonymizer(nil)"
	}
	return "pii.Pseudonymizer{epoch: " + p.epoch + "}"
}

// GoString shows the epoch, never the key.
func (p *Pseudonymizer) GoString() string { return p.String() }

// MarshalJSON writes the epoch, never the key.
func (p *Pseudonymizer) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Epoch   string    `json:"epoch"`
		Created time.Time `json:"created"`
	}{p.epoch, p.created})
}

// forget overwrites the key in memory (best effort: the runtime may have
// copied it).
// ID fails from then on.
func (p *Pseudonymizer) forget() {
	p.key.mu.Lock()
	defer p.key.mu.Unlock()
	clear(p.key.b)
	p.key.b = nil
}

// keyBytes returns a copy of the key for the store's file, nil once
// forgotten.
func (p *Pseudonymizer) keyBytes() []byte {
	p.key.mu.RLock()
	defer p.key.mu.RUnlock()
	return append([]byte(nil), p.key.b...)
}

// Normalise returns the form of value (one detected value: digits of two
// phone numbers would be joined) whose pseudonym is taken, so that
// one value written differently is one pseudonym: the detection view of
// the value, or of its decoding (percent, JSON escape, HTML reference)
// when only that is a whole value of kind; then, by kind:
//   - email: lower case;
//   - phone, phone_loose: digits only, with "+" for an international number
//     ("00" becomes "+": E.164 when the country code is written);
//   - iban: blanks removed, upper case;
//   - card, be_niss, nl_bsn, us_ssn: digits only; fr_nir: digits and the
//     Corsican letter, upper case;
//   - ip: the canonical address (an IPv4-mapped IPv6 address is the IPv4
//     one; zones dropped);
//   - person_name: lower case, blanks collapsed to one space;
//   - other kinds: the detection view with surrounding blanks trimmed.
func Normalise(kind, value string) string {
	if len(value) > DetectLimit {
		return value // past what views cover: the value itself, whole
	}
	v := wholeValueView(kind, value)
	switch kind {
	case "email":
		return strings.ToLower(strings.TrimSpace(v))
	case "phone", "phone_loose":
		t := strings.TrimLeft(v, " (")
		if strings.HasPrefix(t, "+") || strings.HasPrefix(t, "00") {
			// "+32 (0)475...": the trunk 0 is not dialled from abroad.
			t = strings.Replace(t, "(0)", "", 1)
		}
		d := digitsOf(t)
		switch {
		case strings.HasPrefix(t, "+") && strings.HasPrefix(d, "00"):
			return "+" + d[2:]
		case strings.HasPrefix(t, "+"):
			return "+" + d
		case strings.HasPrefix(d, "00"):
			return "+" + d[2:]
		}
		return d
	case "iban":
		return strings.Map(func(r rune) rune {
			// An IBAN is ASCII letters and digits: anything else is a
			// separator (and upper-casing stays idempotent).
			if r >= 'a' && r <= 'z' {
				return r - 'a' + 'A'
			}
			if r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, v)
	case "card", "be_niss", "nl_bsn", "us_ssn":
		return digitsOf(v)
	case "fr_nir":
		return strings.ToUpper(strings.Map(func(r rune) rune {
			if isDigit(byte(r)) && r < 0x80 || r == 'a' || r == 'b' || r == 'A' || r == 'B' {
				return r
			}
			return -1
		}, v))
	case "person_name":
		return strings.ToLower(strings.Join(strings.Fields(v), " "))
	case "ip":
		t := strings.Trim(strings.TrimSpace(v), "[]")
		if a, err := netip.ParseAddr(t); err == nil {
			return a.WithZone("").Unmap().String()
		}
		return strings.ToLower(t)
	}
	return strings.TrimSpace(v)
}

// wholeValueView returns the text of the first detection view of value
// (DetectionViews order) that a detector of kind finds whole, or the plain
// detection view when none does or kind has no detector here.
func wholeValueView(kind, value string) string {
	vs := DetectionViews(value)
	ds, err := Detectors([]string{kind})
	if err != nil || len(vs) == 1 {
		return vs[0].Text
	}
	for _, v := range vs {
		t := strings.TrimSpace(v.Text)
		if ms := Find(t, ds); len(ms) == 1 && ms[0].Start == 0 && ms[0].End == len(t) {
			return v.Text
		}
	}
	return vs[0].Text
}
