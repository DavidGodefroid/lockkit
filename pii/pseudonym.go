package pii

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode"
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

	mu  sync.RWMutex
	key []byte // nil once forgotten
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
	return &Pseudonymizer{epoch: id, created: now.UTC().Truncate(time.Second), key: key}, nil
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
	return &Pseudonymizer{epoch: epoch, created: created.UTC(), key: append([]byte(nil), key...)}, nil
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

func validEpochID(s string) bool {
	if len(s) != EpochLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(crockford, s[i]) < 0 {
			return false
		}
	}
	return true
}

// Epoch returns the epoch id: random, it says nothing about the key.
func (p *Pseudonymizer) Epoch() string { return p.epoch }

// Created returns when the epoch began (to the second).
func (p *Pseudonymizer) Created() time.Time { return p.created }

// ID returns the pseudonym of value as a value of kind (a detector name:
// "email", "phone", ...): the first PseudonymLen characters of the
// Crockford base32 of HMAC-SHA256(key, kind || 0x00 || Normalise(kind,
// value)). Different kinds give different IDs for the same text. Once the
// epoch's key was deleted (EpochStore.Prune), ID fails with
// ErrForgottenEpoch and never computes an ID: the caller redacts the value.
func (p *Pseudonymizer) ID(kind, value string) (string, error) {
	norm := Normalise(kind, value)
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.key) != KeyLen {
		return "", ErrForgottenEpoch
	}
	m := hmac.New(sha256.New, p.key)
	m.Write([]byte(kind))
	m.Write([]byte{0})
	m.Write([]byte(norm))
	return encodeID(m.Sum(nil)), nil
}

// Forgotten reports whether the epoch's key was deleted.
func (p *Pseudonymizer) Forgotten() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.key) != KeyLen
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
func ValidID(s string) bool {
	if len(s) != PseudonymLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(crockford, s[i]) < 0 {
			return false
		}
	}
	return true
}

// String shows the epoch, never the key.
func (p *Pseudonymizer) String() string { return "pii.Pseudonymizer{epoch: " + p.epoch + "}" }

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
	p.mu.Lock()
	defer p.mu.Unlock()
	clear(p.key)
	p.key = nil
}

// Normalise returns the form of value whose pseudonym is taken, so that
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
//   - other kinds: the detection view with surrounding blanks trimmed.
func Normalise(kind, value string) string {
	v := wholeValueView(kind, value)
	switch kind {
	case "email":
		return strings.ToLower(strings.TrimSpace(v))
	case "phone", "phone_loose":
		d := digitsOf(v)
		switch t := strings.TrimLeft(v, " ("); {
		case strings.HasPrefix(t, "+"):
			return "+" + d
		case strings.HasPrefix(d, "00"):
			return "+" + d[2:]
		}
		return d
	case "iban":
		return strings.ToUpper(strings.Map(func(r rune) rune {
			if unicode.IsSpace(r) {
				return -1
			}
			return r
		}, v))
	case "card", "be_niss", "nl_bsn", "us_ssn":
		return digitsOf(v)
	case "fr_nir":
		return strings.ToUpper(strings.Map(func(r rune) rune {
			if isDigit(byte(r)) && r < 0x80 || r == 'a' || r == 'b' || r == 'A' || r == 'B' {
				return r
			}
			return -1
		}, v))
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
