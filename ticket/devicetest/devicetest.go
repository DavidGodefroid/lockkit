// Package devicetest is a virtual WebAuthn authenticator for tests: it
// signs device assertions as a phone's platform authenticator would, so
// locks and the hub can test device-signed decisions without a browser.
package devicetest

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"

	"github.com/DavidGodefroid/lockkit/ticket"
)

var enc = base64.RawURLEncoding

// Authenticator is one virtual device: a WebAuthn credential (ES256) and
// an X25519 sealing key.
type Authenticator struct {
	RPID, Origin string
	Name         string
	Cred         []byte
	Key          *ecdsa.PrivateKey
	Seal         *ecdh.PrivateKey
	Counter      uint32
}

// New is a fresh authenticator for the relying party rpID at origin.
func New(rpID, origin, name string) *Authenticator {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	cred := make([]byte, 32)
	rand.Read(cred)
	return &Authenticator{RPID: rpID, Origin: origin, Name: name, Cred: cred, Key: k, Seal: x}
}

// PublicKey is the credential's uncompressed P-256 point.
func (a *Authenticator) PublicKey() []byte {
	ek, err := a.Key.PublicKey.ECDH()
	if err != nil {
		panic(err)
	}
	return ek.Bytes()
}

// Device is the record a lock pins for a.
func (a *Authenticator) Device() ticket.Device {
	return ticket.Device{V: ticket.Version, ID: ticket.DeviceID(a.Cred), Credential: enc.EncodeToString(a.Cred),
		Name: a.Name, RPID: a.RPID, Origin: a.Origin, ES256: enc.EncodeToString(a.PublicKey()),
		X25519: enc.EncodeToString(a.Seal.PublicKey().Bytes())}
}

// Options change an assertion, to test what a verifier refuses.
type Options struct {
	Type   string // default webauthn.get
	Origin string // default a.Origin
	RPID   string // default a.RPID
	Flags  *byte  // default UP|UV
	Cross  bool
}

// Assert signs challenge as a user-verified assertion.
func (a *Authenticator) Assert(challenge []byte) *ticket.DeviceAssertion {
	return a.AssertWith(challenge, Options{})
}

// AssertWith signs challenge with o.
func (a *Authenticator) AssertWith(challenge []byte, o Options) *ticket.DeviceAssertion {
	if o.Type == "" {
		o.Type = "webauthn.get"
	}
	if o.Origin == "" {
		o.Origin = a.Origin
	}
	if o.RPID == "" {
		o.RPID = a.RPID
	}
	flags := byte(0x05)
	if o.Flags != nil {
		flags = *o.Flags
	}
	cd, _ := json.Marshal(map[string]any{"type": o.Type, "challenge": enc.EncodeToString(challenge), "origin": o.Origin, "crossOrigin": o.Cross})
	a.Counter++
	rp := sha256.Sum256([]byte(o.RPID))
	ad := append(rp[:], flags)
	ad = binary.BigEndian.AppendUint32(ad, a.Counter)
	cdh := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte(nil), ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.Key, digest[:])
	if err != nil {
		panic(err)
	}
	return &ticket.DeviceAssertion{Device: ticket.DeviceID(a.Cred), AuthData: enc.EncodeToString(ad),
		ClientData: enc.EncodeToString(cd), Sig: enc.EncodeToString(sig)}
}

// Decide makes d a decision taken on a: approver and facade, then the
// assertion over its statement. d is signed by the hub afterwards.
func (a *Authenticator) Decide(d *ticket.Decision) {
	id := ticket.DeviceID(a.Cred)
	d.Approver.ID, d.Facade = id, ticket.FacadeMobile
	ch, err := d.Statement(id).Challenge()
	if err != nil {
		panic(err)
	}
	d.Device = a.Assert(ch)
}
