package ticket

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// A device is a human's own approval device (a phone running lockhub's
// mobile facade): a WebAuthn credential that signs each decision the human
// takes on it, and an X25519 key the lock may seal its clear screen to.
// The lock pins its devices (Device records the human confirmed at the
// host's terminal) and verifies a device's signature itself, after the
// hub's, over the lock's own signed ticket: a hub that holds no device key
// cannot make a decision pass for one taken on a device, nor get a device
// signature for a ticket the lock did not sign.
//
// Limits, by design: the device's code is a web app the hub serves. A hub
// that serves malicious code can show one ticket and ask the human to
// verify themselves for another of the same lock's pending tickets, and
// can read the clear screens sealed to the device while the human looks
// at them (which is why sealing them is a separate opt-in). A synced
// passkey lives in the platform's account too. The sign counter
// (VerifyAssertion's result) is checked by the hub; a lock does not keep
// one.

// FacadeMobile is the facade name of decisions taken on a device.
const FacadeMobile = "mobile"

const (
	// ContextDeviceDecision is hashed with a DeviceStatement into the
	// WebAuthn challenge a device signs.
	ContextDeviceDecision Context = "lockkit/device-decision/v1"
	// ContextClearScreen is the associated data of a clear screen sealed
	// to a device (with the ticket and device ids).
	ContextClearScreen Context = "lockkit/clear-screen/v1"
)

// devicePrefix starts every device id.
const devicePrefix = "webauthn:"

// Device is a pinned approval device. Its ID derives from its WebAuthn
// credential id; Fingerprint is what the human compares between the
// host's terminal and the device when pairing.
type Device struct {
	V int `json:"v"`
	// ID is DeviceID(credential): "webauthn:" and 16 bytes of hex.
	ID string `json:"id"`
	// Credential is the WebAuthn credential id (base64url).
	Credential string `json:"credential"`
	// Name is the human's label ("phone"), for display.
	Name string `json:"name"`
	// RPID is the WebAuthn relying party id (the facade's host name) and
	// Origin the facade's origin ("https://hub.example.net").
	RPID   string `json:"rp_id"`
	Origin string `json:"origin"`
	// ES256 is the credential's P-256 public key, uncompressed (65 bytes,
	// base64url).
	ES256 string `json:"es256"`
	// X25519 is the device's sealing key (32 bytes, base64url).
	X25519 string `json:"x25519"`
}

// DeviceID is the id of the device whose WebAuthn credential id is cred.
func DeviceID(cred []byte) string {
	sum := sha256.Sum256(cred)
	return devicePrefix + hex.EncodeToString(sum[:16])
}

// ValidDeviceID reports whether s has the form of a device id.
func ValidDeviceID(s string) bool {
	h, ok := strings.CutPrefix(s, devicePrefix)
	return ok && len(h) == 32 && isLowerHex(h)
}

// maxCredential bounds a WebAuthn credential id (the spec's 1023 bytes).
const maxCredential = 1023

// Validate checks d's fields: version, id, keys, relying party.
func (d *Device) Validate() error {
	if d.V != Version {
		return invalid("device: unsupported version %d", d.V)
	}
	cred, err := enc.DecodeString(d.Credential)
	if err != nil || len(cred) == 0 || len(cred) > maxCredential {
		return invalid("device: credential")
	}
	if d.ID != DeviceID(cred) {
		return invalid("device: id %q is not the credential's", d.ID)
	}
	if err := checkStr("device: name", d.Name, 64); err != nil {
		return err
	}
	if _, err := d.es256(); err != nil {
		return err
	}
	if _, err := d.SealingKey(); err != nil {
		return err
	}
	if err := checkSet("device: rp_id", d.RPID); err != nil {
		return err
	}
	u, err := url.Parse(d.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return invalid("device: origin %q is not an https origin", d.Origin)
	}
	// The origin as a browser serializes it: lowercase, no default port.
	if u.String() != d.Origin || strings.ToLower(d.Origin) != d.Origin || u.Port() == "443" {
		return invalid("device: origin %q is not in serialized form", d.Origin)
	}
	if strings.ToLower(d.RPID) != d.RPID || strings.ContainsAny(d.RPID, ":/ ") {
		return invalid("device: rp_id %q is not a lowercase host name", d.RPID)
	}
	if h := u.Hostname(); h != d.RPID && !strings.HasSuffix(h, "."+d.RPID) {
		return invalid("device: origin %q is not within rp_id %q", d.Origin, d.RPID)
	}
	return nil
}

func (d *Device) es256() (*ecdsa.PublicKey, error) {
	raw, err := enc.DecodeString(d.ES256)
	if err != nil || len(raw) != 65 {
		return nil, invalid("device: es256")
	}
	// ecdh validates the point (on the curve, not the identity).
	if _, err := ecdh.P256().NewPublicKey(raw); err != nil {
		return nil, invalid("device: es256")
	}
	k, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return nil, invalid("device: es256")
	}
	return k, nil
}

// SealingKey is d's X25519 key.
func (d *Device) SealingKey() (*ecdh.PublicKey, error) {
	raw, err := enc.DecodeString(d.X25519)
	if err != nil || len(raw) != 32 {
		return nil, invalid("device: x25519")
	}
	k, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, invalid("device: x25519")
	}
	return k, nil
}

// Fingerprint is the SHA-256 of d's canonical form, as groups of four hex
// digits: the human compares it on the terminal and on the device before
// the device is pinned.
func (d *Device) Fingerprint() (string, error) {
	b, err := Canonical(d)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:10])
	var g []string
	for i := 0; i < len(h); i += 4 {
		g = append(g, h[i:i+4])
	}
	return strings.Join(g, " "), nil
}

// MaxDevices bounds the devices a lock pins.
const MaxDevices = 8

// DeviceSet is the file of a lock's pinned devices (--devices-file).
type DeviceSet struct {
	V       int      `json:"v"`
	Devices []Device `json:"devices"`
}

// ParseDevices reads a DeviceSet in canonical JSON (MarshalDevices): no
// unknown or duplicate member, no trailing data, every device valid, ids
// unique, at most MaxDevices.
func ParseDevices(data []byte) ([]Device, error) {
	var s DeviceSet
	if err := decodeStrict(data, &s); err != nil {
		return nil, fmt.Errorf("devices: %w", err)
	}
	if s.V != Version {
		return nil, invalid("devices: unsupported version %d", s.V)
	}
	if len(s.Devices) > MaxDevices {
		return nil, invalid("devices: more than %d", MaxDevices)
	}
	seen := map[string]bool{}
	for i := range s.Devices {
		if err := s.Devices[i].Validate(); err != nil {
			return nil, err
		}
		if seen[s.Devices[i].ID] {
			return nil, invalid("devices: %s twice", s.Devices[i].ID)
		}
		seen[s.Devices[i].ID] = true
	}
	return s.Devices, nil
}

// MarshalDevices is the canonical DeviceSet of devs, as ParseDevices
// reads it.
func MarshalDevices(devs []Device) ([]byte, error) {
	if devs == nil {
		devs = []Device{}
	}
	return Canonical(DeviceSet{V: Version, Devices: devs})
}

// DeviceAssertion is a WebAuthn assertion of a device over a decision's
// DeviceStatement, as the browser returned it (all base64url).
type DeviceAssertion struct {
	Device     string `json:"device"` // Device.ID
	AuthData   string `json:"auth_data"`
	ClientData string `json:"client_data"`
	Sig        string `json:"sig"`
}

// Assertion bounds.
const (
	maxAuthData   = 1024
	maxClientData = 4096
	maxDeviceSig  = 128
)

func (a *DeviceAssertion) validate() error {
	if !ValidDeviceID(a.Device) {
		return invalid("device.device %q", a.Device)
	}
	for _, f := range []struct {
		n, v     string
		min, max int
	}{
		{"device.auth_data", a.AuthData, 37, maxAuthData},
		{"device.client_data", a.ClientData, 2, maxClientData},
		{"device.sig", a.Sig, 8, maxDeviceSig},
	} {
		b, err := enc.DecodeString(f.v)
		if err != nil || len(b) < f.min || len(b) > f.max {
			return invalid("%s", f.n)
		}
	}
	return nil
}

// DeviceStatement is what a device signs for a decision: every field of
// the decision a lock acts on, the hub's signature and the assertion
// aside, and the hash of the lock-signed ticket the device showed. A lock
// rebuilds it from the decision it received and its own signed ticket: a
// hub that shows the device another screen, another clear screen or other
// flags than the lock's gets a signature over another ticket hash.
type DeviceStatement struct {
	V        int       `json:"v"`
	Ticket   string    `json:"ticket"`
	Instance string    `json:"instance"`
	KeyID    string    `json:"key_id"`
	PlanHash string    `json:"plan_hash"`
	Decision Outcome   `json:"decision"`
	Reason   string    `json:"reason"`
	Approver string    `json:"approver"`
	Display  string    `json:"display"`
	Facade   string    `json:"facade"`
	At       time.Time `json:"at"`
	Nonce    string    `json:"nonce"`
	HubKeyID string    `json:"hub_key_id"`
	Device   string    `json:"device"`
	// TicketHash is TicketHash of the signed ticket, as the lock sent it.
	TicketHash string `json:"ticket_hash"`
}

// TicketHash is "sha256:" and the hex SHA-256 of a signed ticket's bytes
// as the lock sent them (its canonical form, Ticket.Marshal).
func TicketHash(signed []byte) string {
	sum := sha256.Sum256(signed)
	return hashPrefix + hex.EncodeToString(sum[:])
}

// Statement is the statement a device signs for d, as device dev, about
// the signed ticket whose TicketHash is ticketHash.
func (d *Decision) Statement(dev, ticketHash string) DeviceStatement {
	return DeviceStatement{V: d.V, Ticket: d.Ticket, Instance: d.Instance, KeyID: d.KeyID, PlanHash: d.PlanHash,
		Decision: d.Decision, Reason: d.Reason, Approver: d.Approver.ID, Display: d.Approver.Display, Facade: d.Facade,
		At: d.At, Nonce: d.Nonce, HubKeyID: d.HubKeyID, Device: dev, TicketHash: ticketHash}
}

// Challenge is the WebAuthn challenge of s: the SHA-256 of
// ContextDeviceDecision, a NUL and the canonical form of s.
func (s DeviceStatement) Challenge() ([]byte, error) {
	b, err := Canonical(s)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(ContextDeviceDecision.message(b))
	return sum[:], nil
}

// ErrDevice: a device assertion does not verify, or a decision that needs
// one has none.
var ErrDevice = errors.New("ticket: device signature refused")

// WebAuthn authenticator data flags.
const (
	flagUP = 0x01 // user present
	flagUV = 0x04 // user verified
)

// VerifyAssertion checks a WebAuthn assertion of dev over challenge: the
// client data is a webauthn.get for dev's origin carrying challenge, the
// authenticator data is for dev's relying party with the user present and
// verified, and the ES256 signature verifies under dev's key. It returns
// the authenticator's signature counter.
func VerifyAssertion(dev *Device, challenge []byte, a *DeviceAssertion) (uint32, error) {
	if err := dev.Validate(); err != nil {
		return 0, err
	}
	if err := a.validate(); err != nil {
		return 0, err
	}
	if a.Device != dev.ID {
		return 0, fmt.Errorf("%w: assertion of %s, not %s", ErrDevice, a.Device, dev.ID)
	}
	authData, _ := enc.DecodeString(a.AuthData)
	clientData, _ := enc.DecodeString(a.ClientData)
	sig, _ := enc.DecodeString(a.Sig)
	var cd struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}
	if err := json.Unmarshal(clientData, &cd); err != nil {
		return 0, fmt.Errorf("%w: client data: %v", ErrDevice, err)
	}
	switch {
	case cd.Type != "webauthn.get":
		return 0, fmt.Errorf("%w: client data type %q", ErrDevice, cd.Type)
	case cd.Challenge != enc.EncodeToString(challenge):
		return 0, fmt.Errorf("%w: the assertion is over another challenge", ErrDevice)
	case cd.Origin != dev.Origin:
		return 0, fmt.Errorf("%w: origin %q, pinned %q", ErrDevice, cd.Origin, dev.Origin)
	case cd.CrossOrigin:
		return 0, fmt.Errorf("%w: cross-origin assertion", ErrDevice)
	}
	rp := sha256.Sum256([]byte(dev.RPID))
	switch {
	case !bytes.Equal(authData[:32], rp[:]):
		return 0, fmt.Errorf("%w: authenticator data for another relying party", ErrDevice)
	case authData[32]&flagUP == 0:
		return 0, fmt.Errorf("%w: user not present", ErrDevice)
	case authData[32]&flagUV == 0:
		return 0, fmt.Errorf("%w: user not verified", ErrDevice)
	}
	pub, err := dev.es256()
	if err != nil {
		return 0, err
	}
	cdh := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte(nil), authData...), cdh[:]...))
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return 0, fmt.Errorf("%w: signature", ErrDevice)
	}
	return binary.BigEndian.Uint32(authData[33:37]), nil
}

// VerifyDevice checks that d was taken on dev about the ticket signed:
// d names dev as its device and approver, on the mobile facade, and dev's
// assertion verifies over d's statement for that ticket. signed is the
// lock's own signed ticket (never one the hub sent back). The caller
// verified d's hub signature first (VerifyDecision), matched d to the
// ticket (Match), and picks dev among its pinned devices by
// d.Device.Device.
func VerifyDevice(dev *Device, d *Decision, signed []byte) error {
	switch {
	case d.Device == nil:
		return fmt.Errorf("%w: the decision carries no device signature", ErrDevice)
	case d.Device.Device != dev.ID:
		return fmt.Errorf("%w: decision of device %s, not %s", ErrDevice, d.Device.Device, dev.ID)
	case d.Approver.ID != dev.ID:
		return fmt.Errorf("%w: approver %q is not device %s", ErrDevice, d.Approver.ID, dev.ID)
	case d.Facade != FacadeMobile:
		return fmt.Errorf("%w: a device decision on facade %q", ErrDevice, d.Facade)
	}
	ch, err := d.Statement(dev.ID, TicketHash(signed)).Challenge()
	if err != nil {
		return err
	}
	_, err = VerifyAssertion(dev, ch, d.Device)
	return err
}

// DeviceBox is a clear screen sealed to one device.
type DeviceBox struct {
	Device string `json:"device"`
	Box    Sealed `json:"box"`
}

// ClearScreenAAD is the associated data of ticket id's clear screen sealed
// to device dev.
func ClearScreenAAD(id, dev string) []byte {
	return ContextClearScreen.message([]byte(id + "\x00" + dev))
}

// MaxClearScreen bounds the canonical clear screen sealed to a device;
// a larger one is not sealed (the device shows the masked screen only).
const MaxClearScreen = 256 << 10

// ErrTooLarge: a clear screen over MaxClearScreen.
var ErrTooLarge = errors.New("ticket: clear screen too large to seal")

// SealClearScreen seals the clear screen s of ticket id to dev, with
// SealAlgGCM (a browser opens it with WebCrypto).
func SealClearScreen(dev *Device, id string, s Screen) (*DeviceBox, error) {
	pub, err := dev.SealingKey()
	if err != nil {
		return nil, err
	}
	if s.Body == nil {
		s.Body = []string{}
	}
	if s.Warnings == nil {
		s.Warnings = []string{}
	}
	pt, err := Canonical(s)
	if err != nil {
		return nil, err
	}
	if len(pt) > MaxClearScreen {
		return nil, ErrTooLarge
	}
	box, err := SealGCM(pub, pt, ClearScreenAAD(id, dev.ID))
	if err != nil {
		return nil, err
	}
	return &DeviceBox{Device: dev.ID, Box: *box}, nil
}

// OpenClearScreen opens the clear screen of ticket id sealed to device
// dev, whose sealing key is priv. A box for another device is ErrOpen.
func OpenClearScreen(priv *ecdh.PrivateKey, id, dev string, b *DeviceBox) (Screen, error) {
	if b.Device != dev {
		return Screen{}, ErrOpen
	}
	pt, err := Open(priv, &b.Box, ClearScreenAAD(id, dev))
	if err != nil {
		return Screen{}, err
	}
	var s Screen
	if err := json.Unmarshal(pt, &s); err != nil {
		return Screen{}, ErrOpen
	}
	return s, nil
}
