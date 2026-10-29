package ticket

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// SealAlg is the only sealed-box construction: an ephemeral X25519 key
// agreement, HKDF-SHA256 over the shared secret (salt: the ephemeral then
// the recipient public key), XChaCha20-Poly1305 with a random nonce.
const SealAlg = "x25519-hkdf-sha256-xchacha20poly1305"

// sealInfo is the HKDF info of SealAlg.
const sealInfo = "lockkit/sealed/v1"

// ErrOpen: a sealed box does not open with this key and associated data.
var ErrOpen = errors.New("ticket: sealed box does not open")

// Sealed is a sealed box: what only the holder of one X25519 private key
// can read, relayed by a hub that cannot (a secret for unlock, a clear
// screen for a facade's device, a reveal).
type Sealed struct {
	Alg   string `json:"alg"`
	EPK   string `json:"epk"`   // ephemeral X25519 public key
	Nonce string `json:"nonce"` // 24 bytes
	CT    string `json:"ct"`    // ciphertext and tag
}

// maxSealed bounds the base64 ciphertext of a sealed box (about 1.5 MiB
// of plaintext).
const maxSealed = 2 << 20

func (s *Sealed) validate() error {
	if s.Alg != SealAlg {
		return invalid("sealed: alg %q", s.Alg)
	}
	if b, err := enc.DecodeString(s.EPK); err != nil || len(b) != 32 {
		return invalid("sealed: epk")
	}
	if b, err := enc.DecodeString(s.Nonce); err != nil || len(b) != chacha20poly1305.NonceSizeX {
		return invalid("sealed: nonce")
	}
	if len(s.CT) > maxSealed {
		return invalid("sealed: ciphertext longer than %d bytes", maxSealed)
	}
	if b, err := enc.DecodeString(s.CT); err != nil || len(b) < chacha20poly1305.Overhead {
		return invalid("sealed: ct")
	}
	return nil
}

func sealKey(shared, epk, rpk []byte) ([]byte, error) {
	salt := append(append([]byte(nil), epk...), rpk...)
	return hkdf.Key(sha256.New, shared, salt, sealInfo, chacha20poly1305.KeySize)
}

// Seal encrypts plaintext to the X25519 key to. aad is bound to the box
// and must be given again to Open (a ticket id, a context): a box sealed
// for one ticket does not open as another's.
func Seal(to *ecdh.PublicKey, plaintext, aad []byte) (*Sealed, error) {
	if to.Curve() != ecdh.X25519() {
		return nil, errors.New("ticket: Seal needs an X25519 key")
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(to)
	if err != nil {
		return nil, err
	}
	epk := eph.PublicKey().Bytes()
	key, err := sealKey(shared, epk, to.Bytes())
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, aad)
	return &Sealed{Alg: SealAlg, EPK: enc.EncodeToString(epk), Nonce: enc.EncodeToString(nonce), CT: enc.EncodeToString(ct)}, nil
}

// Open decrypts s with priv and aad. Any failure is ErrOpen.
func Open(priv *ecdh.PrivateKey, s *Sealed, aad []byte) ([]byte, error) {
	if priv.Curve() != ecdh.X25519() || s.validate() != nil {
		return nil, ErrOpen
	}
	epkRaw, _ := enc.DecodeString(s.EPK)
	nonce, _ := enc.DecodeString(s.Nonce)
	ct, _ := enc.DecodeString(s.CT)
	epk, err := ecdh.X25519().NewPublicKey(epkRaw)
	if err != nil {
		return nil, ErrOpen
	}
	shared, err := priv.ECDH(epk) // refuses the all-zero (low-order) secret
	if err != nil {
		return nil, ErrOpen
	}
	key, err := sealKey(shared, epkRaw, priv.PublicKey().Bytes())
	if err != nil {
		return nil, ErrOpen
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrOpen
	}
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

// KeyCert is an X25519 public key signed by an Ed25519 key: a lock's
// sealing key (ContextKeyCert), or a facade's ephemeral key for one reveal
// (ContextReveal, Bind = the ticket id). Whoever seals to it checks the
// signature under the Ed25519 key they pinned: a hub cannot substitute its
// own key.
type KeyCert struct {
	V      int    `json:"v"`
	KeyID  string `json:"key_id"` // the signing Ed25519 key
	X25519 string `json:"x25519"`
	// Bind ties the key to one use ("" for a long-lived key).
	Bind string `json:"bind"`
	Sig  string `json:"sig,omitempty"`
}

// CertifyX25519 signs pub with key under context c (ContextKeyCert or
// ContextReveal), bound to bind.
func CertifyX25519(key ed25519.PrivateKey, c Context, pub *ecdh.PublicKey, bind string) (*KeyCert, error) {
	if pub.Curve() != ecdh.X25519() {
		return nil, errors.New("ticket: CertifyX25519 needs an X25519 key")
	}
	if err := checkStr("bind", bind, maxField); err != nil {
		return nil, err
	}
	kc := &KeyCert{V: Version, KeyID: KeyID(key.Public().(ed25519.PublicKey)), X25519: enc.EncodeToString(pub.Bytes()), Bind: bind}
	b, err := Canonical(kc)
	if err != nil {
		return nil, err
	}
	kc.Sig = SignBytes(key, c, b)
	return kc, nil
}

// VerifyKeyCert decodes a key certificate signed by signer under context c
// and bound to bind, and returns its X25519 key.
func VerifyKeyCert(signer ed25519.PublicKey, c Context, bind string, data []byte) (*ecdh.PublicKey, error) {
	var kc KeyCert
	if err := decodeStrict(data, &kc); err != nil {
		return nil, err
	}
	if kc.V != Version {
		return nil, invalid("unsupported version %d", kc.V)
	}
	if kc.KeyID != KeyID(signer) {
		return nil, fmt.Errorf("%w: certificate names key %s, pinned key is %s", ErrBadSignature, kc.KeyID, KeyID(signer))
	}
	if kc.Bind != bind {
		return nil, fmt.Errorf("%w: key bound to %q, expected %q", ErrMismatch, kc.Bind, bind)
	}
	sig := kc.Sig
	kc.Sig = ""
	b, err := Canonical(&kc)
	if err != nil {
		return nil, err
	}
	if err := VerifyBytes(signer, c, b, sig); err != nil {
		return nil, err
	}
	raw, err := enc.DecodeString(kc.X25519)
	if err != nil {
		return nil, invalid("x25519")
	}
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, invalid("x25519")
	}
	return pub, nil
}
