package ticket

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ErrBadSignature: the signature does not verify under the key given, or
// the key is not the one the signed value names.
var ErrBadSignature = errors.New("ticket: bad signature")

// Context separates what one Ed25519 key signs: a lock's key signs its
// tickets, its X25519 key and its requests to the hub, and none of these
// signatures is valid as another. A new signed kind gets a new context.
type Context string

const (
	ContextTicket   Context = "lockkit/ticket/v1"
	ContextDecision Context = "lockkit/decision/v1"
	// ContextKeyCert signs an X25519 public key with an Ed25519 key.
	ContextKeyCert Context = "lockkit/x25519-key/v1"
	// ContextRequest signs a lock's HTTP request to the hub (Lock-Sig).
	ContextRequest Context = "lockkit/request/v1"
	// ContextReveal signs a facade's ephemeral key for a reveal.
	ContextReveal Context = "lockkit/reveal/v1"
)

// message is what is signed: the context, a NUL, the message.
func (c Context) message(msg []byte) []byte {
	m := make([]byte, 0, len(c)+1+len(msg))
	m = append(m, c...)
	m = append(m, 0)
	return append(m, msg...)
}

// SignBytes signs msg under context c.
func SignBytes(key ed25519.PrivateKey, c Context, msg []byte) string {
	return enc.EncodeToString(ed25519.Sign(key, c.message(msg)))
}

// VerifyBytes checks sig, as SignBytes returns it, over msg under c.
func VerifyBytes(pub ed25519.PublicKey, c Context, msg []byte, sig string) error {
	raw, err := enc.DecodeString(sig)
	if err != nil || len(pub) != ed25519.PublicKeySize || len(raw) != ed25519.SignatureSize ||
		!ed25519.Verify(pub, c.message(msg), raw) {
		return ErrBadSignature
	}
	return nil
}

// enc is the encoding of signatures, keys, nonces and ciphertexts on the
// wire: unpadded base64url.
var enc = base64.RawURLEncoding

// keyIDPrefix starts every Ed25519 key id.
const keyIDPrefix = "ed25519:"

// KeyID names an Ed25519 public key: "ed25519:" and the first 16 bytes of
// its SHA-256, in hex. It names a key, it does not vouch for one: the
// verifier always uses the key it pinned.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return keyIDPrefix + hex.EncodeToString(sum[:16])
}

func validKeyID(s string) bool {
	h, ok := strings.CutPrefix(s, keyIDPrefix)
	return ok && len(h) == 32 && isLowerHex(h)
}

// hashPrefix starts every hash: plan_hash and policy_fp.
const hashPrefix = "sha256:"

// HashOf is "sha256:" and the hex SHA-256 of the canonical form of v: the
// plan hash of a plan's inputs, a policy fingerprint.
func HashOf(v any) (string, error) {
	b, err := Canonical(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hashPrefix + hex.EncodeToString(sum[:]), nil
}

func validHash(s string) bool {
	h, ok := strings.CutPrefix(s, hashPrefix)
	return ok && len(h) == 64 && isLowerHex(h)
}

func isLowerHex(s string) bool {
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// nonceSize is the random bytes of a nonce.
const nonceSize = 16

// NewNonce is a fresh random nonce: 16 bytes, base64url.
func NewNonce() string {
	b := make([]byte, nonceSize)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("ticket: crypto/rand: %v", err))
	}
	return enc.EncodeToString(b)
}

func validNonce(s string) bool {
	b, err := enc.DecodeString(s)
	return err == nil && len(b) == nonceSize
}

// RequestMessage is what a lock signs, under ContextRequest, for one HTTP
// request to the hub (the Lock-Sig header): the method, the path with its
// query, the signing instance (Lock-Instance), the Unix time in seconds
// (Lock-Time), the request nonce (Lock-Nonce) and the hex SHA-256 of the
// body, one per line. The hub accepts it within a minute of its own clock
// and each nonce once.
func RequestMessage(method, pathQuery, instance string, at time.Time, nonce string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte(method + "\n" + pathQuery + "\n" + instance + "\n" + strconv.FormatInt(at.Unix(), 10) + "\n" + nonce + "\n" + hex.EncodeToString(sum[:]))
}
