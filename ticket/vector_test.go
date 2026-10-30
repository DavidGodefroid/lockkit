package ticket

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The device vectors pin, for other implementations (lockhub's web app,
// which opens boxes and builds challenges with WebCrypto), the exact
// bytes of a SealAlgGCM clear-screen box and of a device challenge.
type deviceVectors struct {
	Note string `json:"note"`
	Seal struct {
		Recipient string `json:"recipient_x25519_private"`
		Ephemeral string `json:"ephemeral_x25519_private"`
		Nonce     string `json:"nonce"`
		AADHex    string `json:"aad_hex"`
		Plaintext string `json:"plaintext"`
		Box       Sealed `json:"box"`
	} `json:"seal_gcm"`
	Statement     stmtVector `json:"device_statement"`
	StatementMS   stmtVector `json:"device_statement_ms"`
	TimeNote      string     `json:"time_note"`
}

type stmtVector struct {
	Statement    DeviceStatement `json:"statement"`
	CanonicalHex string          `json:"canonical_hex"`
	Challenge    string          `json:"challenge"`
}

func stmtOf(st DeviceStatement) stmtVector {
	c, _ := Canonical(st)
	ch, _ := st.Challenge()
	return stmtVector{st, hex.EncodeToString(c), enc.EncodeToString(ch)}
}

func makeDeviceVectors(t *testing.T) deviceVectors {
	t.Helper()
	var v deviceVectors
	v.Note = "TEST KEYS ONLY: published, never use outside tests"
	rk, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x55}, 32))
	ek, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x66}, 32))
	nonce := bytes.Repeat([]byte{0x77}, gcmNonceSize)
	dev := devicePrefix + strings.Repeat("ab", 16)
	aad := ClearScreenAAD("01JBDN0Z0000000000000000AB", dev)
	pt, _ := Canonical(Screen{Header: "crm / shop", Body: []string{"UPDATE customers SET email = 'jane@example.com'"}, Warnings: []string{}})
	box, err := sealWith(SealAlgGCM, ek, nonce, rk.PublicKey(), pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	v.Seal.Recipient, v.Seal.Ephemeral, v.Seal.Nonce = enc.EncodeToString(rk.Bytes()), enc.EncodeToString(ek.Bytes()), enc.EncodeToString(nonce)
	v.Seal.AADHex, v.Seal.Plaintext, v.Seal.Box = hex.EncodeToString(aad), string(pt), *box
	st := DeviceStatement{V: 1, Ticket: "01JBDN0Z0000000000000000AB", Instance: "crm-prod", KeyID: KeyID(lockPub),
		PlanHash: "sha256:" + strings.Repeat("1", 64), Decision: Approved, Reason: "", Approver: dev, Display: "phone",
		Facade: FacadeMobile, At: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC), Nonce: "AAECAwQFBgcICQoLDA0ODw",
		HubKeyID: KeyID(hubPub), Device: dev, TicketHash: "sha256:" + strings.Repeat("2", 64)}
	v.Statement = stmtOf(st)
	st.At = time.Date(2026, 10, 30, 12, 0, 0, 120e6, time.UTC)
	v.StatementMS = stmtOf(st)
	v.TimeNote = "at is RFC 3339 in UTC with trailing zeros of the fraction trimmed (Go's time.Time JSON): 12:00:00.12Z, not .120Z; an implementation copies the hub's at string, never re-formats it"
	return v
}

func TestDeviceVectors(t *testing.T) {
	path := filepath.Join("testdata", "device-v1.json")
	got := makeDeviceVectors(t)
	b, _ := json.MarshalIndent(got, "", "  ")
	b = append(b, '\n')
	if *update {
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, b) {
		t.Fatalf("%s changed: the device wire format is frozen within a Version", path)
	}
	// The committed box opens.
	rk, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x55}, 32))
	aad, _ := hex.DecodeString(got.Seal.AADHex)
	if pt, err := Open(rk, &got.Seal.Box, aad); err != nil || string(pt) != got.Seal.Plaintext {
		t.Fatalf("vector box: %q %v", pt, err)
	}
	if !strings.Contains(string(mustCanon(got.StatementMS.Statement)), `"at":"2026-10-30T12:00:00.12Z"`) {
		t.Fatal("time format of the statement changed")
	}
	// Keys are separated between the algorithms (HKDF info).
	shared := bytes.Repeat([]byte{1}, 32)
	k1, _ := sealKey(SealAlg, shared, shared, shared)
	k2, _ := sealKey(SealAlgGCM, shared, shared, shared)
	if bytes.Equal(k1, k2) {
		t.Fatal("same key under both algorithms")
	}
}

func mustCanon(v any) []byte {
	b, err := Canonical(v)
	if err != nil {
		panic(err)
	}
	return b
}
