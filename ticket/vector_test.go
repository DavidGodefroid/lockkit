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
	Statement struct {
		Statement    DeviceStatement `json:"statement"`
		CanonicalHex string          `json:"canonical_hex"`
		Challenge    string          `json:"challenge"`
	} `json:"device_statement"`
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
	c, _ := Canonical(st)
	ch, _ := st.Challenge()
	v.Statement.Statement, v.Statement.CanonicalHex, v.Statement.Challenge = st, hex.EncodeToString(c), enc.EncodeToString(ch)
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
	// Keys are separated between the algorithms: the same inputs under
	// SealAlg, with a nonce of its size, give another ciphertext.
	ek, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x66}, 32))
	x, _ := sealWith(SealAlg, ek, bytes.Repeat([]byte{0x77}, 24), rk.PublicKey(), []byte(got.Seal.Plaintext), aad)
	if x.CT[:20] == got.Seal.Box.CT[:20] {
		t.Fatal("same keystream under both algorithms")
	}
}
