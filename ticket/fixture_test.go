package ticket

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// The fixtures under testdata are the cross-repository contract: lockhub
// verifies them against the lockkit it pins and the one before. They must
// not change within a ticket Version; go test -run TestFixtures -update
// rewrites them only when Version changes.
var update = flag.Bool("update", false, "rewrite testdata fixtures")

// x25519Fixture is the lock's X25519 sealing key of the fixtures (test
// only).
var x25519Fixture = bytes.Repeat([]byte{0x44}, 32)

type fixtureKeys struct {
	Note       string `json:"note"`
	LockSeed   string `json:"lock_ed25519_seed"`
	LockKeyID  string `json:"lock_key_id"`
	HubSeed    string `json:"hub_ed25519_seed"`
	HubKeyID   string `json:"hub_key_id"`
	LockX25519 string `json:"lock_x25519_private"`
}

func fixtureFiles(t *testing.T) map[string][]byte {
	t.Helper()
	tk := sampleTicket(t)
	keysJSON, _ := json.MarshalIndent(fixtureKeys{
		Note:       "TEST KEYS ONLY: published, never use outside tests",
		LockSeed:   enc.EncodeToString(lockSeed),
		LockKeyID:  KeyID(lockPub),
		HubSeed:    enc.EncodeToString(hubSeed),
		HubKeyID:   KeyID(hubPub),
		LockX25519: enc.EncodeToString(x25519Fixture),
	}, "", "  ")
	files := map[string][]byte{
		"keys.json":                 append(keysJSON, '\n'),
		"ticket-v1.json":            mustMarshal(t, tk),
		"decision-approved-v1.json": mustMarshal(t, sampleDecision(t, tk, Approved)),
		"decision-denied-v1.json":   mustMarshal(t, sampleDecision(t, tk, Denied)),
	}
	x, err := ecdh.X25519().NewPrivateKey(x25519Fixture)
	if err != nil {
		t.Fatal(err)
	}
	kc, err := CertifyX25519(lockKey, ContextKeyCert, x.PublicKey(), "")
	if err != nil {
		t.Fatal(err)
	}
	files["keycert-v1.json"], _ = Canonical(kc)
	return files
}

func TestFixtures(t *testing.T) {
	files := fixtureFiles(t)
	if *update {
		for name, b := range files {
			if err := os.WriteFile(filepath.Join("testdata", name), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		writeSealedFixture(t)
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s changed: the ticket contract moved without a Version bump\ngot  %s\nwant %s", name, got, want)
		}
	}
}

// The committed fixtures verify with the published keys alone.
func TestFixturesVerify(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	tk, err := VerifyTicket(lockPub, read("ticket-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"decision-approved-v1.json", "decision-denied-v1.json"} {
		d, err := VerifyDecision(hubPub, read(name))
		if err != nil {
			t.Fatal(name, err)
		}
		if err := d.Match(tk); err != nil {
			t.Fatal(name, err)
		}
	}
	x, _ := ecdh.X25519().NewPrivateKey(x25519Fixture)
	pub, err := VerifyKeyCert(lockPub, ContextKeyCert, "", read("keycert-v1.json"))
	if err != nil || !pub.Equal(x.PublicKey()) {
		t.Fatalf("keycert: %v", err)
	}
	var s Sealed
	if err := json.Unmarshal(read("sealed-v1.json"), &s); err != nil {
		t.Fatal(err)
	}
	pt, err := Open(x, &s, []byte(tk.ID))
	if err != nil || string(pt) != "s3cret password" {
		t.Fatalf("sealed: %q %v", pt, err)
	}
}

// writeSealedFixture writes testdata/sealed-v1.json once: a sealed box is
// randomized, so it is only opened afterwards.
func writeSealedFixture(t *testing.T) {
	path := filepath.Join("testdata", "sealed-v1.json")
	if _, err := os.Stat(path); err == nil {
		return
	}
	x, _ := ecdh.X25519().NewPrivateKey(x25519Fixture)
	s, err := Seal(x.PublicKey(), []byte("s3cret password"), []byte("01JBDN0Z0000000000000000AB"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Canonical(s)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
