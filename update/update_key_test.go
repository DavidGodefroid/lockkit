//go:build unix

package update

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func pkixPEM(t *testing.T, pub any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pemBlock("PUBLIC KEY", der)
}

func testPublicKey(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pkixPEM(t, &k.PublicKey)
}

// fakeKeyCosign is a cosign that records its arguments, then the content
// and the mode of the file passed after --key.
func fakeKeyCosign(t *testing.T) (bin, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	bin = filepath.Join(dir, "cosign")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\n" +
		"while [ $# -gt 0 ]; do if [ \"$1\" = --key ]; then cat \"$2\" > " + argsFile + ".key; ls -l \"$2\" > " + argsFile + ".mode; fi; shift; done\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, argsFile
}

func TestVerifyKeyRunsCosignWithTheKey(t *testing.T) {
	bin, args := fakeKeyCosign(t)
	key := testPublicKey(t)
	dir := t.TempDir()
	art, bun := filepath.Join(dir, "checksums.txt"), filepath.Join(dir, "checksums.txt.sigstore.json")
	for _, p := range []string{art, bun} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := VerifyFiles(context.Background(), art, bun, Identity{PublicKey: key}, Options{Cosign: bin}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(args)
	got := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(got) != 6 || got[0] != "verify-blob" || got[1] != "--bundle" || got[2] != bun || got[3] != "--key" || got[5] != art {
		t.Fatalf("args = %q", got)
	}
	if k, _ := os.ReadFile(args + ".key"); !bytes.Equal(k, key) {
		t.Errorf("key file = %q, want the PEM given", k)
	}
	if m, _ := os.ReadFile(args + ".mode"); !strings.HasPrefix(string(m), "-rw------- ") {
		t.Errorf("key file mode: %q", m)
	}
	if _, err := os.Stat(got[4]); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("key file left behind: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(got[4])); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("key dir left behind: %v", err)
	}
}

func TestVerifyNeverIgnoresTheTlog(t *testing.T) {
	for name, id := range map[string]Identity{"keyless": testIdentity, "key": {PublicKey: testPublicKey(t)}} {
		bin, args := fakeCosign(t, 0)
		if err := Verify(context.Background(), []byte("a"), []byte("b"), id, Options{Cosign: bin}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if raw, _ := os.ReadFile(args); strings.Contains(string(raw), "tlog") {
			t.Errorf("%s: args = %q", name, raw)
		}
	}
}

func TestVerifyKeyErrors(t *testing.T) {
	id := Identity{PublicKey: testPublicKey(t)}
	bin, _ := fakeCosign(t, 1)
	var ve *VerifyError
	if err := Verify(context.Background(), []byte("x"), []byte("y"), id, Options{Cosign: bin}); !errors.As(err, &ve) {
		t.Errorf("failing cosign: err = %#v", err)
	}
	t.Setenv("PATH", t.TempDir())
	if err := Verify(context.Background(), []byte("x"), []byte("y"), id, Options{}); !errors.Is(err, ErrCosignMissing) {
		t.Errorf("no cosign: err = %v", err)
	}
}

func TestIdentityCheckKey(t *testing.T) {
	ec := testPublicKey(t)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ec384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for name, k := range map[string][]byte{
		"ecdsa p256": ec, "ecdsa p384": pkixPEM(t, &ec384.PublicKey),
		"ed25519": pkixPEM(t, edPub), "rsa 2048": pkixPEM(t, &rsa2048.PublicKey),
	} {
		if err := (Identity{PublicKey: k}).check(); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}

	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ec224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ecPriv.PublicKey, ecPriv)
	if err != nil {
		t.Fatal(err)
	}
	der := func(k []byte) []byte { b, _ := pem.Decode(k); return b.Bytes }(ec)
	bad := map[string]Identity{
		"both modes":            {PublicKey: ec, CertIdentityRegexp: testIdentity.CertIdentityRegexp, OIDCIssuer: testIdentity.OIDCIssuer},
		"key and issuer":        {PublicKey: ec, OIDCIssuer: testIdentity.OIDCIssuer},
		"neither":               {},
		"not pem":               {PublicKey: der},
		"certificate":           {PublicKey: pemBlock("CERTIFICATE", cert)},
		"encrypted private key": {PublicKey: pemBlock("ENCRYPTED PRIVATE KEY", der)},
		"garbage after":         {PublicKey: append(append([]byte{}, ec...), "trailing"...)},
		"bad pkix":              {PublicKey: pemBlock("PUBLIC KEY", []byte("not a key at all, just bytes"))},
		"rsa 1024":              {PublicKey: pkixPEM(t, &rsa1024.PublicKey)},
		"ecdsa p224":            {PublicKey: pkixPEM(t, &ec224.PublicKey)},
	}
	for name, id := range bad {
		err := id.check()
		if err == nil {
			t.Errorf("%s accepted", name)
			continue
		}
		msg := err.Error()
		for _, line := range strings.Split(string(id.PublicKey), "\n") {
			if len(line) >= 16 && !strings.HasPrefix(line, "-----") && strings.Contains(msg, line) {
				t.Errorf("%s: the error quotes the key: %q", name, msg)
			}
		}
		if len(der) > 0 && strings.Contains(msg, string(der)) {
			t.Errorf("%s: the error quotes the key: %q", name, msg)
		}
	}
}

// TestVerifyKeyRealCosign verifies the checked-in fixtures of testdata/key
// (gen.sh) with the real cosign. It needs network access to the sigstore
// TUF root.
func TestVerifyKeyRealCosign(t *testing.T) {
	if _, err := exec.LookPath("cosign"); err != nil {
		t.Skip("cosign is not in PATH")
	}
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", "key", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	pub, other := read("cosign.pub"), read("other.pub")
	art, bun, notlog := read("artifact"), read("artifact.sigstore.json"), read("artifact.notlog.sigstore.json")
	ctx := context.Background()
	if err := Verify(ctx, art, bun, Identity{PublicKey: pub}, Options{}); err != nil {
		t.Fatalf("good bundle: %v", err)
	}
	var ve *VerifyError
	tampered := append(append([]byte{}, art...), '\n')
	for name, err := range map[string]error{
		"tampered artifact": Verify(ctx, tampered, bun, Identity{PublicKey: pub}, Options{}),
		"other key":         Verify(ctx, art, bun, Identity{PublicKey: other}, Options{}),
		"no tlog entry":     Verify(ctx, art, notlog, Identity{PublicKey: pub}, Options{}),
	} {
		if !errors.As(err, &ve) {
			t.Errorf("%s: err = %v, want *VerifyError", name, err)
		}
	}
}
