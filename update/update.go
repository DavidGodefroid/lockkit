// Package update checks a release's signature before a product installs
// anything from it: the cosign signature of an artifact (typically
// checksums.txt), keyless against the identity of the release workflow or
// key-pair against a public key, then the checksums of the files. A product's `update` command and lockfile's
// plugin install share it.
//
// Verification runs the cosign CLI (verify-blob with a sigstore bundle). A
// missing cosign is a refusal, never a skip. Both modes require the
// bundle's transparency log (Rekor) entry: --insecure-ignore-tlog is never
// passed.
package update

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Identity is who must have signed: keyless, the certificate identity (a
// regular expression over the signing workflow's URL, anchored at
// "^https://") and the OIDC issuer of the certificate; or key-pair, a
// cosign public key.
type Identity struct {
	CertIdentityRegexp string
	OIDCIssuer         string
	// PublicKey is a PEM cosign public key ("-----BEGIN PUBLIC KEY-----").
	// When set, CertIdentityRegexp and OIDCIssuer must be empty. The
	// product reads the key file itself; lockkit only takes its bytes.
	PublicKey []byte
}

func (id Identity) check() error {
	if len(id.PublicKey) > 0 {
		if id.CertIdentityRegexp != "" || id.OIDCIssuer != "" {
			return errors.New("update: the signing identity is either a public key or a certificate identity and issuer, not both")
		}
		return checkPublicKey(id.PublicKey)
	}
	if !strings.HasPrefix(id.CertIdentityRegexp, "^https://") || !strings.HasPrefix(id.OIDCIssuer, "https://") {
		return errors.New("update: the signing identity must be an anchored https:// regexp and an https:// issuer, or a public key")
	}
	return nil
}

// checkPublicKey accepts one PEM PUBLIC KEY block (PKIX: ECDSA P-256 or
// P-384, Ed25519, RSA of at least 2048 bits) and nothing else. Its errors
// never quote the key.
func checkPublicKey(b []byte) error {
	blk, rest := pem.Decode(b)
	if blk == nil {
		return errors.New("update: the public key is not PEM")
	}
	if blk.Type != "PUBLIC KEY" {
		return fmt.Errorf("update: the public key is a PEM %q block, want \"PUBLIC KEY\"", blk.Type)
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return errors.New("update: the public key has data after its PEM block")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return errors.New("update: the public key is not a valid PKIX key")
	}
	switch k := k.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return errors.New("update: the ECDSA public key must be P-256 or P-384")
		}
	case ed25519.PublicKey:
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return fmt.Errorf("update: the RSA public key has %d bits, want at least 2048", k.N.BitLen())
		}
	default:
		return fmt.Errorf("update: unsupported public key type %T", k)
	}
	return nil
}

// Options configure Verify.
type Options struct {
	// Cosign is the cosign binary; "" looks it up in PATH.
	Cosign string
}

// ErrCosignMissing means cosign is not installed: the signature cannot be
// checked, so nothing may be installed.
var ErrCosignMissing = errors.New("cosign is not installed")

// VerifyError is a signature that does not verify; Output is cosign's.
type VerifyError struct {
	Err    error
	Output string
}

func (e *VerifyError) Error() string {
	return fmt.Sprintf("cosign: the signature does not verify (%v): %s", e.Err, e.Output)
}

func (e *VerifyError) Unwrap() error { return e.Err }

// Verify checks that bundle (a sigstore bundle) is a valid signature of
// artifact by id.
func Verify(ctx context.Context, artifact, bundle []byte, id Identity, o Options) error {
	if err := id.check(); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "lockkit-verify-")
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	defer os.RemoveAll(dir)
	art, bun := filepath.Join(dir, "artifact"), filepath.Join(dir, "artifact.sigstore.json")
	for p, b := range map[string][]byte{art: artifact, bun: bundle} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			return fmt.Errorf("update: %w", err)
		}
	}
	return VerifyFiles(ctx, art, bun, id, o)
}

// VerifyFiles is Verify for files already on disk.
func VerifyFiles(ctx context.Context, artifact, bundle string, id Identity, o Options) error {
	if err := id.check(); err != nil {
		return err
	}
	cosign := o.Cosign
	if cosign == "" {
		p, err := exec.LookPath("cosign")
		if err != nil {
			return ErrCosignMissing
		}
		cosign = p
	}
	args := []string{"verify-blob", "--bundle", bundle}
	if len(id.PublicKey) > 0 {
		dir, err := os.MkdirTemp("", "lockkit-verify-key-")
		if err != nil {
			return fmt.Errorf("update: %w", err)
		}
		defer os.RemoveAll(dir)
		key := filepath.Join(dir, "cosign.pub")
		if err := os.WriteFile(key, id.PublicKey, 0o600); err != nil {
			return fmt.Errorf("update: %w", err)
		}
		args = append(args, "--key", key)
	} else {
		args = append(args,
			"--certificate-identity-regexp", id.CertIdentityRegexp,
			"--certificate-oidc-issuer", id.OIDCIssuer)
	}
	out, err := exec.CommandContext(ctx, cosign, append(args, artifact)...).CombinedOutput()
	if err != nil {
		return &VerifyError{Err: err, Output: strings.TrimSpace(string(out))}
	}
	return nil
}

// ChecksumFor returns the sha256 (lower case) a checksums.txt lists for
// name ("<hex>  <name>" or "<hex> *<name>").
func ChecksumFor(sums []byte, name string) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("%s is not listed in checksums.txt", name)
}

// CheckSHA256 reports whether data has the hex sha256 want.
func CheckSHA256(data []byte, want string) error {
	got := sha256.Sum256(data)
	if hex.EncodeToString(got[:]) != strings.ToLower(want) {
		return errors.New("update: checksum mismatch")
	}
	return nil
}
