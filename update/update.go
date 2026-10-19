// Package update checks a release's signature before a product installs
// anything from it: the keyless cosign signature of an artifact (typically
// checksums.txt) against the identity of the release workflow, then the
// checksums of the files. A product's `update` command and lockfile's
// plugin install share it.
//
// Verification runs the cosign CLI (verify-blob with a sigstore bundle). A
// missing cosign is a refusal, never a skip.
package update

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Identity is who must have signed: the certificate identity (a regular
// expression over the signing workflow's URL, anchored at "^https://") and
// the OIDC issuer of the certificate.
type Identity struct {
	CertIdentityRegexp string
	OIDCIssuer         string
}

func (id Identity) check() error {
	if !strings.HasPrefix(id.CertIdentityRegexp, "^https://") || !strings.HasPrefix(id.OIDCIssuer, "https://") {
		return errors.New("update: the signing identity must be an anchored https:// regexp and an https:// issuer")
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

// Verify checks that bundle (a sigstore bundle) is a valid keyless
// signature of artifact by id.
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
	out, err := exec.CommandContext(ctx, cosign, "verify-blob",
		"--bundle", bundle,
		"--certificate-identity-regexp", id.CertIdentityRegexp,
		"--certificate-oidc-issuer", id.OIDCIssuer,
		artifact).CombinedOutput()
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
