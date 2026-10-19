//go:build unix

package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testIdentity = Identity{
	CertIdentityRegexp: `^https://github\.com/example/tool/\.github/workflows/release\.yml@refs/tags/v[0-9]`,
	OIDCIssuer:         "https://token.actions.githubusercontent.com",
}

// fakeCosign writes a cosign that records its arguments and the content of
// the files it was given, then exits with code.
func fakeCosign(t *testing.T, code int) (bin, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	bin = filepath.Join(dir, "cosign")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\nfor a in \"$@\"; do [ -f \"$a\" ] && cat \"$a\" >> " + argsFile + ".files; done\n"
	if code != 0 {
		script += "echo 'Error: none of the expected identities matched' >&2\nexit " + string(rune('0'+code)) + "\n"
	}
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, argsFile
}

func TestVerifyRunsCosignWithTheIdentity(t *testing.T) {
	bin, args := fakeCosign(t, 0)
	err := Verify(context.Background(), []byte("checksums"), []byte(`{"bundle":1}`), testIdentity, Options{Cosign: bin})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(args)
	got := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(got) != 8 || got[0] != "verify-blob" || got[1] != "--bundle" || got[3] != "--certificate-identity-regexp" ||
		got[4] != testIdentity.CertIdentityRegexp || got[5] != "--certificate-oidc-issuer" || got[6] != testIdentity.OIDCIssuer || got[7] == "" {
		t.Fatalf("args = %q", got)
	}
	files, _ := os.ReadFile(args + ".files")
	if !strings.Contains(string(files), "checksums") || !strings.Contains(string(files), `{"bundle":1}`) {
		t.Fatalf("cosign did not get the artifact and the bundle: %q", files)
	}
	// The temporary files are gone.
	if _, err := os.Stat(got[2]); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("bundle file left behind: %v", err)
	}
}

func TestVerifyRefusesABadSignature(t *testing.T) {
	bin, _ := fakeCosign(t, 1)
	err := Verify(context.Background(), []byte("x"), []byte("y"), testIdentity, Options{Cosign: bin})
	var ve *VerifyError
	if !errors.As(err, &ve) || !strings.Contains(ve.Output, "none of the expected identities matched") {
		t.Fatalf("err = %#v", err)
	}
}

func TestVerifyWithoutCosign(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	err := Verify(context.Background(), []byte("x"), []byte("y"), testIdentity, Options{})
	if !errors.Is(err, ErrCosignMissing) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyRefusesAnEmptyIdentity(t *testing.T) {
	bin, _ := fakeCosign(t, 0)
	for _, id := range []Identity{{}, {CertIdentityRegexp: "x"}, {OIDCIssuer: "y"}, {CertIdentityRegexp: ".*", OIDCIssuer: "y"}} {
		if err := Verify(context.Background(), []byte("x"), []byte("y"), id, Options{Cosign: bin}); err == nil {
			t.Errorf("identity %+v accepted", id)
		}
	}
}

func TestChecksumFor(t *testing.T) {
	sums := []byte("ABC123  tool_1.0_linux_amd64.tar.gz\ndef456 *tool_1.0_darwin_arm64.tar.gz\n")
	if s, err := ChecksumFor(sums, "tool_1.0_linux_amd64.tar.gz"); err != nil || s != "abc123" {
		t.Errorf("linux: %q %v", s, err)
	}
	if s, err := ChecksumFor(sums, "tool_1.0_darwin_arm64.tar.gz"); err != nil || s != "def456" {
		t.Errorf("darwin: %q %v", s, err)
	}
	if _, err := ChecksumFor(sums, "other"); err == nil {
		t.Error("missing name accepted")
	}
	if err := CheckSHA256([]byte("hello"), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"); err != nil {
		t.Error(err)
	}
	if err := CheckSHA256([]byte("hello!"), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"); err == nil {
		t.Error("mismatch accepted")
	}
}
