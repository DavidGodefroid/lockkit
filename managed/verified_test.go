//go:build lockfamily_managed_test

package managed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/update"
)

// End to end, on real files: lox verifies on the host and stamps; a lock
// with no verifier reads the same directory, signed, until a byte changes.
func TestVerifiedStampEndToEnd(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	for name, data := range map[string]string{FileName: sample, BundleName: "bundle", SignerName: signerTOML} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	host := newSource(path)
	host.skipOwner = true
	host.verify = func(context.Context, []byte, []byte, update.Identity) error { return nil }
	f, err := host.Load(ctx)
	if err != nil || !f.Signed {
		t.Fatalf("host: %v, %v", f, err)
	}
	stamp, err := VerifiedStamp(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, VerifiedName), []byte(stamp+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	lock := newSource(path)
	lock.skipOwner = true
	lock.verify = func(context.Context, []byte, []byte, update.Identity) error {
		t.Fatal("the lock ran the verifier")
		return nil
	}
	if f, err := lock.Load(ctx); err != nil || !f.Signed {
		t.Fatalf("lock: %v, %v", f, err)
	}

	edited := []byte(strings.Replace(sample, "Example Corp", "Example Corq", 1))
	if err := os.WriteFile(path, edited, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := lock.Load(ctx); err == nil || !strings.Contains(err.Error(), VerifiedName+" does not match") {
		t.Fatalf("edited file: %v", err)
	}
}
