//go:build unix && lockfamily_managed_test

package console

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/managed"
)

// A server built with NewServer and LoadManaged = managed.Load picks up a
// managed file tightened on disk while it serves, at the next poll, as Run.
func TestNewServerReadsManagedFileFromDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), managed.FileName)
	write := func(data string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(peekBound)
	managed.SetTestPath(path)
	defer managed.SetTestPath(managed.DefaultPath())
	mf, err := managed.Load(context.Background())
	if err != nil || mf == nil {
		t.Fatalf("Load: %v, %v", mf, err)
	}
	start := uat()
	start.Tier = "peek"
	if err := CheckManaged(testProduct, &fakeBackend{}, start, mf); err != nil {
		t.Fatalf("start refused: %v", err)
	}
	h := newHarness(t, start, func(c *ServerConfig) { c.Managed, c.LoadManaged = mf, managed.Load })
	h.s.CheckPolicy()
	if _, ended := h.s.Ended(); ended || len(h.records(t)) != 0 {
		t.Fatalf("unchanged file: records %v\n%s", h.records(t), h.io.plain())
	}

	write(readBound)
	h.s.CheckPolicy()
	r := h.records(t)
	if len(r) == 0 || r[0]["decision"] != DecisionManagedChanged || r[0]["managed"] == mf.Fingerprint {
		t.Fatalf("change not recorded: %v", r)
	}
	if reason, ended := h.s.Ended(); !ended || !strings.Contains(reason, "beyond the managed configuration") {
		t.Fatalf("session not ended: %q\n%s", reason, h.io.plain())
	}
}
