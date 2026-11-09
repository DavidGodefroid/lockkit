package config

import (
	"os"
	"strings"
	"testing"
)

func TestSaveApprovedManaged(t *testing.T) {
	type pol struct {
		Tier string `json:"tier"`
	}
	state := t.TempDir()
	if err := SaveApprovedManaged(testProduct, state, "user-p", pol{Tier: "read"}, "abc123"); err != nil {
		t.Fatal(err)
	}
	path, _ := ApprovedPath(testProduct, state, "user-p")
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"managed_sha256": "abc123"`) || !strings.HasSuffix(string(raw), "\n") {
		t.Fatalf("file %s", raw)
	}
	var back pol
	if ok, err := LoadApproved(testProduct, state, "user-p", &back); !ok || err != nil || back.Tier != "read" {
		t.Fatalf("load back: %+v, %v", back, err)
	}
	// Without a managed file, the policy is written as is.
	if err := SaveApprovedManaged(testProduct, state, "user-p", pol{Tier: "read"}, ""); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(path); strings.Contains(string(raw), ManagedField) {
		t.Fatalf("file %s", raw)
	}
	if err := SaveApprovedManaged(testProduct, state, "user-p", []string{"x"}, "abc"); err == nil {
		t.Fatal("a non-object policy accepted")
	}
	if err := SaveApprovedManaged(testProduct, state, "user-p", map[string]string{ManagedField: "forged"}, "abc"); err == nil {
		t.Fatal("a policy with its own managed field accepted")
	}
}
