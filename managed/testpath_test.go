//go:build lockfamily_managed_test

package managed

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The test build moves the machine's file, without the ownership check.
func TestSetTestPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, []byte(sample), 0o644); err != nil {
		t.Fatal(err)
	}
	SetTestPath(path)
	defer SetTestPath(DefaultPath())
	f, err := Load(context.Background())
	if err != nil || f == nil || f.Path != path {
		t.Fatalf("Load: %v, %v", f, err)
	}
	SetTestPath("")
	if f, err := Load(context.Background()); f != nil || err != nil {
		t.Fatalf("no path: %v, %v", f, err)
	}
}
