//go:build unix

package agentwire

import (
	"os"
	"path/filepath"
	"testing"
)

// A settings.local.json that is a symlink, out of the project or to the
// shared settings.json, is refused and nothing is written.
func TestInitClaudeAllowProjectRefusesSymlinks(t *testing.T) {
	for name, target := range map[string]func(t *testing.T, dir string) string{
		"out of the project": func(t *testing.T, dir string) string {
			p := filepath.Join(t.TempDir(), "elsewhere.json")
			if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
			return p
		},
		"to the shared settings": func(t *testing.T, dir string) string {
			if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"permissions":{"allow":["Read"]}}`), 0o644); err != nil {
				t.Fatal(err)
			}
			return "settings.json"
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, ".claude")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target(t, dir), filepath.Join(dir, "settings.local.json")); err != nil {
				t.Fatal(err)
			}
			if _, err := projectAllowWiring().Init(root, "claude"); err == nil {
				t.Fatal("init wrote through a symlink")
			}
			if b, err := os.ReadFile(filepath.Join(dir, "settings.json")); err == nil && string(b) != `{"permissions":{"allow":["Read"]}}` {
				t.Fatalf("shared settings changed: %s", b)
			}
			if _, err := os.Stat(filepath.Join(root, ".mcp.json")); err == nil {
				t.Fatal("a file was written")
			}
		})
	}
}
