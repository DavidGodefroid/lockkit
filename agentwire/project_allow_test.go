//go:build unix

package agentwire

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func projectAllowWiring() Wiring {
	w := testWiring
	w.Assets.ClaudeAllowProject = true
	return w
}

// A project init merges ClaudeAllow into .claude/settings.local.json, never
// into the shared .claude/settings.json; the notes say what was written.
func TestInitClaudeAllowProjectGolden(t *testing.T) {
	root := t.TempDir()
	res, err := projectAllowWiring().Init(root, "claude")
	if err != nil {
		t.Fatal(err)
	}
	got := files(t, root)
	want := "{\n  \"permissions\": {\n    \"allow\": [\n      \"mcp__lockmq__lockmq_status\",\n      \"Bash(lockmq status:*)\"\n    ]\n  }\n}\n"
	if got[".claude/settings.local.json"] != want {
		t.Fatalf("settings.local.json = %q", got[".claude/settings.local.json"])
	}
	if _, ok := got[".claude/settings.json"]; ok {
		t.Fatal("the shared settings.json was written")
	}
	wantNotes := "The calls below never touch data without the console's approval; they were added\n" +
		"to \"permissions.allow\" in .claude/settings.local.json (personal, not shared), so\n" +
		"Claude Code does not prompt for them. Remove them there to be asked again:\n\n" +
		"  \"mcp__lockmq__lockmq_status\",\n  \"Bash(lockmq status:*)\"\n\nReads are approved in the console.\n\n"
	if !strings.HasSuffix(res.Notes, wantNotes) {
		t.Fatalf("notes = %q", res.Notes)
	}
	var seen bool
	for _, a := range res.Actions {
		if a.Path == ".claude/settings.local.json" && a.Status == StatusCreated {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("actions = %+v", res.Actions)
	}
	// Idempotent.
	res, err = projectAllowWiring().Init(root, "claude")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range res.Actions {
		if a.Status != StatusUnchanged {
			t.Errorf("second run: %+v", a)
		}
	}
}

// An existing settings.local.json keeps its other keys, its own allow
// entries and their order; only the missing entries are appended.
func TestInitClaudeAllowProjectMerges(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	in := `{"model":"opus","permissions":{"deny":["Bash(rm:*)"],"allow":["Bash(ls:*)","Bash(lockmq status:*)"]},"env":{"A":"1"}}`
	if err := os.WriteFile(filepath.Join(dir, "settings.local.json"), []byte(in), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := projectAllowWiring().Init(root, "claude"); err != nil {
		t.Fatal(err)
	}
	got := files(t, root)[".claude/settings.local.json"]
	want := "{\n  \"model\": \"opus\",\n  \"permissions\": {\n    \"deny\": [\n      \"Bash(rm:*)\"\n    ],\n    \"allow\": [\n      \"Bash(ls:*)\",\n      \"Bash(lockmq status:*)\",\n      \"mcp__lockmq__lockmq_status\"\n    ]\n  },\n  \"env\": {\n    \"A\": \"1\"\n  }\n}\n"
	if got != want {
		t.Fatalf("merged = %q", got)
	}
	st, err := os.Stat(filepath.Join(dir, "settings.local.json"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v (want the file's own 0600 kept)", st.Mode(), err)
	}
}

// An invalid settings.local.json, or one that is a symlink out of the
// project, leaves the whole project untouched.
func TestInitClaudeAllowProjectRefuses(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T, dir string){
		"invalid json": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "settings.local.json"), []byte("{nope"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"allow not an array": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "settings.local.json"), []byte(`{"permissions":{"allow":"x"}}`), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"escaping symlink": func(t *testing.T, dir string) {
			outside := filepath.Join(t.TempDir(), "elsewhere.json")
			if err := os.WriteFile(outside, []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(dir, "settings.local.json")); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, ".claude")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			setup(t, dir)
			if _, err := projectAllowWiring().Init(root, "claude"); err == nil {
				t.Fatal("init accepted it")
			}
			if _, err := os.Stat(filepath.Join(root, ".mcp.json")); err == nil {
				t.Fatal("a file was written")
			}
		})
	}
}

// Off by default: the siblings' project init writes no settings file.
func TestInitClaudeAllowProjectOffByDefault(t *testing.T) {
	root := t.TempDir()
	res, err := testWiring.Init(root, "claude")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files(t, root)[".claude/settings.local.json"]; ok {
		t.Fatal("settings.local.json written without ClaudeAllowProject")
	}
	if !strings.Contains(res.Notes, "Optional: the calls below") {
		t.Fatalf("notes = %q", res.Notes)
	}
}
