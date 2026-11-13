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
	wantNotes := "The calls below answer within the console's policy and budgets, without a prompt.\n" +
		"They are in \"permissions.allow\" in .claude/settings.local.json (personal:\n" +
		"check that git ignores it). Remove them there to be asked again:\n\n" +
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
	in := `{"model":"opus","permissions":{"deny":["Bash(rm:*)"],"allow":["Bash(a && b <x>)","Bash(lockmq status:*)"]},"env":{"A":"1"}}`
	if err := os.WriteFile(filepath.Join(dir, "settings.local.json"), []byte(in), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := projectAllowWiring().Init(root, "claude"); err != nil {
		t.Fatal(err)
	}
	got := files(t, root)[".claude/settings.local.json"]
	want := "{\n  \"model\": \"opus\",\n  \"permissions\": {\n    \"deny\": [\n      \"Bash(rm:*)\"\n    ],\n    \"allow\": [\n      \"Bash(a && b <x>)\",\n      \"Bash(lockmq status:*)\",\n      \"mcp__lockmq__lockmq_status\"\n    ]\n  },\n  \"env\": {\n    \"A\": \"1\"\n  }\n}\n"
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
	if !strings.Contains(res.Notes, "Optional: to stop Claude Code prompting") {
		t.Fatalf("notes = %q", res.Notes)
	}
}

const foreignMCP = `{"mcpServers":{"lockmq":{"command":"sh","args":["-c","echo"]}}}`

const foreignWarning = ".mcp.json already has a \"lockmq\" server that lockmq init did not write: check what it runs before Claude Code asks you to approve it; no calls were allowed. Remove that entry and run init again to wire lockmq.\n\n"

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func status(res Result, path string) string {
	for _, a := range res.Actions {
		if a.Path == path {
			return a.Status
		}
	}
	return ""
}

// A .mcp.json entry of the product's name that init did not write is
// foreign: it is kept, nothing is allowed for it, and the notes only warn.
func TestInitClaudeAllowProjectForeignEntry(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".mcp.json"), foreignMCP)
	res, err := projectAllowWiring().Init(root, "claude")
	if err != nil {
		t.Fatal(err)
	}
	got := files(t, root)
	if got[".mcp.json"] != foreignMCP {
		t.Fatalf(".mcp.json = %q", got[".mcp.json"])
	}
	if s := status(res, ".mcp.json"); s != StatusKept {
		t.Fatalf(".mcp.json status = %q", s)
	}
	if _, ok := got[".claude/settings.local.json"]; ok {
		t.Fatal("settings.local.json written for a foreign entry")
	}
	if s := status(res, ".claude/settings.local.json"); s != "" {
		t.Fatalf("settings.local.json action = %q", s)
	}
	if res.Notes != foreignWarning {
		t.Fatalf("notes = %q", res.Notes)
	}
}

// With a foreign entry, an existing settings.local.json is left byte for
// byte.
func TestInitClaudeAllowProjectForeignEntryKeepsSettings(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".mcp.json"), foreignMCP)
	in := `{"permissions":{"allow":["Bash(ls:*)"]}}`
	writeFile(t, filepath.Join(root, ".claude", "settings.local.json"), in)
	res, err := projectAllowWiring().Init(root, "claude")
	if err != nil {
		t.Fatal(err)
	}
	if got := files(t, root)[".claude/settings.local.json"]; got != in {
		t.Fatalf("settings.local.json = %q", got)
	}
	if res.Notes != foreignWarning {
		t.Fatalf("notes = %q", res.Notes)
	}
}

// Without ClaudeAllowProject, a foreign entry gets the same warning instead
// of the optional allow list.
func TestInitClaudeForeignEntryOptional(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".mcp.json"), foreignMCP)
	res, err := testWiring.Init(root, "claude")
	if err != nil {
		t.Fatal(err)
	}
	if res.Notes != foreignWarning {
		t.Fatalf("notes = %q", res.Notes)
	}
}

// Our exact entry already in .mcp.json (unchanged) is ours: the allow list
// is still merged.
func TestInitClaudeAllowProjectOwnEntry(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".mcp.json"), `{"mcpServers":{"lockmq":{"type":"stdio","command":"lockmq","args":["mcp","--quiet"]}}}`)
	res, err := projectAllowWiring().Init(root, "claude")
	if err != nil {
		t.Fatal(err)
	}
	if s := status(res, ".mcp.json"); s != StatusUnchanged {
		t.Fatalf(".mcp.json status = %q", s)
	}
	if s := status(res, ".claude/settings.local.json"); s != StatusCreated {
		t.Fatalf("settings.local.json status = %q", s)
	}
	if !strings.Contains(files(t, root)[".claude/settings.local.json"], "mcp__lockmq__lockmq_status") {
		t.Fatal("allow list not merged")
	}
	if !strings.Contains(res.Notes, "approve it.") || !strings.Contains(res.Notes, "\"mcp__lockmq__lockmq_status\"") {
		t.Fatalf("notes = %q", res.Notes)
	}
}

// The product's ClaudeAllowNote replaces the default sentence in both
// branches; no note promises that calls never touch data.
func TestInitClaudeAllowNote(t *testing.T) {
	for _, project := range []bool{true, false} {
		for _, note := range []string{"", "Searches return masked lines only.\n"} {
			w := testWiring
			w.Assets.ClaudeAllowProject = project
			w.Assets.ClaudeAllowNote = note
			res, err := w.Init(t.TempDir(), "claude")
			if err != nil {
				t.Fatal(err)
			}
			want := defaultAllowNote
			if note != "" {
				want = "Searches return masked lines only."
			}
			intro := "approve it.\n" + want + "\n"
			if project {
				intro += "They are in \"permissions.allow\""
			} else {
				intro += "Optional: to stop"
			}
			if !strings.Contains(res.Notes, intro) {
				t.Errorf("project=%v note=%q: notes = %q", project, note, res.Notes)
			}
			if strings.Contains(res.Notes, "never touch data") {
				t.Errorf("project=%v note=%q: notes promise too much: %q", project, note, res.Notes)
			}
		}
	}
}

// E2E: a foreign entry allows nothing; once the human removes it, init
// wires the product and allows the calls.
func TestInitClaudeAllowProjectForeignThenRemoved(t *testing.T) {
	root := t.TempDir()
	mcp := filepath.Join(root, ".mcp.json")
	writeFile(t, mcp, `{"mcpServers":{"other":{"command":"x"},"lockmq":{"command":"sh","args":["-c","echo"]}}}`)
	w := projectAllowWiring()
	res, err := w.Init(root, "claude")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files(t, root)[".claude/settings.local.json"]; ok || res.Notes != foreignWarning {
		t.Fatalf("first run allowed calls: notes = %q", res.Notes)
	}

	writeFile(t, mcp, `{"mcpServers":{"other":{"command":"x"}}}`)
	res, err = w.Init(root, "claude")
	if err != nil {
		t.Fatal(err)
	}
	if s := status(res, ".mcp.json"); s != StatusUpdated {
		t.Fatalf(".mcp.json status = %q", s)
	}
	got := files(t, root)
	if !strings.Contains(got[".mcp.json"], `"lockmq": {`) || !strings.Contains(got[".mcp.json"], `"other"`) {
		t.Fatalf(".mcp.json = %q", got[".mcp.json"])
	}
	want := "{\n  \"permissions\": {\n    \"allow\": [\n      \"mcp__lockmq__lockmq_status\",\n      \"Bash(lockmq status:*)\"\n    ]\n  }\n}\n"
	if got[".claude/settings.local.json"] != want {
		t.Fatalf("settings.local.json = %q", got[".claude/settings.local.json"])
	}
	if !strings.Contains(res.Notes, "  \"mcp__lockmq__lockmq_status\",\n  \"Bash(lockmq status:*)\"\n") {
		t.Fatalf("notes = %q", res.Notes)
	}
}
