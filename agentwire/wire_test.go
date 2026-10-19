//go:build unix

package agentwire

import (
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/BurntSushi/toml"

	"github.com/DavidGodefroid/lockkit/kit"
)

var testWiring = Wiring{
	Product: kit.Product{Name: "lockmq", Account: "lockmq", ClientsGroup: "lockmq-clients", KeychainService: "lockmq", EnvPrefix: "LOCKMQ_"},
	Assets: Assets{
		MCPCommand:        []string{"lockmq", "mcp", "--quiet"},
		Skill:             []byte("---\nname: lockmq\n---\nskill\n"),
		Instructions:      []byte("Use lockmq_status first.\n"),
		CursorFrontMatter: []byte("---\nalwaysApply: false\n---\n"),
		ProjectConfig:     []byte("# example\n"),
		ClaudeAllow:       []string{"mcp__lockmq__lockmq_status", "Bash(lockmq status:*)"},
		ClaudeNote:        "Reads are approved in the console.",
	},
}

func files(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			out[filepath.ToSlash(rel)] = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestInitNamesEverythingAfterTheProduct(t *testing.T) {
	root := t.TempDir()
	notes := map[string]string{}
	for _, a := range Agents() {
		res, err := testWiring.Init(root, a)
		if err != nil {
			t.Fatalf("%s: %v", a, err)
		}
		notes[a] = res.Notes
	}
	got := files(t, root)
	want := []string{".claude/skills/lockmq/SKILL.md", ".cursor/mcp.json", ".cursor/rules/lockmq.mdc", ".gemini/settings.json",
		".lockmq/config.toml", ".mcp.json", "AGENTS.md", "GEMINI.md"}
	var names []string
	for k := range got {
		names = append(names, k)
	}
	slices.Sort(names)
	if !slices.Equal(names, want) {
		t.Fatalf("files = %v", names)
	}
	var mcp struct {
		MCPServers map[string]map[string]any `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(got[".mcp.json"]), &mcp); err != nil {
		t.Fatal(err)
	}
	if s := mcp.MCPServers["lockmq"]; s["command"] != "lockmq" || s["type"] != "stdio" || len(s["args"].([]any)) != 2 {
		t.Fatalf(".mcp.json = %s", got[".mcp.json"])
	}
	if !strings.HasPrefix(got["AGENTS.md"], "<!-- lockmq:begin -->\nUse lockmq_status first.\n<!-- lockmq:end -->") {
		t.Fatalf("AGENTS.md = %q", got["AGENTS.md"])
	}
	if got[".cursor/rules/lockmq.mdc"] != "---\nalwaysApply: false\n---\nUse lockmq_status first.\n" {
		t.Fatalf("cursor rule = %q", got[".cursor/rules/lockmq.mdc"])
	}
	if !strings.Contains(got[".gemini/settings.json"], `"timeout": 600000`) {
		t.Fatalf("gemini = %s", got[".gemini/settings.json"])
	}
	if !strings.Contains(notes["claude"], `"mcp__lockmq__lockmq_status",`+"\n"+`  "Bash(lockmq status:*)"`+"\n\nReads are approved in the console.\n\n") {
		t.Fatalf("claude notes = %q", notes["claude"])
	}
	if !strings.Contains(notes["codex"], "[mcp_servers.lockmq]\ncommand = \"lockmq\"\nargs = [\"mcp\", \"--quiet\"]\ntool_timeout_sec = 600\n") ||
		!strings.HasPrefix(notes["codex"], "lockmq init writes") {
		t.Fatalf("codex notes = %q", notes["codex"])
	}
	for name, body := range got {
		if strings.Contains(body, "locksql") {
			t.Errorf("%s names locksql", name)
		}
	}
	// Idempotent.
	before := files(t, root)
	for _, a := range Agents() {
		res, err := testWiring.Init(root, a)
		if err != nil {
			t.Fatal(err)
		}
		for _, act := range res.Actions {
			if act.Status != StatusUnchanged {
				t.Errorf("%s second run: %+v", a, act)
			}
		}
	}
	if after := files(t, root); len(after) != len(before) {
		t.Fatal("second run changed files")
	}
}

func TestInitWithoutProjectConfig(t *testing.T) {
	w := testWiring
	w.Assets.ProjectConfig = nil
	root := t.TempDir()
	if _, err := w.Init(root, "codex"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ".lockmq")); err == nil {
		t.Fatal("config written without a template")
	}
}

func TestInitRefusesBadWiring(t *testing.T) {
	w := testWiring
	w.Assets.MCPCommand = nil
	if _, err := w.Init(t.TempDir(), "claude"); err == nil {
		t.Fatal("empty MCP command accepted")
	}
	w = testWiring
	w.Product.Name = "Bad Name"
	if _, err := w.InitUser(Env{}, "claude"); err == nil {
		t.Fatal("invalid product accepted")
	}
}

func fakeEnv(t *testing.T, onPath ...string) (Env, *[][]string) {
	t.Helper()
	home := t.TempDir()
	var calls [][]string
	e := Env{
		Home:   home,
		Getenv: func(string) string { return "" },
		LookPath: func(n string) (string, error) {
			if slices.Contains(onPath, n) {
				return "/usr/bin/" + n, nil
			}
			return "", exec.ErrNotFound
		},
		Run: func(n string, a ...string) ([]byte, error) {
			calls = append(calls, append([]string{n}, a...))
			return nil, os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers":{"lockmq":{}}}`), 0o600)
		},
	}
	return e, &calls
}

func TestInitUserAndUnwired(t *testing.T) {
	e, calls := fakeEnv(t, "claude", "codex")
	found, pending := testWiring.Unwired(e)
	if !slices.Equal(found, []string{"claude", "codex"}) || !slices.Equal(pending, found) {
		t.Fatalf("Unwired = %v %v", found, pending)
	}
	for _, a := range found {
		if _, err := testWiring.InitUser(e, a); err != nil {
			t.Fatalf("%s: %v", a, err)
		}
	}
	if want := []string{"claude", "mcp", "add", "--scope", "user", "lockmq", "--", "lockmq", "mcp", "--quiet"}; len(*calls) != 1 || !slices.Equal((*calls)[0], want) {
		t.Fatalf("calls = %v", *calls)
	}
	got := files(t, e.Home)
	if !strings.Contains(got[".claude/settings.json"], "mcp__lockmq__lockmq_status") || got[".claude/skills/lockmq/SKILL.md"] == "" {
		t.Fatalf("claude files = %v", got)
	}
	var m map[string]any
	if _, err := toml.Decode(got[".codex/config.toml"], &m); err != nil || !strings.Contains(got[".codex/config.toml"], "[mcp_servers.lockmq]") {
		t.Fatalf("codex config = %q (%v)", got[".codex/config.toml"], err)
	}
	if _, pending := testWiring.Unwired(e); len(pending) != 0 {
		t.Fatalf("still pending: %v", pending)
	}
}

func TestErrorsNameTheProduct(t *testing.T) {
	e, _ := fakeEnv(t, "codex")
	os.MkdirAll(filepath.Join(e.Home, ".codex"), 0o755)
	os.WriteFile(filepath.Join(e.Home, ".codex", "config.toml"), []byte("mcp_servers = { other = { command = \"x\" } }\n"), 0o644)
	_, err := testWiring.InitUser(e, "codex")
	if err == nil || err.Error() != "~/.codex/config.toml: adding [mcp_servers.lockmq] would not be valid TOML; fix it or add the lockmq server by hand" {
		t.Fatalf("err = %v", err)
	}
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(`{"mcpServers":{"lockmq":{"command":"mine"}}}`), 0o644)
	res, err := testWiring.Init(root, "claude")
	if err != nil || res.Actions[0].Status != StatusKept || res.Actions[0].Detail != "already has a lockmq server entry of its own" {
		t.Fatalf("Init = %+v %v", res, err)
	}
}

func TestTOMLString(t *testing.T) {
	for in, want := range map[string]string{"mcp": `"mcp"`, `a"b\c`: `"a\"b\\c"`, "x\ny": `"x\u000Ay"`, "é": `"é"`} {
		got := tomlString(in)
		if got != want {
			t.Errorf("%q: got %s want %s", in, got, want)
		}
		var v struct{ S string }
		if _, err := toml.Decode("S = "+got, &v); err != nil || v.S != in {
			t.Errorf("%q does not round-trip: %v %q", in, err, v.S)
		}
	}
}

func TestAssignsPrefix(t *testing.T) {
	for doc, want := range map[string]bool{
		"mcp_servers = { other = { command = \"x\" } }\n": true,
		"  \"mcp_servers\" = {}\n":                        true,
		"mcp_servers = 3\n":                               true,
		"mcp_servers.other = { command = \"x\" }\n":       false,
		"[mcp_servers.other]\ncommand = \"x\"\n":          false,
		"[x]\nmcp_servers = {}\n":                         false,
		"model = \"o3\"\n":                                false,
	} {
		if got := assignsPrefix([]byte(doc), "mcp_servers.lockmq"); got != want {
			t.Errorf("%q: got %v", doc, got)
		}
	}
}

func TestFirstLineSanitises(t *testing.T) {
	got := firstLine([]byte("\n\x1b[31mError:\x1b[0m bad\x07 thing\r\nmore"))
	if got != "Error: bad thing" {
		t.Fatalf("firstLine = %q", got)
	}
	long := strings.Repeat("é", 150) // 300 bytes
	got = firstLine([]byte(long))
	if len(got) > 200 || !utf8.ValidString(got) {
		t.Fatalf("cut: %d bytes, valid %v", len(got), utf8.ValidString(got))
	}
}

func TestSystemRunTimesOut(t *testing.T) {
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("no sleep command")
	}
	_, err := runWithTimeout(50*time.Millisecond, time.Second)("sleep", "5")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v", err)
	}
}

func TestSystemRunBoundWithGrandchild(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	start := time.Now()
	// The grandchild keeps the output pipe open after sh is killed.
	_, err := runWithTimeout(50*time.Millisecond, 100*time.Millisecond)("sh", "-c", "sleep 10 & sleep 10")
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("err = %v after %s", err, time.Since(start))
	}
}
