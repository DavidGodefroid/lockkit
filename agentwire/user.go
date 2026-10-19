// User scope: wires agents through files under the home directory (and
// `claude mcp add --scope user`). Symlinks are followed: these are the
// human's own files, often managed as dotfiles.
package agentwire

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Env is the user account wiring works on, and how it looks for and runs
// the agents' commands.
type Env struct {
	Home     string
	Getenv   func(string) string
	LookPath func(string) (string, error)
	// Run runs a command and returns its combined output.
	Run func(name string, args ...string) ([]byte, error)
}

// SystemEnv is the current account: its home directory, environment and
// PATH.
func SystemEnv() (Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Env{}, err
	}
	return Env{
		Home: home, Getenv: os.Getenv, LookPath: exec.LookPath,
		Run: runWithTimeout(commandTimeout, commandWaitDelay),
	}, nil
}

// commandTimeout bounds every command SystemEnv runs, so a hung agent CLI
// never blocks the product.
const commandTimeout = 30 * time.Second

// commandWaitDelay bounds the wait for the output pipe once the command is
// killed or has exited: a grandchild can hold it open.
const commandWaitDelay = 2 * time.Second

// runWithTimeout runs a command and returns its combined output, killing it
// after d and giving up on its output wait later.
func runWithTimeout(d, wait time.Duration) func(string, ...string) ([]byte, error) {
	return func(n string, a ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), d)
		defer cancel()
		cmd := exec.CommandContext(ctx, n, a...)
		cmd.WaitDelay = wait
		out, err := cmd.CombinedOutput()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return out, fmt.Errorf("%s timed out after %s", n, d)
		}
		return out, err
	}
}

// dir is the directory named by envVar when it is set and absolute, else
// def under the home directory.
func (e Env) dir(envVar, def string) string {
	if v := e.Getenv(envVar); v != "" && filepath.IsAbs(v) {
		return v
	}
	return filepath.Join(e.Home, def)
}

func (e Env) has(cmds ...string) bool {
	for _, c := range cmds {
		if _, err := e.LookPath(c); err == nil {
			return true
		}
	}
	return false
}

func isDir(p string) bool { st, err := os.Stat(p); return err == nil && st.IsDir() }

// Detect lists the installed agents, in Agents() order.
func Detect(e Env) []string {
	var out []string
	if e.has("claude") {
		out = append(out, "claude")
	}
	if e.has("codex") || isDir(e.dir("CODEX_HOME", ".codex")) {
		out = append(out, "codex")
	}
	if e.has("cursor", "cursor-agent") || isDir(filepath.Join(e.Home, ".cursor")) {
		out = append(out, "cursor")
	}
	if e.has("gemini") || isDir(filepath.Join(e.Home, ".gemini")) {
		out = append(out, "gemini")
	}
	return out
}

// userBase roots a user-scope step at dir; paths display with ~ under home.
func (e Env) userBase(dir string) base {
	return base{root: dir, contained: false, display: func(rel string) string {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if r, err := filepath.Rel(e.Home, p); err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)) {
			return "~/" + filepath.ToSlash(r)
		}
		return p
	}}
}

type group struct {
	b     base
	steps []step
}

func (w Wiring) groups(e Env, agent string) ([]group, error) {
	n := w.name()
	switch agent {
	case "claude":
		cd := e.dir("CLAUDE_CONFIG_DIR", ".claude")
		steps := []step{w.plainFile("skills/"+n+"/SKILL.md", w.Assets.Skill)}
		if len(w.Assets.ClaudeAllow) > 0 {
			steps = append(steps, w.jsonStrings("settings.json", []string{"permissions", "allow"}, w.Assets.ClaudeAllow))
		}
		return []group{{e.userBase(cd), append(steps, w.claudeMCP(e))}}, nil
	case "codex":
		return []group{{e.userBase(e.dir("CODEX_HOME", ".codex")), []step{
			w.tomlTable("config.toml", "mcp_servers."+n, w.codexTable(true)),
			w.section("AGENTS.md"),
		}}}, nil
	case "cursor":
		return []group{{e.userBase(filepath.Join(e.Home, ".cursor")), []step{
			w.mcpEntry("mcp.json", w.mcpServer(nil)),
		}}}, nil
	case "gemini":
		return []group{{e.userBase(filepath.Join(e.Home, ".gemini")), []step{
			w.mcpEntry("settings.json", w.mcpServer(map[string]any{"timeout": 600000})),
			w.section("GEMINI.md"),
		}}}, nil
	}
	return nil, fmt.Errorf("unknown agent %q (want one of %s)", agent, strings.Join(Agents(), ", "))
}

// wired reports whether agent counts as wired without looking at its
// other steps. Claude Code is wired once its user MCP entry and the skill
// exist: the permissions are merged only on a run that wires it, so an
// entry the human removed from permissions.allow stays removed.
func (w Wiring) wired(e Env, agent string) bool {
	if agent != "claude" {
		return false
	}
	skill := filepath.Join(e.dir("CLAUDE_CONFIG_DIR", ".claude"), "skills", w.name(), "SKILL.md")
	_, err := os.Stat(skill)
	return err == nil && w.claudeUserMCP(e)
}

// InitUser wires agent for the current account, in every project.
func (w Wiring) InitUser(e Env, agent string) (Result, error) {
	if err := w.check(); err != nil {
		return Result{}, err
	}
	if w.wired(e, agent) {
		return Result{}, nil
	}
	gs, err := w.groups(e, agent)
	if err != nil {
		return Result{}, err
	}
	var res Result
	for _, g := range gs {
		acts, _, err := w.apply(g.b, g.steps, false, e.Run)
		res.Actions = append(res.Actions, acts...)
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

// PendingUser reports whether InitUser would write or run anything.
func (w Wiring) PendingUser(e Env, agent string) (bool, error) {
	if err := w.check(); err != nil {
		return false, err
	}
	if w.wired(e, agent) {
		return false, nil
	}
	gs, err := w.groups(e, agent)
	if err != nil {
		return false, err
	}
	for _, g := range gs {
		_, pending, err := w.apply(g.b, g.steps, true, e.Run)
		if err != nil || pending {
			return pending, err
		}
	}
	return false, nil
}

// Unwired lists the installed agents and, among them, those InitUser would
// still wire (or cannot check): the doctor's "agent wiring" finding.
func (w Wiring) Unwired(e Env) (found, pending []string) {
	found = Detect(e)
	for _, a := range found {
		if p, err := w.PendingUser(e, a); err != nil || p {
			pending = append(pending, a)
		}
	}
	return found, pending
}

// tomlTable appends block to a TOML file unless key (dotted) is already
// defined, as a table or inline. An unparsable file is an error.
func (w Wiring) tomlTable(rel, key, block string) step {
	n := w.name()
	return func(b base) (change, error) {
		target, data, mode, exists, err := read(b, rel)
		if err != nil {
			return change{}, err
		}
		c := change{rel: rel, target: target, mode: mode, action: Action{Path: b.display(rel)}}
		var m map[string]any
		if exists {
			md, err := toml.Decode(string(data), &m)
			if err != nil {
				return change{}, fmt.Errorf("%s: not valid TOML; fix it or add the %s server by hand", b.display(rel), n)
			}
			if md.IsDefined(strings.Split(key, ".")...) {
				c.action.Status = StatusUnchanged
				return c, nil
			}
		}
		s := string(data)
		if s != "" && !strings.HasSuffix(s, "\n") {
			s += "\n"
		}
		if s != "" {
			s += "\n"
		}
		// The block can still clash with what is there, such as an inline
		// mcp_servers table, which the TOML spec forbids extending (and Codex
		// rejects) while BurntSushi/toml accepts it: never write a file Codex
		// could not read.
		var check map[string]any
		if _, err := toml.Decode(s+block, &check); err != nil || assignsPrefix(data, key) {
			return change{}, fmt.Errorf("%s: adding [%s] would not be valid TOML; fix it or add the %s server by hand", b.display(rel), key, n)
		}
		c.content = []byte(s + block)
		c.action.Status = StatusCreated
		if exists {
			c.action.Status = StatusUpdated
		}
		return c, nil
	}
}

// assignsPrefix reports whether a TOML document assigns a value, such as an
// inline table, to a proper prefix of the dotted key, at the root (before
// the first table header). Such a table cannot be extended by a
// [key] header. A match inside a multi-line string errs on the side of
// refusing.
func assignsPrefix(doc []byte, key string) bool {
	parts := strings.Split(key, ".")
	var alts []string
	for i := 1; i < len(parts); i++ {
		var ps []string
		for _, p := range parts[:i] {
			q := regexp.QuoteMeta(p)
			ps = append(ps, `(?:`+q+`|"`+q+`"|'`+q+`')`)
		}
		alts = append(alts, strings.Join(ps, `\s*\.\s*`))
	}
	if alts == nil {
		return false
	}
	re := regexp.MustCompile(`^\s*(?:` + strings.Join(alts, "|") + `)\s*=`)
	for _, line := range strings.Split(string(doc), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "[") {
			return false
		}
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// jsonStrings adds the missing items to the string array at path in a JSON
// object file, keeping every other key in its place.
func (w Wiring) jsonStrings(rel string, path []string, items []string) step {
	n := w.name()
	return func(b base) (change, error) {
		target, data, mode, exists, err := read(b, rel)
		if err != nil {
			return change{}, err
		}
		c := change{rel: rel, target: target, mode: mode, action: Action{Path: b.display(rel)}}
		bad := fmt.Errorf("%s: %s is not an object holding an array of strings; fix it or add the %s entries by hand", b.display(rel), strings.Join(path, "."), n)
		var top, parent orderedObject
		if exists && len(bytes.TrimSpace(data)) > 0 {
			if err := json.Unmarshal(data, &top); err != nil {
				return change{}, fmt.Errorf("%s: not a JSON object (%v); fix it or add the %s entries by hand", b.display(rel), err, n)
			}
		}
		if raw, ok := top.get(path[0]); ok && string(bytes.TrimSpace(raw)) != "null" {
			if err := json.Unmarshal(raw, &parent); err != nil {
				return change{}, bad
			}
		}
		var have []string
		if raw, ok := parent.get(path[1]); ok && string(bytes.TrimSpace(raw)) != "null" {
			if err := json.Unmarshal(raw, &have); err != nil {
				return change{}, bad
			}
		}
		added := false
		for _, it := range items {
			if !slices.Contains(have, it) {
				have, added = append(have, it), true
			}
		}
		if !added {
			c.action.Status = StatusUnchanged
			return c, nil
		}
		arr, err := json.Marshal(have)
		if err != nil {
			return change{}, err
		}
		parent.set(path[1], arr)
		pj, err := json.Marshal(&parent)
		if err != nil {
			return change{}, err
		}
		top.set(path[0], pj)
		out, err := json.MarshalIndent(&top, "", "  ")
		if err != nil {
			return change{}, err
		}
		c.content = append(out, '\n')
		c.action.Status = StatusCreated
		if exists {
			c.action.Status = StatusUpdated
		}
		return c, nil
	}
}

// claudeMCP registers the user-scope MCP server through Claude Code's own
// CLI, which owns .claude.json. Whether it is already there is read from
// that file, never asked of the CLI: `claude mcp get` starts the server to
// check it, and matches an entry of any scope.
func (w Wiring) claudeMCP(e Env) step {
	return func(b base) (change, error) {
		c := change{action: Action{Path: fmt.Sprintf("user MCP server %q", w.name())}}
		if w.claudeUserMCP(e) {
			c.action.Status = StatusUnchanged
			return c, nil
		}
		c.exec = append([]string{"claude", "mcp", "add", "--scope", "user", w.name(), "--"}, w.Assets.MCPCommand...)
		c.action.Status = StatusCreated
		return c, nil
	}
}

// claudeUserMCP reports whether Claude Code's .claude.json holds a
// user-scope server of the product: a top-level mcpServers.<name> key.
// Entries under "projects" are other scopes. A missing or unparsable file
// counts as not wired. The file is only read.
func (w Wiring) claudeUserMCP(e Env) bool {
	p := filepath.Join(e.Home, ".claude.json")
	if v := e.Getenv("CLAUDE_CONFIG_DIR"); v != "" && filepath.IsAbs(v) {
		p = filepath.Join(v, ".claude.json")
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	var cj struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if json.Unmarshal(data, &cj) != nil {
		return false
	}
	_, ok := cj.MCPServers[w.name()]
	return ok
}
