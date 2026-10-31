// Package agentwire connects coding agents (Claude Code, Codex, Cursor,
// Gemini CLI) to a product's MCP server: in one project (`<name> init
// <agent>`) or for the user's account in every project (bare `<name>`,
// `<name> doctor --fix`). The product supplies its texts and its MCP
// command (Assets); agentwire owns the file mechanics.
//
// It never overwrites a file the human may have edited: an existing skill
// or rule is kept, an MCP config gets the product's entry merged in (other
// servers and keys are kept), and a Markdown instructions file gets one
// marked section appended. Running it again changes nothing. Every change
// is computed and checked before the first write. In a project every path
// is resolved through symlinks and refused if it leaves the project; in the
// user scope symlinks are followed (dotfiles) but a file of another account
// is never replaced.
package agentwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/kit"
)

// Action statuses.
const (
	StatusCreated   = "created"   // the file did not exist
	StatusUpdated   = "updated"   // the product's entry was merged into an existing file
	StatusUnchanged = "unchanged" // the file already holds the product's content
	StatusKept      = "kept"      // the file differs and was left as the human wrote it
)

// Action reports what wiring did to one file.
type Action struct {
	Path   string // slash-separated, relative to the project root (or ~/... in the user scope)
	Status string
	Detail string // why a file was kept, when it was
}

// Result is the outcome of a wiring.
type Result struct {
	Root    string
	Actions []Action
	Notes   string // agent-specific steps for the human, such as a global file to edit
}

// Assets are a product's texts and command. agentwire writes them as they
// are.
type Assets struct {
	// MCPCommand starts the product's MCP server ({"lockmq", "mcp"}).
	MCPCommand []string
	// Skill is the Claude Code skill (skills/<name>/SKILL.md).
	Skill []byte
	// Instructions are the shared agent instructions: the marked section of
	// AGENTS.md and GEMINI.md, and the body of the Cursor rule.
	Instructions []byte
	// CursorFrontMatter starts the Cursor rule (.cursor/rules/<name>.mdc).
	CursorFrontMatter []byte
	// ProjectConfig is the commented example .<name>/config.toml a project
	// init creates when there is none; nil creates none.
	ProjectConfig []byte
	// ClaudeAllow are the calls merged into Claude Code's
	// permissions.allow at user scope, and listed in the project notes:
	// only calls that never touch data without the console's approval.
	ClaudeAllow []string
	// ClaudeAllowProject also merges ClaudeAllow into the project's
	// .claude/settings.local.json (personal, not the shared
	// .claude/settings.json) on a project init: for a product whose listed
	// calls only ever see masked data.
	ClaudeAllowProject bool
	// ClaudeNote ends the Claude Code notes of a project init (optional).
	ClaudeNote string
}

// Wiring wires agents to one product.
type Wiring struct {
	Product kit.Product
	Assets  Assets
}

// Agents returns the supported agent names.
func Agents() []string { return []string{"claude", "codex", "cursor", "gemini"} }

// ProjectRoot returns the directory a project init writes to: the nearest
// ancestor of cwd holding .<name>/config.toml, else the nearest one holding
// .git, else cwd itself.
func ProjectRoot(p kit.Product, cwd string) string {
	abs, err := filepath.Abs(cwd)
	if err != nil {
		abs = filepath.Clean(cwd)
	}
	if root, ok := config.FindProjectRoot(p, abs); ok {
		return root
	}
	for dir := abs; ; {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return abs
		}
		dir = parent
	}
}

// name is the product's MCP server name and file stem.
func (w Wiring) name() string { return w.Product.Name }

func (w Wiring) sectionBegin() string { return "<!-- " + w.name() + ":begin -->" }
func (w Wiring) sectionEnd() string   { return "<!-- " + w.name() + ":end -->" }

// mcpServer is the JSON MCP entry: command and args, plus extra keys.
func (w Wiring) mcpServer(extra map[string]any) map[string]any {
	m := map[string]any{"command": w.Assets.MCPCommand[0], "args": append([]string{}, w.Assets.MCPCommand[1:]...)}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func (w Wiring) check() error {
	if err := w.Product.Validate(); err != nil {
		return err
	}
	if len(w.Assets.MCPCommand) == 0 || w.Assets.MCPCommand[0] == "" {
		return errors.New("agentwire: Assets.MCPCommand is empty")
	}
	return nil
}

// base is where a set of steps writes: a root directory, whether every
// path must stay inside it, and how a relative path is shown to the human.
type base struct {
	root      string
	contained bool
	display   func(rel string) string
}

// change is one planned file write, or one command to run.
type change struct {
	rel     string
	target  string // resolved absolute path
	content []byte // nil when nothing is written
	mode    fs.FileMode
	exec    []string // a command apply runs after the file writes, instead of writing a file
	action  Action
}

type step func(base) (change, error)

// Init writes the integration files of agent into the project at root.
// An invalid existing file or an escaping symlink leaves the project
// untouched.
func (w Wiring) Init(root, agent string) (Result, error) {
	if err := w.check(); err != nil {
		return Result{}, err
	}
	n := w.name()
	var steps []step
	var notes string
	switch agent {
	case "claude":
		steps = []step{
			w.mcpEntry(".mcp.json", w.mcpServer(map[string]any{"type": "stdio"})),
			w.plainFile(".claude/skills/"+n+"/SKILL.md", w.Assets.Skill),
		}
		if w.Assets.ClaudeAllowProject && len(w.Assets.ClaudeAllow) > 0 {
			steps = append(steps, w.localSettings(w.jsonStrings(".claude/settings.local.json", []string{"permissions", "allow"}, w.Assets.ClaudeAllow)))
		}
		notes = w.claudeNotes()
	case "codex":
		steps = []step{w.section("AGENTS.md")}
		notes = w.codexNotes()
	case "cursor":
		steps = []step{
			w.mcpEntry(".cursor/mcp.json", w.mcpServer(nil)),
			w.plainFile(".cursor/rules/"+n+".mdc", w.cursorRule()),
		}
		notes = w.cursorNotes()
	case "gemini":
		steps = []step{
			// Gemini CLI's timeout is in milliseconds; it must cover the
			// console's 5 minute approval timeout.
			w.mcpEntry(".gemini/settings.json", w.mcpServer(map[string]any{"timeout": 600000})),
			w.section("GEMINI.md"),
		}
	default:
		return Result{}, fmt.Errorf("unknown agent %q (want one of %s)", agent, strings.Join(Agents(), ", "))
	}
	if w.Assets.ProjectConfig != nil {
		steps = append(steps, w.configIfAbsent(w.Product.ProjectDir()+"/config.toml"))
	}

	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return Result{}, fmt.Errorf("project root: %w", err)
	}
	realRoot, err = filepath.Abs(realRoot)
	if err != nil {
		return Result{}, fmt.Errorf("project root: %w", err)
	}
	b := base{root: realRoot, contained: true, display: func(r string) string { return r }}
	acts, _, err := w.apply(b, steps, false, nil)
	if err != nil && acts == nil { // a step failed: nothing was written
		return Result{}, err
	}
	return Result{Root: root, Actions: acts, Notes: notes}, err
}

// apply computes every change of steps, then, unless dry, writes the files
// and runs the commands, in that order. It returns the actions and whether
// anything would be (or was) written or run. A step error leaves everything
// untouched; after a write or command error, the actions of the changes
// already made are returned with it.
func (w Wiring) apply(b base, steps []step, dry bool, run func(string, ...string) ([]byte, error)) ([]Action, bool, error) {
	changes := make([]change, 0, len(steps))
	pending := false
	for _, st := range steps {
		c, err := st(b)
		if err != nil {
			return nil, false, err
		}
		if c.content != nil || c.exec != nil {
			pending = true
		}
		if c.content != nil && !b.contained {
			// The user scope writes into the human's own dotfiles: never
			// replace a file of another account, which a rename in a
			// writable directory would do.
			if err := writable(c.target, b.display(c.rel), w.name()); err != nil {
				return nil, false, err
			}
		}
		changes = append(changes, c)
	}
	if dry {
		acts := make([]Action, 0, len(changes))
		for _, c := range changes {
			acts = append(acts, c.action)
		}
		return acts, pending, nil
	}

	done := make([]bool, len(changes))
	made := func() []Action {
		acts := []Action{}
		for i, c := range changes {
			if done[i] {
				acts = append(acts, c.action)
			}
		}
		return acts
	}
	for i, c := range changes {
		if c.exec != nil {
			continue
		}
		if c.content != nil {
			if err := writeAtomic(c.target, c.content, c.mode, "."+w.name()+"-init-*"); err != nil {
				return made(), pending, fmt.Errorf("%s: %w", b.display(c.rel), err)
			}
		}
		done[i] = true
	}
	for i, c := range changes {
		if c.exec == nil {
			continue
		}
		if out, err := run(c.exec[0], c.exec[1:]...); err != nil {
			msg := firstLine(out)
			if msg == "" {
				msg = err.Error()
			}
			return made(), pending, fmt.Errorf("%s failed: %s", strings.Join(c.exec[:min(3, len(c.exec))], " "), msg)
		}
		done[i] = true
	}
	return made(), pending, nil
}

// ansiRe matches terminal escape sequences (CSI and OSC).
var ansiRe = regexp.MustCompile(`\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?|[@-_])`)

// firstLine returns the first non-empty line of out, without escape
// sequences or control characters, cut to at most 200 bytes on a rune
// boundary. It relays another program's output to the human's terminal.
func firstLine(out []byte) string {
	clean := ansiRe.ReplaceAllString(strings.ToValidUTF8(string(out), ""), "")
	for _, l := range strings.Split(clean, "\n") {
		l = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				return -1
			}
			return r
		}, l)
		if l = strings.TrimSpace(l); l != "" {
			for len(l) > 200 {
				_, size := utf8.DecodeLastRuneInString(l)
				l = l[:len(l)-size]
			}
			return l
		}
	}
	return ""
}

// resolve maps rel to an absolute path under b.root, following symlinks of
// every existing component. When b is contained, a path that leaves the
// root is refused.
func resolve(b base, rel string) (string, error) {
	p := filepath.Join(b.root, filepath.FromSlash(rel))
	existing, rest := p, ""
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("%s: %w", rel, err)
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return "", fmt.Errorf("%s: no existing ancestor", rel)
		}
		rest = filepath.Join(filepath.Base(existing), rest)
		existing = parent
	}
	real, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", fmt.Errorf("%s: %w", rel, err)
	}
	target := filepath.Join(real, rest)
	if !b.contained {
		return target, nil
	}
	r, err := filepath.Rel(b.root, target)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) || filepath.IsAbs(r) {
		return "", fmt.Errorf("%s: resolves outside the project (%s); refusing to write there", rel, target)
	}
	return target, nil
}

// read resolves rel and returns its content, or nil when it does not exist.
func read(b base, rel string) (target string, data []byte, mode fs.FileMode, exists bool, err error) {
	target, err = resolve(b, rel)
	if err != nil {
		return "", nil, 0, false, err
	}
	st, err := os.Stat(target)
	if errors.Is(err, fs.ErrNotExist) {
		return target, nil, 0o644, false, nil
	}
	if err != nil {
		return "", nil, 0, false, fmt.Errorf("%s: %w", rel, err)
	}
	if !st.Mode().IsRegular() {
		return "", nil, 0, false, fmt.Errorf("%s: not a regular file", rel)
	}
	data, err = os.ReadFile(target)
	if err != nil {
		return "", nil, 0, false, fmt.Errorf("%s: %w", rel, err)
	}
	return target, data, st.Mode().Perm(), true, nil
}

// plainFile creates rel with want. An existing file is unchanged when it
// already matches, and kept otherwise.
func (w Wiring) plainFile(rel string, want []byte) step {
	return func(b base) (change, error) {
		target, data, mode, exists, err := read(b, rel)
		if err != nil {
			return change{}, err
		}
		c := change{rel: rel, target: target, mode: mode, action: Action{Path: b.display(rel)}}
		switch {
		case !exists:
			c.content, c.action.Status = want, StatusCreated
		case bytes.Equal(data, want):
			c.action.Status = StatusUnchanged
		default:
			c.action.Status = StatusKept
			c.action.Detail = "differs from the template; delete it and run init again to regenerate it"
		}
		return c, nil
	}
}

// cursorRule is the Cursor rule: its front matter plus the shared
// instructions.
func (w Wiring) cursorRule() []byte {
	return append(append([]byte{}, w.Assets.CursorFrontMatter...), w.Assets.Instructions...)
}

// configIfAbsent creates the commented example project config. Any existing
// config is the human's and is left alone.
func (w Wiring) configIfAbsent(rel string) step {
	return func(b base) (change, error) {
		target, _, mode, exists, err := read(b, rel)
		if err != nil {
			return change{}, err
		}
		c := change{rel: rel, target: target, mode: mode, action: Action{Path: b.display(rel), Status: StatusUnchanged}}
		if !exists {
			c.content, c.action.Status = w.Assets.ProjectConfig, StatusCreated
		}
		return c, nil
	}
}

// section appends the shared instructions to a Markdown file, once,
// between markers.
func (w Wiring) section(rel string) step {
	return func(b base) (change, error) {
		target, data, mode, exists, err := read(b, rel)
		if err != nil {
			return change{}, err
		}
		block := w.sectionBegin() + "\n" + string(w.Assets.Instructions) + w.sectionEnd() + "\n"
		c := change{rel: rel, target: target, mode: mode, action: Action{Path: b.display(rel)}}
		switch {
		case !exists || len(bytes.TrimSpace(data)) == 0:
			c.content, c.action.Status = []byte(block), StatusCreated
			if exists {
				c.action.Status = StatusUpdated
			}
		case bytes.Contains(data, []byte(w.sectionBegin())):
			c.action.Status = StatusUnchanged
		default:
			s := string(data)
			if !strings.HasSuffix(s, "\n") {
				s += "\n"
			}
			c.content, c.action.Status = []byte(s+"\n"+block), StatusUpdated
		}
		return c, nil
	}
}

// mcpEntry merges mcpServers.<name> into a JSON MCP config, keeping every
// other key in its place. An existing entry of the product is never
// replaced.
func (w Wiring) mcpEntry(rel string, entry map[string]any) step {
	n := w.name()
	return func(b base) (change, error) {
		target, data, mode, exists, err := read(b, rel)
		if err != nil {
			return change{}, err
		}
		c := change{rel: rel, target: target, mode: mode, action: Action{Path: b.display(rel)}}
		entryJSON, err := json.Marshal(entry)
		if err != nil {
			return change{}, err
		}
		var top orderedObject
		if exists && len(bytes.TrimSpace(data)) > 0 {
			if err := json.Unmarshal(data, &top); err != nil {
				return change{}, fmt.Errorf("%s: not a JSON object (%v); fix it or add the %s server by hand", b.display(rel), err, n)
			}
		}
		var servers orderedObject
		if raw, ok := top.get("mcpServers"); ok && string(bytes.TrimSpace(raw)) != "null" {
			if err := json.Unmarshal(raw, &servers); err != nil {
				return change{}, fmt.Errorf("%s: mcpServers is not a JSON object; fix it or add the %s server by hand", b.display(rel), n)
			}
		}
		if cur, ok := servers.get(n); ok {
			if jsonEqual(cur, entryJSON) {
				c.action.Status = StatusUnchanged
			} else {
				c.action.Status = StatusKept
				c.action.Detail = "already has a " + n + " server entry of its own"
			}
			return c, nil
		}
		servers.set(n, entryJSON)
		sj, err := json.Marshal(&servers)
		if err != nil {
			return change{}, err
		}
		top.set("mcpServers", sj)
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

func jsonEqual(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return bytes.Equal(xa, ya)
}

// orderedObject is a JSON object that keeps its key order.
type orderedObject struct {
	keys []string
	vals map[string]json.RawMessage
}

func (o *orderedObject) get(k string) (json.RawMessage, bool) {
	v, ok := o.vals[k]
	return v, ok
}

func (o *orderedObject) set(k string, v json.RawMessage) {
	if o.vals == nil {
		o.vals = map[string]json.RawMessage{}
	}
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

func (o *orderedObject) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("expected an object")
	}
	*o = orderedObject{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return errors.New("expected an object key")
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return err
		}
		o.set(key, v)
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	if _, err := dec.Token(); err == nil {
		return errors.New("trailing data after the object")
	}
	return nil
}

func (o *orderedObject) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(o.vals[k])
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// writeAtomic writes data to path through a temporary file (named after
// pattern) in the same directory, so a crash never leaves a half-written
// config.
func writeAtomic(path string, data []byte, mode fs.FileMode, pattern string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// localSettings guards the project's personal settings step: a
// settings.local.json that is a symlink (to the shared settings.json or
// anywhere else) is refused, so the shared file is never written.
func (w Wiring) localSettings(st step) step {
	return func(b base) (change, error) {
		rel := ".claude/settings.local.json"
		p := filepath.Join(b.root, filepath.FromSlash(rel))
		if fi, err := os.Lstat(p); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
			return change{}, fmt.Errorf("%s: a symlink; refusing to write through it (add the %s entries by hand)", rel, w.name())
		}
		c, err := st(b)
		if err != nil {
			return c, err
		}
		if shared, err := resolve(b, ".claude/settings.json"); err == nil && shared == c.target {
			return change{}, fmt.Errorf("%s: resolves to the shared .claude/settings.json; refusing", rel)
		}
		return c, nil
	}
}

// claudeNotes lists the calls the human may allow, then ClaudeNote.
func (w Wiring) claudeNotes() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Claude Code asks once whether to use the project MCP server %q; approve it.\n", w.name())
	if len(w.Assets.ClaudeAllow) > 0 && w.Assets.ClaudeAllowProject {
		b.WriteString("The calls below never touch data without the console's approval; they are in\n" +
			"\"permissions.allow\" in .claude/settings.local.json (personal: check that git\n" +
			"ignores it), so Claude Code does not prompt for them. Remove them there to be\n" +
			"asked again:\n\n")
		for i, a := range w.Assets.ClaudeAllow {
			q, _ := json.Marshal(a)
			b.WriteString("  " + string(q))
			if i < len(w.Assets.ClaudeAllow)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
	} else if len(w.Assets.ClaudeAllow) > 0 {
		b.WriteString("Optional: the calls below never touch data without the console's approval. To stop\n" +
			"Claude Code prompting for them, add them to \"permissions.allow\" in\n" +
			".claude/settings.local.json (personal) or .claude/settings.json (shared):\n\n")
		for i, a := range w.Assets.ClaudeAllow {
			q, _ := json.Marshal(a)
			b.WriteString("  " + string(q))
			if i < len(w.Assets.ClaudeAllow)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
	}
	b.WriteString("\n")
	if w.Assets.ClaudeNote != "" {
		b.WriteString(w.Assets.ClaudeNote)
		if !strings.HasSuffix(w.Assets.ClaudeNote, "\n") {
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func (w Wiring) codexNotes() string {
	return w.name() + " init writes no file outside the project. To give Codex the MCP tools,\n" +
		"add this to ~/.codex/config.toml (tool_timeout_sec covers the console's\n" +
		"5 minute approval timeout):\n\n" +
		w.codexTable(false) + "\n"
}

func (w Wiring) cursorNotes() string {
	return "Enable the \"" + w.name() + "\" server in Cursor's MCP settings if Cursor asks.\n\n"
}

// codexTable is the [mcp_servers.<name>] table of Codex's config.toml;
// commented explains its timeout.
func (w Wiring) codexTable(commented bool) string {
	args := make([]string, 0, len(w.Assets.MCPCommand)-1)
	for _, a := range w.Assets.MCPCommand[1:] {
		args = append(args, tomlString(a))
	}
	s := "[mcp_servers." + w.name() + "]\ncommand = " + tomlString(w.Assets.MCPCommand[0]) + "\nargs = [" + strings.Join(args, ", ") + "]\n"
	if commented {
		s += "# covers the console's 5 minute approval timeout\n"
	}
	return s + "tool_timeout_sec = 600\n"
}

// tomlString quotes s as a TOML basic string.
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, "\\u%04X", r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
