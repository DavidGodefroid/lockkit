# lockkit guide

lockkit is the product-neutral half of locksql: everything that keeps a
secret-holding console separate from an AI agent, asks the human, and
records what happened. A product (locksql, lockmq, lockfile) supplies its
names and its operations; lockkit supplies the rest. This guide is the
contract between lockkit and the products built on it.

> Status: v0.1, no stability promise before v1: pin an exact version.
> locksql runs on every package below except `console.Run`/`console.Server`:
> its console still keeps its own modes, status row, policy review and
> start-up sequence (they are interleaved with its SQL state), on lockkit's
> terminal, approvers, isolation checks and request loop. Moving locksql
> onto `console.Run` is the next locksql PR; until then the two copies of
> that logic must stay in step (the framework is the reference).

## 1. Package map

| Package | Owns |
|---|---|
| `kit` | `kit.Product`: a product's names and directories |
| `refusal` | refusal codes registry, `refusal.Error`, structured `Info` with span |
| `secrets` | credential sources: terminal prompt, OS keychain (`Keychain`), Vault CLI; `Sanitize`, `Wipe` |
| `fingerprint` | fprintd verification (desktop security level 2) and a fake for tests |
| `sysconf` | the machine-wide `/etc/<name>/system.toml` of the separated setup; process, tty and relay probes |
| `ui` | palette, banner, status marks of human-facing output |
| `audit` | the console's append-only JSONL audit log, `audit.Record`, `audit.Base` |
| `config` | config file lookup, secret-safe TOML decoding, profile base, TLS/SSH, `Policy`, diff helpers, approved store |
| `ipc` | console socket (private or shared dir), peer credentials, 1 MiB newline-delimited JSON-RPC 2.0, lockkit's methods and error codes |
| `client` | the secret-free side: dial (with the "no console" hint naming the start command), hello, `Call` |
| `tunnel` | SSH bastion: known_hosts, key/agent/password auth, keepalive, `Dial` to any address through it |
| `pii` | value detectors, mask modes, name heuristics (`LooksPersonal`, `LooksQuasi`), the redacted-reference store |
| `render` | capped, escaped output for agents: `Value` (any typed JSON result) and `Table` (TSV/JSON) |
| `sanitize` | error text scrubbing (known secrets + registered patterns) and terminal-safe text |
| `update` | cosign keyless signature check of a release artifact, checksums |
| `console` | the human side: terminal, approvers (typed, desktop, fingerprint), isolation checks, request loop, the generic `Server` and `Run` that host a product `Backend` |
| `mcpkit` | the agent side's MCP plumbing: server + stdio, profile resolution, progress while the human decides, untrusted framing, "no console" answer, structured refusals, exact integers |
| `agentwire` | wiring Claude Code, Codex, Cursor and Gemini CLI to your MCP server, in a project or for the account: merge, never clobber |

## 2. `kit.Product`

Every lockkit function that used to say `locksql` takes a `kit.Product`
(or one of its fields). Declare one value in your product and pass it
everywhere:

```go
var P = kit.Product{
	Name:            "lockmq",                                     // binary, .lockmq/, <config>/lockmq, sockets
	Tagline:         "Your AI reads the queue. You hold the key.", // banner
	Account:         "lockmq",                                     // console account
	ClientsGroup:    "lockmq-clients",                             // may reach the console
	KeychainService: "lockmq",                                     // OS keychain service
	EnvPrefix:       "LOCKMQ_",                                    // LOCKMQ_RUNTIME_DIR, ...
}
```

| Method | Value for `Name: "lockmq"` |
|---|---|
| `ProjectDir()` | `.lockmq` |
| `UserConfigDir()` | `os.UserConfigDir()/lockmq` |
| `StateDir()` | `$XDG_STATE_HOME/lockmq` or `~/.local/state/lockmq` (macOS: user config dir) |
| `RuntimeDir()` | `$LOCKMQ_RUNTIME_DIR/lockmq`, else `$XDG_RUNTIME_DIR/lockmq` (macOS `$TMPDIR/lockmq`), else `/tmp/lockmq-<uid>` |
| `SystemConfigPath()` | `/etc/lockmq/system.toml` |
| `SharedSocketDir()` | `/run/lockmq` (macOS `/usr/local/var/run/lockmq`) |

`Validate()` refuses a product whose names are unusable. Two products never
share a directory, a socket, an environment variable or a keychain item.

## 3. Refusals

lockkit defines one code, `refusal.Policy` (`E_POLICY`, fail closed). A
product registers its own at init time:

```go
func init() {
	refusal.Register("E_VHOST_NOT_SERVED", refusal.RetryAskUser,
		"a vhost this profile does not serve", "use a vhost listed by lockmq_status, or ask the user")
}
```

Codes are part of your client protocol: never rename one; `refusal.Retire`
keeps an old code known for past audit records.

## 4. Secrets

```go
kc := secrets.NewKeychain(P.KeychainService)
pw, legacy, err := kc.Get(profile, host, port, defaultPort)
```

`secrets.PromptPassword` reads from the controlling terminal;
`secrets.VaultRead` runs the `vault` CLI (the console never handles the
Vault token). Wipe every secret you are done with (`secrets.Wipe`).

## 5. Audit

```go
log, err := audit.Open(P, stateBase) // <stateBase>/<P.Name>/audit.log, dir 0700, file 0600, O_APPEND
err = log.Append(rec)               // one JSON line: {"ts": RFC 3339 ms, then rec's fields in order}
```

A record is any value implementing `audit.Record` (`AuditEvent() string`)
whose JSON is an object. `audit.Base` holds the product-neutral fields
(event, profile, decision, error, code, span, warnings, intent, reason,
approval, peer uid/pid/user); a product with fields of its own declares its
own struct with the same JSON names. Never put a secret, a row, a message
body or a file's content in a record; sanitise `Error` first. The event
names (`audit.EventLogin`, `EventApproved`, ...) are shared by every
product.

## 6. Config and policy: the AI tightens, the human loosens

Files: `.<name>/config.toml` in the project (found by walking up,
`config.FindProjectRoot(P, cwd)`) and `<user config>/<name>/config.toml`
(`config.UserConfigPath(P)`). Decode your own raw profile struct with
`config.Decode(P, data, name, &raw)`: it refuses any key that looks like a
secret (password, token, ...), any unknown key, and never quotes a value
in an error. Check every free-text value shown on an approval screen with
`config.CheckValue(P, key, val)` (embedded DSN passwords, terminal control
or bidi characters) and profile names with `config.CheckProfileName`.

Shared profile part: `config.Base` (user, credentials `ask|keychain|vault`,
vault_path, credentials_ttl, tls, tls_ca/cert/key, production, ssh bastion,
idle_timeout, max_session), `config.ParseSSH` for the `ssh` table, and
`config.DiffBase` for its loosening rules.

Your policy implements `config.Policy`:

```go
type Policy interface {
	Diff(approved Policy) []Change // your loosening rules; call DiffBase for the shared part
	Describe() []string            // lines for the console's status screen
}
```

The rule: a change with `Loosens: true` takes effect only after the human
confirms the diff in the console; a tightening applies at once. Helpers:
`SetDiff` (lists where a removal or an addition loosens), `LooserLimit`
(0 = unlimited), `TLSRank`, `SortedSet`. The approved store
(`LoadApproved/SaveApproved(P, stateBase, ApprovedKey(root, profile), v)`)
keeps the last policy the human accepted; `Fingerprint(v)` hashes a
canonical form. Never let an IPC method loosen anything: an agent proposes
a loosening (`change.request`), only the console's human applies it.

## 7. IPC, client, tunnel

The wire protocol is newline-delimited JSON-RPC 2.0, one message ≤ 1 MiB
(`ipc.WriteMsg`, `ipc.ReadMsg`), `ipc.ProtocolMajor` exchanged in `hello`.
lockkit's methods, served by every console: `hello`, `status`, `pii.list`,
`pii.add`, `change.request`, `logout` (`pii.*` once your backend implements
`console.PIIBackend`, see §10; without it they answer "method not found"). Your methods use their own names
(`op.run`, `query.plan`, ...); errors use the shared codes (`CodeRefused`
with a `refusal.Info` in `Data`, `CodeDenied`, `CodeTimeout`,
`CodePolicyPending`, ...).

Sockets: `ipc.SocketPath(P, projectKey, profile)` in the user's private
runtime dir (0700, socket 0600) or `ipc.SharedSocketPath(dir, ...)` in a
separated setup (`ipc.ListenShared(P, path, gid)`, dir 0710/2710, socket
0660). `ipc.PeerCred` is the kernel's word on who is calling.

```go
c, err := client.Dial(P, cwd, profile)  // *client.NoConsoleError (errors.Is ErrNoConsole) names the start command
err = c.Call(ctx, "op.run", params, &result) // hello first, no client-side timeout; ctx cancel closes the connection
```

`tunnel.Open(ctx, tunnel.Options{Profile: sshProfile, HostKey: tunnel.KnownHosts(...), Secret: ask, ClientName: P.Name})`
then `t.Dial(ctx, "tcp", "broker:5671")`: one tunnel serves every port the
bastion reaches; no local port is ever opened.

## 8. Personal data

- `pii.Detectors([]string{"email", "phone", "iban", "card"})` (also `be_niss`,
  `fr_nir`, `nl_bsn`, `us_ssn`, and the opt-in `phone_loose`);
  `pii.Detect(v, ds)` masks what they find in a text or integer value, or an
  integral float (`|f| < 1e19`), scanning at most `DetectLimit` bytes.
  - `email`: Unicode letters, digits and marks in the local part and the
    domain labels (RFC 6531); a letters-only top-level domain.
  - Wherever a space separates digits, U+00A0, U+202F and U+2009 do too;
    full-width digits count as digits. Other Unicode forms (full-width
    letters, other compatibility characters) are not folded.
  - `phone`: `+` and 8 to 15 digits, `00` and 10 to 17 digits, or a
    national number: a trunk 0, 9 to 11 digits, a first group of at least
    2 digits. `phone_loose` adds national numbers without a trunk 0
    (`(415) 555-2671`, `612 345 678`): 9 to 11 digits in at least two
    groups, the first of 2 to 4 digits; it also masks some grouped amounts
    (`123 456 789`), hence opt-in.
- `pii.MaskValue(v, mode)` / `pii.Mask(mode, s)`: `redact` → `<redacted>`,
  `partial` → `j***(12)`, `email` → `j***@example.com`.
- `pii.LooksPersonal(name)` and `pii.LooksQuasi(name)` read a field name in
  en/fr/nl/de/es: use them to propose mask rules (a proposal tightens: apply
  it at once).
- `pii.RefStore`: `n := s.Begin()` per result, `s.PutDistinct(n, value)`
  (or `Put(n, "row.col", value)`) returns `rN.K`; show
  `pii.RedactedRef(ref)`; resolve with `Get` in the console only. Values
  never leave the console's memory.

Which field is personal (columns, JSON paths, headers) is your product's
decision; never send an unmasked value to a client unless the human
unmasked it in the console.

## 9. Output, sanitising, signatures

**Results are typed JSON, not rows.** `render.Value(w, v, render.Caps{MaxCellChars, MaxOutputBytes})`
writes any value as one JSON line: every string (keys included) escaped
and cut at `MaxCellChars` characters, numbers/booleans/nulls kept, the
whole at most `MaxOutputBytes` (else `render.ErrOutputCap`, nothing
written: page or narrow your result). `render.Table` + `render.Render(w,
t, caps, "tsv"|"json")` is one helper among others, for tabular results.

**Errors.** Every error text that leaves the console (client, audit log)
goes through a `sanitize.Sanitizer`:

```go
san := sanitize.New(sanitize.URLUserinfo)          // your patterns: AMQP/HTTP URIs with userinfo, ...
san.Register(regexp.MustCompile(`Authorization: [^\r\n]*`)) // groups are removed, else the match becomes ***
msg := san.Error(err, password)                     // known secrets first (every encoded form), then patterns
```

Text printed for the human (approval screens, console lines) goes through
`sanitize.Terminal(s, multiline)`: client-supplied text cannot drive or
spoof the terminal.

**Signatures.** `update.Verify(ctx, artifact, sigstoreBundle, update.Identity{CertIdentityRegexp: "^https://github\\.com/<you>/<repo>/\\.github/workflows/release\\.yml@refs/tags/v[0-9]", OIDCIssuer: "https://token.actions.githubusercontent.com"}, update.Options{})`
runs `cosign verify-blob`; a missing cosign is `update.ErrCosignMissing`
(refuse, never skip), a bad signature an `*update.VerifyError`. Then
`update.ChecksumFor(sums, name)` and `update.CheckSHA256(data, want)`.

## 10. The console and the `Backend` seam

Your `console` command is one call:

```go
err := console.Run(ctx, P, backend, console.Options{
	Profile: "prod", ProjectRoot: root, IO: term, TTY: os.Stdin,
	Sanitizer: sanitize.New(sanitize.URLUserinfo),
})
```

`Run` does, in order: the isolation checks (separated account, session or
desktop shape, X11, relays; refuses before any prompt or file write), core
dumps off (refused on production if it fails), the policy review (first
start: describe and approve; since the approved policy: tightenings apply,
loosenings are asked), the production banner and typed profile name, the
user and the secret (`ask`, `keychain` with an offer to save, `vault` read
at every connection), `Backend.Connect`, `Backend.Checks` (red findings,
typed `continue`; any finding refuses on production), the socket (private
or shared), then the request loop until logout, `:quit`, Ctrl-C, the idle
timeout or the maximum session.

```go
type Backend interface {
	Methods() map[string]console.Handler                                  // your IPC methods (not hello/status/change.request/logout)
	Connect(ctx context.Context, c console.Credentials) (console.Session, error) // c.Secret is wiped after the call
	Checks(ctx context.Context, s console.Session) []console.Finding      // privilege audit of the account
	LoadPolicy() (console.Policy, error)                                  // read from your config files, every 2s
	Status(s console.Session) any                                         // your part of `status`
}
type Policy interface {
	Diff(approved config.Policy) []config.Change // your loosening rules (DiffBase for the shared part)
	Describe() []string
	Profile() console.Profile                    // name, production, where, host/port, user, credentials, vault, ttl, session limits
}
type Handler func(ctx context.Context, req ipc.Request, env console.Env) ipc.Response
```

A policy with mask rules implements `console.PIIBackend` on the backend;
the console then serves `pii.list` and `pii.add` (a mask rule only
tightens: saved to the file on disk, applied at once, kept in a pending
loosening, audited as `policy`/`tightened`):

```go
type PIIBackend interface {
	PIIRules(p console.Policy) (mask, allow []string)
	CheckMask(pattern string) (string, error)          // your syntax; returns the canonical form
	SaveMask(pattern string) error                     // append to the config file as it is on disk
	WithMask(p console.Policy, pattern string) console.Policy // pure: p plus the rule
}
```

A handler that needs the human calls `env.Approve(ctx, req.ID, screen)`:

```go
a := env.Approve(ctx, req.ID, console.Screen{
	Header:    "rabbitmq.example.com / orders · tier peek",
	Note:      params.Intent,                          // the agent's reason, escaped and audited
	Body:      []string{"PEEK orders.failed  count 3"},
	Warnings:  []string{"NOT READ-ONLY: 3 messages requeued, redelivered=true"},
	NeverAuto: true,                                   // never approved by auto mode
})
if !a.Approved {
	return a.Refusal // denied (with the human's reason), timed out, client gone, no finger
}
```

The console frames the screen (red on production), asks `y` or, on
production, the typed profile name, takes a finger at level 2, times out
after 5 minutes, and audits the decision (`approved`, `denied`, `timeout`,
`abandoned`, `auto`) before `Approve` returns. Use `Screen.Record` to write
the decision as your own audit record type. `env.Session(ctx)` gives the
live session (reconnecting after `env.Lost()`, a `credentials_ttl` or a
Vault lease); `env.Level(ctx, start)` levels the response time; `env.Auto()`,
`env.ShowResults()`, `env.UnmaskAllowed()` are the human's switches;
`env.Sanitizer()` scrubs error text; `env.Safe` escapes text for the
console.

A minimal product:

```go
type queueBackend struct{ cfg *Config }

func (b *queueBackend) Methods() map[string]console.Handler {
	return map[string]console.Handler{"op.read": b.read}
}
func (b *queueBackend) Connect(ctx context.Context, c console.Credentials) (console.Session, error) {
	return dialBroker(ctx, b.cfg.URL, c.User, c.Secret)
}
func (b *queueBackend) Checks(ctx context.Context, s console.Session) []console.Finding {
	if s.(*broker).IsAdministrator(ctx) {
		return []console.Finding{{Text: "the account has the administrator tag", Refuse: true}}
	}
	return nil
}
func (b *queueBackend) LoadPolicy() (console.Policy, error) { return loadPolicy(b.cfg.Root, b.cfg.Profile) }
func (b *queueBackend) Status(s console.Session) any         { return s.(*broker).Overview() }

func (b *queueBackend) read(ctx context.Context, req ipc.Request, env console.Env) ipc.Response {
	var p readParams
	if r := console.Decode(req, &p); r != nil {
		return *r
	}
	sess, err := env.Session(ctx)
	if err != nil {
		return console.ErrResp(req.ID, ipc.CodeConnLost, err.Error())
	}
	if a := env.Approve(ctx, req.ID, readScreen(p)); !a.Approved {
		return a.Refusal
	}
	msgs, err := sess.(*broker).Read(ctx, p)
	if err != nil {
		return console.ErrResp(req.ID, ipc.CodeInternal, env.Sanitizer().Error(err))
	}
	return console.OKResp(req.ID, mask(msgs)) // typed JSON; render.Value caps it client-side
}
```

The console's own commands and keys: `:review` (pending loosening and
change requests), `:status`, `:mode` / Shift+Tab (auto mode, never on
production; takes a finger at level 2), `:results` / Ctrl-O (clear results,
refused at levels 1 and 2, as is `--show-results` at start), `:unmask` (confirmed), `:quit`.

The pieces are exported for a product that assembles its own console:
`console.NewTerminal`, `console.NewTypedApprover` / `NewDesktopTypedApprover`
/ `NewFingerprintApprover`, `console.CheckIsolation` + `RealIsolationEnv`,
`console.Harden`, `console.Loop`, `console.WithPeer` / `PeerText` /
`StampPeer`, `console.Level`, `console.ErrResp` / `OKResp` / `Decode`.

## 11. Do not reimplement in your product

- a socket, a peer check or the JSON-RPC framing: `ipc`, `client`;
- an approval prompt, a production typed name, a fingerprint wait, an
  approval timeout or the audit of a decision: `console.Env.Approve`;
- auto/manual mode, clear results, unmask switches, the status row:
  `console.Server`;
- reading a secret from the terminal, the keychain or Vault: `console.Run`
  (or `secrets`);
- the config lookup, secret-key refusal, approved store, fingerprints and
  the "AI tightens, human loosens" review: `config` + `console`;
- isolation checks, core-dump hardening: `console`;
- detectors, mask modes, references: `pii`; capped output: `render`;
- error scrubbing: `sanitize`; release signature checks: `update`;
- MCP plumbing (server, stdio, profile argument, progress, untrusted
  framing, the no-console answer, refusals, large integers): `mcpkit`;
- agent wiring (MCP entries, skills, rules, instructions sections, Codex
  TOML, Claude permissions, `claude mcp add`): `agentwire`.

## 12. MCP server and agent wiring

**MCP server.** Your tools are yours (names `<name>_*`, descriptions,
instructions, texts): declare them with the SDK
(`github.com/modelcontextprotocol/go-sdk/mcp`, the version lockkit's go.mod
pins), each a thin adapter over `client.Call`. mcpkit gives the rest:

```go
s := mcpkit.New(P, version, instructions)        // Implementation{Name: P.Name}
profiles := mcpkit.Profiles{Product: P, Pinned: pinnedFlag, List: configuredNames}

mcp.AddTool(s, &mcp.Tool{Name: "lockmq_read", Description: "..."}, func(ctx context.Context, req *mcp.CallToolRequest, in ReadIn) (*mcp.CallToolResult, ReadOut, error) {
	profile, err := profiles.Resolve(in.Profile)                  // pinned / unknown / several: errors the model can act on
	if err != nil {
		return nil, ReadOut{}, err
	}
	stop := mcpkit.Progress(ctx, req, 0, mcpkit.WaitingMessage(P)) // every 5 s while the human decides
	out, err := read(ctx, profile, in)
	stop()
	if res, info, ok := mcpkit.Refused(err); ok {                  // err is a *mcpkit.ToolError with a Refusal
		return res, ReadOut{Refusal: info}, nil
	}
	if err != nil {
		return nil, ReadOut{}, err
	}
	return mcpkit.Text(mcpkit.Untrusted("messages", "the broker") + "\n" + text(out)), out, nil
})
return mcpkit.Serve(ctx, s, os.Stdin, os.Stdout)                // stdout carries only the protocol
```

A status tool reports `profiles.ForStatus(arg)` and, per profile whose
dial fails, `mcpkit.NoConsole(P, profile, err)` (the exact start command and
what to ask of the user; `NoConsoleLine` for the text). Run integers that
may exceed 2^53 through `mcpkit.Exact`/`ExactRows`; `NonNil` keeps `[]` in
structured output.

**Agent wiring.** Declare your texts once:

```go
var Wiring = agentwire.Wiring{Product: P, Assets: agentwire.Assets{
	MCPCommand:        []string{"lockmq", "mcp"},
	Skill:             skillMD,        // .claude/skills/lockmq/SKILL.md (project) and ~/.claude/skills/... (user)
	Instructions:      agentsMD,       // the <!-- lockmq:begin --> section of AGENTS.md / GEMINI.md, the Cursor rule body
	CursorFrontMatter: cursorFront,    // .cursor/rules/lockmq.mdc
	ProjectConfig:     exampleConfig,  // .lockmq/config.toml when absent (nil: none)
	ClaudeAllow:       []string{"mcp__lockmq__lockmq_status", "Bash(lockmq status:*)"},
	ClaudeNote:        "...",          // optional end of the project notes
}}
```

then `Wiring.Init(agentwire.ProjectRoot(P, cwd), agent)` for `<name> init
<agent>`, `Wiring.InitUser(env, agent)` / `PendingUser` for the account
(`env, _ := agentwire.SystemEnv()`), `agentwire.Detect(env)` and
`Wiring.Unwired(env)` for your doctor's "agent wiring" line. Only list in
`ClaudeAllow` calls that never touch data without the console's approval.

## 13. Asking for a lockkit change

lockkit has one owner. Do not copy a lockkit package into your product
and do not work around it: send a request to the lockkit owner naming the
need, the API you would like, and the product code that needs it. Build
against a local checkout with an uncommitted `go.work`:

```
go 1.26.0

use (
	.
	../lockkit
)
```

(`go.work` and `go.work.sum` stay out of git: add them to
`.git/info/exclude`.) For CI, pin the pushed commit or tag:
`go get github.com/DavidGodefroid/lockkit@<commit or vX.Y.Z>`.
