# lockkit guide

lockkit is the product-neutral half of locksql: everything that keeps a
secret-holding console separate from an AI agent, asks the human, and
records what happened. A product (locksql, lockmq, lockfile, lockhttp) supplies its
names and its operations; lockkit supplies the rest. This guide is the
contract between lockkit and the products built on it.

> Status: v0.3, no stability promise before v1: pin an exact version.
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
| `ticket` | the lock ↔ lockhub contract: signed tickets and decisions, closed risk classes and their TTL, RFC 8785 canonical JSON, Ed25519 signatures, X25519 sealed boxes |
| `hubclient` | a lock's client for lockhub: signed requests, `Submit` of masked tickets, long-poll of decisions, `Begin`/`Finish` of a decided plan; the instance key and `hub-key`; `hubclient/hubtest` is a fake hub for tests |
| `plans` | a lock's persisted plans awaiting a decision: bound (peer UID, agent token, policy fingerprint, plan hash), single use, 0600 |
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
`secrets.VaultRead` runs the `vault` CLI, which finds the Vault token
itself (VAULT_TOKEN or `~/.vault-token`); `secrets.VaultReadToken` gives
it a token the console holds (typed by the human) in the CLI's environment
only, never its arguments, and returns `ErrVaultAuth` when Vault refuses
it. Wipe every secret you are done with (`secrets.Wipe`).

## 5. Audit

```go
log, err := audit.Open(P, stateBase) // <stateBase>/<P.Name>/audit.log, dir 0700, file 0600, O_APPEND
err = log.Append(rec)               // one JSON line: {"ts": RFC 3339 ms, rec's fields in order, "prev_hash" last}
sum, err := audit.Verify(file)      // checks the chain; *audit.ChainError names the broken line
```

A record is any value implementing `audit.Record` (`AuditEvent() string`)
whose JSON is an object. `audit.Base` holds the product-neutral fields
(event, profile, decision, error, code, span, warnings, intent, reason,
approval, peer uid/pid/user, and in hub mode ticket, approver, facade and
hub_sig from the hub's signed decision); a product with fields of its own
declares its own struct with the same JSON names. Do not name a field
`ts` or `prev_hash`: `Append` writes them.

Each line carries `prev_hash`, the `audit.LineHash` of the line before it
(`audit.Genesis` on the first line of an empty log). `audit.Verify` refuses
a record edited, removed, inserted or reordered; records written before the
chain (without `prev_hash`) are read as legacy at the start of the log.
A cut tail, or a chain stripped of every `prev_hash` (read as legacy),
leaves a log that verifies: keep `Summary.Anchor()` elsewhere (the hub's
own log) and check with `audit.VerifyAnchored`. Appends hold a lock on the file, so a product
command may write the console's log while the console runs. When `Append`
returns an error, the event is not audited: in hub mode, refuse the
execution. A request handed to the hub is recorded as `audit.EventPending`
with its `Ticket` before the requester hears `pending`; when that record
fails, refuse the request and withdraw the ticket (`hubclient.Withdraw`),
never answer pending for an unrecorded ticket. Never put a secret, a row, a message
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
- For text bound for a model, use `pii.FindInViews(s, ds)`: the values
  found in `s` and in every detection view of it, as byte ranges of `s`
  (`[]pii.Match{Start, End, Kind}`, sorted, non-overlapping; `Kind` is the
  detector name; overlapping matches merge, the earliest detector naming
  the kind). A value written behind an escape, a look-alike or an
  invisible character is covered whole, in its written form. Replace each
  match with your own placeholder (a pseudonym).
  - `pii.DetectionView(s)` is `s` folded, NFKC (full-width letters,
    ligatures), every decimal digit as its ASCII digit (`٤`, `३`), and
    without what a value can hide behind: default-ignorable characters
    (format characters, variation selectors, the combining grapheme
    joiner, Hangul fillers), controls (C0 but tab and line ends, DEL, C1),
    the braille blank, combining marks; hyphens, dashes and minus signs
    read as `-`, ideographic full stops as `.`, and
    Cyrillic and Greek letters drawn like Latin ones as those. Invalid
    UTF-8 bytes are kept in it; `DetectionViews` adds a view without them,
    so a value an invalid byte splits is found whole: after masking,
    replace them (U+FFFD) rather than drop them before the text leaves
    your product. `View.Source(start, end)` maps a range of `View.Text`
    back to `s`, covering what was dropped inside it.
    `pii.DetectionViews(s)` adds views without terminal sequences
    (introduced by ESC, a C1 control or a raw 8-bit C1 byte): CSI (C0
    controls and DEL inside skipped, CAN and SUB cancelling it), OSC, DCS,
    SOS, PM and APC strings (ended by their terminator, CAN or SUB), nF
    and two-byte escapes, each aborted by the next ESC or C1 control, dropped whole
    whatever their length (otherwise only their introducer); one view
    keeps the strings' payload. These views are also made of every
    decoded view below, so `\u001b[31m` inside a value does not split it.
    Then a view where introducers and final bytes read as spaces, the
    payload kept; the detection view of `s` percent-decoded (once,
    twice), with JSON escapes decoded (`\u0040`), with HTML character
    references decoded (`&#64;`, `&commat;`), with all of them chained
    (`jean%40example&#46;com`; until nothing changes, at most 16 rounds,
    the view cleaned up between rounds: `jean％40`, `%4`+zero-width+`0`,
    `%4`+ESC `[m`+`0`; a text still decoding after 16 rounds is one match
    whole), with `\xHH`, `\e` and `\033` escapes decoded, and
    form-decoded (`+` as a space) then percent-decoded. A view of a long
    text may stop early: apply only the matches of `Find`/`FindInViews` to
    a text, never ranges you computed on a view yourself.
  - `pii.Find(s, ds)` is what `Detect` masks, as ranges: masking each with
    `pii.MaskText` gives `Detect`'s output, except that Find masks more
    where a later detector matched across an earlier mask, and a
    `Detector` of your own (no ranges) makes the whole text one match.
  - Past `DetectLimit` (and where a view expands past twice that) the
    unscanned rest is one more match of kind `pii.CutKind`, starting
    earlier where a value runs across that point: at the start of the word
    the cut falls in, however long (blanks between digit groups included),
    or of a match the detectors found running across it (they scan 4 KiB
    past it): the matches are always safe to apply to `s` itself.
- Opt-in `person_name` (never in `AllDetectors`): a full name in free
  text, from embedded gazetteers (given names, family names, titles, in
  the languages above and common immigrant names). A known given name
  followed by a known surname in the same case ("Jean Dupont", "JOHN
  SMITH", "john smith", "john.smith", "john_smith"), or, in title case,
  by a title-case or upper-case word that is neither a common word nor
  camel case ("Kevin Vandeputte", "Kevin VANDEPUTTE"); an initial and a
  known surname ("J. Smith"); a title-case title before capitalised words
  ("Mr. Smith", "Mme Lefebvre", "Dr Janssens"; an upper-case title only
  before an upper-case name; "Ms", "Sr", "Miss" only before a known
  name); middle initials, particles ("van der") and hyphenated given
  names. Given names that are also words, places or months ("Will",
  "Max", "Jan", "Austin") need a known surname that is no common word,
  and are never joined by `.`/`_` ("max_price"). Not found: a given or
  family name alone, surname first ("DUPONT Jean", "Smith, John"), names
  whose given name is outside the gazetteer (about 1 350 given and 500
  family names, Latin script only: Cyrillic, Arabic, CJK names are never
  found) without a title (see the held-out recall), user names other than
  first.last and first_last. Three-word names extend over one more
  title-case word. `TestPersonNameRecall`,
  `TestPersonNameHeldOutRecall` and `TestPersonNameFalsePositives` log the
  numbers of each release.
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

**Approval screens that leave the lock** (to lockhub, in a ticket) are
`render.MaskedScreen` values, built only by `render.MaskScreen`: draw the
screen as `render.ScreenSource` with each body line in `render.Part`s,
structure apart from values, and name the column of each value you know.

```go
src := render.ScreenSource{Header: "db / shop · tier read", Note: note, Body: []render.Line{{
	{Text: "SELECT id FROM customers WHERE email = "}, {Text: "'" + email + "'", Value: true, Column: "email"},
}}}
ms := render.MaskScreen(src, render.Masking{Detectors: ds}) // ds: pii.Detectors(policy's names)
t.Screen, t.PII.Touched = ms.Screen(), ms.Touched()
```

A value whose column looks personal (`pii.LooksPersonalColumn`, or your
`Masking.Personal`) is masked whole; the detectors run over everything
else, structure included, which otherwise stays visible. The zero
`MaskedScreen` is not valid and does not encode.

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

**Signatures.** `update.Verify(ctx, artifact, sigstoreBundle, update.Identity{CertIdentityRegexp: "^https://github\\.com/<you>/<repo>/\\.github/workflows/release\\.yml@refs/tags/v1\\.2\\.3$", OIDCIssuer: "https://token.actions.githubusercontent.com"}, update.Options{})`
runs `cosign verify-blob`; a missing cosign is `update.ErrCosignMissing`
(refuse, never skip), a bad signature an `*update.VerifyError`. Then
`update.ChecksumFor(sums, name)` and `update.CheckSHA256(data, want)`.
Bind the identity to the exact tag you install (anchored, dots escaped),
never to `v[0-9]`: a tag moved to an older release's signed files would
verify.

**Deployment.** The products run in Docker only: the separated setup
(`sysconf`'s `system.toml`, the console account, the clients group, the
socket directory) is baked into each product's image, and the host gets one
command, a POSIX shell launcher that runs every subcommand in the image with
the account and volumes it needs, pinned to the image digest its release's
cosign signature verifies. lockkit has no package for it: the launcher is
per product, its pattern is locksql's
[docs/launcher.md](https://github.com/DavidGodefroid/locksql/blob/main/docs/launcher.md).
Code that assumes a host install (installing the separated setup, replacing
the binary in place) serves only a product's legacy commands, which the
image refuses.

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
`abandoned`, `auto`) before `Approve` returns. An approval it cannot
record (the log unwritable, `Screen.Record` returning no valid record) is
refused with `ipc.CodeInternal` and told to the human; three failed
writes in a row end the session. Use `Screen.Record` to write the
decision as your own audit record type. `env.Session(ctx)` gives the
live session (reconnecting after `env.Lost()`, a `credentials_ttl` or a
Vault lease); `env.Level(ctx, start)` levels the response time; `env.Auto()`,
`env.ShowResults()`, `env.UnmaskAllowed()` are the human's switches;
`env.Sanitizer()` scrubs error text; `env.Safe` escapes text for the
console.

A product that draws its own approval screen, and prompts inside it (a
value to type before the decision), closes it with a `console.Asker`
rather than `env.Approve`: `Asker.Ask` rings the bell, prompts (typed
profile name on production, an optional retype answer), takes the finger
and returns the same `Approval`, handing each outcome to a record callback.
`Server.Approve` is built on it, so both decide the same way.

`Backend.Connect` gets the policy in force in `Credentials.Policy` (at
start and at every reconnection): connect to what it says, never to what
the config files say now (an unconfirmed edit). The console wraps a
session whose login expires (a Vault lease): `console.Unwrap(s)` returns
yours, in `Checks` and after `env.Session`.

**Product hooks.** A product that ported a console of its own keeps what
its users and clients see by implementing optional interfaces on the
backend; a backend that implements none gets the console's behaviour
unchanged. `StatusAnswerer` answers the `status` method itself (a flat
answer instead of `product`); `StatusRower` lists the `:status` rows
(`StatusModeRow`, `StatusResultsRow`, `StatusUnmaskRow`,
`StatusPendingRow`, `StatusBoundaryRow` give the console's own values);
`StatusLiner` adds to the status row; `ChangeFormatter` renders policy
diffs; `ConnectionComparer` widens the connection change that ends the
session (a TLS setting, a tunnel); `PolicyApplier` compiles what the
product derives from a policy before it is in force (an error refuses the
policy, neither saved nor applied); `Worder` words the console's lines
(`Words`: statements rather than requests, the reconnection and lease
lines, the end of a session that became production). A `Reconnect` that
returns an `EndError` ends the session with its reason. A handler that
paints its own approval screen decides with `console.AskerOf(env)` (a
switch pressed meanwhile is refused, as for `env.Approve`), reads a
pending loosening with `console.PolicyPendingOf(env)`, and records its own
approvals with `Server.WriteAudit`, which returns the failure (fail
closed). `Server.PolicyRefused` reports a refused loosening still in the
files.

**Hub mode.** `console.HubOptions.Register(fs)` adds the flags `lock up`
writes: `--hub URL --hub-key-file PATH --instance NAME`, plus `--hub-plain-http` for an http:// hub on its own network (all three or
none; `--auto` is refused with them). Pass them as `Options.Hub`: `Run`
then reads the pinned hub key, the instance key (`hubclient.InstanceKey`
in the home volume) and opens the plans and the hub state under the
product's state directory. Requests are no longer asked on the terminal:
`env.Approve` pushes a ticket and answers `pending` (a result, with the
ticket id). For that the product puts a `console.HubTicket` on the
screen: the plan (made in `console.HubOf(env).Store`), its caller, the
risk class and the `render.MaskedScreen`; a screen without one is refused
in hub mode, never asked here. The run of a decided ticket is the
product's: `h.Client.Begin(h.Store, ticket, caller, recheck)` (verified,
matched, still usable, binding unchanged, nonce consumed; it returns
the decision, whose approver, facade and signature go in the audit
record), the effect, then `h.Client.Finish`. A pending answer is
audited (`audit.EventPending`, approval `hub`, the ticket); one that
cannot be recorded is withdrawn and refused. A product with its own console lifecycle
calls the same pieces as `Run`: `console.OpenHub`, `hub.Approver(base)`
for its `Asker` (base keeps the console's own decisions), and
`hub.Watch(ctx, io)` in a goroutine. A product also wires `<lock> hub-key --instance
NAME` to `hubclient.HubKeyCommand`: it prints the instance's public key
for `lock up` to pin.

**Reveal and re-approval.** In hub mode pass the console's clear screen
to `SubmitClear` (the console's own `Submit` does): it stays in the plan,
and a local facade the lock pins (`--facade-keys-file`) can ask for it
(Ctrl-O); `Watch` seals it to the facade's ephemeral key and audits the
reveal (`Hub.Requests`). When `Begin` answers `ticket.ErrExpired`, answer
`h.RenewResp(ctx, id, ticket, caller)`: the ticket is asked again and
the agent gets pending with the new ticket. Record the plan-hash inputs
at plan time (`Binding.Inputs = ticket.InputDigests(inputs)`) and give
`h.Client.SetRecompute` (from `Options.OnHub` under `Run`) the same
digests recomputed now: the human then
sees which inputs moved, and an unchanged non-production renewal is one
click.

**Hub mode off (rollback).** A console started without the hub flags
after running with them withdraws the plans its hub mode left pending
(`console.WithdrawStandalone`: `plans.Store.WithdrawAll`, the plans
marked untold; the next start with `--hub` withdraws their tickets at the
hub, `hubclient.Client.Sync`) and answers any request naming a `ticket`
param with `ipc.CodeWithdrawn` (`console.WithdrawnResp`), before the
product sees it: `ticket` is therefore a reserved param name of product
methods. `Run` does both, and any `console.Server` without a hub refuses
tickets itself; a product with its own console lifecycle calls
`WithdrawStandalone` at its standalone start, and one that does not serve
through `console.Server` (a gate) refuses a run by ticket with
`WithdrawnResp`.

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

**Hub mode.** Put `mcpkit.RequesterFromEnv()` (an `ipc.Requester`: lea's
`LEA_AGENT` and the hash of `LEA_AGENT_TOKEN`, so the raw token never
reaches the console; empty outside lea; never write `Token` to the audit
log, a screen or an error) in the params of
your plan and run calls; the console binds the plan to the token and
answers another agent's run with `ipc.CodeWrongRequester` (a guard against
mistakes, not a boundary: agents of one UID can read each other's token).
When the console answers that the run waits on a hub ticket, return
`mcpkit.Pending(P.Name, ticketID)`: not an error, the fixed text "Pending
human approval: ticket … on <lock>. Do not retry. End your turn; you will
be told when it is decided." and the structured
`{"status":"pending","ticket":…,"lock":…}` that lea's hook reads to
suspend the agent. A typed run tool embeds `mcpkit.PendingResult` in its
output.

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
`ClaudeAllow` is merged into `permissions.allow` at user scope by
`InitUser`; a project `Init` only lists it in the notes, unless
`ClaudeAllowProject` is set: then `Init(root, "claude")` also merges it into
the project's `.claude/settings.local.json` (personal, never the shared
`.claude/settings.json`), keeping the file's other keys and entries, and
the notes say what was written. Set it only when every listed call answers
with masked data and every approved operation is approved at the console
or the hub (the human, not the allow list, decides). Codex and Gemini get
600 s tool timeouts from agentwire, which cover the console's 5 minute
approval and a queued call.

## 13. Hub tickets (`ticket`)

In hub mode a lock does not ask the human itself: it pushes a signed
`ticket.Ticket` to lockhub and acts only on a `ticket.Decision` signed by
the hub key it pinned. The package is the contract with lockhub; its
`testdata` fixtures are verified by lockhub's CI and do not change within a
`ticket.Version`.

```go
t := ticket.NewTicket(ticket.Source{Lock: "locksql", Instance: "crm-prod"},
	ticket.RiskProdWrite, planHash, policyFP, time.Now(), ticket.ClampTTL(ticket.RiskProdWrite, cfgTTL))
t.Screen = masked // built by render, never by hand
if err := t.Sign(lockKey); err != nil { ... }
body, _ := t.Marshal() // canonical JSON

d, err := ticket.VerifyDecision(pinnedHubKey, data) // schema + signature
err = d.Match(t)                                   // same ticket, instance, key, plan hash
err = d.Usable(t, time.Now(), ticket.ClampTTL(t.Risk, cfgTTL)) // ErrDenied unless approved
// then consume d.Nonce once, recompute the plan hash, execute
```

- **Risk classes** are closed: `read`, `read-pii`, `write`, `prod-write`,
  `policy-loosen`, `unlock`. Map each operation onto one; an unknown name
  does not decode. `Risk.TTL()`: reads never expire, `write` and
  `policy-loosen` 24 h, `prod-write` and `unlock` 4 h; `ClampTTL` lets an
  instance shorten it, never lengthen it.
- **Signatures** are Ed25519 over `Context` + NUL + the canonical JSON
  without `sig`. Contexts keep a ticket, a decision, a key certificate, a
  hub request (`ContextRequest`, for `Lock-Sig`) and a reveal key apart:
  sign other bytes with `SignBytes`/`VerifyBytes` and a context of their
  own. Verification decodes strictly (unknown members, duplicate members,
  lone surrogates and trailing data are refused), so what verifies is
  exactly what you read, and only its exact canonical bytes verify.
  `KeyID` names a key; it never replaces the key you pinned. Dedupe and
  refuse replays on the ticket id and the decision nonce, not on bytes.
- **Sealed boxes** (`Seal`/`Open`: X25519, HKDF-SHA256,
  XChaCha20-Poly1305) carry what the hub must not read: an `unlock`
  secret, a clear screen for a device, a reveal. The associated data binds
  a box to its ticket. Seal only to a key whose `KeyCert` verifies under an
  Ed25519 key you pinned.
- `HashOf(v)` is the plan hash or policy fingerprint of any value:
  `sha256:` over its canonical JSON.

`plans` keeps the plans themselves, in the lock's volume (one 0600 file
per plan in a 0700 directory, refused if wider), so a pending plan
survives a restart:

```go
st, err := plans.Open(filepath.Join(home, "plans"))
caller := plans.Caller{UID: peer.UID, Token: requesterToken}
p, err := st.Create(plans.Binding{UID: peer.UID, Agent: agent, TokenHash: plans.HashToken(requesterToken),
	PolicyFP: fp, PlanHash: hash}, body, 10*time.Minute)
// run(plan_id) in hub mode:
if q, ok := st.FindPending(caller, hash); ok { /* answer q.Ticket again */ }
err = st.MarkPending(p.ID, caller, t) // the signed ticket, kept for Match
// run(ticket): q, _ := st.ByTicket(id, caller); own, _ := q.LockTicket(lockPub)
// then VerifyDecision, d.Match(own), d.Usable(own, ...), and:
err = st.Check(p.ID, caller, recomputedFP, recomputedHash) // ErrStale: new plan, new ticket
err = st.Begin(p.ID, caller, d.Nonce)                      // single use; ErrReplay, ErrUsed
// ... execute ...
err = st.Finish(p.ID, caller, ok, reason)
```

Another peer UID gets `ErrWrongPeer`, another agent token
`ErrWrongRequester` (this catches mistakes; agents of one UID can read
each other's token, so it is no security boundary). The token itself is
never written, only its hash. A plan executing when the lock stopped
comes back `Failed` and never runs again. `End` records a denial,
withdrawal or staleness, `WithdrawAll` withdraws every pending plan (a
lock started without its hub), `Prune` expires and removes final plans
after `Retention`; consumed nonces are kept.

## 14. Asking for a lockkit change

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
