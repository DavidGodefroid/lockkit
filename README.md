<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/banner-dark.svg">
    <img alt="lockkit: the shared Go core of every Lock." src="docs/assets/banner-light.svg" width="600">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/DavidGodefroid/lockkit/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/DavidGodefroid/lockkit/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/DavidGodefroid/lockkit/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/DavidGodefroid/lockkit?include_prereleases&sort=semver&label=release&color=1f4a9c"></a>
  <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-575146"></a>
  <a href="go.mod"><img alt="Go version" src="https://img.shields.io/github/go-mod/go-version/DavidGodefroid/lockkit?color=575146&logo=go&logoColor=white"></a>
</p>

<p align="center">
  <b>The shared Go core of every Lock: write the operations,<br>
  get the console, the approvals, the masking and the audit for free.</b>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="#the-lock-family">Lock Family</a>
</p>

---

lockkit is the shared foundation of the [Lock Family](https://github.com/DavidGodefroid/lockfamily),
harness security for AI agents. It holds everything that keeps a
secret-holding console separate from an AI agent, asks the human, and
records what happened.

A product supplies its names and its operations, through a `Backend`;
lockkit supplies the rest.

> [!NOTE]
> **No stability promise before v1.** Products pin an exact version.
> [GUIDE.md](GUIDE.md) is the contract between lockkit and the products built on it.

## Why lockkit

- **One security model for every Lock.** The console, its isolated account
  and socket, and the policy review behave the same in locksql, lockmq,
  lockfile, lockhttp, locklog and lockssh.
- **The AI tightens, only the human loosens.** Policy files, their review
  and the approved store are shared code, not re-implemented per product.
- **Masking and audit you do not write twice.** Personal-data detectors,
  masks, capped output, error scrubbing and the append-only audit log.
- **One contract with the hub.** Signed tickets and decisions, the client
  for lockhub, and the launcher verbs `lox add` calls.

## Install

lockkit is a Go library (Go 1.26 or later). Pin an exact version:

```sh
go get github.com/DavidGodefroid/lockkit@v0.14.0
```

To work on a Lock and lockkit together, use an uncommitted `go.work`
(see [GUIDE.md § 15](GUIDE.md#15-asking-for-a-lockkit-change)).

## Quick start

A new Lock builds on lockkit in a few steps, each detailed in [GUIDE.md](GUIDE.md):

1. **Declare your product** once, a `kit.Product` with its names
   (binary, console account, clients group, keychain service, env prefix),
   and pass it everywhere.
2. **Register your refusal codes** with `refusal.Register`: they are part of
   your client protocol.
3. **Implement `console.Backend`:** your IPC methods, `Connect`, `Checks`,
   `LoadPolicy` and `Status`.
4. **Start the console** with one call, `console.Run(ctx, P, backend, opts)`,
   launched by lockhub (`lox run`) with the hub options.
5. **Expose MCP tools** with `mcpkit` (each a thin adapter over `client.Call`)
   and wire the agents with `agentwire`.
6. **Implement the launcher verbs** (`init`, `profile add`, `doctor`) with
   `verbs`, so `lox add` can set your Lock up.

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

## Highlights

<table>
<tr>
<td width="50%" valign="top">

**🖥️ The console, done**<br>
`console.Run` does the isolation checks, the policy review, the secret
(ask, OS keychain or Vault), the socket and the request loop. Your
`Backend` only runs operations.

</td>
<td width="50%" valign="top">

**🎭 Masking built in**<br>
`pii` detects emails, phones, IBANs, cards, national IDs, public IPs and
secrets; `render` caps and escapes output; `sanitize` scrubs errors.

</td>
</tr>
<tr>
<td valign="top">

**✍️ Signed tickets**<br>
`ticket` is the lock ↔ lockhub contract: RFC 8785 canonical JSON, Ed25519
signatures, X25519 sealed boxes. `hubclient` submits tickets and waits for
signed decisions.

</td>
<td valign="top">

**🔌 Any MCP client**<br>
`mcpkit` gives the MCP plumbing; `agentwire` wires Claude Code, Codex,
Cursor and Gemini CLI to your server, in a project or for the account,
merging and never clobbering.

</td>
</tr>
</table>

## How it works

lockkit splits a Lock in two sides that never share an account:

- **The human side, `console`:** it holds the credentials and the only
  connection, shows the policy for approval, and serves a socket. In hub
  mode it sends masked, signed tickets to lockhub and acts only on a
  decision signed by the hub key it pinned.
- **The agent side, `client` + `mcpkit`:** secret-free. It dials the
  console's socket (peer credentials checked by the kernel) and calls it
  over newline-delimited JSON-RPC 2.0.

The product plugs its own operations in between, through `console.Backend`.

### Packages

| Area | Package | Owns |
|---|---|---|
| Product | `kit` | `kit.Product`: a product's names and directories |
| | `refusal` | refusal codes registry, `refusal.Error`, structured `Info` |
| Human side | `console` | terminal, approvers (typed, desktop, fingerprint), isolation checks, request loop, the generic `Server` and `Run` that host a `Backend` |
| | `ui` | palette, banner, status marks of human-facing output |
| | `fingerprint` | fprintd verification (desktop security level 2) and a fake for tests |
| | `sysconf` | the machine-wide `/etc/<name>/system.toml` of the separated setup; process, tty and relay probes |
| Config and secrets | `config` | config lookup, secret-safe TOML decoding, profiles, `Policy`, diff helpers, approved store |
| | `managed` | the company-managed `managed.toml` of the family: root-owned, optionally signed, bounds users may tighten but never loosen |
| | `secrets` | credential sources: terminal prompt, OS keychain, Vault CLI; `Sanitize`, `Wipe` |
| | `plans` | a lock's persisted plans awaiting a decision: bound, single use, 0600 |
| Data protection | `pii` | value detectors, mask modes, name heuristics, the redacted-reference store |
| | `render` | capped, escaped output for agents: `Value` and `Table` |
| | `sanitize` | error text scrubbing and terminal-safe text |
| | `audit` | the console's append-only JSONL audit log |
| Transport | `ipc` | console socket, peer credentials, 1 MiB JSON-RPC 2.0 framing, lockkit's methods and error codes |
| | `client` | the secret-free side: dial, hello, `Call` |
| | `tunnel` | SSH bastion: known_hosts, key/agent/password auth, `Dial` and `NewSession` through it |
| | `lazyconn` | backend connections opened on a connect ticket's approval, closed when idle |
| Hub | `ticket` | signed tickets and decisions, risk classes and TTLs, ticket kinds, canonical JSON, sealed boxes |
| | `hubclient` | a lock's client for lockhub: `Submit`, long-poll of decisions, `Begin`/`Finish`, `Ask`; `hubclient/hubtest` fake hub |
| Agent side | `mcpkit` | MCP server and stdio, profile resolution, progress while the human decides, untrusted framing, structured refusals |
| | `agentwire` | wiring Claude Code, Codex, Cursor and Gemini CLI to your MCP server |
| | `verbs` | the launcher verbs every lock shares (`init`, `profile add`, `doctor`) and the JSON `lox add` reads |
| Release | `update` | cosign keyless signature check of a release artifact, checksums |

The full map, with what not to reimplement in your product, is in
[GUIDE.md § 1](GUIDE.md#1-package-map) and [§ 11](GUIDE.md#11-do-not-reimplement-in-your-product).

### Who uses it

Every Lock is built on lockkit: [locksql](https://github.com/DavidGodefroid/locksql),
[lockmq](https://github.com/DavidGodefroid/lockmq),
[lockfile](https://github.com/DavidGodefroid/lockfile),
[lockhttp](https://github.com/DavidGodefroid/lockhttp),
[locklog](https://github.com/DavidGodefroid/locklog) and
[lockssh](https://github.com/DavidGodefroid/lockssh).
[lockhub](https://github.com/DavidGodefroid/lockhub) uses its `ticket`
package to verify what the locks sign, and [lea](https://github.com/DavidGodefroid/lea)
builds on it too.

## Safety model

- The agent side holds no secret: credentials, the connection and the
  approved policy stay in the console's separated account.
- The boundary is the operating system's: separate accounts, the kernel's
  peer credentials on the socket.
- A policy change the agent proposes can only tighten; loosening is asked
  of the human, and on production takes the typed profile name.
- In hub mode, a lock executes only on a decision signed by the hub key it
  pinned, bound to the exact plan that was approved.
- The agent must run confined (lea is the reference containment):
  unconfined agents are refused by default, see
  [Confined agents](#confined-agents).
- Masking is best effort. PII detection quality: precision and recall per
  detector and language on a synthetic bench, held to a CI baseline, in
  [pii/testdata/bench/RESULTS.md](pii/testdata/bench/RESULTS.md); its
  Known gaps section lists what the detectors miss most.

### Confined agents

The Locks' guarantees hold only if the agent cannot reach what protects
them. An agent run directly on your machine (plain `claude` or `codex` in
a terminal) runs as you: it can read the hub facades' private keys and
sign its own approvals, use Docker to open a lock's container and read its
credentials, and edit `lockfamily.yaml` or stop `lox run`. Unconfined, a
lock protects you against a **confused** agent, not against a
**prompt-injected** one.

So every lock client checks where it runs and says so in its `hello`; the
console decides. An agent is confined when all of these hold:

| Check | Reason code when it fails |
|---|---|
| it runs in a container (Linux only; on macOS a client is never confined) | `in_container` |
| no rootful runtime socket is reachable or mounted (`/var/run/docker.sock`, `/run/docker.sock`, `/run/podman/podman.sock`, `/run/containerd/containerd.sock`); a rootless Podman inside the container is fine | `no_host_runtime` |
| the Lock Family's state directory (`$XDG_STATE_HOME/lockfamily`) is absent or unreadable | `no_family_state` |
| the project's `.lockfamily/`, if any, is read-only | `lockfamily_read_only` |

The console adds what the kernel says: a client holding a group that owns
a runtime socket (`docker`) is unconfined (`runtime_group`), whatever it
reports, and a client too old to report is unconfined (`old_client`).

- By default an unconfined agent is refused: `refused: this agent does not
  run confined (...); run it inside lea, or ask the human to set
  unconfined = true on this non-production profile`.
- `unconfined = true` in a profile lets it in. It is part of the reviewed
  policy: switching it on is a loosening you approve at the console. The
  console then prints a red banner (`unconfined: this lock protects
  against mistakes, not against a compromised agent`) at start and at
  every unconfined connection, every audit record of that connection says
  `"unconfined":true` with its reasons, and its hub tickets say so too.
- Never on production: a production profile with `unconfined = true` does
  not start. A managed file with `require_confined_agent = true` refuses
  unconfined agents whatever the profile says.
- No method is served on a connection before its `hello` is accepted, and
  the decision is taken again at every request: a policy that becomes
  production, or a managed file that comes to require a confined agent,
  cuts an unconfined connection already open.

What this proves, and what it does not: the check makes the safe setup the
default and stops honest or confused agents run on the host. It does not
stop a host process that deliberately lies about where it runs: such a
process already runs as you and can drive Docker, so no lock-side check
could stop it. What makes the guarantees hold against prompt injection is
the containment itself: a confined agent (lea) cannot reach the runtime,
the keys or the console's terminal.

Details: [GUIDE.md § 6](GUIDE.md#6-config-and-policy-the-ai-tightens-the-human-loosens),
[§ 7](GUIDE.md#7-ipc-client-tunnel),
[§ 10](GUIDE.md#10-the-console-and-the-backend-seam) and
[§ 13](GUIDE.md#13-hub-tickets-ticket).

## Documentation

| Doc | What it covers |
|---|---|
| [GUIDE.md](GUIDE.md) | The contract with products: every package, the console and its `Backend`, MCP and agent wiring, hub tickets, launcher verbs |
| [CHANGELOG.md](CHANGELOG.md) | Release notes, with what each version changes for products |

## The Lock Family

Every Lock is built on the same console, separation and approval model, and
one hub approves for all of them. Start at [lockfamily.dev](https://lockfamily.dev).

| Repo | What it does |
|---|---|
| [lockfamily](https://github.com/DavidGodefroid/lockfamily) | The family site and `install.sh`: everything in one install |
| [locksql](https://github.com/DavidGodefroid/locksql) | SQL databases: the agent queries, PII comes back masked; connections and writes wait for you |
| [lockmq](https://github.com/DavidGodefroid/lockmq) | RabbitMQ: masked queue inspection; connections, peeks and unmasked reads wait for you |
| [lockfile](https://github.com/DavidGodefroid/lockfile) | Files (S3, SFTP, disk): the agent asks yes/no questions about files it never reads |
| [lockhttp](https://github.com/DavidGodefroid/lockhttp) | Outbound HTTP(S): reads of trusted hosts pass; anything that sends data or reaches an unknown host waits for you |
| [locklog](https://github.com/DavidGodefroid/locklog) | Logs: masked, bounded log search; the agent reads the logs, not the people in them |
| [lockssh](https://github.com/DavidGodefroid/lockssh) | Commands over SSH: allow-listed commands run at once, the rest waits for you; the SSH key never leaves the console |
| [lockhub](https://github.com/DavidGodefroid/lockhub) | The approval hub and its `lox` CLI: `lox run` approves outside the agent's harness |
| [lockkit](https://github.com/DavidGodefroid/lockkit) | The shared Go core of every Lock: console, policies, masking, signed tickets, audit, MCP wiring |
| [lea](https://github.com/DavidGodefroid/lea) | Runs many agents in containers, wired to the Locks |

## Contributing · Security · License

- **Contributing:** lockkit has one owner. Do not copy a package into your
  product or work around it: ask for the change, as
  [GUIDE.md § 15](GUIDE.md#15-asking-for-a-lockkit-change) describes. Tests:
  `go vet ./... && go test ./...`.
- **Docs:** docs are published at
  [lockfamily.dev/docs](https://lockfamily.dev/docs/) from this repo's
  Markdown. Adding a file under `docs/`, or renaming or removing a README H2
  section, needs a matching change to
  [lockfamily's `docs-site/nav.toml`](https://github.com/DavidGodefroid/lockfamily/blob/main/docs-site/nav.toml):
  open a lockfamily PR, or the nightly docs build fails.
- **Security:** report vulnerabilities privately through
  [GitHub security advisories](https://github.com/DavidGodefroid/lockkit/security/advisories/new).
- **License:** Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
