# Changelog

lockkit has no stability promise before v1: pin an exact version.
GUIDE.md is the contract between lockkit and the products built on it.

## Unreleased

- `mcpkit` (#31): `Pending(lock, ticket)` is the shared answer of a run
  waiting on a hub ticket: not an error, a fixed "do not retry, end your
  turn" text and the structured `PendingResult`
  `{"status":"pending","ticket":…,"lock":…}`. `RequesterFromEnv` reads
  lea's `LEA_AGENT` and `LEA_AGENT_TOKEN` into the new `ipc.Requester`,
  carried in plan and run params; `ipc.CodeWrongRequester` refuses a plan
  or ticket to another agent's token.

- `ticket` (new, #25): the contract between a lock and lockhub. Signed
  `Ticket` (lock key) and `Decision` (hub key, carrying the ticket's
  instance, lock key id and plan hash: `Match` refuses a decision for
  another instance or plan), closed `Risk` classes with their TTL
  (reads none, write and policy-loosen 24 h, prod-write and unlock 4 h;
  `ClampTTL` only shortens), RFC 8785 canonical JSON (`Canonical`,
  `CanonicalizeJSON`), Ed25519 signatures with domain separation
  (`SignBytes`/`VerifyBytes` and `Context`), strict verification, X25519
  sealed boxes (`Seal`/`Open`) and signed X25519 keys (`KeyCert`), ULID ids,
  nonces, `HashOf`, `RequestMessage` (what `Lock-Sig` signs). Only the
  exact canonical form verifies; `Canonical` refuses integers a double
  cannot hold and invalid UTF-8 rather than encode them with a loss.
  Signed fixtures under `ticket/testdata` for lockhub's
  compatibility tests.

- `console` (#2): while a prompt waits, a control key or command never
  widens a switch (auto mode on, clear results shown, unmasked output
  allowed): it is refused with a line saying to answer the prompt first;
  narrowing stays allowed. `Decision.For` names the decision, and the level
  2 finger prompt says it ("… on the reader to approve the request above").

## v0.2.1 (2026-10-28)

- `console` (#3): a policy that becomes production while the console runs
  re-applies every start-up refusal of a production profile before the
  backend's checks, and ends the session when one fails.
  `ServerConfig.RefuseProduction` carries them; `Run` sets it.
- `pii` (locksql#18): `LooksPersonalColumn` also reports `mail`,
  `e_mail`, `login` (unless the column is a date or time, as Django's
  `last_login`), `username`, `nickname`, `displayname`, `pseudo` and
  `handle`; `username`, `nickname` and `displayname` count inside unsplit
  compounds like `firstname`. `LooksQuasi` also reports free-text columns
  (`notes`, `comment`, `bio`, `remarks` and their French, Dutch, German and
  Spanish forms) and coordinates (`lat`, `lng`, `lon`, `latitude`,
  `longitude`, `coordinates`). `neutralLast` still excludes `*_id`,
  `*_count`, `*_verified`.

## v0.2.0 (2026-10-28)

- `secrets` (locksql#51): `VaultReadToken(ctx, path, token)` reads a
  login from Vault with a token the caller holds, such as one the human
  typed: passed to the vault CLI as VAULT_TOKEN in the child's environment
  only (never argv, never disk), over any VAULT_TOKEN of the console and
  its `~/.vault-token`. An empty token or one Vault refuses (expired,
  revoked, not allowed) is `ErrVaultAuth`, whose hint asks for another
  token rather than `vault login`; the token is cut out of the CLI's
  message. `VaultRead` is unchanged.

- `pii` (locksql#17): Unicode e-mail domains; U+00A0, U+202F, U+2009 and
  full-width digits in phone, IBAN, card and national-id values; opt-in
  `phone_loose` detector for national numbers without a trunk 0; `Detect`
  scans integral floats; `CutAt` also retreats over Unicode letters and
  typographic spaces. Detectors only mask more.

- `console`: clear results are refused at desktop security level 1 too
  (the agent's account can read the console window): `Run` returns
  `ErrConfig` for `ShowResults` at level 1, `NewServer` refuses
  `ShowResults` at any level but 0, and Ctrl-O / `:results` leave the
  results masked at level 1 with `results stay masked at level 1: the
  agent's account can read this window`; a refused switch is not audited.
  `--auto` and `--allow-unmask` are unchanged at level 1. Levels 0 and 2
  are unchanged.

## v0.1.0 (unreleased)

First release: the product-neutral half of
[locksql](https://github.com/DavidGodefroid/locksql), extracted with no
behaviour change for locksql, for the lock* tools to share.

- `kit`: `kit.Product`, a product's names and directories.
- `refusal`: refusal codes registry (`Register`, `Retire`), `refusal.Error`,
  structured `Info`; `E_POLICY` built in.
- `secrets`: terminal prompt, OS keychain, Vault CLI, `Sanitize`, `Wipe`.
- `fingerprint`: fprintd verification for the desktop security level 2.
- `sysconf`: the machine-wide `/etc/<name>/system.toml` and process, tty and
  relay probes.
- `ui`: palette, banner, status marks.
- `audit`: append-only JSONL audit log, `audit.Record`, `audit.Base`.
- `config`: config lookup, secret-safe TOML decoding, profile base, TLS/SSH,
  `Policy` with the "AI tightens, human loosens" diff helpers, approved
  store and fingerprints.
- `ipc`, `client`, `tunnel`: console sockets and peer credentials,
  newline-delimited JSON-RPC 2.0, the secret-free client with the "no
  console" hint, the SSH bastion tunnel.
- `pii`: value detectors, mask modes, name heuristics, redacted references.
- `render`, `sanitize`, `update`: capped typed output, error scrubbing and
  terminal-safe text, cosign signature checks.
- `console`: terminal, approvers (typed, desktop, fingerprint), isolation
  checks, request loop, and the generic console framework (`Run`,
  `Server`, the `Backend` seam, `PIIBackend` for `pii.list`/`pii.add`).
- `mcpkit`: MCP server plumbing (stdio, profiles, progress, untrusted
  framing, no-console answer, structured refusals, exact integers).
- `agentwire`: wiring Claude Code, Codex, Cursor and Gemini CLI to a
  product's MCP server, in a project or for the account.
