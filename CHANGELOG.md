# Changelog

lockkit has no stability promise before v1: pin an exact version.
GUIDE.md is the contract between lockkit and the products built on it.

## Unreleased



- `console` (#28, part 1): `Decision.Screen` carries the approval screen
  to the approver (a terminal approver ignores it). An `AsyncApprover`
  (lockhub) takes requests with `Submit`: the request is answered
  pending (`PendingResp`: `{"status":"pending","ticket":…,"lock":…}`, a
  result, not an error), set as `Approval.Pending` and as
  `Approval.Refusal` so that a product returning the refusal answers
  pending. A hub that refuses or cannot be reached keeps the request
  pending, never asked on the terminal instead; no ticket at all fails
  the request. The console's auto mode is off with an AsyncApprover.

- `hubclient` (new, #29): a lock's client for lockhub. Requests signed
  with the instance key (`Lock-Instance`, `Lock-Time`, `Lock-Nonce`,
  `Lock-Sig`), decisions verified under a pinned hub key only (`New`
  refuses a config without one; no discovery). `Submit` takes a
  `render.MaskedScreen` (an unmasked one is refused), signs the ticket,
  records it in the plan store and pushes it; it is idempotent (same plan,
  same ticket) and dedupes by plan hash, with a pending cap (20) and a rate
  limit (10 new tickets / 5 min). A hub that cannot be reached leaves the
  plan pending (`ErrUnreachable`), never a fallback; `Sync` resends.
  `Poll`/`Watch` long-poll decisions with a cursor kept in a 0600 state
  file with the decisions not yet acted on; `Begin` checks `Match`,
  `Usable` and the plan's binding, then consumes the decision nonce and
  returns the verified decision (approver, facade, signature for the audit);
  `Finish` and `Withdraw` tell the hub.

- `audit`: `EventPending`, the record of a request handed to the hub
  (`ticket` set), written before the requester is told pending; a failed
  write refuses the request and withdraws its ticket (GUIDE §5).

- `console` (#5): audit writes fail closed. An approval (typed or auto)
  whose record cannot be written, the log being unwritable or
  `Screen.Record` returning no valid record, is refused with
  `ipc.CodeInternal`, and the human sees why; three failed writes in a
  row end the session. Denials stay denials.

- `console`: widenings take effect only once recorded. Auto mode on,
  clear results shown, unmask allowed and a loosened policy approved (at
  `:review` or at start) write their audit record first; if it cannot be
  written they stay off (the policy is neither saved nor applied; at start
  the console does not start), and the console says so.

- `mcpkit` (#31): `Pending(lock, ticket)` is the shared answer of a run
  waiting on a hub ticket: not an error, a fixed "do not retry, end your
  turn" text and the structured `PendingResult`
  `{"status":"pending","ticket":…,"lock":…}`. `RequesterFromEnv` reads
  lea's `LEA_AGENT` and `LEA_AGENT_TOKEN` into the new `ipc.Requester`,
  carried in plan and run params; `ipc.CodeWrongRequester` refuses a plan
  or ticket to another agent's token.

- `audit` (#30): hash chain and hub fields, additive. Every record now
  carries `prev_hash` (after `ts`), the `LineHash` of the line before it,
  `Genesis` on the first line of an empty log; `Verify` checks a log and
  returns a `*ChainError` at the first broken line (a record edited,
  removed, inserted or reordered). Old logs stay readable: their records
  count as legacy, and the first chained record links to the last of
  them. `Base` gains `ticket`, `approver`, `facade` and `hub_sig`, written
  in hub mode only. A cut last line is left alone and the next record
  starts a line of its own. Every append holds a lock on the file
  (flock, LockFileEx), so that two processes writing one log (a console
  and a product command beside it) keep one chain.

- `kit`, `console`, `ipc`: the same-user refusal, the client-group and
  socket-directory errors no longer tell the human to run `sudo <name>
  install`, which the products' images refuse: they point to the launcher
  (`Product.LauncherHint`).

- `plans` (new, #27): a lock's persisted plan store, one 0600 file per
  plan in a 0700 directory (wider modes and symlinks refused). A plan is
  bound to the peer UID, the requesting agent's token (stored hashed),
  the policy fingerprint and the plan hash; `Check` marks it stale when
  either hash moved, `Begin` runs it once under a decision nonce recorded
  durably (`ErrReplay`, `ErrUsed`). `FindPending` dedupes a repeated run
  onto the existing ticket. Plans survive restarts; one executing at the
  stop comes back failed.

- `render` (#26): `MaskedScreen`, the only form in which an approval
  screen leaves the lock, built only by `MaskScreen(ScreenSource,
  Masking)`: values in personal columns (`pii.LooksPersonalColumn` or
  `Masking.Personal`) masked whole, the detectors over everything else,
  the structure of the request kept. `Screen()` is the `ticket.Screen`,
  `Touched()` the kinds masked; the zero value is not `Valid` and does not
  encode (`ErrUnmasked`).

- `ticket`: `Decision.Usable` refuses a decision that is not an approval
  (`ErrDenied`).

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

- `console`: `Asker` takes a console's human decisions: `Ask` closes an
  approval screen with the prompt (typed profile name on production, retype
  answer, fingerprint) and returns the `Approval`, its outcome recorded
  through a callback; `Decide` asks for any other decision. `Server.Approve`
  runs on it, unchanged, and a product that draws its own approval screen
  (prompting inside it) uses it too, so every approval is decided in one
  place.
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
