# Changelog

lockkit has no stability promise before v1: pin an exact version.
GUIDE.md is the contract between lockkit and the products built on it.

## v0.7.0 (2026-10-30)

Console product hooks (locksql#96: locksql's console runs on this one).
A backend that implements none of them keeps the console's behaviour, so
lockfile and lockmq see no change; the console goldens are unchanged.

- `Backend.Connect` gets the policy in force: `Credentials.Policy` (#12),
  at start and at every reconnection (`ServerConfig.ReconnectPolicy`,
  used instead of `Reconnect` when set; `Run` sets it).
- `console.Unwrap`: the backend's own session behind a Vault-leased one
  (`expiringSession.Unwrap`) (#13).
- Optional backend interfaces: `StatusAnswerer` (the whole `status`
  answer, flat), `StatusRower` and `StatusLiner` (`:status` rows, status
  row parts; `StatusView`, `StatusModeRow`, `StatusResultsRow`,
  `StatusUnmaskRow`, `StatusPendingRow`, `StatusBoundaryRow`),
  `ChangeFormatter` (policy diffs at start, on a tightening, at
  `:review`), `ConnectionComparer` (more changes of the policy that end
  the session, on top of where/user/host/port), `PolicyApplier` (prepares
  the backend for a policy before it is in force; a refused loosening
  stays out, a refused tightening is audited and ends the session, a
  failed save applies the policy in force back, and ends the session if
  that fails; `NewServer` refuses a start policy it refuses, audited by
  `Run`), `Worder`
  (`Words`: the console's lines in the product's terms; an empty field
  keeps the console's, `NoAutoHub` refuses auto mode in hub mode).
- `EndError`: a `Reconnect` error that ends the session with its reason.
- `AskerOf(env)` and `PolicyPendingOf(env)` for a handler that paints its
  own approval screen; `Server.Asker`, `Server.WriteAudit` (returns the
  write failure, counted like the console's own), `Server.PolicyRefused`.
- A tightening that cannot be saved as the approved policy now applies
  anyway (audited `policy`/`unsaved`, told on the console): before, the
  looser policy stayed in force (fail open). A loosening that cannot be
  saved still stays out.
- `:review` no longer says "policy change applied" when applying it ended
  the session (connection settings changed, production refused): the
  console already said why.

## v0.6.0 (2026-10-30)

Renewal hardening, from wiring v0.5.0 into the locks: an input a lock
cannot check now is named `unchecked` (never one click); a chain of
renewals diffs against the human's last approval; an aged approval can
be renewed from the hub before the agent's run; `console.Options.OnHub`
registers the recompute before any request. Hubs and facades must run
v0.6.0 before locks send `unchecked`.

- `ticket.UncheckedInput` / `ChangeUnchecked`: a Recompute marks an input
  it cannot check now (no session) instead of passing its stored digest;
  the renewal names it `unchecked` and is never one click.
- `hubclient`: renewing a ticket whose renewal expired renews that
  renewal (one link at a time); one whose renewal ran, was denied or
  withdrawn is `not_renewable` (it no longer returns a used ticket). A
  renewal in a chain lists the changes since what the human last approved
  (the newest approved link, else the first plan), never since an
  undecided link (`plans.Store.PlanByID`); a pruned link makes it
  unchecked. A renewal denied at the hub, or whose approval aged, is
  handled before the agent's run. Facades and hubs must run lockkit with
  `unchecked` (this release) before locks send it (#84).
- `hubclient`: a hub `renew` request for a pending ticket whose approval
  aged past its TTL ends the plan Expired (`ExpireApproval`, as `Begin`
  would at the agent's run) and renews it: the hub can offer an aged
  approval for re-approval before the agent comes back (#81).
- `console.Options.OnHub`: called with the hub once `Run` opened it,
  before any request: where a product registers `SetRecompute` (#82).

## v0.5.0 (2026-10-30)

Reveal and re-approval (lockhub's local facades): a human at the host's
terminal or the lea deck can see a ticket's clear screen, sealed by the
lock to the facade's own key (the hub relays ciphertext only), and
approve an expired ticket again in one step, seeing which plan-hash
inputs moved. Locks wire `SetRecompute`, `Binding.Inputs` and
`Hub.RenewResp`; `lock up` pins the facade keys (`--facade-keys-file`).
#78 merged after the v0.4.0 tag; nothing else changed.

- Reveal (Ctrl-O on a local facade): `ticket.HubRequest` (signed by the
  hub, `ContextHubRequest`, kinds `reveal` and `renew`) arrives in the
  `requests` of the decisions long poll; `ticket.RevealKey` is the
  facade's ephemeral X25519 key signed by its Ed25519 key
  (`ContextRevealKey`, `NewRevealKey`, `Verify` against the lock's
  `PinnedFacade`s; `CanReveal`: `tty`, `deck` only); the lock answers
  `POST /v1/requests/{id}/answer` with a `RevealAnswer` signed by its key
  (`SealReveal`, `ContextRevealAnswer`), which the facade opens with
  `OpenReveal`. The hub relays ciphertext only. `FacadeSet`,
  `ParseFacades`, `hubclient.ReadFacades`, `Config.Facades`, console flag
  `--facade-keys-file` (`HubOptions.FacadeKeysFile`, in `Args`).
  `SubmitClear` keeps the clear screen in the plan (`plans.Plan.Clear`,
  `MarkPendingClear`), the one both reveals and devices see.
- Re-approval of expired tickets (H1): `Ticket.Renews` (`Renewal`: the
  expired ticket, `expired` or `approval-expired` with `approved_at`,
  `checked`, `changes`: the names of the plan-hash inputs that moved
  (`changed`/`new`/`gone`), never values nor digests; `InputDigests`
  stays in the lock, `DiffInputs`, `Unchanged`). A changed policy
  fingerprint is no renewal (`policy_changed`: plan again). `hubclient.Client.Renew`
  (agent path) and the hub's `renew` request make a new ticket for the
  same plan, re-checked through `SetRecompute`; `Begin` answers an
  expired ticket `ticket.ErrExpired` and records an aged approval
  (`plans.Store.ExpireApproval`). `plans`: `Binding.Inputs`, `Renew`,
  `ExpiredByTicket`, `TicketPlan`, `RenewalOf`, `OwnerOf`, `ErrRenewed`.
  Failed requests are answered with a fixed code (`hubclient.AnswerCode`),
  never the error text. Console:
  `Hub.RenewResp`, `Hub.Requests` (audit events `reveal`, `renew`).
  `hubtest`: `Request`, `RawRequest`, `Requeue`, `Answer`.

## v0.4.0 (2026-10-30)

Approval devices (lockhub's mobile facade): a decision taken on a phone is
signed by the phone itself, over the lock's own signed ticket, and the
lock checks that signature: the hub's key alone cannot make an approval
pass for one taken on the device, nor get one for a ticket the lock did
not sign. Limits: the device runs a web app the hub serves, so a hub that
serves malicious code can still ask the human to verify themselves for
another pending ticket of the same lock, and read the clear screens sealed
to the device while they are shown (hence sealing is a separate opt-in).

- `ticket`: `Device` (a WebAuthn credential and an X25519 sealing key,
  pinned by the lock; `DeviceSet`, `ParseDevices` in canonical JSON,
  `MarshalDevices`, `Fingerprint`); `Decision.Device`, an optional
  WebAuthn assertion over `Decision.Statement` (every field a lock acts
  on, the approver's display name and `TicketHash` of the signed ticket,
  under `ContextDeviceDecision`), present only with facade `mobile`;
  `VerifyAssertion` (ES256, user present and verified, origin, rp id) and
  `VerifyDevice(dev, decision, signedTicket)`. The hub relays the lock's
  ticket bytes to the device unchanged: the device hashes exactly what the
  lock signed. A decision without a device
  member is unchanged on the wire; locks on older lockkit refuse one with
  it (unknown member).
- `ticket`: `SealGCM` (`SealAlgGCM`: X25519, HKDF-SHA256, AES-256-GCM), a
  sealed box WebCrypto opens; `Open` reads both algorithms.
  `PII.SealedFor` carries the clear screen sealed to each pinned device
  (`SealClearScreen`, up to `MaxClearScreen`; `OpenClearScreen`), omitted
  otherwise. Fixed vectors in `testdata/device-v1.json`.
- `hubclient`: `Config.Devices`: a decision with a device signature, or
  from the `mobile` facade, runs only if it verifies under a pinned
  device over the lock's own ticket (checked in `Begin`; the decision is
  dropped otherwise). `Config.RequireDevice`: approvals of those risk
  classes without a device signature end the plan Denied.
  `Config.SealClear` with `SubmitClear` seals the clear screen to the
  devices. `ReadDevices`, `ParseRisks`.
- `console` hub mode: `--devices-file`, `--require-device`, `--seal-clear`.
  `HubOptions.Args` renders the hub flags back, for products that start
  their console again.
- `ticket/devicetest`: a virtual WebAuthn authenticator for tests.

- Hub mode rollback: a console started without `--hub` withdraws the
  plans its hub mode left pending (`console.WithdrawStandalone`) and
  answers a run of a hub ticket with the new `ipc.CodeWithdrawn`
  (`console.WithdrawnResp`, `console.TicketParam`) before the product
  sees it. `plans.Store.WithdrawAll` marks the plans `Untold` (kept past
  the retention until told); `hubclient.Client.Sync` withdraws them at the
  hub on the next start in hub mode (`Untold`, `MarkTold`).
  `hubtest.Hub.SetWithdrawStatus` for tests.

## v0.3.1 (2026-10-30)

Fixes to hub mode found after v0.3.0. A lock reaching its hub over plain
http on the hub's own network must now pass `--hub-plain-http`.

- `mcpkit`: `RequesterFromEnv` sends the hash of `LEA_AGENT_TOKEN`
  (`plans.HashToken`), not the token: the raw token stays in the agent's
  process. The console's binding compares the same (#61).

- `hubclient` (#57): an `http://` hub URL is refused unless the host is a
  loopback address, or `Config.PlainHTTP` (console flag `--hub-plain-http`,
  `HubOptions.PlainHTTP`) is set for a service name without a dot or a
  private address; redirects are refused (a 3xx is an error, the `Lock-*`
  headers are never sent elsewhere); the state file must be a plain file
  with no group or other access.

- `plans`: a test that the store's directory lock dies with a killed
  holder (#73).

## v0.3.0 (2026-10-30)

Hub support: the packages a lock needs to ask the human through lockhub
instead of its own console window (`ticket`, `render` masked screens,
`plans`, the asynchronous console and its hub mode, `hubclient`, the audit
chain, the `mcpkit` pending answer). Standalone consoles keep their
prompts, with stricter rules: audit writes and widenings fail closed, no
widening while a prompt waits, and production refusals re-applied when
the policy becomes production. Audit lines gain `prev_hash` at the end.

- `hubclient`: the hub key file and the instance key are read through one
  descriptor opened without waiting, checked regular and small: a FIFO,
  a device or a directory is refused at once instead of blocking the
  console. `pii.AllDetectors` panics rather than return none.

- `plans` (#60): `Open` locks the store directory (flock, LockFileEx),
  without waiting: a second store on the same directory (two consoles on
  one volume) fails with `ErrLocked`, so a decision nonce is accepted
  once. `Store.Close` releases it; `console.Hub.Close` too, and `Run`
  closes its hub when it returns.

- `audit` (#59): `VerifyAnchored(r, Anchor)` checks a log against an
  anchor kept elsewhere (the hub's): a log cut before it, or whose chain
  was stripped (every `prev_hash` removed, which `Verify` alone reads as
  legacy), is a `*ChainError`. `Summary.Anchor()` makes the anchor.

- `render` (#58): `MaskScreen` with no detectors runs every detector
  (`pii.AllDetectors`: all but the opt-in `phone_loose`), never none: a
  product that forgets `pii.Detectors` sends no header, note or structure
  in clear.

- `console` (#63): a product handler that panics no longer takes the
  console down: its client gets an internal error with a generic text,
  the console prints one line, the audit records a failed run, and the
  session goes on (and stops when its context ends). `Loop` recovers a
  panicking `Handle` too.

- `mcpkit`, `console`: the pending answer names the lock instance in hub
  mode (`"instance"`, the console's `--instance`): `mcpkit.PendingOn`,
  `PendingResult.Instance`, `console.Pending.Instance`; without one the
  answer is unchanged.

- `console` hub mode (#28): `HubOptions` (`--hub`, `--hub-key-file`,
  `--instance`, all three or none, `--auto` refused with them) put `Run`
  in hub mode: requests with a `Screen.Hub` (`HubTicket`: plan, caller,
  risk, `render.MaskedScreen`) are pushed to lockhub and answered pending;
  one without is refused, never asked on the terminal. `HubOf(env)` gives
  the product the plans and the client to run a decided ticket.
  `hubclient.InstanceKey` / `HubKeyCommand` (`<lock> hub-key --instance
  NAME`) make and print the instance key; `hubclient/hubtest` is a fake
  hub for tests.

- `audit`: `prev_hash` is now the last member of a line, not the second:
  the chain is additive at the end, so a product's pinned record format
  (locksql's 0.8 lines) stays a byte-identical prefix. A record naming
  `prev_hash` itself is refused. On Windows the append lock covers one
  byte far past the log (LockFileEx locks are mandatory), so a reader is
  never refused; CI runs the audit tests on Windows.

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
  carries `prev_hash`, the `LineHash` of the line before it,
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

- `console` (#3): a policy that becomes production while the console runs
  re-applies every start-up refusal of a production profile before the
  backend's checks, and ends the session when one fails.
  `ServerConfig.RefuseProduction` carries them; `Run` sets it.

## v0.2.1 (2026-10-28)

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
