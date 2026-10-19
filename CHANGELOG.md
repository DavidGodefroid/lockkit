# Changelog

lockkit has no stability promise before v1: pin an exact version.
GUIDE.md is the contract between lockkit and the products built on it.

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
