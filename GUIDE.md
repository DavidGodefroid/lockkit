# lockkit guide

lockkit is the product-neutral half of locksql: everything that keeps a
secret-holding console separate from an AI agent, asks the human, and
records what happened. A product (locksql, lockmq, lockfile) supplies its
names and its operations; lockkit supplies the rest. This guide is the
contract between lockkit and the products built on it.

> Status: being extracted. Sections marked *(pending)* land with the
> following packages.

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

## 7. Asking for a lockkit change

lockkit has one owner. Do not copy a lockkit package into your product
and do not work around it: send a request to the lockkit owner naming the
need, the API you would like, and the product code that needs it.
