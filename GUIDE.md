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

## 5. Asking for a lockkit change

lockkit has one owner. Do not copy a lockkit package into your product
and do not work around it: send a request to the lockkit owner naming the
need, the API you would like, and the product code that needs it.
