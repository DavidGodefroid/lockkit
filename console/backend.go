package console

import (
	"context"
	"time"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/sanitize"
)

// Backend is what a product plugs into the console: its methods, its
// connection to the backend it guards, the checks of that connection and
// its policy. Everything else — the terminal, the isolation, the approval
// screen, the modes, the policy review, the session limits, the audit log,
// the socket — is the console's.
type Backend interface {
	// Methods are the product's IPC methods, beyond the console's own
	// (hello, status, change.request, logout). A name the console serves
	// is refused at start.
	Methods() map[string]Handler
	// Connect opens a session with the credentials the console obtained
	// (asked, from the OS keychain, or from Vault). It is called at start
	// and again after a lost connection or an expired login. The console
	// wipes c.Secret once Connect returns.
	Connect(ctx context.Context, c Credentials) (Session, error)
	// Checks audits a new session: what the backend account can do beyond
	// the profile (a red warning, typed "continue" to go on), or a reason
	// to refuse it. On a production profile every finding refuses.
	Checks(ctx context.Context, s Session) []Finding
	// LoadPolicy reads the current policy from the config files. The
	// console calls it at start and every PolicyPoll.
	LoadPolicy() (Policy, error)
	// Status is the product's part of the status method's answer.
	Status(s Session) any
}

// Session is one connection of a backend.
type Session interface {
	Close() error
}

// Credentials are what Connect needs: the user and its secret.
type Credentials struct {
	User string
	// Secret is nil for a profile with credentials "none".
	Secret []byte
}

// Finding is one result of Checks.
type Finding struct {
	// Refuse stops the console (or the reconnection) whatever the profile.
	Refuse bool
	Text   string
}

// CredentialsNone is the credentials mode of a backend that needs no
// secret (a local file, a socket the account owns).
const CredentialsNone = "none"

// Profile is what the console needs to know of a profile.
type Profile struct {
	Name       string
	Production bool
	// Where names the backend for the human (host:port, a path): it is
	// shown escaped.
	Where string
	// Host, Port and DefaultPort name the OS keychain item of the secret
	// ("<profile>@<host>:<port>").
	Host              string
	Port, DefaultPort int
	// User is the backend account; "" asks the human (or comes from Vault).
	User string
	// Credentials is config.CredentialsAsk, CredentialsKeychain,
	// CredentialsVault or CredentialsNone; VaultPath is read for "vault".
	Credentials string
	VaultPath   string
	// CredentialsTTL asks for the secret again (and reconnects) once the
	// connection is that old; 0 keeps it for the session.
	CredentialsTTL time.Duration
	// IdleTimeout ends the session after that long without activity,
	// MaxSession after that long in all. 0 takes 20m and 4h.
	IdleTimeout, MaxSession time.Duration
}

// PIIBackend is implemented by a backend whose policy has mask rules: the
// console then serves pii.list and pii.add for it. A pattern's syntax
// (db.table.column, a JSON path, a header name) is the product's. Adding a
// mask rule only tightens the policy, so it applies at once.
type PIIBackend interface {
	// PIIRules returns the mask and allow rules of p.
	PIIRules(p Policy) (mask, allow []string)
	// CheckMask validates a pattern sent by a client and returns its
	// canonical form; an error is shown to the client (invalid params).
	CheckMask(pattern string) (string, error)
	// SaveMask adds the canonical pattern to the config file as it is on
	// disk, so the human's unconfirmed edits are neither lost nor applied.
	SaveMask(pattern string) error
	// WithMask returns p with the canonical pattern added (canonical form,
	// sorted lists); p itself is not changed.
	WithMask(p Policy, pattern string) Policy
}

// Policy is a product's policy: the diff and description of config.Policy,
// plus the profile the console needs. Its JSON encoding is what the
// console fingerprints and stores as the approved policy, so it must be
// canonical (sorted lists, defaults applied) and decode back into the same
// type.
type Policy interface {
	config.Policy
	Profile() Profile
}

// Handler serves one product method. env is the console: the approval
// screen, the modes, the session, the audit log.
type Handler func(ctx context.Context, req ipc.Request, env Env) ipc.Response

// Env is what a Handler may use of the console.
type Env interface {
	// Approve shows s and asks the human (or approves it in auto mode, see
	// Screen.NeverAuto). The decision is audited before Approve returns.
	Approve(ctx context.Context, id int64, s Screen) Approval
	// Auto reports auto mode in effect (never on a production profile).
	Auto() bool
	// ShowResults reports the clear results switch (Ctrl-O).
	ShowResults() bool
	// UnmaskAllowed reports whether clients may ask for unmasked output
	// (:unmask), each such request approved by the human.
	UnmaskAllowed() bool
	// Session returns the live session, reconnecting first when the login
	// expired (credentials_ttl, a Vault lease) or the connection was lost
	// (Lost).
	Session(ctx context.Context) (Session, error)
	// Lost drops the session after a lost connection: the next Session
	// reconnects.
	Lost()
	// Policy is the approved policy in force.
	Policy() Policy
	// Audit writes rec as is; AuditBase stamps b with the profile and the
	// client behind ctx first.
	Audit(rec audit.Record)
	AuditBase(ctx context.Context, b audit.Base)
	// Println writes one console line; Safe escapes client text for it.
	Println(line string)
	Safe(s string) string
	// Sanitizer scrubs error text for a client or the audit log.
	Sanitizer() *sanitize.Sanitizer
	// Level levels a response time (Options.Quantum) from start.
	Level(ctx context.Context, start time.Time)
	// End ends the session after the current request.
	End(reason string)
}

// Screen is the content of an approval screen, entirely supplied by the
// product. The console frames it (red on production), closes it with the
// prompt and keeps the rules: typed profile name on production, timeout,
// fingerprint at level 2, audit of the decision.
type Screen struct {
	// Header follows the profile name on the top line ("db / shop · tier read").
	Header string
	// Requester names the client; "" takes the peer behind the request.
	Requester string
	// Note is the agent's one-line reason (untrusted, escaped, audited).
	Note string
	// Body are the lines of the request; Warnings are shown in red.
	Body     []string
	Warnings []string
	// Production forces the production prompt; the profile's own flag
	// always does.
	Production bool
	// NeverAuto is never approved by auto mode (an unmasked read, a
	// destructive-looking operation): the human answers every time.
	NeverAuto bool
	// Red frames the screen in red outside production too.
	Red bool
	// Retype, when set, is an answer that asks to retype values; Approve
	// then returns Approval.Retype.
	Retype string
	// Record, when set, turns the decision record into the product's own
	// (with its fields); nil writes the audit.Base.
	Record func(audit.Base) audit.Record
	// Hub is the plan and masked screen for the hub, in hub mode
	// (HubOf(env) not nil); a request without one is refused there.
	Hub *HubTicket
}

// Approval is the outcome of Env.Approve.
type Approval struct {
	Approved bool
	// Auto: approved by auto mode, without a prompt.
	Auto bool
	// Retype: the human typed Screen.Retype.
	Retype bool
	// Refusal is the answer to send when neither Approved nor Retype: the
	// human denied (with the reason they typed after "n"), the approval
	// timed out, the client left, or no finger matched. For a Pending
	// request it is the pending answer (PendingResp).
	Refusal ipc.Response
	// Pending: an AsyncApprover took the request; it is decided elsewhere.
	Pending *Pending
}

// PendingResp is the answer to a request waiting for a decision taken
// elsewhere: a result, not an error, so that the agent stops and waits
// rather than retries.
func PendingResp(id int64, lock string, p Pending) ipc.Response {
	return OKResp(id, map[string]string{"status": "pending", "ticket": p.Ticket, "lock": lock})
}
