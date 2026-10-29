// Package audit writes the console's JSONL audit trail: one record per
// event, never secrets and never row data. The file is opened O_APPEND,
// mode 0600 in a 0700 directory of the console account's state: the agent
// account cannot read or alter it, while the console account and root
// can. Each record carries prev_hash, the hash of the line before it, so
// that Verify detects a record edited, removed, inserted or reordered;
// records written before the chain stay readable (see Verify). On Linux,
// chattr +a makes the file append-only for the console account too.
package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/refusal"
	"github.com/DavidGodefroid/lockkit/ticket"
)

// Events of the console.
const (
	EventLogin     = "login"
	EventPolicy    = "policy"    // policy change, applied or refused (see Decision)
	EventRefused   = "refused"   // request refused by the policy
	EventApproved  = "approved"  // the human approved
	EventDenied    = "denied"    // the human denied
	EventTimeout   = "timeout"   // approval timed out
	EventAbandoned = "abandoned" // the client left while its approval was pending
	EventAuto      = "auto"      // auto-approved under auto mode
	// EventRun is the outcome of an approved or auto-approved request
	// (Decision ok or failed). It follows the approval record, which is
	// written before anything runs.
	EventRun     = "run"
	EventCatalog = "catalog" // catalog read
	// EventMode, EventResults and EventUnmask are the console's switches,
	// changed from its keyboard: Decision is the new state (manual or
	// auto; shown or hidden; allowed or off).
	EventMode    = "mode"
	EventResults = "results"
	EventUnmask  = "unmask"
	EventLogout  = "logout"
)

// Record is one audit event of a product. Its JSON encoding must be an
// object whose fields hold no password and no row or message data: Error
// and every free text must already be sanitised by the caller.
// AuditEvent is the record's event name, never empty.
type Record interface {
	AuditEvent() string
}

// Base is the product-neutral record: a product with no fields of its own
// writes it as is; another declares its own struct (with the same JSON
// names for these fields) and implements Record.
type Base struct {
	Event    string `json:"event"`
	Profile  string `json:"profile,omitempty"`
	Decision string `json:"decision,omitempty"`
	Error    string `json:"error,omitempty"`
	// Code is the refusal code of a refused record (package refusal), and
	// Span where the refusal points in the request, when known.
	Code     string        `json:"code,omitempty"`
	Span     *refusal.Span `json:"span,omitempty"`
	Warnings []string      `json:"warnings,omitempty"`
	// Intent is the agent's one-line reason for a request (untrusted
	// text), kept on every record of that request.
	Intent string `json:"intent,omitempty"`
	// Reason is the human's reason for a denial, escaped.
	Reason string `json:"reason,omitempty"`
	// Approval is how the human approved: "session" (typed in a login
	// session of the console account), "desktop+typed" (typed in a desktop
	// window, level 1) or "desktop+fingerprint" (level 2).
	Approval string `json:"approval,omitempty"`
	// The client behind a request, from the kernel's peer credentials:
	// set on the records of client requests only. PeerUID is nil when
	// unknown (uid 0 is root); PeerUser is the account name when it
	// resolves. The process name is the agent's choice and is not kept.
	PeerUID  *int   `json:"peer_uid,omitempty"`
	PeerPID  int    `json:"peer_pid,omitempty"`
	PeerUser string `json:"peer_user,omitempty"`
	// The hub's decision behind a record, in hub mode only: the ticket
	// ID, who answered it and on which facade (from the signed decision),
	// and the hub's signature of that decision, so that the record can be
	// checked against the hub's key later.
	Ticket   string           `json:"ticket,omitempty"`
	Approver *ticket.Approver `json:"approver,omitempty"`
	Facade   string           `json:"facade,omitempty"`
	HubSig   string           `json:"hub_sig,omitempty"`
}

// AuditEvent implements Record.
func (b Base) AuditEvent() string { return b.Event }

// Log appends records to <stateDir>/<product>/audit.log. The file is opened in
// append mode for each record, so it is never truncated and never held open.
// Logs of one file in one process share a lock, and every append holds a
// lock on the file itself, so that each record links to the line written
// just before it, whatever process writes it.
type Log struct {
	path string
	mu   *sync.Mutex
}

// fileLocks holds one lock per audit file path of this process.
var fileLocks sync.Map // string -> *sync.Mutex

// Open prepares the audit log of p under stateDir (kit.StateBase() in
// production): the directory <stateDir>/<p.Name> is 0700 and the file
// 0600 (Unix), created if missing; existing content is kept.
func Open(p kit.Product, stateDir string) (*Log, error) {
	if stateDir == "" {
		return nil, errors.New("audit: empty state dir")
	}
	if p.Name == "" {
		return nil, errors.New("audit: product without a name")
	}
	dir := filepath.Join(stateDir, p.Name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	path := filepath.Join(dir, "audit.log")
	mu, _ := fileLocks.LoadOrStore(path, new(sync.Mutex))
	l := &Log{path: path, mu: mu.(*sync.Mutex)}
	f, err := l.open()
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	return l, nil
}

func (l *Log) open() (*os.File, error) {
	f, err := os.OpenFile(l.path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("audit: %w", err)
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("audit: %s is not a regular file", l.path)
	}
	if fi.Mode().Perm() != 0o600 {
		if err := f.Chmod(0o600); err != nil {
			f.Close()
			return nil, fmt.Errorf("audit: %w", err)
		}
	}
	return f, nil
}

// Path is the audit log file.
func (l *Log) Path() string { return l.path }

// Append writes rec as one JSON line: {"ts": the current time in RFC 3339
// with milliseconds, "prev_hash": the LineHash of the file's last line
// (Genesis in an empty file), then rec's fields in their encoding order}.
// A last line cut short is left as it is and the record starts a line of
// its own. An error means nothing was written, or the write failed: the
// caller must not treat the event as audited.
func (l *Log) Append(rec Record) error {
	if rec == nil || rec.AuditEvent() == "" {
		return errNoEvent
	}
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	obj := bytes.TrimRight(body.Bytes(), "\n")
	if len(obj) < 2 || obj[0] != '{' || obj[len(obj)-1] != '}' {
		return errors.New("audit: a record must encode to a JSON object")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := l.open()
	if err != nil {
		return err
	}
	// Another process (a product command beside its console) may append
	// to the same log: read the last line and write under the file lock.
	if err := lockFile(f); err != nil {
		f.Close()
		return fmt.Errorf("audit: lock: %w", err)
	}
	last, cut, err := lastLine(f)
	if err != nil {
		f.Close()
		return fmt.Errorf("audit: %w", err)
	}
	prev := Genesis
	if last != nil {
		prev = LineHash(last)
	}
	var buf bytes.Buffer
	if cut {
		buf.WriteByte('\n')
	}
	buf.WriteString(`{"ts":"`)
	buf.WriteString(time.Now().Format("2006-01-02T15:04:05.000Z07:00"))
	buf.WriteString(`","prev_hash":"`)
	buf.WriteString(prev)
	buf.WriteByte('"')
	if len(obj) > 2 {
		buf.WriteByte(',')
	}
	buf.Write(obj[1:])
	buf.WriteByte('\n')
	// One write call per record: with O_APPEND the line lands whole.
	if _, err := f.Write(buf.Bytes()); err != nil {
		f.Close()
		return fmt.Errorf("audit: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	return nil
}
