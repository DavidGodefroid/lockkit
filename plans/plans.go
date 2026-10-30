// Package plans is a lock's store of plans awaiting a decision: one file
// per plan in the lock's volume (0600 in a 0700 directory), surviving
// restarts. A plan is bound to the peer UID that made it, the requesting
// agent's token, the policy fingerprint and the plan hash; it runs once.
//
// The store keeps the product's plan as an opaque body: the product
// recomputes the plan hash from it before running (Check), and runs
// nothing whose binding moved.
//
// One Store owns a store directory: Open locks it (a second Open fails
// with ErrLocked until Close), so that a decision nonce is accepted once
// whatever the number of consoles on a volume. A Store is safe for
// concurrent use.
package plans

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"
)

// State of a plan.
type State string

const (
	// Planned: made, never run.
	Planned State = "planned"
	// Pending: run asked, a ticket awaits the human.
	Pending State = "pending"
	// Executing: a decision was accepted and consumed; the plan is running.
	Executing State = "executing"
	Executed  State = "executed"
	Failed    State = "failed"
	// Stale: the binding moved (plan hash, policy) before it ran.
	Stale     State = "stale"
	Denied    State = "denied"
	Withdrawn State = "withdrawn"
	Expired   State = "expired"
)

// Final reports whether s is a final state: nothing leaves it.
func (s State) Final() bool {
	switch s {
	case Planned, Pending, Executing:
		return false
	}
	return true
}

var (
	// ErrNoSuchPlan: unknown, pruned or expired plan id.
	ErrNoSuchPlan = errors.New("plans: no such plan")
	// ErrWrongPeer: the plan was made by another peer UID.
	ErrWrongPeer = errors.New("plans: plan made by another peer")
	// ErrWrongRequester: the plan was made by another agent (token).
	ErrWrongRequester = errors.New("plans: plan made by another agent")
	// ErrStale: the plan hash or policy fingerprint moved since planning.
	ErrStale = errors.New("plans: plan is stale")
	// ErrUsed: the plan already ran, or is in a final state.
	ErrUsed = errors.New("plans: plan already used")
	// ErrReplay: the decision nonce was consumed before.
	ErrReplay = errors.New("plans: decision nonce already consumed")
	// ErrState: the transition is not allowed from the plan's state.
	ErrState = errors.New("plans: transition not allowed")
	// ErrFull: the store holds MaxPlans live plans.
	ErrFull = errors.New("plans: too many plans")
	// ErrUnsafe: the store directory or a file in it has unsafe
	// permissions; nothing is loaded.
	ErrUnsafe = errors.New("plans: unsafe permissions")
	// ErrLocked: another Store (another console on the same volume) has
	// the directory open.
	ErrLocked = errors.New("plans: the store is open in another process")
)

// HashToken is the stored form of an agent token: hex SHA-256. The token
// itself is never written.
func HashToken(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Caller is who presents a plan id.
type Caller struct {
	UID int
	// Token is the agent's lea token (LEA_AGENT_TOKEN), "" without lea.
	Token string

	// owner: the caller is the plan's own binding (OwnerOf), for the lock
	// acting on a plan without its agent; hash is its token hash.
	owner bool
	hash  string
}

// OwnerOf is the caller a plan is bound to, for the lock itself acting on
// the plan for its agent (a renewal the human asked for on the hub). Only
// this package makes one: a product builds callers from its clients.
func OwnerOf(p *Plan) Caller {
	return Caller{UID: p.Binding.UID, owner: true, hash: p.Binding.TokenHash}
}

// tokenHash is the stored form of c's token.
func (c Caller) tokenHash() string {
	if c.owner {
		return c.hash
	}
	return HashToken(c.Token)
}

// Binding is what a plan is bound to.
type Binding struct {
	UID int `json:"uid"`
	// Agent is the requesting agent's label (display only).
	Agent string `json:"agent"`
	// TokenHash is HashToken of the agent's token ("" without one).
	TokenHash string `json:"token_hash"`
	PolicyFP  string `json:"policy_fp"`
	PlanHash  string `json:"plan_hash"`
	// Inputs are the digests of the plan hash's inputs by name
	// (ticket.InputDigests), when the product gives them: a renewal shows
	// which of them moved (ticket.DiffInputs).
	Inputs map[string]string `json:"inputs,omitempty"`
}

// Plan is one stored plan.
type Plan struct {
	ID      string  `json:"id"`
	State   State   `json:"state"`
	Binding Binding `json:"binding"`
	// Ticket is the hub ticket id, once pending, and SignedTicket the
	// ticket as the lock signed and pushed it: a decision is matched
	// against it (ticket.Decision.Match), never against one rebuilt.
	Ticket       string          `json:"ticket,omitempty"`
	SignedTicket json.RawMessage `json:"signed_ticket,omitempty"`
	// Nonce is the decision nonce consumed when the plan began executing.
	Nonce string `json:"nonce,omitempty"`
	// Reason says why the plan reached its final state (denial reason,
	// failure, what went stale).
	Reason string `json:"reason,omitempty"`
	// Untold: the plan's ticket was withdrawn here (WithdrawAll, a start
	// without the hub) and the hub has not been told yet; the next start
	// in hub mode tells it (hubclient.Client.Sync), then MarkTold.
	Untold  bool       `json:"untold,omitempty"`
	Created time.Time  `json:"created"`
	Updated time.Time  `json:"updated"`
	Expires *time.Time `json:"expires,omitempty"`
	// Body is the product's plan, opaque to the store.
	Body json.RawMessage `json:"body"`
	// Clear is the clear screen of the plan's ticket: it stays in the
	// lock's volume and leaves only sealed (a reveal, a device).
	Clear *ticket.Screen `json:"clear,omitempty"`
	// ApprovedAt is when an approval that aged before the run was given
	// (an Expired plan whose decision came too late to be used).
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
	// Renews is the expired plan this one asks again for; RenewedBy, on
	// an expired plan, the plan that renews it.
	Renews    string `json:"renews,omitempty"`
	RenewedBy string `json:"renewed_by,omitempty"`
}

// LockTicket decodes the signed ticket of a pending plan, verified under
// the lock's own key pub (the store is the lock's, but a file is only
// trusted once its signature checks).
func (p *Plan) LockTicket(pub ed25519.PublicKey) (*ticket.Ticket, error) {
	if len(p.SignedTicket) == 0 {
		return nil, fmt.Errorf("%w: plan %s has no ticket", ErrState, p.ID)
	}
	return ticket.VerifyTicket(pub, p.SignedTicket)
}

// Defaults.
const (
	// MaxPlans bounds the live (not final) plans of a store.
	MaxPlans = 1000
	// MaxBody bounds a plan's body.
	MaxBody = 1 << 20
	// Retention keeps a final plan this long before Prune removes it.
	Retention = 24 * time.Hour
)

// Store is a directory of plans.
type Store struct {
	dir string
	now func() time.Time

	lock *os.File // the directory lock, held until Close

	mu     sync.Mutex
	plans  map[string]*Plan
	nonces map[string]bool
}

// Option configures Open.
type Option func(*Store)

// WithClock sets the store's clock (tests).
func WithClock(now func() time.Time) Option { return func(s *Store) { s.now = now } }

const (
	planExt   = ".json"
	nonceFile = "nonces"
	lockFile  = ".lock"
)

// Open opens or creates the store in dir (created 0700). It refuses a
// directory, plan or nonce file readable or writable by group or others,
// and loads every plan.
func Open(dir string, opts ...Option) (*Store, error) {
	s := &Store{dir: dir, now: time.Now, plans: map[string]*Plan{}, nonces: map[string]bool{}}
	for _, o := range opts {
		o(s)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("plans: %w", err)
	}
	if err := checkPerm(dir, true); err != nil {
		return nil, err
	}
	lf, err := os.OpenFile(filepath.Join(dir, lockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("plans: %w", err)
	}
	if ok, err := tryLock(lf); err != nil || !ok {
		lf.Close()
		if err != nil {
			return nil, fmt.Errorf("plans: lock: %w", err)
		}
		return nil, ErrLocked
	}
	s.lock = lf
	opened := false
	defer func() {
		if !opened {
			s.Close()
		}
	}()
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("plans: %w", err)
	}
	for _, e := range ents {
		name := e.Name()
		path := filepath.Join(dir, name)
		switch {
		case strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".tmp"):
			_ = os.Remove(path) // an interrupted write
		case name == nonceFile:
			if err := s.loadNonces(path); err != nil {
				return nil, err
			}
		case strings.HasSuffix(name, planExt) && ticket.ValidID(strings.TrimSuffix(name, planExt)):
			p, err := loadPlan(path)
			if err != nil {
				return nil, err
			}
			if p.ID+planExt != name {
				return nil, fmt.Errorf("plans: %s holds plan %s", name, p.ID)
			}
			s.plans[p.ID] = p
			if p.Nonce != "" {
				s.nonces[p.Nonce] = true
			}
		}
	}
	// A plan executing when the lock stopped never runs again: whether its
	// effect happened is unknown, and its decision is consumed.
	for _, p := range s.plans {
		if p.State == Executing {
			if err := s.setState(p, Failed, "interrupted by a restart"); err != nil {
				return nil, err
			}
		}
	}
	opened = true
	return s, nil
}

// Close releases the store directory for another Open. The Store must
// not be used after it.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}

// checkPerm refuses a path whose mode lets group or others in, or that is
// not the kind expected. Windows has no such mode bits: there the
// directory's ACL is the operator's.
func checkPerm(path string, dir bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("plans: %w", err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 || fi.IsDir() != dir {
		return fmt.Errorf("%w: %s is not a plain %s", ErrUnsafe, path, map[bool]string{true: "directory", false: "file"}[dir])
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s is mode %v (want no group or other access)", ErrUnsafe, path, fi.Mode().Perm())
	}
	return nil
}

func loadPlan(path string) (*Plan, error) {
	if err := checkPerm(path, false); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("plans: %w", err)
	}
	var p Plan
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("plans: %s: %w", path, err)
	}
	return &p, nil
}

func (s *Store) loadNonces(path string) error {
	if err := checkPerm(path, false); err != nil {
		return err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("plans: %w", err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			s.nonces[l] = true
		}
	}
	return nil
}

// write atomically writes p's file, 0600.
func (s *Store) write(p *Plan) error {
	b, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("plans: %w", err)
	}
	return writeAtomic(s.dir, p.ID+planExt, append(b, '\n'))
}

func writeAtomic(dir, name string, b []byte) error {
	tmp, err := os.CreateTemp(dir, "."+name+".*.tmp")
	if err != nil {
		return fmt.Errorf("plans: %w", err)
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("plans: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		return fmt.Errorf("plans: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("plans: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("plans: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("plans: %w", err)
	}
	ok = true
	syncDir(dir)
	return nil
}

// syncDir makes a rename durable; best effort (not on Windows).
func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// appendNonce records a consumed nonce durably before it is acted on.
func (s *Store) appendNonce(n string) error {
	path := filepath.Join(s.dir, nonceFile)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("plans: %w", err)
	}
	if _, err := f.WriteString(n + "\n"); err != nil {
		_ = f.Close()
		return fmt.Errorf("plans: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("plans: %w", err)
	}
	return f.Close()
}

func clone(p *Plan) *Plan {
	c := *p
	c.Body = append(json.RawMessage(nil), p.Body...)
	c.SignedTicket = append(json.RawMessage(nil), p.SignedTicket...)
	if p.Expires != nil {
		e := *p.Expires
		c.Expires = &e
	}
	if p.ApprovedAt != nil {
		a := *p.ApprovedAt
		c.ApprovedAt = &a
	}
	if p.Clear != nil {
		cl := cloneScreen(*p.Clear)
		c.Clear = &cl
	}
	if p.Binding.Inputs != nil {
		c.Binding.Inputs = make(map[string]string, len(p.Binding.Inputs))
		for k, v := range p.Binding.Inputs {
			c.Binding.Inputs[k] = v
		}
	}
	return &c
}

func cloneScreen(s ticket.Screen) ticket.Screen {
	s.Body = append([]string(nil), s.Body...)
	s.Warnings = append([]string(nil), s.Warnings...)
	return s
}

// Create stores a new Planned plan bound to b, with the product's body,
// expiring after ttl unless run (0: never).
func (s *Store) Create(b Binding, body json.RawMessage, ttl time.Duration) (*Plan, error) {
	if len(body) > MaxBody {
		return nil, fmt.Errorf("plans: body longer than %d bytes", MaxBody)
	}
	if !json.Valid(body) {
		return nil, errors.New("plans: body is not JSON")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	live := 0
	for _, p := range s.plans {
		if !p.State.Final() {
			live++
		}
	}
	if live >= MaxPlans {
		return nil, ErrFull
	}
	now := s.now().UTC()
	p := &Plan{ID: ticket.NewID(now), State: Planned, Binding: b, Created: now, Updated: now,
		Body: append(json.RawMessage(nil), body...)}
	if ttl > 0 {
		e := now.Add(ttl)
		p.Expires = &e
	}
	if err := s.write(p); err != nil {
		return nil, err
	}
	s.plans[p.ID] = p
	return clone(p), nil
}

// lookup returns plan id for c, expiring it if its time is up. Locked.
func (s *Store) lookup(id string, c Caller) (*Plan, error) {
	p, ok := s.plans[id]
	if !ok {
		return nil, ErrNoSuchPlan
	}
	if p.Binding.UID != c.UID {
		return nil, ErrWrongPeer
	}
	if subtle.ConstantTimeCompare([]byte(p.Binding.TokenHash), []byte(c.tokenHash())) != 1 {
		return nil, ErrWrongRequester
	}
	if !p.State.Final() && p.State != Executing && p.Expires != nil && !s.now().Before(*p.Expires) {
		if err := s.setState(p, Expired, "expired"); err != nil {
			return nil, err
		}
		p = s.plans[id]
	}
	if p.State == Expired {
		return nil, ErrNoSuchPlan
	}
	return p, nil
}

// Get returns plan id as caller c may see it: same peer UID, same agent
// token. An expired plan is ErrNoSuchPlan.
func (s *Store) Get(id string, c Caller) (*Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.lookup(id, c)
	if err != nil {
		return nil, err
	}
	return clone(p), nil
}

// ByTicket returns the plan waiting on ticket id, for caller c.
func (s *Store) ByTicket(ticketID string, c Caller) (*Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.plans {
		if p.Ticket == ticketID {
			p, err := s.lookup(p.ID, c)
			if err != nil {
				return nil, err
			}
			return clone(p), nil
		}
	}
	return nil, ErrNoSuchPlan
}

// FindPending returns the pending plan of caller c (peer UID and agent
// token) with planHash, if any: a second run of the same plan reuses its
// ticket instead of opening a new one.
func (s *Store) FindPending(c Caller, planHash string) (*Plan, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	th := c.tokenHash()
	var found *Plan
	for _, p := range s.plans {
		if p.State == Pending && p.Binding.UID == c.UID && p.Binding.TokenHash == th && p.Binding.PlanHash == planHash &&
			(p.Expires == nil || now.Before(*p.Expires)) && (found == nil || p.Created.Before(found.Created)) {
			found = p
		}
	}
	if found == nil {
		return nil, false
	}
	return clone(found), true
}

// Pending lists the pending plans, oldest first.
func (s *Store) Pending() []*Plan {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Plan
	for _, p := range s.plans {
		if p.State == Pending {
			out = append(out, clone(p))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// Check compares a plan's binding with what the product recomputed just
// before running it: a different policy fingerprint or plan hash marks the
// plan Stale and returns ErrStale.
func (s *Store) Check(id string, c Caller, policyFP, planHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.lookup(id, c)
	if err != nil {
		return err
	}
	if p.State.Final() {
		return ErrUsed
	}
	var moved []string
	if subtle.ConstantTimeCompare([]byte(p.Binding.PolicyFP), []byte(policyFP)) != 1 {
		moved = append(moved, "policy")
	}
	if subtle.ConstantTimeCompare([]byte(p.Binding.PlanHash), []byte(planHash)) != 1 {
		moved = append(moved, "plan")
	}
	if len(moved) == 0 {
		return nil
	}
	if p.State == Executing {
		return fmt.Errorf("%w: %s changed while executing", ErrStale, strings.Join(moved, " and "))
	}
	if err := s.setState(p, Stale, strings.Join(moved, " and ")+" changed"); err != nil {
		return err
	}
	return fmt.Errorf("%w: %s changed", ErrStale, strings.Join(moved, " and "))
}

// MarkPending records that plan id waits on t, the ticket the lock signed
// for it, until t.Expires (nil: no expiry). t must carry the plan's hash
// and policy fingerprint.
func (s *Store) MarkPending(id string, c Caller, t *ticket.Ticket) error {
	return s.MarkPendingClear(id, c, t, nil)
}

// MarkPendingClear is MarkPending keeping clear, the clear screen of the
// ticket, in the plan (Plan.Clear) for a later reveal.
func (s *Store) MarkPendingClear(id string, c Caller, t *ticket.Ticket, clear *ticket.Screen) error {
	if t == nil || t.Sig == "" {
		return errors.New("plans: MarkPending needs the signed ticket")
	}
	if err := t.Validate(); err != nil {
		return fmt.Errorf("plans: %w", err)
	}
	signed, err := t.Marshal()
	if err != nil {
		return fmt.Errorf("plans: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.lookup(id, c)
	if err != nil {
		return err
	}
	if p.State != Planned {
		return fmt.Errorf("%w: %s → pending", ErrState, p.State)
	}
	if t.PlanHash != p.Binding.PlanHash || t.PolicyFP != p.Binding.PolicyFP {
		return fmt.Errorf("%w: the ticket's hashes are not the plan's", ErrStale)
	}
	u := clone(p)
	u.State, u.Ticket, u.SignedTicket, u.Updated = Pending, t.ID, signed, s.now().UTC()
	if clear != nil {
		cl := cloneScreen(*clear)
		u.Clear = &cl
	}
	u.Expires = nil
	if t.Expires != nil {
		e := t.Expires.UTC()
		u.Expires = &e
	}
	if err := s.write(u); err != nil {
		return err
	}
	s.plans[id] = u
	return nil
}

// Begin starts executing plan id under the decision nonce: single use.
// The nonce is recorded durably before the plan changes state; a nonce
// seen before is ErrReplay, a plan not Planned or Pending is ErrUsed.
// Without a hub (standalone), nonce is "".
func (s *Store) Begin(id string, c Caller, nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.lookup(id, c)
	if err != nil {
		return err
	}
	if p.State != Planned && p.State != Pending {
		return fmt.Errorf("%w: plan is %s", ErrUsed, p.State)
	}
	if nonce != "" {
		if s.nonces[nonce] {
			return ErrReplay
		}
		if strings.ContainsAny(nonce, "\n\r") {
			return fmt.Errorf("plans: invalid nonce")
		}
		if err := s.appendNonce(nonce); err != nil {
			return err
		}
		s.nonces[nonce] = true
	}
	u := clone(p)
	u.State, u.Nonce, u.Updated = Executing, nonce, s.now().UTC()
	if err := s.write(u); err != nil {
		return err
	}
	s.plans[id] = u
	return nil
}

// Finish ends an executing plan: Executed, or Failed with reason.
func (s *Store) Finish(id string, c Caller, ok bool, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.lookup(id, c)
	if err != nil {
		return err
	}
	if p.State != Executing {
		return fmt.Errorf("%w: %s → finished", ErrState, p.State)
	}
	st := Executed
	if !ok {
		st = Failed
	}
	return s.setState(p, st, reason)
}

// End moves a plan that has not begun to a final state: Denied, Withdrawn,
// Stale or Expired, with reason. It is how the lock records a decision
// other than an approval, or a ticket withdrawn.
func (s *Store) End(id string, c Caller, st State, reason string) error {
	switch st {
	case Denied, Withdrawn, Stale, Expired:
	default:
		return fmt.Errorf("%w: End to %s", ErrState, st)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.lookup(id, c)
	if err != nil {
		return err
	}
	if p.State != Planned && p.State != Pending {
		return fmt.Errorf("%w: %s → %s", ErrState, p.State, st)
	}
	return s.setState(p, st, reason)
}

// ExpireApproval ends a pending plan Expired because its approval, given
// at approvedAt, aged before the run: a renewal says so.
func (s *Store) ExpireApproval(id string, c Caller, approvedAt time.Time, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.lookup(id, c)
	if err != nil {
		return err
	}
	if p.State != Pending {
		return fmt.Errorf("%w: %s → %s", ErrState, p.State, Expired)
	}
	u := clone(p)
	a := approvedAt.UTC()
	u.State, u.Reason, u.Updated, u.ApprovedAt = Expired, reason, s.now().UTC(), &a
	if err := s.write(u); err != nil {
		return err
	}
	s.plans[id] = u
	return nil
}

// ErrNotExpired: Renew of a plan that is not Expired.
var ErrNotExpired = errors.New("plans: plan has not expired")

// ExpiredByTicket returns the expired plan of ticket ticketID, for caller
// c (its binding: same peer UID, same agent token): what a renewal starts
// from. A plan of the ticket in any other state is ErrNotExpired.
func (s *Store) ExpiredByTicket(ticketID string, c Caller) (*Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.plans {
		if p.Ticket != ticketID {
			continue
		}
		if _, err := s.lookup(p.ID, c); err != nil && !errors.Is(err, ErrNoSuchPlan) {
			return nil, err
		}
		p = s.plans[p.ID]
		if p.State != Expired {
			return nil, fmt.Errorf("%w: plan is %s", ErrNotExpired, p.State)
		}
		return clone(p), nil
	}
	return nil, ErrNoSuchPlan
}

// TicketPlan returns the plan of ticket ticketID whatever its caller: for
// the lock itself (a request of the hub about one of its tickets), never
// for a client.
func (s *Store) TicketPlan(ticketID string) (*Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.plans {
		if p.Ticket == ticketID {
			if p.Binding.UID < 0 {
				break
			}
			if _, err := s.lookup(p.ID, OwnerOf(p)); err != nil && !errors.Is(err, ErrNoSuchPlan) {
				return nil, err
			}
			return clone(s.plans[p.ID]), nil
		}
	}
	return nil, ErrNoSuchPlan
}

// Renew makes a new Planned plan asking again for expired plan id: the
// same body, binding and clear screen, under the policy fingerprint, plan
// hash and inputs the lock computed now. The expired plan records it
// (RenewedBy); a plan already renewed returns its renewal with
// ErrRenewed.
func (s *Store) Renew(id string, policyFP, planHash string, inputs map[string]string) (*Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.plans[id]
	if !ok {
		return nil, ErrNoSuchPlan
	}
	if old.RenewedBy != "" {
		if r, ok := s.plans[old.RenewedBy]; ok {
			return clone(r), ErrRenewed
		}
	}
	if old.State != Expired {
		return nil, fmt.Errorf("%w: plan is %s", ErrNotExpired, old.State)
	}
	live := 0
	for _, p := range s.plans {
		if !p.State.Final() {
			live++
		}
	}
	if live >= MaxPlans {
		return nil, ErrFull
	}
	now := s.now().UTC()
	b := old.Binding
	b.PolicyFP, b.PlanHash, b.Inputs = policyFP, planHash, nil
	if inputs != nil {
		b.Inputs = make(map[string]string, len(inputs))
		for k, v := range inputs {
			b.Inputs[k] = v
		}
	}
	n := &Plan{ID: ticket.NewID(now), State: Planned, Binding: b, Created: now, Updated: now,
		Body: append(json.RawMessage(nil), old.Body...), Renews: old.ID}
	if old.Clear != nil {
		cl := cloneScreen(*old.Clear)
		n.Clear = &cl
	}
	if err := s.write(n); err != nil {
		return nil, err
	}
	u := clone(old)
	u.RenewedBy, u.Updated = n.ID, now
	if err := s.write(u); err != nil {
		_ = os.Remove(filepath.Join(s.dir, n.ID+planExt))
		return nil, err
	}
	s.plans[n.ID], s.plans[id] = n, u
	return clone(n), nil
}

// ErrRenewed: the expired plan was renewed already; Renew returns the
// renewal.
var ErrRenewed = errors.New("plans: plan already renewed")

// WithdrawAll ends every pending plan as Withdrawn (a lock starting
// without its hub) and returns them.

// WithdrawAll ends every pending plan as Withdrawn, as a lock starting
// without its hub does, and returns them, oldest first. They are marked
// Untold: the hub still shows their ticket until a start in hub mode
// withdraws it there (Untold, MarkTold).
func (s *Store) WithdrawAll(reason string) ([]*Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Plan
	for _, p := range s.plans {
		if p.State != Pending {
			continue
		}
		u := clone(p)
		u.State, u.Reason, u.Updated, u.Untold = Withdrawn, reason, s.now().UTC(), true
		if err := s.write(u); err != nil {
			return out, err
		}
		s.plans[p.ID] = u
		out = append(out, clone(u))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out, nil
}

// Untold lists the withdrawn plans whose ticket the hub was not told
// about, oldest first.
func (s *Store) Untold() []*Plan {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Plan
	for _, p := range s.plans {
		if p.Untold {
			out = append(out, clone(p))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// MarkTold records that the hub was told plan id's ticket is withdrawn.
func (s *Store) MarkTold(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.plans[id]
	if !ok {
		return ErrNoSuchPlan
	}
	if !p.Untold {
		return nil
	}
	u := clone(p)
	u.Untold = false // Updated stays the withdrawal's: the retention counts from it
	if err := s.write(u); err != nil {
		return err
	}
	s.plans[id] = u
	return nil
}

// setState writes p in state st. Locked.
func (s *Store) setState(p *Plan, st State, reason string) error {
	u := clone(p)
	u.State, u.Reason, u.Updated = st, reason, s.now().UTC()
	if err := s.write(u); err != nil {
		return err
	}
	s.plans[p.ID] = u
	return nil
}

// Prune expires plans whose time is up and removes final plans older than
// Retention. Their nonces stay recorded. It returns how many it removed.
func (s *Store) Prune() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	n := 0
	for id, p := range s.plans {
		if (p.State == Planned || p.State == Pending) && p.Expires != nil && !now.Before(*p.Expires) {
			if err := s.setState(p, Expired, "expired"); err != nil {
				return n, err
			}
			p = s.plans[id]
		}
		// An untold plan stays until the hub hears of it: its ticket would
		// wait there for nothing otherwise.
		if p.State.Final() && !p.Untold && now.Sub(p.Updated) >= Retention {
			if err := os.Remove(filepath.Join(s.dir, id+planExt)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return n, fmt.Errorf("plans: %w", err)
			}
			delete(s.plans, id)
			n++
		}
	}
	return n, nil
}
