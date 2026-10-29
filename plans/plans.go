// Package plans is a lock's store of plans awaiting a decision: one file
// per plan in the lock's volume (0600 in a 0700 directory), surviving
// restarts. A plan is bound to the peer UID that made it, the requesting
// agent's token, the policy fingerprint and the plan hash; it runs once.
//
// The store keeps the product's plan as an opaque body: the product
// recomputes the plan hash from it before running (Check), and runs
// nothing whose binding moved.
//
// One process owns a store directory; a Store is safe for concurrent use
// within it.
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
	Reason  string     `json:"reason,omitempty"`
	Created time.Time  `json:"created"`
	Updated time.Time  `json:"updated"`
	Expires *time.Time `json:"expires,omitempty"`
	// Body is the product's plan, opaque to the store.
	Body json.RawMessage `json:"body"`
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
	return s, nil
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
	return &c
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
	if subtle.ConstantTimeCompare([]byte(p.Binding.TokenHash), []byte(HashToken(c.Token))) != 1 {
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
	th := HashToken(c.Token)
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

// WithdrawAll ends every pending plan as Withdrawn (a lock starting
// without its hub) and returns them.
func (s *Store) WithdrawAll(reason string) ([]*Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Plan
	for _, p := range s.plans {
		if p.State == Pending {
			if err := s.setState(p, Withdrawn, reason); err != nil {
				return out, err
			}
			out = append(out, clone(s.plans[p.ID]))
		}
	}
	return out, nil
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
		if p.State.Final() && now.Sub(p.Updated) >= Retention {
			if err := os.Remove(filepath.Join(s.dir, id+planExt)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return n, fmt.Errorf("plans: %w", err)
			}
			delete(s.plans, id)
			n++
		}
	}
	return n, nil
}
