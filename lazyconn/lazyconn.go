// Package lazyconn opens a lock's backend connections only when an
// agent's request needs one, on a decision: a lock starts disconnected;
// the first request for a profile sends a connect ticket
// (ticket.KindConnect) to the hub, the connection opens on a signed
// approval, is shared by the requests that follow, and closes once it has
// been idle for Config.Idle. The next request asks again.
//
// When the profile needs its secret from the decider (credentials "ask",
// or an expired Vault token: Profile.NeedSecret), the ticket carries a
// one-use X25519 key of the lock (Subject.SecretTo); `lox run` seals the
// secret to it in the decision (ticket.SealSecret), the hub relays a box
// it cannot open, and the pool opens it (Decision.OpenSecret) for Dial
// only. The agent never sees it: it only gets a connection or an error.
//
// locksql and lockmq use one Pool per lock, the hub client as the Asker
// (hubclient.Client.Ask).
package lazyconn

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/DavidGodefroid/lockkit/render"
	"github.com/DavidGodefroid/lockkit/ticket"
)

// Defaults of Config.
const (
	// DefaultIdle is how long an unused connection stays open.
	DefaultIdle = 2 * time.Minute
	// DefaultAskTimeout is how long a connect ticket waits for a decision
	// (its Expires).
	DefaultAskTimeout = 10 * time.Minute
	// DefaultMaxAge is the age past which a connect approval is not acted
	// on (ticket.Decision.Usable).
	DefaultMaxAge = 5 * time.Minute
)

// ErrClosed: the pool is closed.
var ErrClosed = errors.New("lazyconn: pool closed")

// Asker sends a connect ticket and waits for its decision:
// hubclient.Client.Ask. It sets the ticket's instance, key, screen and
// touched kinds, signs it, and returns the decision verified under the
// pinned hub key and matching the ticket, approval or denial.
type Asker interface {
	Ask(ctx context.Context, t *ticket.Ticket, screen render.MaskedScreen) (*ticket.Decision, error)
}

// consumer is an Asker that is told when a decision was acted on.
type consumer interface {
	Consumed(ctx context.Context, ticketID string) error
}

// Profile is what a connect ticket asks for one profile, as the lock's
// configuration says at the time of the request.
type Profile struct {
	// Endpoint is the backend, without userinfo ("db.internal:5432/shop").
	Endpoint string
	// Credential is the profile's credential source (ticket.Credential*).
	Credential string
	// NeedSecret asks the decider for the secret (credentials "ask", an
	// expired Vault token): the ticket carries a one-use key and Dial gets
	// the secret in Grant.Secret.
	NeedSecret bool
	// PolicyFP is the fingerprint of the policy in force (ticket.HashOf).
	PolicyFP string
	// Risk is the ticket's risk class (ticket.KindRisks of connect); ""
	// is unlock with NeedSecret, prod-write in production, read otherwise.
	Risk ticket.Risk
	// Production marks a production profile; NeverAuto keeps an auto
	// rule from approving the connection.
	Production, NeverAuto bool
	// Masking masks the screen (render.MaskScreen; zero: every detector).
	Masking render.Masking
}

// Request is one agent request that needs a profile's connection.
type Request struct {
	Profile string
	// Requester, Workspace and Note are shown with the ticket (display
	// only, untrusted).
	Requester ticket.Requester
	Workspace string
	Note      string
}

// Grant is what Dial connects with: the lock's signed ticket, the
// verified approval, and the secret the decider sealed to the lock (nil
// when the profile did not need one). The pool wipes Secret when Dial
// returns: Dial copies what it keeps.
type Grant struct {
	Ticket   *ticket.Ticket
	Decision *ticket.Decision
	Secret   []byte
}

// Timer is a pending idle close (*time.Timer).
type Timer interface{ Stop() bool }

// EventKind is what happened to a profile's connection.
type EventKind string

const (
	// EventConnected: a connection opened on Decision.
	EventConnected EventKind = "connected"
	// EventDenied: the decider refused the connection (Decision).
	EventDenied EventKind = "denied"
	// EventFailed: asking or connecting failed (Err).
	EventFailed EventKind = "failed"
	// EventClosed: the connection closed, idle or with the pool.
	EventClosed EventKind = "closed"
)

// Event is one change of a profile's connection, for the lock's audit:
// Decision names the deciding rule (Decision.Rule) and facade.
type Event struct {
	Kind     EventKind
	Profile  string
	Ticket   string
	Decision *ticket.Decision
	Err      error
}

// Config configures a Pool. Lock, Asker, Profile and Dial are required.
type Config[C io.Closer] struct {
	// Lock is the product ("locksql"), the ticket's Source.Lock.
	Lock  string
	Asker Asker
	// Profile reads a profile's configuration at each connect; an error
	// fails the request without a ticket.
	Profile func(name string) (Profile, error)
	// Dial opens the backend connection for profile name on g.
	Dial func(ctx context.Context, name string, g Grant) (C, error)
	// Idle, AskTimeout and MaxAge default to DefaultIdle,
	// DefaultAskTimeout and DefaultMaxAge when <= 0.
	Idle, AskTimeout, MaxAge time.Duration
	// Now is the clock (nil: time.Now); AfterFunc schedules the idle
	// close (nil: time.AfterFunc).
	Now       func() time.Time
	AfterFunc func(time.Duration, func()) Timer
	// OnEvent, if set, is called for every Event, outside the pool's
	// lock.
	OnEvent func(Event)
}

// Pool holds at most one connection per profile. It is safe for
// concurrent use.
type Pool[C io.Closer] struct {
	cfg Config[C]

	mu      sync.Mutex
	closed  bool
	entries map[string]*entry[C]
}

type entry[C io.Closer] struct {
	conn    C
	open    bool
	ticket  string
	gen     uint64 // bumped at each connection
	users   int
	timer   Timer
	idleSeq uint64 // bumped at each idle timer
	call    *call  // the connect under way
}

type call struct {
	done chan struct{}
	err  error
}

// New checks cfg and returns a pool with no connection open.
func New[C io.Closer](cfg Config[C]) (*Pool[C], error) {
	switch {
	case cfg.Lock == "":
		return nil, errors.New("lazyconn: no lock name")
	case cfg.Asker == nil:
		return nil, errors.New("lazyconn: no asker")
	case cfg.Profile == nil:
		return nil, errors.New("lazyconn: no profile lookup")
	case cfg.Dial == nil:
		return nil, errors.New("lazyconn: no dialer")
	}
	if cfg.Idle <= 0 {
		cfg.Idle = DefaultIdle
	}
	if cfg.AskTimeout <= 0 {
		cfg.AskTimeout = DefaultAskTimeout
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = DefaultMaxAge
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.AfterFunc == nil {
		cfg.AfterFunc = func(d time.Duration, f func()) Timer { return time.AfterFunc(d, f) }
	}
	return &Pool[C]{cfg: cfg, entries: map[string]*entry[C]{}}, nil
}

// Acquire returns the connection of r.Profile, asking for it first when
// none is open: concurrent requests for a profile share one ticket and
// one connection. release gives the connection back (once; later calls do
// nothing); the last release starts the idle timer. A denial is
// ticket.ErrDenied with the reason; a later Acquire asks again.
func (p *Pool[C]) Acquire(ctx context.Context, r Request) (conn C, release func(), err error) {
	var zero C
	p.mu.Lock()
	for {
		if p.closed {
			p.mu.Unlock()
			return zero, nil, ErrClosed
		}
		e := p.entries[r.Profile]
		if e == nil {
			e = &entry[C]{}
			p.entries[r.Profile] = e
		}
		if e.open {
			e.users++
			if e.timer != nil {
				e.timer.Stop()
				e.timer = nil
			}
			c, gen := e.conn, e.gen
			p.mu.Unlock()
			return c, p.releaser(r.Profile, gen), nil
		}
		if cl := e.call; cl != nil {
			p.mu.Unlock()
			select {
			case <-cl.done:
			case <-ctx.Done():
				return zero, nil, ctx.Err()
			}
			// The asker's own context ended: ask again under ours.
			canceled := errors.Is(cl.err, context.Canceled) || errors.Is(cl.err, context.DeadlineExceeded)
			if cl.err != nil && !(canceled && ctx.Err() == nil) {
				return zero, nil, cl.err
			}
			p.mu.Lock()
			continue
		}
		cl := &call{done: make(chan struct{})}
		e.call = cl
		p.mu.Unlock()

		c, tid, d, err := p.connect(ctx, r)

		p.mu.Lock()
		e.call = nil
		if err == nil && p.closed {
			err = ErrClosed
			_ = c.Close()
		}
		cl.err = err
		close(cl.done)
		if err != nil {
			p.mu.Unlock()
			return zero, nil, err
		}
		e.conn, e.open, e.ticket = c, true, tid
		e.gen++
		e.users++
		gen := e.gen
		p.mu.Unlock()
		p.emit(Event{Kind: EventConnected, Profile: r.Profile, Ticket: tid, Decision: d})
		return c, p.releaser(r.Profile, gen), nil
	}
}

// releaser is the release of one Acquire of connection gen of profile.
func (p *Pool[C]) releaser(profile string, gen uint64) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			e := p.entries[profile]
			if e == nil || !e.open || e.gen != gen {
				return // closed since
			}
			e.users--
			if e.users > 0 {
				return
			}
			e.idleSeq++
			seq := e.idleSeq
			e.timer = p.cfg.AfterFunc(p.cfg.Idle, func() { p.idle(profile, gen, seq) })
		})
	}
}

// idle closes connection gen of profile if it is still unused since the
// timer seq was set.
func (p *Pool[C]) idle(profile string, gen, seq uint64) {
	p.mu.Lock()
	e := p.entries[profile]
	if e == nil || !e.open || e.gen != gen || e.users > 0 || e.idleSeq != seq {
		p.mu.Unlock()
		return
	}
	c, tid := e.conn, e.ticket
	var zero C
	e.conn, e.open, e.timer = zero, false, nil
	p.mu.Unlock()
	err := c.Close()
	p.emit(Event{Kind: EventClosed, Profile: profile, Ticket: tid, Err: err})
}

// Connected reports whether profile's connection is open.
func (p *Pool[C]) Connected(profile string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	e := p.entries[profile]
	return e != nil && e.open
}

// Close closes every open connection, in use or not, and refuses further
// Acquires.
func (p *Pool[C]) Close() error {
	p.mu.Lock()
	p.closed = true
	type open struct {
		profile, ticket string
		c               C
	}
	var conns []open
	var zero C
	for name, e := range p.entries {
		if e.timer != nil {
			e.timer.Stop()
			e.timer = nil
		}
		if e.open {
			conns = append(conns, open{name, e.ticket, e.conn})
			e.conn, e.open = zero, false
		}
	}
	p.mu.Unlock()
	var errs []error
	for _, o := range conns {
		err := o.c.Close()
		errs = append(errs, err)
		p.emit(Event{Kind: EventClosed, Profile: o.profile, Ticket: o.ticket, Err: err})
	}
	return errors.Join(errs...)
}

func (p *Pool[C]) emit(ev Event) {
	if p.cfg.OnEvent != nil {
		p.cfg.OnEvent(ev)
	}
}

// connect asks for r.Profile's connection and opens it.
func (p *Pool[C]) connect(ctx context.Context, r Request) (C, string, *ticket.Decision, error) {
	var zero C
	fail := func(tid string, d *ticket.Decision, err error) (C, string, *ticket.Decision, error) {
		kind := EventFailed
		if errors.Is(err, ticket.ErrDenied) {
			kind = EventDenied
		}
		p.emit(Event{Kind: kind, Profile: r.Profile, Ticket: tid, Decision: d, Err: err})
		return zero, "", nil, err
	}
	prof, err := p.cfg.Profile(r.Profile)
	if err != nil {
		return fail("", nil, err)
	}
	subj := ticket.Subject{Profile: r.Profile, Endpoint: prof.Endpoint, Credential: prof.Credential}
	var priv *ecdh.PrivateKey
	if prof.NeedSecret {
		if priv, err = ecdh.X25519().GenerateKey(rand.Reader); err != nil {
			return fail("", nil, err)
		}
		subj.SecretTo = ticket.EncodeX25519(priv.PublicKey())
	}
	risk := prof.Risk
	switch {
	case risk != "":
	case prof.NeedSecret:
		risk = ticket.RiskUnlock
	case prof.Production:
		risk = ticket.RiskProdWrite
	default:
		risk = ticket.RiskRead
	}
	now := p.cfg.Now()
	t, err := ticket.NewConnectTicket(ticket.Source{Lock: p.cfg.Lock}, risk, subj, prof.PolicyFP, now, p.cfg.AskTimeout)
	if err != nil {
		return fail("", nil, err)
	}
	t.Requester, t.Workspace = r.Requester, r.Workspace
	t.Flags.Production, t.Flags.NeverAuto = prof.Production, prof.NeverAuto
	screen := render.MaskScreen(connectScreen(r, prof), prof.Masking)

	actx, cancel := context.WithTimeout(ctx, p.cfg.AskTimeout)
	defer cancel()
	d, err := p.cfg.Asker.Ask(actx, t, screen)
	if err != nil {
		return fail(t.ID, nil, err)
	}
	// The asker checked the decision; the pool acts on it only once it
	// checked it too, against its own ticket.
	if err := d.Match(t); err != nil {
		return fail(t.ID, d, err)
	}
	if err := d.Usable(t, p.cfg.Now(), p.cfg.MaxAge); err != nil {
		if errors.Is(err, ticket.ErrDenied) && d.Reason != "" {
			err = fmt.Errorf("%w: %s", err, d.Reason)
		}
		return fail(t.ID, d, err)
	}
	secret, err := d.OpenSecret(t, priv)
	if err != nil {
		return fail(t.ID, d, err)
	}
	c, err := p.cfg.Dial(ctx, r.Profile, Grant{Ticket: t, Decision: d, Secret: secret})
	clear(secret)
	if err != nil {
		return fail(t.ID, d, err)
	}
	if cs, ok := p.cfg.Asker.(consumer); ok {
		// The hub's bookkeeping only: the connection is open either way.
		_ = cs.Consumed(ctx, t.ID)
	}
	return c, t.ID, d, nil
}

// connectScreen is the approval screen of a connect ticket.
func connectScreen(r Request, prof Profile) render.ScreenSource {
	src := render.ScreenSource{
		Header: r.Profile + " · connect",
		Note:   r.Note,
		Body: []render.Line{
			render.Structure("endpoint: " + prof.Endpoint),
			render.Structure("credentials: " + prof.Credential),
		},
		Warnings: []string{},
	}
	if prof.NeedSecret {
		src.Body = append(src.Body, render.Structure("secret: typed on the decider, sealed to the lock"))
	}
	if prof.Production {
		src.Warnings = append(src.Warnings, "production")
	}
	return src
}
