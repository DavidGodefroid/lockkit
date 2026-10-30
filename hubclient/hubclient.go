// Package hubclient is a lock's client for lockhub, the approval hub: it
// pushes signed tickets, long-polls the hub's decisions and turns an
// approval into a plan that runs once.
//
// Every request but Hello is signed with the lock instance's key (the
// Lock-Instance, Lock-Time, Lock-Nonce and Lock-Sig headers, see
// ticket.RequestMessage); every decision is verified with the hub key the
// lock pinned, never one the hub sends. A screen leaves the lock only as a
// render.MaskedScreen.
//
// The client fails closed: a hub that cannot be reached leaves the plan
// pending, and nothing falls back to another approver. A ticket the hub
// did not acknowledge is pushed again by the next Submit of its plan or by
// Sync.
package hubclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/render"
	"github.com/DavidGodefroid/lockkit/ticket"
)

var (
	// ErrUnreachable: the hub did not answer, or answered 5xx. A ticket
	// signed for the plan stays pending.
	ErrUnreachable = errors.New("hubclient: hub unreachable")
	// ErrRateLimited: too many pending tickets or too many new tickets in
	// the rate window, here or at the hub; no ticket was opened.
	ErrRateLimited = errors.New("hubclient: too many tickets")
	// ErrPending: no decision on the ticket yet.
	ErrPending = errors.New("hubclient: no decision yet")
	// ErrDenied: the human denied the ticket; the plan is Denied.
	ErrDenied = errors.New("hubclient: denied")
	// ErrBadDecision: the hub sent a decision that does not verify under
	// the pinned hub key or is not for this instance; it was dropped.
	ErrBadDecision = errors.New("hubclient: decision refused")
)

// HubError is an error answer of the hub.
type HubError struct {
	Status  int
	Code    string
	Message string
}

func (e *HubError) Error() string {
	return fmt.Sprintf("hubclient: hub answered %d %s: %s", e.Status, e.Code, e.Message)
}

// Is maps 429 to ErrRateLimited and 5xx to ErrUnreachable.
func (e *HubError) Is(target error) bool {
	switch target {
	case ErrRateLimited:
		return e.Status == http.StatusTooManyRequests
	case ErrUnreachable:
		return e.Status >= 500
	}
	return false
}

// Defaults.
const (
	// MaxPending bounds the pending tickets of an instance.
	MaxPending = 20
	// RateN new tickets per RateWindow at most.
	RateN      = 10
	RateWindow = 5 * time.Minute
	// MaxWait bounds a long poll (the hub's own bound).
	MaxWait = 60 * time.Second
	// MaxInbox bounds the decisions kept for plans not yet run.
	MaxInbox = plans.MaxPlans
	// maxAnswer bounds an answer of the hub.
	maxAnswer = 8 << 20
)

// Config configures a Client. URL, Instance, Key, HubKey and StateFile
// are required: there is no discovery and no unpinned hub.
type Config struct {
	// URL is the hub's base URL ("http://lockhub:8443").
	URL string
	// Instance is the lock instance's name (Lock-Instance, Source.Instance).
	Instance string
	// Key is the instance's Ed25519 key: it signs tickets and requests.
	Key ed25519.PrivateKey
	// HubKey is the pinned hub key decisions must verify under.
	HubKey ed25519.PublicKey
	// StateFile keeps the decision cursor and the decisions not yet acted
	// on, in the lock's volume (written 0600).
	StateFile string
	// ApprovalTTL is the instance's approval lifetime (ticket.ClampTTL; 0
	// keeps each risk class's).
	ApprovalTTL time.Duration
	// MaxPending, RateN and RateWindow override the defaults when > 0.
	MaxPending int
	RateN      int
	RateWindow time.Duration
	// HTTP is the HTTP client (nil: one without a global timeout; long
	// polls are bounded by MaxWait). Redirects are refused unless it sets
	// its own CheckRedirect.
	HTTP *http.Client
	// PlainHTTP (the flag --hub-plain-http) allows an http:// URL to a hub
	// on a network of its own (lock up's): a service name without a dot or
	// a private address only. Off, http is refused but to a loopback
	// address; use https. Requests and decisions are signed either way.
	PlainHTTP bool
	// Devices are the approval devices the lock pins (--devices-file): a
	// decision that carries a device signature, or that names the mobile
	// facade, is kept only if it verifies under one of them, over the
	// lock's own signed ticket (ticket.VerifyDevice).
	Devices []ticket.Device
	// SealClear (--seal-clear) seals each ticket's clear screen to every
	// pinned device (SubmitClear). Off, clear screens never leave the
	// lock. The device's code comes from the hub: see the ticket package
	// on what a hub that serves malicious code can read.
	SealClear bool
	// RequireDevice lists the risk classes whose approvals must be signed
	// by a pinned device, whatever facade the hub says they came from
	// (--require-device): an approval without one ends the plan Denied.
	RequireDevice []ticket.Risk
	// Now is the clock (nil: time.Now).
	Now func() time.Time
}

// Client talks to one hub for one lock instance. It is safe for
// concurrent use.
type Client struct {
	cfg  Config
	base *url.URL
	pub  ed25519.PublicKey

	pollMu sync.Mutex // one long poll at a time

	mu     sync.Mutex
	cursor int64
	inbox  map[string]entry // by ticket id
	acked  map[string]bool  // tickets the hub acknowledged, this process
	recent []time.Time      // new tickets in the rate window
}

// entry is a decision kept until its plan runs.
type entry struct {
	Seq      int64           `json:"seq"`
	Ticket   string          `json:"ticket"`
	Decision json.RawMessage `json:"decision"`
}

type state struct {
	Cursor    int64   `json:"cursor"`
	Decisions []entry `json:"decisions"`
}

// New checks cfg and loads the state file, if any.
func New(cfg Config) (*Client, error) {
	switch {
	case cfg.URL == "":
		return nil, errors.New("hubclient: no hub URL")
	case !ValidInstance(cfg.Instance):
		return nil, fmt.Errorf("hubclient: invalid instance name %q", cfg.Instance)
	case len(cfg.Key) != ed25519.PrivateKeySize:
		return nil, errors.New("hubclient: no lock key")
	case len(cfg.HubKey) != ed25519.PublicKeySize:
		return nil, errors.New("hubclient: no pinned hub key")
	case cfg.StateFile == "":
		return nil, errors.New("hubclient: no state file")
	case len(cfg.Devices) > ticket.MaxDevices:
		return nil, fmt.Errorf("hubclient: more than %d devices", ticket.MaxDevices)
	case len(cfg.RequireDevice) > 0 && len(cfg.Devices) == 0:
		return nil, errors.New("hubclient: approvals must be signed by a device, and no device is pinned")
	case cfg.SealClear && len(cfg.Devices) == 0:
		return nil, errors.New("hubclient: clear screens to seal, and no device is pinned")
	}
	seen := map[string]bool{}
	for i := range cfg.Devices {
		if err := cfg.Devices[i].Validate(); err != nil {
			return nil, fmt.Errorf("hubclient: %w", err)
		}
		if seen[cfg.Devices[i].ID] {
			return nil, fmt.Errorf("hubclient: device %s twice", cfg.Devices[i].ID)
		}
		seen[cfg.Devices[i].ID] = true
	}
	for _, r := range cfg.RequireDevice {
		if !r.Valid() {
			return nil, fmt.Errorf("hubclient: unknown risk class %q", r)
		}
	}
	base, err := url.Parse(strings.TrimRight(cfg.URL, "/"))
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil, fmt.Errorf("hubclient: bad hub URL %q", cfg.URL)
	}
	// Signatures protect integrity, not privacy: tickets carry masked
	// screens and the kinds of personal data touched.
	if base.Scheme == "http" && !loopback(base.Hostname()) {
		switch {
		case !cfg.PlainHTTP:
			return nil, fmt.Errorf("hubclient: hub URL %q: use https; plain http only to a loopback address, or with --hub-plain-http to a hub on a network of its own", cfg.URL)
		case !internalHost(base.Hostname()):
			return nil, fmt.Errorf("hubclient: hub URL %q: --hub-plain-http is only for a service name without a dot or a private address; use https", cfg.URL)
		}
	}
	if cfg.MaxPending <= 0 {
		cfg.MaxPending = MaxPending
	}
	if cfg.RateN <= 0 {
		cfg.RateN = RateN
	}
	if cfg.RateWindow <= 0 {
		cfg.RateWindow = RateWindow
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{}
	}
	if cfg.HTTP.CheckRedirect == nil {
		// A redirect would send the Lock-* headers again, elsewhere: a 3xx
		// is the answer, an error like any other non-2xx.
		h := *cfg.HTTP
		h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		cfg.HTTP = &h
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	c := &Client{cfg: cfg, base: base, pub: cfg.Key.Public().(ed25519.PublicKey),
		inbox: map[string]entry{}, acked: map[string]bool{}}
	if err := c.load(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) load() error {
	fi, err := os.Lstat(c.cfg.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("hubclient: %w", err)
	}
	// The cursor and the decisions not yet acted on: a file another account
	// could write, or a link to one, is not the lock's.
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("hubclient: state file %s is not a plain file", c.cfg.StateFile)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("hubclient: state file %s is mode %v (want no group or other access)", c.cfg.StateFile, fi.Mode().Perm())
	}
	b, err := os.ReadFile(c.cfg.StateFile)
	if err != nil {
		return fmt.Errorf("hubclient: %w", err)
	}
	var s state
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("hubclient: state file: %w", err)
	}
	c.cursor = s.Cursor
	for _, e := range s.Decisions {
		c.inbox[e.Ticket] = e
	}
	return nil
}

// save writes the state file atomically. Locked.
func (c *Client) save() error {
	s := state{Cursor: c.cursor, Decisions: make([]entry, 0, len(c.inbox))}
	for _, e := range c.inbox {
		s.Decisions = append(s.Decisions, e)
	}
	sort.Slice(s.Decisions, func(i, j int) bool { return s.Decisions[i].Seq < s.Decisions[j].Seq })
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	dir := filepath.Dir(c.cfg.StateFile)
	f, err := os.CreateTemp(dir, "."+filepath.Base(c.cfg.StateFile)+".*.tmp")
	if err != nil {
		return fmt.Errorf("hubclient: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return fmt.Errorf("hubclient: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return fmt.Errorf("hubclient: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("hubclient: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("hubclient: %w", err)
	}
	if err := os.Rename(tmp, c.cfg.StateFile); err != nil {
		return fmt.Errorf("hubclient: %w", err)
	}
	return nil
}

// do sends one request, signed unless it is the hello, and decodes a 2xx
// JSON answer into out (nil: ignored).
func (c *Client) do(ctx context.Context, method, pathQuery string, body []byte, signed bool, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+pathQuery, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("hubclient: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if signed {
		now, nonce := c.cfg.Now(), ticket.NewNonce()
		req.Header.Set("Lock-Instance", c.cfg.Instance)
		req.Header.Set("Lock-Time", strconv.FormatInt(now.Unix(), 10))
		req.Header.Set("Lock-Nonce", nonce)
		req.Header.Set("Lock-Sig", ticket.SignBytes(c.cfg.Key, ticket.ContextRequest,
			ticket.RequestMessage(method, req.URL.RequestURI(), c.cfg.Instance, now, nonce, body)))
	}
	resp, err := c.cfg.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	if len(b) > maxAnswer {
		return fmt.Errorf("hubclient: answer longer than %d bytes", maxAnswer)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		he := &HubError{Status: resp.StatusCode}
		var e struct{ Error, Message string }
		if json.Unmarshal(b, &e) == nil {
			he.Code, he.Message = e.Error, e.Message
		}
		return he
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("hubclient: hub answer: %w", err)
		}
	}
	return nil
}

// Hello is the hub's answer to GET /v1/hello.
type Hello struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	API     int    `json:"api"`
}

// Hello asks the hub who it is (unsigned; it proves nothing about the hub).
func (c *Client) Hello(ctx context.Context) (Hello, error) {
	var h Hello
	if err := c.do(ctx, http.MethodGet, "/v1/hello", nil, false, &h); err != nil {
		return Hello{}, err
	}
	if h.API != 1 {
		return h, fmt.Errorf("hubclient: hub speaks API %d, not 1", h.API)
	}
	return h, nil
}

// push sends p's signed ticket; a 410 ends the plan Expired.
func (c *Client) push(ctx context.Context, st *plans.Store, p *plans.Plan, caller plans.Caller) error {
	err := c.pushRaw(ctx, p.Ticket, p.SignedTicket)
	var he *HubError
	if errors.As(err, &he) && he.Status == http.StatusGone {
		_ = st.End(p.ID, caller, plans.Expired, "expired at the hub")
	}
	return err
}

// resend pushes p's ticket again unless the hub acknowledged it.
func (c *Client) resend(ctx context.Context, st *plans.Store, p *plans.Plan, caller plans.Caller) (string, error) {
	c.mu.Lock()
	acked := c.acked[p.Ticket]
	c.mu.Unlock()
	if acked {
		return p.Ticket, nil
	}
	return p.Ticket, c.push(ctx, st, p, caller)
}

// Submit asks the hub for a decision on plan planID of caller and returns
// the ticket id. t is the product's ticket for the plan (NewTicket; its
// plan hash and policy fingerprint the plan's); Submit sets its instance,
// key id, screen and touched kinds from screen, signs it, records it in st
// and pushes it.
//
// Submit is idempotent: a plan already pending returns its ticket, and a
// pending plan of caller with the same plan hash lends its ticket instead
// of opening a new one. A screen MaskScreen did not build is refused
// (render.ErrUnmasked). With the hub unreachable, Submit returns the ticket
// id with ErrUnreachable: the plan is pending, and the ticket goes out on a
// later Submit or Sync.
func (c *Client) Submit(ctx context.Context, st *plans.Store, planID string, caller plans.Caller, t *ticket.Ticket, screen render.MaskedScreen) (string, error) {
	return c.SubmitClear(ctx, st, planID, caller, t, screen, nil)
}

// SubmitClear is Submit with the clear screen of the request: with
// Config.SealClear, it is sealed to each pinned device
// (ticket.SealClearScreen) in the ticket, which the hub relays without
// being able to read it; otherwise, with clear nil, or a clear screen over
// ticket.MaxClearScreen, it is not sent at all.
func (c *Client) SubmitClear(ctx context.Context, st *plans.Store, planID string, caller plans.Caller, t *ticket.Ticket, screen render.MaskedScreen, clear *ticket.Screen) (string, error) {
	if !screen.Valid() {
		return "", render.ErrUnmasked
	}
	p, err := st.Get(planID, caller)
	if err != nil {
		return "", err
	}
	switch p.State {
	case plans.Pending:
		return c.resend(ctx, st, p, caller)
	case plans.Planned:
	default:
		return "", fmt.Errorf("%w: plan is %s", plans.ErrUsed, p.State)
	}
	if other, ok := st.FindPending(caller, p.Binding.PlanHash); ok {
		return c.resend(ctx, st, other, caller)
	}
	var boxes []ticket.DeviceBox
	if c.cfg.SealClear && clear != nil {
		for i := range c.cfg.Devices {
			box, err := ticket.SealClearScreen(&c.cfg.Devices[i], t.ID, *clear)
			if errors.Is(err, ticket.ErrTooLarge) {
				boxes = nil // the masked screen only
				break
			} else if err != nil {
				return "", err
			}
			boxes = append(boxes, *box)
		}
	}

	c.mu.Lock()
	now := c.cfg.Now()
	kept := c.recent[:0]
	for _, at := range c.recent {
		if now.Sub(at) < c.cfg.RateWindow {
			kept = append(kept, at)
		}
	}
	c.recent = kept
	switch {
	case len(st.Pending()) >= c.cfg.MaxPending:
		c.mu.Unlock()
		return "", fmt.Errorf("%w: %d tickets already pending", ErrRateLimited, c.cfg.MaxPending)
	case len(c.recent) >= c.cfg.RateN:
		c.mu.Unlock()
		return "", fmt.Errorf("%w: %d new tickets in %s", ErrRateLimited, c.cfg.RateN, c.cfg.RateWindow)
	}
	c.recent = append(c.recent, now)
	c.mu.Unlock()

	t.Source.Instance, t.Source.KeyID = c.cfg.Instance, ticket.KeyID(c.pub)
	t.Screen, t.PII.Touched = screen.Screen(), screen.Touched()
	t.PII.SealedFor = boxes
	if err := t.Sign(c.cfg.Key); err != nil {
		return "", err
	}
	if err := st.MarkPending(planID, caller, t); err != nil {
		return "", err
	}
	if p, err = st.Get(planID, caller); err != nil {
		return "", err
	}
	return t.ID, c.push(ctx, st, p, caller)
}

// Sync pushes every pending ticket the hub has not acknowledged since
// this client started: after a restart of the lock or of the hub.
func (c *Client) Sync(ctx context.Context, st *plans.Store) error {
	var errs []error
	for _, p := range st.Pending() {
		c.mu.Lock()
		acked := c.acked[p.Ticket]
		c.mu.Unlock()
		if acked {
			continue
		}
		// Sync acts for the lock, not for an agent: it has no caller token,
		// so it pushes the stored signed ticket as it is.
		if err := c.pushRaw(ctx, p.Ticket, p.SignedTicket); err != nil {
			errs = append(errs, fmt.Errorf("ticket %s: %w", p.Ticket, err))
		}
	}
	return errors.Join(errs...)
}

func (c *Client) pushRaw(ctx context.Context, id string, raw []byte) error {
	var res struct {
		Ticket string `json:"ticket"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/tickets", raw, true, &res); err != nil {
		return err
	}
	if res.Ticket != id {
		return fmt.Errorf("hubclient: hub acknowledged ticket %q, not %s", res.Ticket, id)
	}
	c.mu.Lock()
	c.acked[id] = true
	c.mu.Unlock()
	return nil
}

// Poll long-polls the hub once, waiting up to wait (at most MaxWait) for
// decisions after the cursor, keeps those that verify under the pinned hub
// key for this instance, and advances and saves the cursor. It returns
// how many decisions it kept; decisions it dropped make ErrBadDecision.
func (c *Client) Poll(ctx context.Context, wait time.Duration) (int, error) {
	c.pollMu.Lock()
	defer c.pollMu.Unlock()
	wait = min(max(wait, 0), MaxWait)
	c.mu.Lock()
	since := c.cursor
	c.mu.Unlock()
	var res struct {
		Decisions []entry `json:"decisions"`
		Cursor    int64   `json:"cursor"`
	}
	q := "/v1/decisions?since=" + strconv.FormatInt(since, 10) + "&wait=" + strconv.Itoa(int(wait/time.Second))
	if err := c.do(ctx, http.MethodGet, q, nil, true, &res); err != nil {
		return 0, err
	}
	if res.Cursor < since {
		return 0, fmt.Errorf("hubclient: hub moved the cursor back from %d to %d", since, res.Cursor)
	}
	var bad []error
	kept := 0
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range res.Decisions {
		if e.Seq <= since || e.Seq > res.Cursor {
			bad = append(bad, fmt.Errorf("%w: seq %d outside (%d, %d]", ErrBadDecision, e.Seq, since, res.Cursor))
			continue
		}
		if _, err := c.verify(e); err != nil {
			bad = append(bad, err)
			continue
		}
		c.inbox[e.Ticket] = e
		kept++
	}
	for len(c.inbox) > MaxInbox {
		oldest := ""
		for id, e := range c.inbox {
			if oldest == "" || e.Seq < c.inbox[oldest].Seq {
				oldest = id
			}
		}
		delete(c.inbox, oldest)
	}
	c.cursor = res.Cursor
	if err := c.save(); err != nil {
		return kept, err
	}
	return kept, errors.Join(bad...)
}

// verify checks a decision as the hub sent it: signed by the pinned hub
// key, for this instance and this lock key, for the ticket it is filed
// under; and, taken on a device (a device signature, or the mobile
// facade), naming a device this lock pins (Begin verifies the device's
// signature over the lock's own ticket).
func (c *Client) verify(e entry) (*ticket.Decision, error) {
	d, err := ticket.VerifyDecision(c.cfg.HubKey, e.Decision)
	switch {
	case err != nil:
		return nil, fmt.Errorf("%w: ticket %s: %v", ErrBadDecision, e.Ticket, err)
	case d.Ticket != e.Ticket || d.Instance != c.cfg.Instance || d.KeyID != ticket.KeyID(c.pub):
		return nil, fmt.Errorf("%w: ticket %s: not for this instance", ErrBadDecision, e.Ticket)
	}
	if d.Device != nil || d.Facade == ticket.FacadeMobile {
		// The assertion is checked against the lock's own ticket in Begin;
		// here only that it names a device this lock pins.
		if _, err := c.device(d); err != nil {
			return nil, fmt.Errorf("%w: ticket %s: %v", ErrBadDecision, e.Ticket, err)
		}
	}
	return d, nil
}

// device is the pinned device d names.
func (c *Client) device(d *ticket.Decision) (*ticket.Device, error) {
	if d.Device == nil {
		return nil, fmt.Errorf("%w: a decision of the mobile facade without a device signature", ticket.ErrDevice)
	}
	for i := range c.cfg.Devices {
		if c.cfg.Devices[i].ID == d.Device.Device {
			return &c.cfg.Devices[i], nil
		}
	}
	return nil, fmt.Errorf("%w: device %s is not pinned by this lock", ticket.ErrDevice, d.Device.Device)
}

// verifyDevice checks d's device signature under the pinned device it
// names, over the lock's own signed ticket own.
func (c *Client) verifyDevice(d *ticket.Decision, own *ticket.Ticket) error {
	dev, err := c.device(d)
	if err != nil {
		return err
	}
	signed, err := own.Marshal()
	if err != nil {
		return err
	}
	return ticket.VerifyDevice(dev, d, signed)
}

// needsDevice reports whether approvals of risk must be device-signed.
func (c *Client) needsDevice(r ticket.Risk) bool {
	for _, x := range c.cfg.RequireDevice {
		if x == r {
			return true
		}
	}
	return false
}

// Watch polls until ctx ends, backing off while the hub is unreachable and
// resending unacknowledged tickets (Sync) when it answers again. Errors
// go to report (nil: dropped).
func (c *Client) Watch(ctx context.Context, st *plans.Store, report func(error)) {
	backoff, down := time.Second, true
	for ctx.Err() == nil {
		if down {
			if err := c.Sync(ctx, st); err != nil && report != nil {
				report(err)
			}
		}
		_, err := c.Poll(ctx, MaxWait/2)
		down = errors.Is(err, ErrUnreachable)
		if err != nil && ctx.Err() == nil && report != nil {
			report(err)
		}
		if !down {
			backoff = time.Second
			if err == nil || errors.Is(err, ErrBadDecision) {
				continue
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, MaxWait)
	}
}

// Recheck recomputes, just before running, the policy fingerprint and plan
// hash of a plan from its body and the lock's current state.
type Recheck func(p *plans.Plan) (policyFP, planHash string, err error)

// Begin turns the decision on ticketID into a run of its plan, for caller
// (the agent that made the plan): the decision verifies under the pinned
// hub key and matches the ticket the lock signed (ticket.Decision.Match),
// is still usable, and the plan's binding has not moved (recheck,
// plans.Store.Check). The plan comes back Executing under the decision's
// nonce, consumed: the product runs it, then calls Finish.
//
// Begin also returns the verified decision, for the lock's audit (who
// approved, on which facade, the hub's signature), with the plan or with
// the error of a decision that was matched but not acted on.
//
// A decision taken on a device (facade mobile) must carry the signature of
// a pinned device over the lock's own signed ticket (ticket.VerifyDevice),
// and with Config.RequireDevice an approval of those risk classes must.
//
// No decision yet is ErrPending; a denial ends the plan Denied and is
// ErrDenied with the human's reason; a decision too old or past the
// ticket ends it Expired.
func (c *Client) Begin(st *plans.Store, ticketID string, caller plans.Caller, recheck Recheck) (*plans.Plan, *ticket.Decision, error) {
	p, err := st.ByTicket(ticketID, caller)
	if err != nil {
		return nil, nil, err
	}
	if p.State != plans.Pending {
		return nil, nil, fmt.Errorf("%w: plan is %s", plans.ErrUsed, p.State)
	}
	c.mu.Lock()
	e, ok := c.inbox[ticketID]
	c.mu.Unlock()
	if !ok {
		return nil, nil, ErrPending
	}
	d, err := c.verify(e)
	if err != nil {
		c.drop(ticketID)
		return nil, nil, err
	}
	own, err := p.LockTicket(c.pub)
	if err != nil {
		return nil, nil, err
	}
	if err := d.Match(own); err != nil {
		c.drop(ticketID)
		return nil, nil, fmt.Errorf("%w: %v", ErrBadDecision, err)
	}
	if d.Device != nil || d.Facade == ticket.FacadeMobile {
		if err := c.verifyDevice(d, own); err != nil {
			c.drop(ticketID)
			return nil, nil, fmt.Errorf("%w: %v", ErrBadDecision, err)
		}
	}
	if d.Decision == ticket.Denied {
		if err := st.End(p.ID, caller, plans.Denied, d.Reason); err != nil {
			return nil, d, err
		}
		c.drop(ticketID)
		if d.Reason == "" {
			return nil, d, ErrDenied
		}
		return nil, d, fmt.Errorf("%w: %s", ErrDenied, d.Reason)
	}
	if d.Device == nil && c.needsDevice(own.Risk) {
		// verify checked any device signature; here there is none, and
		// this lock wants one: the hub's approval alone is not enough.
		reason := fmt.Sprintf("a %s approval must be signed by a pinned device; this one came from facade %q", own.Risk, d.Facade)
		if err := st.End(p.ID, caller, plans.Denied, reason); err != nil {
			return nil, d, err
		}
		c.drop(ticketID)
		return nil, d, fmt.Errorf("%w: %w: %s", ErrBadDecision, ticket.ErrDevice, reason)
	}
	if err := d.Usable(own, c.cfg.Now(), ticket.ClampTTL(own.Risk, c.cfg.ApprovalTTL)); err != nil {
		if errors.Is(err, ticket.ErrExpired) {
			_ = st.End(p.ID, caller, plans.Expired, err.Error())
		}
		c.drop(ticketID)
		return nil, d, err
	}
	fp, hash, err := recheck(p)
	if err != nil {
		return nil, d, err
	}
	if err := st.Check(p.ID, caller, fp, hash); err != nil {
		if errors.Is(err, plans.ErrStale) {
			c.drop(ticketID)
		}
		return nil, d, err
	}
	if err := st.Begin(p.ID, caller, d.Nonce); err != nil {
		return nil, d, err
	}
	c.drop(ticketID)
	p, err = st.Get(p.ID, caller)
	if err != nil {
		return nil, d, err
	}
	return p, d, nil
}

// drop forgets the decision on ticketID.
func (c *Client) drop(ticketID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.inbox[ticketID]; ok {
		delete(c.inbox, ticketID)
		_ = c.save()
	}
}

// Finish ends an executing plan (plans.Store.Finish) and tells the hub its
// ticket was consumed. The plan is finished even when the hub cannot be
// told; the error says so.
func (c *Client) Finish(ctx context.Context, st *plans.Store, planID string, caller plans.Caller, ok bool, reason string) error {
	p, err := st.Get(planID, caller)
	if err != nil {
		return err
	}
	if err := st.Finish(planID, caller, ok, reason); err != nil {
		return err
	}
	if p.Ticket == "" {
		return nil
	}
	return c.do(ctx, http.MethodPost, "/v1/tickets/"+url.PathEscape(p.Ticket)+"/consumed", nil, true, nil)
}

// Withdraw ends a plan not yet run as Withdrawn and withdraws its ticket
// at the hub. The plan is withdrawn even when the hub cannot be told; the
// error says so.
func (c *Client) Withdraw(ctx context.Context, st *plans.Store, planID string, caller plans.Caller, reason string) error {
	p, err := st.Get(planID, caller)
	if err != nil {
		return err
	}
	if err := st.End(planID, caller, plans.Withdrawn, reason); err != nil {
		return err
	}
	if p.Ticket == "" {
		return nil
	}
	c.drop(p.Ticket)
	body, _ := json.Marshal(struct {
		Reason string `json:"reason,omitempty"`
	}{reason})
	return c.do(ctx, http.MethodPost, "/v1/tickets/"+url.PathEscape(p.Ticket)+"/withdraw", body, true, nil)
}

// loopback reports a loopback host name or address.
func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}

// internalHost reports a host plain http may reach with PlainHTTP: a name
// without a dot (a compose service name) or a private address.
func internalHost(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().IsPrivate()
	}
	return host != "" && !strings.Contains(host, ".")
}
