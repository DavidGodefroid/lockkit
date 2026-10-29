package console

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/render"
	"github.com/DavidGodefroid/lockkit/sanitize"
	"github.com/DavidGodefroid/lockkit/ticket"
)

// HubOptions put a console in hub mode: requests are decided on lockhub,
// never on this terminal. They are the console flags `lock up` writes:
// --hub URL --hub-key-file PATH --instance NAME, all three or none. There
// is no discovery: without them the console is standalone.
type HubOptions struct {
	// URL is the hub's base URL ("http://lockhub:8443").
	URL string
	// KeyFile holds the pinned hub key (hubclient.ReadHubKey).
	KeyFile string
	// Instance is the lock instance's name (hubclient.ValidInstance).
	Instance string
	// Home is the lock's home volume, where the instance key lives
	// (hubclient.InstanceKey, made by `hub-key`); "" is the user's home.
	Home string
}

// Register adds the hub flags to fs.
func (h *HubOptions) Register(fs *flag.FlagSet) {
	fs.StringVar(&h.URL, "hub", "", "decide requests on lockhub at this URL instead of this terminal (with --hub-key-file and --instance)")
	fs.StringVar(&h.KeyFile, "hub-key-file", "", "the pinned public key of the hub (base64, one line)")
	fs.StringVar(&h.Instance, "instance", "", "the lock instance name the hub knows this console by")
}

// Enabled reports whether any hub flag is set.
func (h HubOptions) Enabled() bool { return h.URL != "" || h.KeyFile != "" || h.Instance != "" }

func (h HubOptions) check() error {
	switch {
	case h.URL == "" || h.KeyFile == "" || h.Instance == "":
		return fmt.Errorf("%w: --hub, --hub-key-file and --instance go together", ErrConfig)
	case !hubclient.ValidInstance(h.Instance):
		return fmt.Errorf("%w: invalid instance name %q", ErrConfig, h.Instance)
	}
	return nil
}

// HubTicket is what a product adds to a Screen in hub mode: the plan the
// decision is about and the masked screen the hub shows. A Screen without
// one is refused in hub mode, never asked on the terminal.
type HubTicket struct {
	// PlanID is the plan in Hub.Store, made by Caller.
	PlanID string
	Caller plans.Caller
	Risk   ticket.Risk
	// Masked is the screen as it leaves the lock (render.MaskScreen).
	Masked render.MaskedScreen
	// Requester and Workspace are shown by the hub (display only).
	Requester ticket.Requester
	Workspace string
}

// Hub is a console's hub mode: the plans awaiting a decision and the hub
// client. A product runs a decided ticket with Client.Begin, then
// Client.Finish.
type Hub struct {
	Client   *hubclient.Client
	Store    *plans.Store
	Instance string
	lock     string
	now      func() time.Time
}

// HubOf returns env's hub, nil when the console is standalone.
func HubOf(env Env) *Hub {
	if h, ok := env.(interface{ Hub() *Hub }); ok {
		return h.Hub()
	}
	return nil
}

// OpenHub opens the hub mode of product p: it checks o, reads the pinned
// hub key and the instance key, and opens the plans and the hub state
// under the product's state directory (stateDir as Options.StateDir; now
// nil is time.Now). Run calls it; a product with its own console
// lifecycle calls it too, then Approver and Watch.
func OpenHub(p kit.Product, o HubOptions, stateDir string, now func() time.Time) (*Hub, error) {
	if err := o.check(); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	hubKey, err := hubclient.ReadHubKey(o.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	home := o.Home
	if home == "" {
		if home, err = os.UserHomeDir(); err != nil {
			return nil, err
		}
	}
	key, err := hubclient.InstanceKey(home, o.Instance)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(stateDir, p.Name, "hub", o.Instance)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("console: %w", err)
	}
	st, err := plans.Open(filepath.Join(dir, "plans"), plans.WithClock(now))
	if err != nil {
		return nil, err
	}
	c, err := hubclient.New(hubclient.Config{URL: o.URL, Instance: o.Instance, Key: key, HubKey: hubKey,
		StateFile: filepath.Join(dir, "state.json"), Now: now})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	return &Hub{Client: c, Store: st, Instance: o.Instance, lock: p.Name, now: now}, nil
}

// Approver is the hub approver: requests (a Decision with a Screen) go to
// the hub, the console's own decisions to base.
func (h *Hub) Approver(base Approver) AsyncApprover {
	return &hubApprover{Approver: base, hub: h, lock: h.lock, now: h.now}
}

// Watch delivers the hub's decisions until ctx ends, printing its errors
// on io (hubclient.Client.Watch).
func (h *Hub) Watch(ctx context.Context, io IO) { h.Client.Watch(ctx, h.Store, watchReport(io)) }

// hubApprover hands requests to the hub; the console's own decisions (a
// policy change, unmask) stay with the terminal approver it wraps.
type hubApprover struct {
	Approver
	hub  *Hub
	lock string
	now  func() time.Time
}

// errNoHubTicket: the product drew a screen without a HubTicket.
var errNoHubTicket = errors.New("the request carries no hub ticket")

// Submit builds the ticket of d's plan and pushes it (hubclient.Submit).
func (a *hubApprover) Submit(ctx context.Context, d Decision) (Pending, error) {
	if d.Screen == nil || d.Screen.Hub == nil {
		return Pending{}, errNoHubTicket
	}
	h := d.Screen.Hub
	p, err := a.hub.Store.Get(h.PlanID, h.Caller)
	if err != nil {
		return Pending{}, err
	}
	t := ticket.NewTicket(ticket.Source{Lock: a.lock}, h.Risk, p.Binding.PlanHash, p.Binding.PolicyFP, a.now(), ticket.ClampTTL(h.Risk, 0))
	t.Workspace, t.Requester = h.Workspace, h.Requester
	t.Flags = ticket.Flags{Production: d.Production, NeverAuto: d.Screen.NeverAuto, Retype: d.Retype}
	id, err := a.hub.Client.Submit(ctx, a.hub.Store, h.PlanID, h.Caller, t, h.Masked)
	return Pending{Ticket: id}, err
}

// watchReport prints the hub client's errors, each once in a row.
func watchReport(io IO) func(error) {
	last := ""
	return func(err error) {
		if msg := err.Error(); msg != last {
			last = msg
			io.Println(Paint.Warn("hub: " + sanitize.Terminal(msg, false)))
		}
	}
}

// Withdraw takes back the ticket of d's plan (the console could not record
// it): the plan ends Withdrawn here, then at the hub.
func (a *hubApprover) Withdraw(ctx context.Context, d Decision, _ string, reason string) error {
	if d.Screen == nil || d.Screen.Hub == nil {
		return errNoHubTicket
	}
	return a.hub.Client.Withdraw(ctx, a.hub.Store, d.Screen.Hub.PlanID, d.Screen.Hub.Caller, reason)
}
