package console

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/ipc"
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
	// PlainHTTP lets URL be http:// to a hub on a network of its own
	// (--hub-plain-http, hubclient.Config.PlainHTTP).
	PlainHTTP bool
	// DevicesFile holds the approval devices this lock pins
	// (--devices-file, hubclient.ReadDevices): decisions taken on a device
	// must carry its signature, and the clear screen is sealed to each.
	DevicesFile string
	// RequireDevice lists the risk classes whose approvals must be signed
	// by a pinned device (--require-device, comma-separated).
	RequireDevice string
	// SealClear seals the clear screen to the pinned devices
	// (--seal-clear, hubclient.Config.SealClear).
	SealClear bool
	// FacadeKeysFile holds the facade keys this lock pins
	// (--facade-keys-file, hubclient.ReadFacades): a reveal (Ctrl-O on a
	// local facade) is sealed only to a key one of them signed.
	FacadeKeysFile string
	// Home is the lock's home volume, where the instance key lives
	// (hubclient.InstanceKey, made by `hub-key`); "" is the user's home.
	Home string
}

// Register adds the hub flags to fs.
func (h *HubOptions) Register(fs *flag.FlagSet) {
	fs.StringVar(&h.URL, "hub", "", "decide requests on lockhub at this URL instead of this terminal (with --hub-key-file and --instance)")
	fs.StringVar(&h.KeyFile, "hub-key-file", "", "the pinned public key of the hub (base64, one line)")
	fs.StringVar(&h.Instance, "instance", "", "the lock instance name the hub knows this console by")
	fs.BoolVar(&h.PlainHTTP, "hub-plain-http", false, "allow an http:// hub URL on a network of its own (a service name without a dot or a private address)")
	fs.StringVar(&h.DevicesFile, "devices-file", "", "the approval devices this lock pins (JSON, written by lock up): device decisions must carry their signature")
	fs.StringVar(&h.FacadeKeysFile, "facade-keys-file", "", "the facade keys this lock pins (JSON, written by lock up): reveals are sealed only to them")
	fs.StringVar(&h.RequireDevice, "require-device", "", "risk classes (comma-separated) whose approvals must be signed by a pinned device, from any facade")
	fs.BoolVar(&h.SealClear, "seal-clear", false, "send the clear screen sealed to the pinned devices (end to end; the hub relays ciphertext)")
}

// Args are the flags of h, as Register reads them back: what a product
// that starts its console again (a handoff) passes on.
func (h HubOptions) Args() []string {
	var out []string
	if h.URL != "" {
		out = append(out, "--hub", h.URL)
	}
	if h.KeyFile != "" {
		out = append(out, "--hub-key-file", h.KeyFile)
	}
	if h.Instance != "" {
		out = append(out, "--instance", h.Instance)
	}
	if h.PlainHTTP {
		out = append(out, "--hub-plain-http")
	}
	if h.DevicesFile != "" {
		out = append(out, "--devices-file", h.DevicesFile)
	}
	if h.RequireDevice != "" {
		out = append(out, "--require-device", h.RequireDevice)
	}
	if h.SealClear {
		out = append(out, "--seal-clear")
	}
	if h.FacadeKeysFile != "" {
		out = append(out, "--facade-keys-file", h.FacadeKeysFile)
	}
	return out
}

// Enabled reports whether any hub flag is set.
func (h HubOptions) Enabled() bool {
	return h.URL != "" || h.KeyFile != "" || h.Instance != "" || h.PlainHTTP || h.DevicesFile != "" || h.RequireDevice != "" || h.SealClear || h.FacadeKeysFile != ""
}

func (h HubOptions) check() error {
	switch {
	case h.URL == "" || h.KeyFile == "" || h.Instance == "":
		return fmt.Errorf("%w: --hub, --hub-key-file and --instance go together", ErrConfig)
	case !hubclient.ValidInstance(h.Instance):
		return fmt.Errorf("%w: invalid instance name %q", ErrConfig, h.Instance)
	case h.RequireDevice != "" && h.DevicesFile == "":
		return fmt.Errorf("%w: --require-device needs --devices-file", ErrConfig)
	case h.SealClear && h.DevicesFile == "":
		return fmt.Errorf("%w: --seal-clear needs --devices-file", ErrConfig)
	}
	if _, err := hubclient.ParseRisks(h.RequireDevice); err != nil {
		return fmt.Errorf("%w: --require-device: %v", ErrConfig, err)
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
	var devices []ticket.Device
	if o.DevicesFile != "" {
		if devices, err = hubclient.ReadDevices(o.DevicesFile); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrConfig, err)
		}
	}
	require, _ := hubclient.ParseRisks(o.RequireDevice) // checked by o.check
	if (len(require) > 0 || o.SealClear) && len(devices) == 0 {
		return nil, fmt.Errorf("%w: --require-device, and %s pins no device", ErrConfig, o.DevicesFile)
	}
	var facades []ticket.PinnedFacade
	if o.FacadeKeysFile != "" {
		if facades, err = hubclient.ReadFacades(o.FacadeKeysFile); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrConfig, err)
		}
	}
	dir := filepath.Join(stateDir, p.Name, "hub", o.Instance)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("console: %w", err)
	}
	st, err := plans.Open(filepath.Join(dir, "plans"), plans.WithClock(now))
	if err != nil {
		return nil, err
	}
	c, err := hubclient.New(hubclient.Config{URL: o.URL, Instance: o.Instance, Key: key, HubKey: hubKey, PlainHTTP: o.PlainHTTP,
		StateFile: filepath.Join(dir, "state.json"), Now: now, Devices: devices, RequireDevice: require, SealClear: o.SealClear, Facades: facades})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	return &Hub{Client: c, Store: st, Instance: o.Instance, lock: p.Name, now: now}, nil
}

// Close releases the plans store (its directory lock): Run closes its
// hub when it returns.
func (h *Hub) Close() error { return h.Store.Close() }

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
	// The screen this console would show: sealed to the pinned devices
	// only (SubmitClear), never sent as it is.
	s := d.Screen
	clear := &ticket.Screen{Header: s.Header, Note: s.Note, Body: s.Body, Warnings: s.Warnings, Red: s.Red}
	id, err := a.hub.Client.SubmitClear(ctx, a.hub.Store, h.PlanID, h.Caller, t, h.Masked, clear)
	return Pending{Ticket: id, Instance: a.hub.Instance}, err
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

// RenewResp answers the run of expired ticket tk (Client.Begin returned
// ticket.ErrExpired): the ticket is renewed (Client.Renew, decision H1)
// and the agent hears pending with the new ticket, which it runs once
// decided. A ticket that cannot be renewed answers CodeTimeout.
func (h *Hub) RenewResp(ctx context.Context, id int64, tk string, caller plans.Caller) ipc.Response {
	n, err := h.Client.Renew(ctx, h.Store, tk, caller)
	if err != nil && n == "" {
		return ErrResp(id, ipc.CodeTimeout, "ticket expired, and could not be asked again: plan the request again")
	}
	// Pushed or not (hub down), the renewal is pending: it goes out later.
	return PendingResp(id, h.lock, Pending{Ticket: n, Instance: h.Instance})
}

// Requests audits and prints the hub requests the lock acts on (reveals
// and renewals) through rec and io. Run sets it; a product with its own
// console lifecycle calls it with its own audit.
func (h *Hub) Requests(io IO, rec func(audit.Base)) {
	h.Client.OnRequest(func(q *ticket.HubRequest, renewal string, err error) {
		if q == nil {
			io.Println(Paint.Warn("hub: " + sanitize.Terminal(err.Error(), false)))
			return
		}
		b := audit.Base{Ticket: q.Ticket, Approver: &ticket.Approver{ID: q.Approver.ID, Display: q.Approver.Display}, Facade: q.Facade, Approval: "hub"}
		who := sanitize.Terminal(q.Approver.ID+" on "+q.Facade, false)
		switch q.Kind {
		case ticket.RequestReveal:
			b.Event, b.Decision = audit.EventReveal, "sealed"
		default:
			b.Event, b.Decision = audit.EventRenew, "renewed"
		}
		if err != nil {
			b.Decision, b.Error = "refused", err.Error()
			io.Println(Paint.Warn(fmt.Sprintf("ticket %s: %s by %s refused: %s", q.Ticket, q.Kind, who, sanitize.Terminal(err.Error(), false))))
		} else if q.Kind == ticket.RequestReveal {
			io.Println(Paint.Step(fmt.Sprintf("ticket %s: clear screen sealed to %s", q.Ticket, who)))
		} else {
			b.Reason = "renewed by ticket " + renewal
			io.Println(Paint.Step(fmt.Sprintf("ticket %s: asked again by %s as ticket %s", q.Ticket, who, renewal)))
		}
		rec(b)
	})
}
