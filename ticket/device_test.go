package ticket_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"
	"github.com/DavidGodefroid/lockkit/ticket/devicetest"
)

var (
	b64     = base64.RawURLEncoding
	hubKey  = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	hubPub  = hubKey.Public().(ed25519.PublicKey)
	lockKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	t0      = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
)

const (
	rpID   = "hub.example.net"
	origin = "https://hub.example.net"
)

func newTicket(t *testing.T, inst string) *ticket.Ticket {
	t.Helper()
	plan, _ := ticket.HashOf("plan " + inst)
	fp, _ := ticket.HashOf("policy")
	tk := ticket.NewTicket(ticket.Source{Lock: "locksql", Instance: inst}, ticket.RiskWrite, plan, fp, t0, 0)
	if err := tk.Sign(lockKey); err != nil {
		t.Fatal(err)
	}
	return tk
}

func deviceDecision(t *testing.T, a *devicetest.Authenticator, tk *ticket.Ticket) *ticket.Decision {
	t.Helper()
	d := &ticket.Decision{V: ticket.Version, Ticket: tk.ID, Instance: tk.Source.Instance, KeyID: tk.Source.KeyID,
		PlanHash: tk.PlanHash, Decision: ticket.Approved, At: t0.Add(time.Minute), Nonce: ticket.NewNonce(),
		HubKeyID: ticket.KeyID(hubPub)}
	a.Decide(d)
	if err := d.Sign(hubKey); err != nil {
		t.Fatal(err)
	}
	return d
}

func roundTrip(t *testing.T, d *ticket.Decision) *ticket.Decision {
	t.Helper()
	b, err := d.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ticket.VerifyDecision(hubPub, b)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestDeviceDecisionVerifies(t *testing.T) {
	a := devicetest.New(rpID, origin, "phone")
	dev := a.Device()
	if err := dev.Validate(); err != nil {
		t.Fatal(err)
	}
	d := roundTrip(t, deviceDecision(t, a, newTicket(t, "crm")))
	if err := ticket.VerifyDevice(&dev, d); err != nil {
		t.Fatal(err)
	}
}

// The hub holds its own key, not the device's: whatever it changes in a
// device decision, or a device decision it makes up, it can re-sign with
// its key, and the device signature no longer verifies.
func TestHubCannotForgeDeviceDecision(t *testing.T) {
	a := devicetest.New(rpID, origin, "phone")
	dev := a.Device()
	tk := newTicket(t, "crm")
	other := newTicket(t, "billing")
	resign := func(d *ticket.Decision) *ticket.Decision {
		d.Sig = ""
		if err := d.Sign(hubKey); err != nil {
			t.Fatal(err)
		}
		return roundTrip(t, d)
	}
	cases := map[string]func(d *ticket.Decision){
		"denial turned approval": func(d *ticket.Decision) {}, // built below
		"other ticket":           func(d *ticket.Decision) { d.Ticket = other.ID },
		"other instance":         func(d *ticket.Decision) { d.Instance = "billing" },
		"other plan":             func(d *ticket.Decision) { d.PlanHash = other.PlanHash },
		"other nonce":            func(d *ticket.Decision) { d.Nonce = ticket.NewNonce() },
		"redated":                func(d *ticket.Decision) { d.At = d.At.Add(3 * time.Hour) },
		"reason":                 func(d *ticket.Decision) { d.Reason = "ok" },
		"assertion of a hub key": func(d *ticket.Decision) {
			fake := devicetest.New(rpID, origin, "phone")
			fake.Cred = a.Cred // same id, the hub's own key
			ch, _ := d.Statement(dev.ID).Challenge()
			d.Device = fake.Assert(ch)
		},
		"no assertion": func(d *ticket.Decision) { d.Device = nil; d.Facade = "tty" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := deviceDecision(t, a, tk)
			if name == "denial turned approval" {
				d = &ticket.Decision{V: ticket.Version, Ticket: tk.ID, Instance: tk.Source.Instance, KeyID: tk.Source.KeyID,
					PlanHash: tk.PlanHash, Decision: ticket.Denied, At: t0.Add(time.Minute), Nonce: ticket.NewNonce(), HubKeyID: ticket.KeyID(hubPub)}
				a.Decide(d)
				d.Decision = ticket.Approved
			} else {
				mutate(d)
			}
			got := resign(d)
			if err := ticket.VerifyDevice(&dev, got); !errors.Is(err, ticket.ErrDevice) {
				t.Fatalf("VerifyDevice = %v, want ErrDevice", err)
			}
		})
	}
}

func TestAssertionRefusals(t *testing.T) {
	a := devicetest.New(rpID, origin, "phone")
	dev := a.Device()
	ch := bytes.Repeat([]byte{7}, 32)
	up := byte(0x01)
	cases := map[string]*ticket.DeviceAssertion{
		"registration type": a.AssertWith(ch, devicetest.Options{Type: "webauthn.create"}),
		"other origin":      a.AssertWith(ch, devicetest.Options{Origin: "https://evil.example.net"}),
		"other rp":          a.AssertWith(ch, devicetest.Options{RPID: "evil.example.net"}),
		"not verified":      a.AssertWith(ch, devicetest.Options{Flags: &up}),
		"cross origin":      a.AssertWith(ch, devicetest.Options{Cross: true}),
		"other challenge":   a.Assert(bytes.Repeat([]byte{8}, 32)),
	}
	for name, as := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ticket.VerifyAssertion(&dev, ch, as); !errors.Is(err, ticket.ErrDevice) {
				t.Fatalf("got %v, want ErrDevice", err)
			}
		})
	}
	n, err := ticket.VerifyAssertion(&dev, ch, a.Assert(ch))
	if err != nil || n != a.Counter {
		t.Fatalf("good assertion: counter %d, %v", n, err)
	}
	other := devicetest.New(rpID, origin, "other").Device()
	if _, err := ticket.VerifyAssertion(&other, ch, a.Assert(ch)); !errors.Is(err, ticket.ErrDevice) {
		t.Fatalf("another device's assertion: %v", err)
	}
}

func TestDecisionDeviceSchema(t *testing.T) {
	a := devicetest.New(rpID, origin, "phone")
	d := deviceDecision(t, a, newTicket(t, "crm"))
	d.Facade = "tty"
	d.Sig = ""
	if err := d.Sign(hubKey); !errors.Is(err, ticket.ErrInvalid) {
		t.Fatalf("device member on tty: %v", err)
	}
	// Without a device member the decision is as before: no "device" key.
	plain := &ticket.Decision{V: ticket.Version, Ticket: d.Ticket, Instance: d.Instance, KeyID: d.KeyID, PlanHash: d.PlanHash,
		Decision: ticket.Approved, Approver: ticket.Approver{ID: "host:uid:1000"}, Facade: "tty", At: d.At, Nonce: d.Nonce}
	if err := plain.Sign(hubKey); err != nil {
		t.Fatal(err)
	}
	b, _ := plain.Marshal()
	if strings.Contains(string(b), `"device"`) {
		t.Fatalf("plain decision has a device member: %s", b)
	}
}

func TestDeviceRecord(t *testing.T) {
	a := devicetest.New(rpID, origin, "phone")
	dev := a.Device()
	fp, err := dev.Fingerprint()
	if err != nil || len(strings.ReplaceAll(fp, " ", "")) != 20 {
		t.Fatalf("fingerprint %q, %v", fp, err)
	}
	bad := map[string]func(d *ticket.Device){
		"id":          func(d *ticket.Device) { d.ID = ticket.DeviceID([]byte("x")) },
		"http origin": func(d *ticket.Device) { d.Origin = "http://hub.example.net" },
		"origin path": func(d *ticket.Device) { d.Origin = origin + "/x" },
		"foreign rp":  func(d *ticket.Device) { d.RPID = "example.org" },
		"es256":       func(d *ticket.Device) { d.ES256 = b64.EncodeToString(make([]byte, 65)) },
		"x25519":      func(d *ticket.Device) { d.X25519 = "AA" },
		"version":     func(d *ticket.Device) { d.V = 2 },
	}
	for name, f := range bad {
		d := dev
		f(&d)
		if err := d.Validate(); !errors.Is(err, ticket.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	set, _ := json.Marshal(ticket.DeviceSet{V: 1, Devices: []ticket.Device{dev}})
	if got, err := ticket.ParseDevices(set); err != nil || len(got) != 1 || got[0] != dev {
		t.Fatalf("ParseDevices: %v %v", got, err)
	}
	twice, _ := json.Marshal(ticket.DeviceSet{V: 1, Devices: []ticket.Device{dev, dev}})
	if _, err := ticket.ParseDevices(twice); err == nil {
		t.Fatal("a device twice was accepted")
	}
	if _, err := ticket.ParseDevices([]byte(`{"v":1,"devices":[],"extra":1}`)); err == nil {
		t.Fatal("unknown member accepted")
	}
}

func TestClearScreenSealed(t *testing.T) {
	a := devicetest.New(rpID, origin, "phone")
	dev := a.Device()
	tk := newTicket(t, "crm")
	clear := ticket.Screen{Header: "crm / shop", Body: []string{"UPDATE customers SET email = 'jane@example.com'"}}
	box, err := ticket.SealClearScreen(&dev, tk.ID, clear)
	if err != nil {
		t.Fatal(err)
	}
	if box.Box.Alg != ticket.SealAlgGCM || strings.Contains(box.Box.CT, "jane") {
		t.Fatalf("box %+v", box.Box)
	}
	got, err := ticket.OpenClearScreen(a.Seal, tk.ID, box)
	if err != nil || got.Body[0] != clear.Body[0] {
		t.Fatalf("open: %+v %v", got, err)
	}
	// Bound to the ticket and the device.
	if _, err := ticket.OpenClearScreen(a.Seal, newTicket(t, "crm").ID, box); !errors.Is(err, ticket.ErrOpen) {
		t.Fatalf("other ticket: %v", err)
	}
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := ticket.OpenClearScreen(other, tk.ID, box); !errors.Is(err, ticket.ErrOpen) {
		t.Fatalf("other key: %v", err)
	}
	// A ticket carries it and still verifies.
	tk2 := newTicket(t, "crm")
	tk2.Sig = ""
	b2, _ := ticket.SealClearScreen(&dev, tk2.ID, clear)
	tk2.PII.SealedFor = []ticket.DeviceBox{*b2}
	if err := tk2.Sign(lockKey); err != nil {
		t.Fatal(err)
	}
	raw, _ := tk2.Marshal()
	if _, err := ticket.VerifyTicket(lockKey.Public().(ed25519.PublicKey), raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("jane")) {
		t.Fatal("clear value in the ticket")
	}
}

// The AES-GCM box is the one WebCrypto opens: X25519, HKDF-SHA256 with
// the ephemeral then the recipient key as salt, AES-256-GCM with a 12-byte
// nonce. This fixed vector is checked by the PWA's own test.
func TestSealGCMShape(t *testing.T) {
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	s, err := ticket.SealGCM(priv.PublicKey(), []byte("hello"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := b64.DecodeString(s.Nonce); len(n) != 12 {
		t.Fatalf("nonce %d bytes", len(n))
	}
	if pt, err := ticket.Open(priv, s, []byte("aad")); err != nil || string(pt) != "hello" {
		t.Fatalf("open: %q %v", pt, err)
	}
	s.Alg = ticket.SealAlg // the other construction does not open it
	if _, err := ticket.Open(priv, s, []byte("aad")); !errors.Is(err, ticket.ErrOpen) {
		t.Fatalf("alg swap: %v", err)
	}
}
