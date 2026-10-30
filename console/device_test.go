//go:build unix

package console

import (
	"context"
	"crypto/ed25519"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/ticket"
	"github.com/DavidGodefroid/lockkit/ticket/devicetest"
)

func TestHubOptionsArgsRoundTrip(t *testing.T) {
	in := HubOptions{URL: "http://lockhub:8443", KeyFile: "/run/lockfamily/hub.pub", Instance: "crm", PlainHTTP: true,
		DevicesFile: "/run/lockfamily/devices.json", RequireDevice: "prod-write,unlock", SealClear: true}
	var out HubOptions
	fs := flag.NewFlagSet("console", flag.ContinueOnError)
	out.Register(fs)
	if err := fs.Parse(in.Args()); err != nil || out != in {
		t.Fatalf("round trip: %+v %v", out, err)
	}
	if err := (HubOptions{URL: "u", KeyFile: "k", Instance: "crm", RequireDevice: "write"}).check(); err == nil {
		t.Fatal("--require-device without --devices-file accepted")
	}
	if err := (HubOptions{URL: "u", KeyFile: "k", Instance: "crm", DevicesFile: "d", RequireDevice: "writes"}).check(); err == nil {
		t.Fatal("unknown risk accepted")
	}
}

func writeDevices(t *testing.T, devs ...ticket.Device) string {
	t.Helper()
	b, _ := ticket.MarshalDevices(devs)
	p := filepath.Join(t.TempDir(), "devices.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// In hub mode with a pinned device, the clear screen reaches the hub only
// sealed to the device, and the device's own decision runs the request.
func TestRunHubModeDevice(t *testing.T) {
	env := runEnv(t)
	home, state := t.TempDir(), t.TempDir()
	key, err := hubclient.InstanceKey(home, hubInstance)
	if err != nil {
		t.Fatal(err)
	}
	hub := hubtest.New(t, hubInstance, key.Public().(ed25519.PublicKey))
	phone := devicetest.New("hub.example.net", "https://hub.example.net", "phone")
	b := &hubBackend{fakeBackend: fakeBackend{policy: uat()}}
	io := &fakeIO{answers: []string{"y"}, secrets: []string{"s3cret"}}
	ready := make(chan string, 1)
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		done <- Run(ctx, testProduct, b, Options{Profile: "uat", IO: io, StateDir: state, Isolation: env,
			Harden: func() error { return nil }, Quantum: -1, Ready: func(s string) { ready <- s },
			Hub: HubOptions{URL: hub.URL(), KeyFile: writeHubKey(t, hub.Pub), Instance: hubInstance, Home: home,
				DevicesFile: writeDevices(t, phone.Device()), RequireDevice: "write", SealClear: true}})
	}()
	var socket string
	select {
	case socket = <-ready:
	case err := <-done:
		t.Fatalf("Run: %v\n%s", err, io.plain())
	case <-time.After(10 * time.Second):
		t.Fatal("no socket")
	}
	m := pendingOf(t, dialAndCall(t, socket, "op.write", map[string]bool{"hub": true}).Result)
	raw := hub.Ticket(m["ticket"])
	if raw == nil || strings.Contains(string(raw), "jane.doe") {
		t.Fatalf("hub ticket: %s", raw)
	}
	tk, err := ticket.VerifyTicket(key.Public().(ed25519.PublicKey), raw)
	if err != nil || len(tk.PII.SealedFor) != 1 {
		t.Fatalf("ticket %+v %v", tk, err)
	}
	clear, err := ticket.OpenClearScreen(phone.Seal, tk.ID, ticket.DeviceID(phone.Cred), &tk.PII.SealedFor[0])
	if err != nil || !slices.Contains(clear.Body, "WRITE jane.doe@example.com") {
		t.Fatalf("clear screen %+v %v", clear, err)
	}
	hub.DecideWith(m["ticket"], ticket.Approved, "", nil, func(d *ticket.Decision) {
		d.HubKeyID = ticket.KeyID(hub.Pub)
		phone.Decide(d, raw)
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		r := dialAndCall(t, socket, "op.run", map[string]string{"ticket": m["ticket"]})
		if r.Error == nil {
			break
		}
		if !strings.Contains(r.Error.Message, "no decision yet") || time.Now().After(deadline) {
			t.Fatalf("op.run: %+v", r.Error)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if b.ran != 1 {
		t.Fatalf("ran %d", b.ran)
	}
	cancel()
	<-done
}
