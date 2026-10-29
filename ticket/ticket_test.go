package ticket

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// Test keys from fixed seeds: test only, published in testdata/keys.json.
var (
	lockSeed  = bytes.Repeat([]byte{0x11}, ed25519.SeedSize)
	hubSeed   = bytes.Repeat([]byte{0x22}, ed25519.SeedSize)
	otherSeed = bytes.Repeat([]byte{0x33}, ed25519.SeedSize)
	lockKey   = ed25519.NewKeyFromSeed(lockSeed)
	hubKey    = ed25519.NewKeyFromSeed(hubSeed)
	otherKey  = ed25519.NewKeyFromSeed(otherSeed)
	lockPub   = lockKey.Public().(ed25519.PublicKey)
	hubPub    = hubKey.Public().(ed25519.PublicKey)
	otherPub  = otherKey.Public().(ed25519.PublicKey)
)

var t0 = time.Date(2026, 10, 29, 22, 0, 0, 0, time.UTC)

func sampleTicket(tb testing.TB) *Ticket {
	tb.Helper()
	plan, err := HashOf(map[string]any{"sql": "UPDATE customers SET tier = $1 WHERE id = $2", "params": []any{"gold", 42}})
	if err != nil {
		tb.Fatal(err)
	}
	fp, err := HashOf(map[string]any{"profile": "crm-prod", "tier": "write"})
	if err != nil {
		tb.Fatal(err)
	}
	tk := NewTicket(Source{Lock: "locksql", Instance: "crm-prod"}, RiskProdWrite, plan, fp, t0, RiskProdWrite.TTL())
	tk.ID = "01JBDN0Z0000000000000000AB" // stable for fixtures
	tk.Workspace = "~/Documents"
	tk.Requester = Requester{Agent: "dev-3", Session: "s-1"}
	tk.Flags = Flags{Production: true, Retype: "crm-prod"}
	tk.Screen = Screen{
		Header:   "crm-prod / shop · tier write",
		Note:     "promote the customer to gold",
		Body:     []string{"UPDATE customers SET tier = 'gold' WHERE id = 42", "1 row (estimate)", "e-mail: j***@e***.com"},
		Warnings: []string{"production"},
	}
	tk.PII = PII{Touched: []string{"email"}}
	if err := tk.Sign(lockKey); err != nil {
		tb.Fatal(err)
	}
	return tk
}

func sampleDecision(tb testing.TB, tk *Ticket, o Outcome) *Decision {
	tb.Helper()
	d := &Decision{
		V: Version, Ticket: tk.ID, Instance: tk.Source.Instance, KeyID: tk.Source.KeyID,
		PlanHash: tk.PlanHash, Decision: o, Approver: Approver{ID: "david", Display: "David"},
		Facade: "tty", At: t0.Add(10 * time.Minute), Nonce: "AAECAwQFBgcICQoLDA0ODw",
	}
	if o == Denied {
		d.Reason = "not today"
	}
	if err := d.Sign(hubKey); err != nil {
		tb.Fatal(err)
	}
	return d
}

func mustMarshal(tb testing.TB, v interface{ Marshal() ([]byte, error) }) []byte {
	tb.Helper()
	b, err := v.Marshal()
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func TestTicketRoundTrip(t *testing.T) {
	tk := sampleTicket(t)
	data := mustMarshal(t, tk)
	got, err := VerifyTicket(lockPub, data)
	if err != nil {
		t.Fatal(err)
	}
	if again := mustMarshal(t, got); !bytes.Equal(again, data) {
		t.Fatalf("round trip changed the ticket:\n%s\n%s", data, again)
	}
	if got.Source.KeyID != KeyID(lockPub) || got.Expires == nil || !got.Expires.Equal(t0.Add(4*time.Hour)) {
		t.Fatalf("bad ticket %+v", got)
	}
	if c, _ := CanonicalizeJSON(data); !bytes.Equal(c, data) {
		t.Fatal("Marshal is not canonical")
	}
}

func TestDecisionRoundTrip(t *testing.T) {
	tk := sampleTicket(t)
	for _, o := range []Outcome{Approved, Denied} {
		d := sampleDecision(t, tk, o)
		data := mustMarshal(t, d)
		got, err := VerifyDecision(hubPub, data)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(mustMarshal(t, got), data) || got.Decision != o {
			t.Fatalf("round trip changed the decision: %s", data)
		}
		if err := got.Match(tk); err != nil {
			t.Fatal(err)
		}
	}
}

// Every member of a signed value is covered by the signature.
func TestTamperedTicketRefused(t *testing.T) {
	tk := sampleTicket(t)
	data := mustMarshal(t, tk)
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	edits := map[string]func(map[string]any){
		"risk":      func(m map[string]any) { m["risk"] = "read" },
		"instance":  func(m map[string]any) { m["source"].(map[string]any)["instance"] = "crm-dev" },
		"plan_hash": func(m map[string]any) { m["plan_hash"] = "sha256:" + strings.Repeat("0", 64) },
		"screen":    func(m map[string]any) { m["screen"].(map[string]any)["body"] = []any{"SELECT 1"} },
		"warnings":  func(m map[string]any) { m["screen"].(map[string]any)["warnings"] = nil },
		"flags":     func(m map[string]any) { m["flags"].(map[string]any)["production"] = false },
		"expires":   func(m map[string]any) { m["expires"] = nil },
		"requester": func(m map[string]any) { m["requester"].(map[string]any)["agent"] = "dev-4" },
		"pii":       func(m map[string]any) { m["pii"].(map[string]any)["touched"] = []any{} },
		"sig":       func(m map[string]any) { m["sig"] = SignBytes(lockKey, ContextDecision, []byte("x")) },
		"no-sig":    func(m map[string]any) { delete(m, "sig") },
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			var c map[string]any
			_ = json.Unmarshal(data, &c)
			edit(c)
			b, _ := Canonical(c)
			if _, err := VerifyTicket(lockPub, b); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("got %v, want ErrBadSignature", err)
			}
		})
	}
}

func TestTicketRefusals(t *testing.T) {
	tk := sampleTicket(t)
	data := mustMarshal(t, tk)
	if _, err := VerifyTicket(otherPub, data); !errors.Is(err, ErrBadSignature) {
		t.Errorf("other key: %v", err)
	}
	// A ticket re-signed by another key but still naming the lock's key.
	forged := *tk
	forged.Sig = ""
	b, _ := Canonical(&forged)
	forged.Sig = SignBytes(otherKey, ContextTicket, b)
	if _, err := VerifyTicket(lockPub, mustMarshal(t, &forged)); !errors.Is(err, ErrBadSignature) {
		t.Errorf("forged: %v", err)
	}
	// A ticket signature is not a decision signature (domain separation).
	forged.Sig = SignBytes(lockKey, ContextDecision, b)
	if _, err := VerifyTicket(lockPub, mustMarshal(t, &forged)); !errors.Is(err, ErrBadSignature) {
		t.Errorf("cross context: %v", err)
	}
	for name, in := range map[string]string{
		"unknown member": strings.Replace(string(data), `{"created"`, `{"extra":1,"created"`, 1),
		"duplicate":      strings.Replace(string(data), `{"created"`, `{"risk":"read","created"`, 1),
		"trailing":       string(data) + "{}",
		"version":        strings.Replace(string(data), `"v":1`, `"v":2`, 1),
		"risk":           strings.Replace(string(data), `"prod-write"`, `"admin"`, 1),
		"case-folded":    strings.Replace(string(data), `"risk":`, `"RISK":`, 1),
		"whitespace":     strings.Replace(string(data), `"v":1`, `"v": 1`, 1),
		"member order":   reorder(string(data)),
		"escaped":        strings.Replace(string(data), `"locksql"`, `"lock\u0073ql"`, 1),
	} {
		if _, err := VerifyTicket(lockPub, []byte(in)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
	// Sign refuses a ticket naming another key, or an invalid one.
	other := sampleTicket(t)
	if err := other.Sign(otherKey); err == nil {
		t.Error("signed a ticket naming another key")
	}
	bad := sampleTicket(t)
	bad.Risk = "admin"
	if err := bad.Sign(lockKey); !errors.Is(err, ErrInvalid) {
		t.Errorf("signed an invalid ticket: %v", err)
	}
}

func TestValidate(t *testing.T) {
	for name, edit := range map[string]func(*Ticket){
		"id":        func(t *Ticket) { t.ID = "not-a-ulid" },
		"lock":      func(t *Ticket) { t.Source.Lock = "" },
		"instance":  func(t *Ticket) { t.Source.Instance = "" },
		"key_id":    func(t *Ticket) { t.Source.KeyID = "rsa:1" },
		"plan_hash": func(t *Ticket) { t.PlanHash = "md5:00" },
		"policy_fp": func(t *Ticket) { t.PolicyFP = "sha256:ABC" },
		"created":   func(t *Ticket) { t.Created = time.Time{} },
		"local":     func(t *Ticket) { t.Created = t.Created.In(time.FixedZone("x", 3600)) },
		"nanos":     func(t *Ticket) { t.Created = t.Created.Add(time.Nanosecond) },
		"expires":   func(t *Ticket) { e := t.Created; t.Expires = &e },
		"utf8":      func(t *Ticket) { t.Screen.Note = "\xff" },
		"long":      func(t *Ticket) { t.Workspace = strings.Repeat("a", maxField+1) },
		"lines":     func(t *Ticket) { t.Screen.Body = make([]string, maxLines+1) },
		"touched":   func(t *Ticket) { t.PII.Touched = []string{""} },
		"sealed":    func(t *Ticket) { t.PII.ClearSealed = &Sealed{Alg: "rsa"} },
	} {
		tk := sampleTicket(t)
		edit(tk)
		if err := tk.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
}

func TestDecisionRefusals(t *testing.T) {
	tk := sampleTicket(t)
	d := sampleDecision(t, tk, Approved)
	data := mustMarshal(t, d)
	if _, err := VerifyDecision(lockPub, data); !errors.Is(err, ErrBadSignature) {
		t.Errorf("lock key: %v", err)
	}
	for name, in := range map[string]string{
		"approved→denied": strings.Replace(string(data), `"approved"`, `"denied"`, 1),
		"instance":        strings.Replace(string(data), `"crm-prod"`, `"crm-dev"`, 1),
		"nonce":           strings.Replace(string(data), d.Nonce, "AAECAwQFBgcICQoLDA0OEA", 1),
	} {
		if _, err := VerifyDecision(hubPub, []byte(in)); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: got %v, want ErrBadSignature", name, err)
		}
	}
	if _, err := VerifyDecision(hubPub, []byte(strings.Replace(string(data), `"approved"`, `"retype"`, 1))); !errors.Is(err, ErrInvalid) {
		t.Errorf("outcome outside the enum: %v", err)
	}
}

// A decision for another instance, key, plan or ticket is refused, even
// correctly signed by the hub.
func TestDecisionMatch(t *testing.T) {
	tk := sampleTicket(t)
	for name, edit := range map[string]func(*Decision){
		"instance":  func(d *Decision) { d.Instance = "crm-dev" },
		"key":       func(d *Decision) { d.KeyID = KeyID(otherPub) },
		"plan_hash": func(d *Decision) { d.PlanHash = "sha256:" + strings.Repeat("1", 64) },
		"ticket":    func(d *Decision) { d.Ticket = "01JBDN0Z0000000000000000AC" },
	} {
		d := sampleDecision(t, tk, Approved)
		edit(d)
		if err := d.Sign(hubKey); err != nil {
			t.Fatal(err)
		}
		got, err := VerifyDecision(hubPub, mustMarshal(t, d))
		if err != nil {
			t.Fatal(err)
		}
		if err := got.Match(tk); !errors.Is(err, ErrMismatch) {
			t.Errorf("%s: got %v, want ErrMismatch", name, err)
		}
	}
}

func TestDecisionUsable(t *testing.T) {
	tk := sampleTicket(t) // prod-write: expires t0+4h
	d := sampleDecision(t, tk, Approved)
	ttl := ClampTTL(tk.Risk, 0)
	if err := d.Usable(tk, d.At.Add(time.Hour), ttl); err != nil {
		t.Fatal(err)
	}
	if err := d.Usable(tk, d.At.Add(4*time.Hour+time.Second), ttl); !errors.Is(err, ErrExpired) {
		t.Errorf("old approval: %v", err)
	}
	if err := d.Usable(tk, d.At.Add(-2*time.Minute), ttl); !errors.Is(err, ErrExpired) {
		t.Errorf("future approval: %v", err)
	}
	late := *d
	late.At = tk.Expires.Add(time.Second)
	if err := late.Usable(tk, late.At, ttl); !errors.Is(err, ErrExpired) {
		t.Errorf("decided after expiry: %v", err)
	}
	early := *d
	early.At = tk.Created.Add(-time.Hour)
	if err := early.Usable(tk, d.At, ttl); err == nil {
		t.Error("decided before the ticket")
	}
	if err := sampleDecision(t, tk, Denied).Usable(tk, d.At, ttl); !errors.Is(err, ErrDenied) {
		t.Errorf("denial usable: %v", err)
	}
	if tk.Expired(t0.Add(time.Hour)) || !tk.Expired(t0.Add(4*time.Hour)) {
		t.Error("Ticket.Expired")
	}
}

func TestRiskTTL(t *testing.T) {
	want := map[Risk]time.Duration{
		RiskRead: 0, RiskReadPII: 0, RiskWrite: 24 * time.Hour, RiskPolicyLoosen: 24 * time.Hour,
		RiskProdWrite: 4 * time.Hour, RiskUnlock: 4 * time.Hour,
	}
	if len(want) != len(Risks) {
		t.Fatal("Risks changed: update the table")
	}
	for r, d := range want {
		if r.TTL() != d {
			t.Errorf("%s: %s, want %s", r, r.TTL(), d)
		}
	}
	if Risk("admin").Valid() || Risk("admin").TTL() != 4*time.Hour {
		t.Error("unknown risk")
	}
	if ClampTTL(RiskWrite, time.Hour) != time.Hour || ClampTTL(RiskWrite, 48*time.Hour) != 24*time.Hour ||
		ClampTTL(RiskRead, time.Hour) != time.Hour || ClampTTL(RiskRead, 0) != 0 || ClampTTL(RiskProdWrite, -1) != 4*time.Hour {
		t.Error("ClampTTL may only shorten")
	}
	var r Risk
	if err := json.Unmarshal([]byte(`"Write"`), &r); err == nil {
		t.Error("risk names are exact")
	}
}

func TestNewID(t *testing.T) {
	a := NewID(t0)
	b := NewID(t0.Add(time.Millisecond))
	if !ValidID(a) || !ValidID(b) || a >= b || a[:10] != "01M64TTMR0" {
		t.Fatalf("ids %s %s", a, b)
	}
	if NewID(t0) == a {
		t.Fatal("ids repeat")
	}
	for _, s := range []string{"", "01JBDQK2Y0", "81JBDQK2Y0000000000000000A", "01JBDQK2Y000000000000000IL", "01jbdqk2y0000000000000000a"} {
		if ValidID(s) {
			t.Errorf("%q accepted", s)
		}
	}
	var max [16]byte
	for i := range max {
		max[i] = 0xff
	}
	if s := encodeULID(max); s != "7ZZZZZZZZZZZZZZZZZZZZZZZZZ" {
		t.Fatalf("max ULID %s", s)
	}
}

func TestSealOpen(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := ecdh.X25519().GenerateKey(nil)
	msg := []byte("s3cret password")
	s, err := Seal(priv.PublicKey(), msg, []byte("01JBDN0Z0000000000000000AB"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s.CT, enc.EncodeToString(msg)) {
		t.Fatal("plaintext visible")
	}
	got, err := Open(priv, s, []byte("01JBDN0Z0000000000000000AB"))
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("open: %q %v", got, err)
	}
	if _, err := Open(other, s, []byte("01JBDN0Z0000000000000000AB")); !errors.Is(err, ErrOpen) {
		t.Errorf("other key: %v", err)
	}
	if _, err := Open(priv, s, []byte("01JBDN0Z0000000000000000AC")); !errors.Is(err, ErrOpen) {
		t.Errorf("other aad: %v", err)
	}
	ct, _ := enc.DecodeString(s.CT)
	ct[0] ^= 1
	bad := *s
	bad.CT = enc.EncodeToString(ct)
	if _, err := Open(priv, &bad, []byte("01JBDN0Z0000000000000000AB")); !errors.Is(err, ErrOpen) {
		t.Errorf("tampered: %v", err)
	}
	// A low-order ephemeral key gives the all-zero secret: refused.
	zero := *s
	zero.EPK = enc.EncodeToString(make([]byte, 32))
	if _, err := Open(priv, &zero, []byte("01JBDN0Z0000000000000000AB")); !errors.Is(err, ErrOpen) {
		t.Errorf("low-order epk: %v", err)
	}
	s2, _ := Seal(priv.PublicKey(), msg, nil)
	if s2.EPK == s.EPK || s2.CT == s.CT {
		t.Error("sealing is not randomized")
	}
}

func TestKeyCert(t *testing.T) {
	x, _ := ecdh.X25519().GenerateKey(nil)
	kc, err := CertifyX25519(lockKey, ContextKeyCert, x.PublicKey(), "")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := Canonical(kc)
	pub, err := VerifyKeyCert(lockPub, ContextKeyCert, "", data)
	if err != nil || !pub.Equal(x.PublicKey()) {
		t.Fatalf("verify: %v", err)
	}
	if _, err := VerifyKeyCert(otherPub, ContextKeyCert, "", data); !errors.Is(err, ErrBadSignature) {
		t.Errorf("other key: %v", err)
	}
	if _, err := VerifyKeyCert(lockPub, ContextReveal, "", data); !errors.Is(err, ErrBadSignature) {
		t.Errorf("other context: %v", err)
	}
	rv, _ := CertifyX25519(otherKey, ContextReveal, x.PublicKey(), "01JBDN0Z0000000000000000AB")
	rdata, _ := Canonical(rv)
	if _, err := VerifyKeyCert(otherPub, ContextReveal, "01JBDN0Z0000000000000000AC", rdata); !errors.Is(err, ErrMismatch) {
		t.Errorf("other bind: %v", err)
	}
	// A hub swapping in its own key under the facade's signature fails.
	y, _ := ecdh.X25519().GenerateKey(nil)
	swapped := *rv
	swapped.X25519 = enc.EncodeToString(y.PublicKey().Bytes())
	sdata, _ := Canonical(&swapped)
	if _, err := VerifyKeyCert(otherPub, ContextReveal, "01JBDN0Z0000000000000000AB", sdata); !errors.Is(err, ErrBadSignature) {
		t.Errorf("swapped key: %v", err)
	}
}

func TestVerifyBytes(t *testing.T) {
	sig := SignBytes(lockKey, ContextRequest, []byte("POST /v1/tickets"))
	if VerifyBytes(lockPub, ContextRequest, []byte("POST /v1/tickets"), sig) != nil {
		t.Fatal("verify")
	}
	for _, c := range []struct {
		pub ed25519.PublicKey
		ctx Context
		msg string
		sig string
	}{
		{otherPub, ContextRequest, "POST /v1/tickets", sig},
		{lockPub, ContextTicket, "POST /v1/tickets", sig},
		{lockPub, ContextRequest, "POST /v1/ticket", sig},
		{lockPub, ContextRequest, "POST /v1/tickets", "!!"},
		{lockPub, ContextRequest, "POST /v1/tickets", ""},
		{nil, ContextRequest, "POST /v1/tickets", sig},
	} {
		if !errors.Is(VerifyBytes(c.pub, c.ctx, []byte(c.msg), c.sig), ErrBadSignature) {
			t.Errorf("accepted %+v", c)
		}
	}
}

// reorder moves the "v" member first: same value, not canonical.
func reorder(s string) string {
	return `{"v":1,` + strings.Replace(s[1:], `,"v":1`, "", 1)
}

func FuzzVerifyTicket(f *testing.F) {
	tk := sampleTicket(f)
	data, _ := tk.Marshal()
	f.Add(data)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := VerifyTicket(lockPub, in)
		if err != nil {
			return
		}
		// Only the exact canonical form verifies.
		out, err := got.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, in) {
			t.Fatalf("verified %q but re-encodes as %q", in, out)
		}
	})
}

func TestRequestMessage(t *testing.T) {
	at := time.Unix(1793318400, 0)
	m := RequestMessage("POST", "/v1/tickets?x=1", "crm-prod", at, "AAECAwQFBgcICQoLDA0ODw", []byte(`{}`))
	want := "POST\n/v1/tickets?x=1\ncrm-prod\n1793318400\nAAECAwQFBgcICQoLDA0ODw\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	if string(m) != want {
		t.Fatalf("got %q", m)
	}
	sig := SignBytes(lockKey, ContextRequest, m)
	if VerifyBytes(lockPub, ContextRequest, RequestMessage("POST", "/v1/tickets?x=1", "crm-prod", at, "AAECAwQFBgcICQoLDA0ODw", []byte(`{ }`)), sig) == nil {
		t.Fatal("body not covered")
	}
	if VerifyBytes(lockPub, ContextRequest, RequestMessage("POST", "/v1/tickets?x=1", "crm-dev", at, "AAECAwQFBgcICQoLDA0ODw", []byte(`{}`)), sig) == nil {
		t.Fatal("instance not covered")
	}
}
