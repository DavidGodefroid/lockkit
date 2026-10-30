package ticket

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	ttyKey  = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	deckKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x55}, ed25519.SeedSize))
	pinned  = []PinnedFacade{
		{Facade: FacadeTTY, Key: ttyKey.Public().(ed25519.PublicKey)},
		{Facade: FacadeDeck, Key: deckKey.Public().(ed25519.PublicKey)},
	}
	clearScreen = Screen{Header: "crm-prod / shop · tier write", Body: []string{"e-mail: jane.doe@example.com"}}
)

func revealRequest(tb testing.TB, rk *RevealKey) *HubRequest {
	tb.Helper()
	q := &HubRequest{V: Version, ID: NewID(t0), Kind: RequestReveal, Ticket: rk.Ticket, Instance: rk.Instance, KeyID: rk.KeyID,
		Approver: Approver{ID: "host:uid:1000"}, Facade: rk.Facade, At: t0, Reveal: rk}
	if err := q.Sign(hubKey); err != nil {
		tb.Fatal(err)
	}
	return q
}

func TestParseFacades(t *testing.T) {
	b64 := func(k ed25519.PrivateKey) string {
		return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
	}
	good := `{"v":1,"facades":[{"facade":"tty","key":"` + b64(ttyKey) + `"},{"facade":"deck","key":"` + b64(deckKey) + `"}]}`
	fs, err := ParseFacades([]byte(good))
	if err != nil || len(fs) != 2 || fs[1].Facade != FacadeDeck {
		t.Fatalf("%v %v", fs, err)
	}
	for name, in := range map[string]string{
		"slack":    `{"v":1,"facades":[{"facade":"slack","key":"` + b64(ttyKey) + `"}]}`,
		"mobile":   `{"v":1,"facades":[{"facade":"mobile","key":"` + b64(ttyKey) + `"}]}`,
		"twice":    `{"v":1,"facades":[{"facade":"tty","key":"` + b64(ttyKey) + `"},{"facade":"deck","key":"` + b64(ttyKey) + `"}]}`,
		"version":  `{"v":2,"facades":[]}`,
		"bad key":  `{"v":1,"facades":[{"facade":"tty","key":"AAAA"}]}`,
		"not json": `{`,
	} {
		if _, err := ParseFacades([]byte(in)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRevealRoundTrip(t *testing.T) {
	tk := sampleTicket(t)
	rk, priv, err := NewRevealKey(ttyKey, FacadeTTY, tk, t0)
	if err != nil {
		t.Fatal(err)
	}
	q := revealRequest(t, rk)
	raw, _ := q.Marshal()
	got, err := VerifyHubRequest(hubPub, raw)
	if err != nil || !got.Fresh(t0.Add(time.Minute)) || got.Fresh(t0.Add(RevealTTL)) || got.Fresh(t0.Add(-2*time.Minute)) {
		t.Fatalf("verify %v", err)
	}
	epk, err := got.Reveal.Verify(pinned)
	if err != nil {
		t.Fatal(err)
	}
	a, err := SealReveal(lockKey, got, epk, clearScreen)
	if err != nil {
		t.Fatal(err)
	}
	ab, _ := a.Marshal()
	if bytes.Contains(ab, []byte("jane.doe")) {
		t.Fatal("clear value in the answer")
	}
	s, err := OpenReveal(lockPub, priv, rk, ab)
	if err != nil || s.Body[0] != clearScreen.Body[0] {
		t.Fatalf("%+v %v", s, err)
	}

	// A hub that seals its own screen to the facade key cannot sign as the
	// lock; one that answers for another reveal is caught.
	fake, _ := SealReveal(otherKey, &HubRequest{Kind: RequestReveal, ID: q.ID, Ticket: q.Ticket, Instance: q.Instance,
		KeyID: KeyID(otherPub), Reveal: rk}, epk, Screen{Body: []string{"forged"}})
	fb, _ := fake.Marshal()
	if _, err := OpenReveal(lockPub, priv, rk, fb); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("forged answer: %v", err)
	}
	var m map[string]any
	_ = json.Unmarshal(ab, &m)
	m["sig"] = SignBytes(otherKey, ContextRevealAnswer, []byte("x"))
	mb, _ := Canonical(m)
	if _, err := OpenReveal(lockPub, priv, rk, mb); err == nil {
		t.Fatal("bad signature accepted")
	}
	rk2, priv2, _ := NewRevealKey(ttyKey, FacadeTTY, tk, t0)
	if _, err := OpenReveal(lockPub, priv2, rk2, ab); !errors.Is(err, ErrMismatch) {
		t.Fatalf("answer for another reveal: %v", err)
	}
	if _, err := OpenReveal(lockPub, priv2, rk, ab); !errors.Is(err, ErrOpen) {
		t.Fatalf("another private key: %v", err)
	}
}

func TestRevealKeyRefused(t *testing.T) {
	tk := sampleTicket(t)
	// Signed by a key no lock pins.
	rk, _, _ := NewRevealKey(otherKey, FacadeTTY, tk, t0)
	if _, err := rk.Verify(pinned); !errors.Is(err, ErrFacade) {
		t.Fatalf("unpinned: %v", err)
	}
	// The deck's key claiming to be the tty.
	rk, _, _ = NewRevealKey(deckKey, FacadeTTY, tk, t0)
	if _, err := rk.Verify(pinned); !errors.Is(err, ErrFacade) {
		t.Fatalf("wrong facade: %v", err)
	}
	// A hub swapping the ephemeral key.
	rk, _, _ = NewRevealKey(ttyKey, FacadeTTY, tk, t0)
	other, _, _ := NewRevealKey(ttyKey, FacadeTTY, tk, t0)
	rk.EPK = other.EPK
	if _, err := rk.Verify(pinned); !errors.Is(err, ErrFacade) {
		t.Fatalf("swapped epk: %v", err)
	}
	// Chat facades and devices never reveal.
	for _, f := range []string{"slack", "telegram", "mobile"} {
		if _, _, err := NewRevealKey(ttyKey, f, tk, t0); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", f, err)
		}
	}
	if _, err := rk.Verify(nil); !errors.Is(err, ErrFacade) {
		t.Fatalf("no pins: %v", err)
	}
}

func TestHubRequestChecks(t *testing.T) {
	tk := sampleTicket(t)
	rk, _, _ := NewRevealKey(ttyKey, FacadeTTY, tk, t0)
	q := revealRequest(t, rk)
	raw, _ := q.Marshal()
	if _, err := VerifyHubRequest(otherPub, raw); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("other hub key: %v", err)
	}
	tampered := bytes.Replace(raw, []byte(`"host:uid:1000"`), []byte(`"host:uid:1001"`), 1)
	if _, err := VerifyHubRequest(hubPub, tampered); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered: %v", err)
	}
	for name, mod := range map[string]func(*HubRequest){
		"kind":            func(q *HubRequest) { q.Kind = "approve" },
		"reveal no key":   func(q *HubRequest) { q.Reveal = nil },
		"key other tk":    func(q *HubRequest) { q.Ticket = NewID(t0) },
		"key other face":  func(q *HubRequest) { q.Facade = FacadeDeck },
		"renew with key":  func(q *HubRequest) { q.Kind = RequestRenew },
		"empty instance":  func(q *HubRequest) { q.Instance = "" },
		"not normalized":  func(q *HubRequest) { q.At = t0.Add(time.Microsecond) },
		"bad lock key id": func(q *HubRequest) { q.KeyID = "ed25519:xx" },
	} {
		c := *q
		c.Sig, c.HubKeyID = "", ""
		mod(&c)
		if err := c.Sign(hubKey); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	renew := &HubRequest{V: Version, ID: NewID(t0), Kind: RequestRenew, Ticket: tk.ID, Instance: tk.Source.Instance,
		KeyID: tk.Source.KeyID, Facade: FacadeTTY, At: t0}
	if err := renew.Sign(hubKey); err != nil {
		t.Fatal(err)
	}
	if _, err := SealReveal(lockKey, renew, nil, clearScreen); !errors.Is(err, ErrInvalid) {
		t.Fatalf("seal a renewal: %v", err)
	}
}

func TestRenewalInTicket(t *testing.T) {
	before, err := InputDigests(struct {
		SQL    string `json:"sql"`
		Schema string `json:"schema"`
	}{"UPDATE t SET a = 1", "v1"})
	if err != nil || len(before) != 2 || !strings.HasPrefix(before["sql"], "sha256:") {
		t.Fatalf("%v %v", before, err)
	}
	after, _ := InputDigests(map[string]any{"sql": "UPDATE t SET a = 1", "schema": "v2", "pins": []string{"x"}})
	ch := DiffInputs(before, after)
	if len(ch) != 2 || ch[0].Input != "pins" || ch[0].Before != "" || ch[1].Input != "schema" || ch[1].Before != before["schema"] {
		t.Fatalf("%+v", ch)
	}
	if DiffInputs(before, before) != nil {
		t.Fatal("no change expected")
	}
	if _, err := InputDigests([]int{1}); err == nil {
		t.Fatal("a list has no named inputs")
	}

	tk := sampleTicket(t)
	at := t0.Add(-time.Hour)
	r := sampleTicket(t)
	r.ID, r.Sig = NewID(t0), ""
	r.Renews = &Renewal{Of: tk.ID, Reason: RenewApprovalExpired, ApprovedAt: &at, Checked: true, Changes: ch}
	if err := r.Sign(lockKey); err != nil {
		t.Fatal(err)
	}
	raw, _ := r.Marshal()
	got, err := VerifyTicket(lockPub, raw)
	if err != nil || got.Renews.Of != tk.ID || len(got.Renews.Changes) != 2 || got.Renews.Unchanged() {
		t.Fatalf("%+v %v", got, err)
	}
	for name, mod := range map[string]func(*Renewal){
		"self":       func(x *Renewal) { x.Of = r.ID },
		"reason":     func(x *Renewal) { x.Reason = "later" },
		"unsorted":   func(x *Renewal) { x.Changes = []Change{ch[1], ch[0]} },
		"same":       func(x *Renewal) { x.Changes = []Change{{Input: "a", Before: ch[1].Before, After: ch[1].Before}} },
		"not digest": func(x *Renewal) { x.Changes = []Change{{Input: "a", Before: "jane.doe@example.com", After: ""}} },
		"unchecked":  func(x *Renewal) { x.Checked = false },
	} {
		c := *r
		rr := *r.Renews
		c.Renews, c.Sig = &rr, ""
		mod(c.Renews)
		if err := c.Sign(lockKey); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !(&Renewal{Checked: true}).Unchanged() || (&Renewal{}).Unchanged() {
		t.Fatal("Unchanged")
	}
}
