package ticket

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"strings"
	"testing"
	"time"
)

// connectX25519 is the one-use key of the connect fixture (test only).
var connectX25519 = bytes.Repeat([]byte{0x88}, 32)

func connectKey(tb testing.TB) *ecdh.PrivateKey {
	tb.Helper()
	k, err := ecdh.X25519().NewPrivateKey(connectX25519)
	if err != nil {
		tb.Fatal(err)
	}
	return k
}

// sampleConnectTicket asks to connect profile crm-prod, the secret typed
// on the decider's side ("ask").
func sampleConnectTicket(tb testing.TB) *Ticket {
	tb.Helper()
	fp, err := HashOf(map[string]any{"profile": "crm-prod", "tier": "write"})
	if err != nil {
		tb.Fatal(err)
	}
	subj := Subject{Profile: "crm-prod", Endpoint: "db.internal:5432/shop", Credential: CredentialAsk,
		SecretTo: enc.EncodeToString(connectKey(tb).PublicKey().Bytes())}
	tk, err := NewConnectTicket(Source{Lock: "locksql", Instance: "crm-prod"}, RiskUnlock, subj, fp, t0, RiskUnlock.TTL())
	if err != nil {
		tb.Fatal(err)
	}
	tk.ID = "01JBDN0Z0000000000000000AD" // stable for fixtures
	tk.Workspace = "~/Documents"
	tk.Requester = Requester{Agent: "dev-3", Session: "s-1"}
	tk.Flags = Flags{Production: true, Retype: "crm-prod"}
	tk.Screen = Screen{
		Header:   "crm-prod · connect",
		Body:     []string{"endpoint: db.internal:5432/shop", "credentials: ask"},
		Warnings: []string{"production"},
	}
	tk.PII = PII{Touched: []string{}}
	if err := tk.Sign(lockKey); err != nil {
		tb.Fatal(err)
	}
	return tk
}

// sampleConnectDecision approves tk under auto rule "prod-connect", the
// secret sealed with a fixed ephemeral key and nonce (fixtures).
func sampleConnectDecision(tb testing.TB, tk *Ticket) *Decision {
	tb.Helper()
	eph, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x99}, 32))
	box, err := sealWith(SealAlg, eph, bytes.Repeat([]byte{0x01}, 24), connectKey(tb).PublicKey(), []byte("s3cret password"), SecretAAD(tk))
	if err != nil {
		tb.Fatal(err)
	}
	d := &Decision{
		V: VersionKinds, Ticket: tk.ID, Instance: tk.Source.Instance, KeyID: tk.Source.KeyID,
		PlanHash: tk.PlanHash, Decision: Approved, Approver: Approver{ID: "lox-run", Display: "lox run"},
		Facade: "lox-run", At: t0.Add(time.Second), Nonce: "AAECAwQFBgcICQoLDA0ODw",
		Rule: &Rule{By: RuleAuto, ID: "prod-connect"}, Secret: box,
	}
	if err := d.Sign(hubKey); err != nil {
		tb.Fatal(err)
	}
	return d
}

func TestKindTicketRoundTrip(t *testing.T) {
	tk := sampleConnectTicket(t)
	b := mustMarshal(t, tk)
	for _, want := range []string{`"v":2`, `"kind":"connect"`, `"credential":"ask"`, `"secret_to":`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("%s not in %s", want, b)
		}
	}
	got, err := VerifyTicket(lockPub, b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != KindConnect || *got.Subject != *tk.Subject || got.EffectiveKind() != KindConnect {
		t.Fatalf("decoded %+v", got)
	}
	if want, _ := ConnectPlanHash(*tk.Subject); got.PlanHash != want {
		t.Fatal("the plan of a connect ticket is its subject")
	}
	// The subject is signed: changing the endpoint or the secret key
	// breaks the signature.
	for _, mod := range []string{
		strings.Replace(string(b), "db.internal", "db.evil", 1),
		strings.Replace(string(b), `"credential":"ask"`, `"credential":"vault"`, 1),
	} {
		if _, err := VerifyTicket(lockPub, []byte(mod)); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("tampered subject: %v", err)
		}
	}
}

func TestKindVersioning(t *testing.T) {
	// A version-1 ticket keeps its encoding: no kind, no subject.
	v1 := sampleTicket(t)
	if b := mustMarshal(t, v1); strings.Contains(string(b), "kind") || strings.Contains(string(b), "subject") {
		t.Fatalf("v1 ticket grew members: %s", b)
	}
	if v1.EffectiveKind() != KindWrite || sampleGrantTicket(t).EffectiveKind() != KindRead {
		t.Fatal("effective kind of v1 tickets")
	}
	resign := func(tk *Ticket) error { tk.Sig = ""; return tk.Sign(lockKey) }
	// A kind in a v1 ticket, or a v2 ticket without one, is refused.
	k := *v1
	k.Kind = KindWrite
	if err := resign(&k); !errors.Is(err, ErrInvalid) {
		t.Fatalf("v1 with kind: %v", err)
	}
	k = *v1
	k.V = VersionKinds
	if err := resign(&k); !errors.Is(err, ErrInvalid) {
		t.Fatalf("v2 without kind: %v", err)
	}
	k.Kind = KindWrite
	if err := resign(&k); err != nil {
		t.Fatalf("v2 write: %v", err)
	}
	k.V = 3
	if err := resign(&k); !errors.Is(err, ErrInvalid) {
		t.Fatalf("v3: %v", err)
	}
	// An unknown kind does not decode.
	b := mustMarshal(t, sampleConnectTicket(t))
	if _, err := VerifyTicket(lockPub, bytes.Replace(b, []byte(`"kind":"connect"`), []byte(`"kind":"connekt"`), 1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown kind: %v", err)
	}
	// A v1 decision on a v2 ticket does not match it: the audit needs the
	// rule.
	tk := sampleConnectTicket(t)
	d := sampleConnectDecision(t, tk)
	d1 := *d
	d1.V, d1.Rule, d1.Secret, d1.Sig = Version, nil, nil, ""
	if err := d1.Sign(hubKey); err != nil {
		t.Fatal(err)
	}
	if err := d1.Match(tk); !errors.Is(err, ErrMismatch) {
		t.Fatalf("v1 decision on v2 ticket: %v", err)
	}
	// A v2 decision answers a v1 ticket.
	d2 := sampleDecision(t, v1, Approved)
	d2.V, d2.Rule, d2.Sig = VersionKinds, &Rule{By: RuleHuman}, ""
	if err := d2.Sign(hubKey); err != nil {
		t.Fatal(err)
	}
	if err := d2.Match(v1); err != nil {
		t.Fatalf("v2 decision on v1 ticket: %v", err)
	}
}

func TestKindRiskAndSubject(t *testing.T) {
	fp, _ := HashOf("fp")
	plan, _ := HashOf("plan")
	src := Source{Lock: "lockmq", Instance: "mq-prod"}
	key := enc.EncodeToString(connectKey(t).PublicKey().Bytes())
	for _, c := range []struct {
		name string
		kind Kind
		risk Risk
		subj *Subject
		ok   bool
	}{
		{"connect", KindConnect, RiskRead, &Subject{Profile: "p", Endpoint: "h:1", Credential: CredentialVault}, true},
		{"connect with key", KindConnect, RiskUnlock, &Subject{Profile: "p", Endpoint: "h:1", Credential: CredentialVault, SecretTo: key}, true},
		{"connect no subject", KindConnect, RiskRead, nil, false},
		{"connect no profile", KindConnect, RiskRead, &Subject{Endpoint: "h:1", Credential: CredentialAsk}, false},
		{"connect no endpoint", KindConnect, RiskRead, &Subject{Profile: "p", Credential: CredentialAsk}, false},
		{"connect bad credential", KindConnect, RiskRead, &Subject{Profile: "p", Endpoint: "h", Credential: "env"}, false},
		{"connect userinfo", KindConnect, RiskRead, &Subject{Profile: "p", Endpoint: "amqp://bob:pw@h", Credential: CredentialAsk}, false},
		{"connect scheme", KindConnect, RiskRead, &Subject{Profile: "p", Endpoint: "amqp://mq.internal:5672/vh", Credential: CredentialAsk}, true},
		{"connect ipv6", KindConnect, RiskRead, &Subject{Profile: "p", Endpoint: "[::1]:5432/shop", Credential: CredentialAsk}, true},
		{"connect DSN", KindConnect, RiskRead, &Subject{Profile: "p", Endpoint: "host=db password=hunter2", Credential: CredentialAsk}, false},
		{"connect query", KindConnect, RiskRead, &Subject{Profile: "p", Endpoint: "db:5432/x?sslpassword=hunter2", Credential: CredentialAsk}, false},
		{"connect fragment", KindConnect, RiskRead, &Subject{Profile: "p", Endpoint: "db:5432/x#hunter2", Credential: CredentialAsk}, false},
		{"connect options", KindConnect, RiskRead, &Subject{Profile: "p", Endpoint: "db;password=hunter2", Credential: CredentialAsk}, false},
		{"connect escape", KindConnect, RiskRead, &Subject{Profile: "p", Endpoint: "db:5432/x%3Fpw", Credential: CredentialAsk}, false},
		{"connect tab", KindConnect, RiskRead, &Subject{Profile: "p", Endpoint: "db\t5432", Credential: CredentialAsk}, false},
		{"connect none with key", KindConnect, RiskRead, &Subject{Profile: "p", Endpoint: "h", Credential: CredentialNone, SecretTo: key}, false},
		{"connect bad key", KindConnect, RiskRead, &Subject{Profile: "p", Endpoint: "h", Credential: CredentialAsk, SecretTo: "AAAA"}, false},
		{"connect verb", KindConnect, RiskRead, &Subject{Profile: "p", Endpoint: "h", Credential: CredentialAsk, Verb: "publish"}, false},
		{"connect grant", KindConnect, RiskGrant, &Subject{Profile: "p", Endpoint: "h", Credential: CredentialAsk}, false},
		{"action", KindAction, RiskWrite, &Subject{Verb: "publish", Target: "orders"}, true},
		{"action path", KindAction, RiskWrite, &Subject{Verb: "DELETE", Target: "/users/42"}, true},
		{"action query", KindAction, RiskWrite, &Subject{Verb: "GET", Target: "/users?email=john@doe.com&token=abc"}, false},
		{"action fragment", KindAction, RiskWrite, &Subject{Verb: "GET", Target: "/users#token=abc"}, false},
		{"action space", KindAction, RiskWrite, &Subject{Verb: "publish", Target: "orders token=abc"}, false},
		{"action newline", KindAction, RiskWrite, &Subject{Verb: "publish", Target: "orders\nx"}, false},
		{"action no verb", KindAction, RiskWrite, &Subject{Target: "orders"}, false},
		{"action bad verb", KindAction, RiskWrite, &Subject{Verb: "rm -rf"}, false},
		{"action credential", KindAction, RiskWrite, &Subject{Verb: "purge", Credential: CredentialAsk}, false},
		{"endpoint", KindEndpoint, RiskRead, &Subject{Endpoint: "api.example.com", Verb: "GET", Target: "/v1/items"}, true},
		{"endpoint query", KindEndpoint, RiskRead, &Subject{Endpoint: "api.example.com/?key=abc", Verb: "GET"}, false},
		{"endpoint no host", KindEndpoint, RiskRead, &Subject{Verb: "GET"}, false},
		{"read", KindRead, RiskReadPII, &Subject{Profile: "p", Target: "customers"}, true},
		{"read bare", KindRead, RiskRead, nil, true},
		{"read grant", KindRead, RiskGrant, nil, true},
		{"read with verb", KindRead, RiskRead, &Subject{Verb: "GET"}, false},
		{"read as write", KindRead, RiskWrite, nil, false},
		{"write prod", KindWrite, RiskProdWrite, nil, true},
		{"ddl", KindDDL, RiskWrite, &Subject{Target: "customers"}, true},
		{"ddl as read", KindDDL, RiskRead, nil, false},
		{"policy", KindPolicy, RiskPolicyLoosen, nil, true},
		{"policy as write", KindPolicy, RiskWrite, nil, false},
		{"write as policy", KindWrite, RiskPolicyLoosen, nil, false},
	} {
		tk := NewKindTicket(src, c.kind, c.risk, c.subj, plan, fp, t0, 0)
		err := tk.Sign(lockKey)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: not ErrInvalid: %v", c.name, err)
		}
		if err == nil {
			b := mustMarshal(t, tk)
			if _, err := VerifyTicket(lockPub, b); err != nil {
				t.Errorf("%s: verify: %v", c.name, err)
			}
		}
	}
	// An empty member is not a second encoding of an absent one.
	tk := NewKindTicket(src, KindAction, RiskWrite, &Subject{Verb: "publish"}, plan, fp, t0, 0)
	if err := tk.Sign(lockKey); err != nil {
		t.Fatal(err)
	}
	b := mustMarshal(t, tk)
	if _, err := VerifyTicket(lockPub, bytes.Replace(b, []byte(`"subject":{`), []byte(`"subject":{"target":"",`), 1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty member: %v", err)
	}
	if _, err := ParseKind("zq-secret"); err == nil || strings.Contains(err.Error(), "zq-secret") {
		t.Fatalf("ParseKind echoes: %v", err)
	}
	if len(KindRisks(KindRead)) != 3 || KindRisks("nope") != nil {
		t.Fatal("KindRisks")
	}
}

func TestDecisionRule(t *testing.T) {
	tk := sampleConnectTicket(t)
	d := sampleConnectDecision(t, tk)
	b := mustMarshal(t, d)
	got, err := VerifyDecision(hubPub, b)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Auto() || got.Rule.ID != "prod-connect" {
		t.Fatalf("rule %+v", got.Rule)
	}
	if err := got.Match(tk); err != nil {
		t.Fatal(err)
	}
	// The rule is signed.
	if _, err := VerifyDecision(hubPub, bytes.Replace(b, []byte("prod-connect"), []byte("prod-connecT"), 1)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered rule: %v", err)
	}
	sign := func(mod func(*Decision)) error {
		x := *d
		x.Sig = ""
		mod(&x)
		return x.Sign(hubKey)
	}
	for name, mod := range map[string]func(*Decision){
		"v2 without rule":     func(x *Decision) { x.Rule = nil },
		"unknown by":          func(x *Decision) { x.Rule = &Rule{By: "robot"} },
		"auto without id":     func(x *Decision) { x.Rule = &Rule{By: RuleAuto} },
		"human with id":       func(x *Decision) { x.Rule = &Rule{By: RuleHuman, ID: "r1"} },
		"secret on a denial":  func(x *Decision) { x.Decision = Denied },
		"bad secret box":      func(x *Decision) { s := *x.Secret; s.Alg = "rot13"; x.Secret = &s },
		"v1 with rule":        func(x *Decision) { x.V, x.Secret = Version, nil },
		"v1 with secret only": func(x *Decision) { x.V, x.Rule = Version, nil },
	} {
		if err := sign(mod); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// An auto approval of a never-auto ticket is not usable; a human's is.
	na := sampleConnectTicket(t)
	na.Flags.NeverAuto, na.Sig = true, ""
	if err := na.Sign(lockKey); err != nil {
		t.Fatal(err)
	}
	da := *d
	da.Rule = &Rule{By: RuleAuto, ID: "r"}
	if err := da.Usable(na, t0.Add(time.Minute), 0); !errors.Is(err, ErrAuto) {
		t.Fatalf("auto on never-auto: %v", err)
	}
	da.Rule = &Rule{By: RuleHuman}
	if err := da.Usable(na, t0.Add(time.Minute), 0); err != nil {
		t.Fatalf("human on never-auto: %v", err)
	}
}

func TestConnectSecret(t *testing.T) {
	tk := sampleConnectTicket(t)
	priv := connectKey(t)
	// The decider seals to the ticket's key; the lock opens it.
	box, err := SealSecret(tk, []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	d := sampleConnectDecision(t, tk)
	d.Secret, d.Sig = box, ""
	if err := d.Sign(hubKey); err != nil {
		t.Fatal(err)
	}
	raw := mustMarshal(t, d)
	if bytes.Contains(raw, []byte("hunter2")) {
		t.Fatal("the secret is in clear in the decision")
	}
	got, err := VerifyDecision(hubPub, raw)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := got.OpenSecret(tk, priv)
	if err != nil || string(sec) != "hunter2" {
		t.Fatalf("open: %q %v", sec, err)
	}
	// Another key, or another ticket's box, does not open.
	other, _ := ecdh.X25519().GenerateKey(bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	if _, err := got.OpenSecret(tk, other); !errors.Is(err, ErrOpen) {
		t.Fatalf("other key: %v", err)
	}
	tk2 := sampleConnectTicket(t)
	tk2.ID, tk2.Sig = "01JBDN0Z0000000000000000AE", ""
	if err := tk2.Sign(lockKey); err != nil {
		t.Fatal(err)
	}
	if _, err := got.OpenSecret(tk2, priv); !errors.Is(err, ErrOpen) {
		t.Fatalf("box of another ticket: %v", err)
	}
	// Asked and not given, given and not asked.
	none := *got
	none.Secret = nil
	if _, err := none.OpenSecret(tk, priv); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("asked, none: %v", err)
	}
	plain := sampleTicket(t)
	if _, err := got.OpenSecret(plain, priv); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("not asked: %v", err)
	}
	if _, err := SealSecret(plain, []byte("x")); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("seal for a ticket that asks none: %v", err)
	}
	// A secret on a decision for a ticket that did not ask for one does
	// not match it.
	vt := sampleTicket(t)
	vt.V, vt.Kind, vt.Sig = VersionKinds, KindWrite, ""
	if err := vt.Sign(lockKey); err != nil {
		t.Fatal(err)
	}
	ds := *got
	ds.Ticket, ds.PlanHash = vt.ID, vt.PlanHash
	if err := ds.Match(vt); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("unasked secret matches: %v", err)
	}
	// No secret asked: OpenSecret gives nil, nil.
	nk := sampleConnectTicket(t)
	nk.Subject.SecretTo, nk.Sig = "", ""
	nk.PlanHash, _ = ConnectPlanHash(*nk.Subject)
	if err := nk.Sign(lockKey); err != nil {
		t.Fatal(err)
	}
	if s, err := none.OpenSecret(nk, nil); s != nil || err != nil {
		t.Fatalf("no secret asked: %q %v", s, err)
	}
}

func TestSubjectValidateAndConnectTicket(t *testing.T) {
	fp, _ := HashOf("fp")
	for _, ep := range []string{"host=db password=hunter2", "db:5432/x?sslpassword=hunter2"} {
		s := Subject{Profile: "p", Endpoint: ep, Credential: CredentialAsk}
		if err := s.Validate(KindConnect); !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "hunter2") {
			t.Fatalf("%q: Validate %v", ep, err)
		}
		if tk, err := NewConnectTicket(Source{Lock: "locksql"}, RiskRead, s, fp, t0, time.Hour); !errors.Is(err, ErrInvalid) || tk != nil {
			t.Fatalf("%q: NewConnectTicket %v", ep, err)
		}
	}
	a := Subject{Verb: "GET", Target: "/users?email=john@doe.com&token=abc"}
	if err := a.Validate(KindAction); !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "token") {
		t.Fatalf("action target: %v", err)
	}
	ok := Subject{Profile: "p", Endpoint: "db.internal:5432/shop", Credential: CredentialAsk}
	if err := ok.Validate(KindConnect); err != nil {
		t.Fatal(err)
	}
	if err := ok.Validate("nope"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown kind: %v", err)
	}
}
