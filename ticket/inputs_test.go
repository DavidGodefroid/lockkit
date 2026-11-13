package ticket

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// inputsX25519 is the one-use key of the inputs fixture (test only).
var inputsX25519 = bytes.Repeat([]byte{0x77}, 32)

func inputsKey(tb testing.TB) *ecdh.PrivateKey {
	tb.Helper()
	k, err := ecdh.X25519().NewPrivateKey(inputsX25519)
	if err != nil {
		tb.Fatal(err)
	}
	return k
}

// sampleInputsTicket is a read ticket asking the human for the values
// named names.
func sampleInputsTicket(tb testing.TB, id string, names ...string) *Ticket {
	tb.Helper()
	plan, err := HashOf(map[string]any{"sql": "SELECT id FROM customers WHERE email = :needle"})
	if err != nil {
		tb.Fatal(err)
	}
	fp, err := HashOf(map[string]any{"profile": "crm-prod", "tier": "read"})
	if err != nil {
		tb.Fatal(err)
	}
	subj := &Subject{Profile: "crm-prod", Target: "customers", Inputs: names,
		SecretTo: EncodeX25519(inputsKey(tb).PublicKey())}
	tk := NewKindTicket(Source{Lock: "locksql", Instance: "crm-prod"}, KindRead, RiskReadPII, subj, plan, fp, t0, time.Hour)
	tk.ID = id
	tk.Flags.NeverAuto = true
	tk.Screen = Screen{Header: "crm-prod · read", Body: []string{"SELECT id FROM customers WHERE email = :needle"}}
	tk.PII = PII{Touched: []string{}}
	if err := tk.Sign(lockKey); err != nil {
		tb.Fatal(err)
	}
	return tk
}

// inputsDecision approves tk by a human, with box as its secret.
func inputsDecision(tb testing.TB, tk *Ticket, box *Sealed) *Decision {
	tb.Helper()
	d := &Decision{
		V: VersionKinds, Ticket: tk.ID, Instance: tk.Source.Instance, KeyID: tk.Source.KeyID,
		PlanHash: tk.PlanHash, Decision: Approved, Approver: Approver{ID: "david"},
		Facade: "lox-run", At: t0.Add(time.Second), Nonce: "AAECAwQFBgcICQoLDA0ODw",
		Rule: &Rule{By: RuleHuman}, Secret: box,
	}
	if err := d.Sign(hubKey); err != nil {
		tb.Fatal(err)
	}
	return d
}

func TestSubjectInputs(t *testing.T) {
	key := EncodeX25519(inputsKey(t).PublicKey())
	many := make([]string, MaxInputs+1)
	for i := range many {
		many[i] = fmt.Sprintf("n%02d", i)
	}
	ok := map[string]struct {
		k Kind
		s Subject
	}{
		"read":         {KindRead, Subject{Inputs: []string{"email", "id"}, SecretTo: key}},
		"action":       {KindAction, Subject{Verb: "move", Inputs: []string{"dest"}, SecretTo: key}},
		"max":          {KindRead, Subject{Inputs: many[:MaxInputs], SecretTo: key}},
		"name of 32":   {KindRead, Subject{Inputs: []string{strings.Repeat("a", 32)}, SecretTo: key}},
		"digits and _": {KindRead, Subject{Inputs: []string{"0_a", "a_1"}, SecretTo: key}},
	}
	for name, c := range ok {
		if err := c.s.Validate(c.k); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]struct {
		k Kind
		s Subject
	}{
		"on write":             {KindWrite, Subject{Inputs: []string{"a"}, SecretTo: key}},
		"on ddl":               {KindDDL, Subject{Inputs: []string{"a"}, SecretTo: key}},
		"on policy":            {KindPolicy, Subject{Inputs: []string{"a"}, SecretTo: key}},
		"on endpoint":          {KindEndpoint, Subject{Endpoint: "api.example.com", Inputs: []string{"a"}, SecretTo: key}},
		"on connect":           {KindConnect, Subject{Profile: "p", Endpoint: "db", Credential: CredentialAsk, Inputs: []string{"a"}, SecretTo: key}},
		"upper case":           {KindRead, Subject{Inputs: []string{"Email"}, SecretTo: key}},
		"dash":                 {KindRead, Subject{Inputs: []string{"e-mail"}, SecretTo: key}},
		"empty name":           {KindRead, Subject{Inputs: []string{""}, SecretTo: key}},
		"name of 33":           {KindRead, Subject{Inputs: []string{strings.Repeat("a", 33)}, SecretTo: key}},
		"duplicate":            {KindRead, Subject{Inputs: []string{"a", "a"}, SecretTo: key}},
		"unsorted":             {KindRead, Subject{Inputs: []string{"b", "a"}, SecretTo: key}},
		"more than 16":         {KindRead, Subject{Inputs: many, SecretTo: key}},
		"inputs, no secret_to": {KindRead, Subject{Inputs: []string{"a"}}},
		"secret_to, no inputs": {KindRead, Subject{SecretTo: key}},
		"secret_to on action":  {KindAction, Subject{Verb: "move", SecretTo: key}},
		"secret_to on write":   {KindWrite, Subject{SecretTo: key}},
		"secret_to not a key":  {KindRead, Subject{Inputs: []string{"a"}, SecretTo: "AAAA"}},
		"value as a name: a@b": {KindRead, Subject{Inputs: []string{"alice@example.org"}, SecretTo: key}},
	}
	for name, c := range bad {
		err := c.s.Validate(c.k)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "alice@example.org") {
			t.Errorf("%s: the error quotes the name: %v", name, err)
		}
	}
}

func TestInputsTicketNeverAuto(t *testing.T) {
	tk := sampleInputsTicket(t, "01JBDN0Z0000000000000000B1", "needle")
	raw := mustMarshal(t, tk)
	got, err := VerifyTicket(lockPub, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !got.AsksInputs() || got.Subject.Inputs[0] != "needle" {
		t.Fatalf("decoded %+v", got.Subject)
	}
	// Without NeverAuto, it does not sign, nor verify.
	x := *tk
	x.Flags.NeverAuto, x.Sig = false, ""
	if err := x.Sign(lockKey); !errors.Is(err, ErrInvalid) {
		t.Fatalf("sign without never_auto: %v", err)
	}
	forged := bytes.Replace(raw, []byte(`"never_auto":true`), []byte(`"never_auto":false`), 1)
	if bytes.Equal(forged, raw) {
		t.Fatal("fixture: no never_auto in the ticket")
	}
	if _, err := VerifyTicket(lockPub, forged); !errors.Is(err, ErrInvalid) {
		t.Fatalf("verify without never_auto: %v", err)
	}
	// An auto approval of it is ErrAuto.
	box, err := SealInputs(tk, map[string][]byte{"needle": []byte("alice@example.org")})
	if err != nil {
		t.Fatal(err)
	}
	d := inputsDecision(t, tk, box)
	da := *d
	da.Rule = &Rule{By: RuleAuto, ID: "r"}
	if err := da.Usable(tk, t0.Add(time.Minute), 0); !errors.Is(err, ErrAuto) {
		t.Fatalf("auto on inputs: %v", err)
	}
	if err := d.Usable(tk, t0.Add(time.Minute), 0); err != nil {
		t.Fatalf("human: %v", err)
	}
}

func TestSealOpenInputs(t *testing.T) {
	tk := sampleInputsTicket(t, "01JBDN0Z0000000000000000B1", "id", "needle")
	priv := inputsKey(t)
	values := map[string][]byte{"needle": []byte("alice@example.org"), "id": []byte("42 é")}
	box, err := SealInputs(tk, values)
	if err != nil {
		t.Fatal(err)
	}
	d := inputsDecision(t, tk, box)
	raw := mustMarshal(t, d)
	if bytes.Contains(raw, []byte("alice@example.org")) {
		t.Fatal("a value is in clear in the decision")
	}
	got, err := VerifyDecision(hubPub, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Match(tk); err != nil {
		t.Fatalf("match: %v", err)
	}
	open, err := got.OpenInputs(tk, priv)
	if err != nil || len(open) != 2 || string(open["needle"]) != "alice@example.org" || string(open["id"]) != "42 é" {
		t.Fatalf("open: %q %v", open, err)
	}

	// A box sealed for another ticket does not open.
	tk2 := sampleInputsTicket(t, "01JBDN0Z0000000000000000B2", "id", "needle")
	if _, err := got.OpenInputs(tk2, priv); !errors.Is(err, ErrOpen) {
		t.Fatalf("box of another ticket: %v", err)
	}
	// Another key does not open.
	other, _ := ecdh.X25519().GenerateKey(bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	if _, err := got.OpenInputs(tk, other); !errors.Is(err, ErrOpen) {
		t.Fatalf("other key: %v", err)
	}
	// A connect secret's box, sealed to the same key and ticket, does not
	// open as inputs; inputs do not open as a connect secret.
	pt, _ := Canonical(map[string]string{"id": "42", "needle": "x"})
	csec, err := Seal(priv.PublicKey(), pt, SecretAAD(tk))
	if err != nil {
		t.Fatal(err)
	}
	dc := inputsDecision(t, tk, csec)
	if _, err := dc.OpenInputs(tk, priv); !errors.Is(err, ErrOpen) {
		t.Fatalf("connect secret as inputs: %v", err)
	}
	if _, err := got.OpenSecret(tk, priv); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("inputs as a connect secret: %v", err)
	}
	ct := sampleConnectTicket(t)
	cd := sampleConnectDecision(t, ct)
	if _, err := cd.OpenInputs(ct, connectKey(t)); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("connect decision opened as inputs: %v", err)
	}
	if _, err := SealInputs(ct, values); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("seal inputs for a connect ticket: %v", err)
	}
	// A box whose names are not the ticket's does not open as its inputs
	// (a decider that sealed by hand, around SealInputs).
	for name, m := range map[string]map[string]string{
		"missing": {"needle": "x"},
		"extra":   {"id": "1", "needle": "x", "other": "y"},
		"renamed": {"id": "1", "needles": "x"},
		"control": {"id": "1", "needle": "a\nb"},
	} {
		pt, _ := Canonical(m)
		b, err := Seal(priv.PublicKey(), pt, InputsAAD(tk))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := inputsDecision(t, tk, b).OpenInputs(tk, priv); !errors.Is(err, ErrInputs) {
			t.Errorf("%s: %v", name, err)
		}
	}
	notJSON, _ := Seal(priv.PublicKey(), []byte("alice@example.org"), InputsAAD(tk))
	if _, err := inputsDecision(t, tk, notJSON).OpenInputs(tk, priv); !errors.Is(err, ErrInputs) {
		t.Errorf("not a map: %v", err)
	}
	// Asked and not given.
	none := *got
	none.Secret = nil
	if _, err := none.OpenInputs(tk, priv); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("asked, none: %v", err)
	}
	// Given and not asked: Match refuses the box first.
	vt := sampleTicket(t)
	vt.V, vt.Kind, vt.Sig = VersionKinds, KindWrite, ""
	if err := vt.Sign(lockKey); err != nil {
		t.Fatal(err)
	}
	ds := *got
	ds.Ticket, ds.PlanHash = vt.ID, vt.PlanHash
	if err := ds.Match(vt); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("unasked inputs match: %v", err)
	}
	if _, err := ds.OpenInputs(vt, priv); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("unasked inputs open: %v", err)
	}
	// Nothing asked, nothing given: nil, nil.
	if m, err := (&Decision{}).OpenInputs(vt, nil); m != nil || err != nil {
		t.Fatalf("none: %v %v", m, err)
	}
}

func TestSealInputsRefusesBadValues(t *testing.T) {
	tk := sampleInputsTicket(t, "01JBDN0Z0000000000000000B1", "id", "needle")
	for name, m := range map[string]map[string][]byte{
		"missing":   {"needle": []byte("x")},
		"extra":     {"id": []byte("1"), "needle": []byte("x"), "z": []byte("y")},
		"renamed":   {"id": []byte("1"), "needlE": []byte("x")},
		"empty":     {"id": []byte(""), "needle": []byte("x")},
		"too long":  {"id": bytes.Repeat([]byte("a"), MaxInputValue+1), "needle": []byte("x")},
		"newline":   {"id": []byte("1\n2"), "needle": []byte("x")},
		"tab":       {"id": []byte("1\t2"), "needle": []byte("x")},
		"escape":    {"id": []byte("\x1b[2J"), "needle": []byte("x")},
		"c1":        {"id": []byte("a\u0085b"), "needle": []byte("x")},
		"bad utf-8": {"id": []byte{0xff, 0xfe}, "needle": []byte("x")},
	} {
		_, err := SealInputs(tk, m)
		if !errors.Is(err, ErrInputs) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := SealInputs(tk, map[string][]byte{"id": bytes.Repeat([]byte("a"), MaxInputValue), "needle": []byte("x")}); err != nil {
		t.Errorf("value of %d bytes: %v", MaxInputValue, err)
	}
	// The error never quotes a value.
	_, err := SealInputs(tk, map[string][]byte{"id": []byte("secret\x01value"), "needle": []byte("x")})
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("error quotes the value: %v", err)
	}
}
