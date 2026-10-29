package render

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/pii"
	"github.com/DavidGodefroid/lockkit/ticket"
)

func detectors(t *testing.T) []pii.Detector {
	t.Helper()
	ds, err := pii.Detectors([]string{"email", "iban", "card", "phone"})
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

// The structure of a request stays visible; a value in a personal column
// and what a detector finds are masked.
func TestMaskScreenKeepsStructure(t *testing.T) {
	src := ScreenSource{
		Header: "db / shop · tier read",
		Note:   "check the order of jean.dupont@example.com",
		Body: []Line{
			{{Text: "SELECT id, status FROM orders WHERE customer_name = "}, {Text: "'Jean Dupont'", Value: true, Column: "customer_name"},
				{Text: " AND status = "}, {Text: "'shipped'", Value: true, Column: "status"},
				{Text: " AND ref = "}, {Text: "'BE68 5390 0754 7034'", Value: true, Column: "ref"}},
			Structure("LIMIT 20"),
		},
		Warnings: []string{"not read-only"},
	}
	m := MaskScreen(src, Masking{Detectors: detectors(t)})
	s := m.Screen()
	body := strings.Join(s.Body, "\n")
	for _, kept := range []string{"SELECT id, status FROM orders WHERE customer_name = ", " AND status = 'shipped'", " AND ref = ", "LIMIT 20"} {
		if !strings.Contains(body, kept) {
			t.Errorf("structure %q lost:\n%s", kept, body)
		}
	}
	for _, leak := range []string{"Jean", "Dupont", "5390"} {
		if strings.Contains(body, leak) {
			t.Errorf("%q shown:\n%s", leak, body)
		}
	}
	if strings.Contains(s.Note, "dupont") || !strings.HasPrefix(s.Note, "check the order of ") {
		t.Errorf("note %q", s.Note)
	}
	if s.Header != src.Header || s.Warnings[0] != "not read-only" {
		t.Errorf("header %q warnings %q", s.Header, s.Warnings)
	}
	if got := strings.Join(m.Touched(), ","); got != "email,iban,personal_column" {
		t.Errorf("touched %q", got)
	}
	// Screen is a copy: changing it leaves m as built.
	s.Body[0] = "changed"
	if m.Screen().Body[0] == "changed" {
		t.Error("Screen shares its lines")
	}
}

// A value split across parts is found on the whole line.
func TestMaskScreenSplitValue(t *testing.T) {
	src := ScreenSource{Body: []Line{
		{{Text: "to = '"}, {Text: "jean.dupont", Value: true}, {Text: "@example.com'"}},
		{{Text: "iban = "}, {Text: "BE68 5390", Value: true}, {Text: " 0754 7034", Value: true}},
	}}
	body := strings.Join(MaskScreen(src, Masking{Detectors: detectors(t)}).Screen().Body, "\n")
	for _, leak := range []string{"dupont", "@example.com", "5390", "7034"} {
		if strings.Contains(body, leak) {
			t.Errorf("%q shown:\n%s", leak, body)
		}
	}
}

// Personal decides which columns are personal.
func TestMaskScreenPersonal(t *testing.T) {
	src := ScreenSource{Body: []Line{{{Text: "x = "}, {Text: "secret-ish", Value: true, Column: "internal_code"}}}}
	m := MaskScreen(src, Masking{Personal: func(c, _ string) bool { return c == "internal_code" }})
	if b := m.Screen().Body[0]; b != "x = s***(10)" {
		t.Errorf("body %q", b)
	}
	if b := MaskScreen(src, Masking{}).Screen().Body[0]; b != "x = secret-ish" {
		t.Errorf("default heuristics: %q", b)
	}
}

// Only MaskScreen builds a MaskedScreen: no exported field, and the zero
// value is not valid and does not encode.
func TestMaskedScreenOpaque(t *testing.T) {
	typ := reflect.TypeOf(MaskedScreen{})
	for i := range typ.NumField() {
		if f := typ.Field(i); f.IsExported() {
			t.Errorf("exported field %s", f.Name)
		}
	}
	var zero MaskedScreen
	if zero.Valid() {
		t.Error("zero value valid")
	}
	if _, err := json.Marshal(zero); !errors.Is(err, ErrUnmasked) {
		t.Errorf("zero value encoded: %v", err)
	}
	if _, err := json.Marshal(ticketWith(zero)); err == nil {
		t.Error("ticket with an unmasked screen encoded")
	}
	m := MaskScreen(ScreenSource{}, Masking{})
	raw, err := json.Marshal(m)
	if !m.Valid() || err != nil || string(raw) != `{"header":"","note":"","body":[],"warnings":[],"red":false}` {
		t.Fatalf("empty screen: %s %v", raw, err)
	}
}

// ticketWith is what a client of the hub sends: the masked screen beside
// the ticket.
func ticketWith(m MaskedScreen) any {
	return struct {
		Ticket ticket.Ticket `json:"ticket"`
		Screen MaskedScreen  `json:"screen"`
	}{Ticket: ticket.Ticket{Screen: m.Screen()}, Screen: m}
}

// gen makes personal values the detectors know, valid where they carry a
// checksum.
type gen struct{ r *rand.Rand }

func (g gen) digits(n int) string {
	var b strings.Builder
	for range n {
		b.WriteByte(byte('0' + g.r.IntN(10)))
	}
	return b.String()
}

func (g gen) word(n int) string {
	var b strings.Builder
	for range n {
		b.WriteByte(byte('a' + g.r.IntN(26)))
	}
	return b.String()
}

func (g gen) email() string {
	return g.word(3+g.r.IntN(8)) + "." + g.word(3+g.r.IntN(6)) + "@" + g.word(4+g.r.IntN(6)) + ".com"
}

func (g gen) iban() string {
	acct := g.digits(10)
	var n int
	fmt.Sscan(acct, &n)
	nat := n % 97
	if nat == 0 {
		nat = 97
	}
	bban := fmt.Sprintf("%s%02d", acct, nat)
	// IBAN check digits: BBAN + "BE00" as digits (B=11, E=14), mod 97.
	check := 98 - mod97(bban+"111400")
	s := fmt.Sprintf("BE%02d%s", check, bban)
	if g.r.IntN(2) == 0 {
		return s[:4] + " " + s[4:8] + " " + s[8:12] + " " + s[12:]
	}
	return s
}

func mod97(digits string) int {
	m := 0
	for _, c := range digits {
		m = (m*10 + int(c-'0')) % 97
	}
	return m
}

func (g gen) card() string {
	d := "4" + g.digits(14)
	sum := 0
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if (len(d)-i)%2 == 1 { // doubled, counting the check digit as position 1
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	d += string(byte('0' + (10-sum%10)%10))
	if g.r.IntN(2) == 0 {
		return d[:4] + " " + d[4:8] + " " + d[8:12] + " " + d[12:]
	}
	return d
}

func (g gen) phone() string {
	return "+32 47" + g.digits(1) + " " + g.digits(2) + " " + g.digits(2) + " " + g.digits(2)
}

func (g gen) name() string {
	return strings.ToUpper(g.word(1)) + g.word(4+g.r.IntN(6)) + " " + strings.ToUpper(g.word(1)) + g.word(4+g.r.IntN(8))
}

// Property: generated personal values never appear in the encoded ticket
// or screen, wherever the product put them.
func TestMaskScreenNoPII(t *testing.T) {
	ds := detectors(t)
	g := gen{rand.New(rand.NewPCG(1, 2))}
	for i := range 500 {
		var secrets []string
		detected := func() string {
			v := []func() string{g.email, g.iban, g.card, g.phone}[g.r.IntN(4)]()
			secrets = append(secrets, v)
			return v
		}
		name := g.name()
		secrets = append(secrets, name)
		src := ScreenSource{
			Header: "db / " + detected(),
			Note:   "because " + detected() + " asked",
			Body: []Line{
				{{Text: "UPDATE customers SET "}, {Text: "full_name"}, {Text: " = "}, {Text: "'" + name + "'", Value: true, Column: "full_name"},
					{Text: " WHERE contact = "}, {Text: "'" + detected() + "'", Value: true, Column: "contact"}},
				Structure("-- " + detected()),
				{{Text: "params: "}, {Text: detected(), Value: true}},
			},
			Warnings: []string{"touches " + detected()},
		}
		m := MaskScreen(src, Masking{Detectors: ds})
		raw, err := json.Marshal(ticketWith(m))
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		for _, s := range secrets {
			for _, form := range []string{s, strings.ReplaceAll(s, " ", "")} {
				if strings.Contains(strings.ReplaceAll(out, " ", ""), strings.ReplaceAll(form, " ", "")) {
					t.Fatalf("case %d: %q in the ticket:\n%s", i, s, out)
				}
			}
		}
		if !strings.Contains(out, "UPDATE customers SET full_name = ") || !strings.Contains(out, " WHERE contact = ") {
			t.Fatalf("case %d: structure lost:\n%s", i, out)
		}
	}
}

// A Masking without detectors is not "no detection": every detector runs
// (#58), so a product that forgets pii.Detectors sends nothing in clear.
func TestMaskScreenNoDetectorsMeansAll(t *testing.T) {
	m := MaskScreen(ScreenSource{Header: "db / crm", Note: "mail jane.doe@example.com about IBAN BE71 0961 2345 6769",
		Body: []Line{Structure("SELECT * FROM t WHERE x = 'john@example.org'")}}, Masking{})
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, clear := range []string{"jane.doe@example.com", "john@example.org", "BE71 0961 2345 6769"} {
		if strings.Contains(string(b), clear) {
			t.Errorf("%q in clear: %s", clear, b)
		}
	}
	if !slices.Contains(m.Touched(), "email") || !slices.Contains(m.Touched(), "iban") {
		t.Errorf("touched %v", m.Touched())
	}
}
