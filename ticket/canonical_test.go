package ticket

import (
	"encoding/json"
	"errors"
	"math"
	"math/rand/v2"
	"reflect"
	"strconv"
	"testing"
)

func TestCanonicalizeRFC8785(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		// RFC 8785 §3.2.2.
		{"rfc-3.2.2",
			`{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/","literals":[null,true,false]}`,
			`{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`},
		// RFC 8785 §3.2.3: members sorted by UTF-16 code units.
		{"rfc-3.2.3",
			`{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`,
			"{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\",\"\u20ac\":\"Euro Sign\",\"\U0001F600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"},
		{"whitespace", " { \"b\" : [ 1 , 2 ] ,\n\"a\":{} } ", `{"a":{},"b":[1,2]}`},
		{"nested-sort", `{"z":{"y":1,"x":2},"a":[{"c":1,"b":2}]}`, `{"a":[{"b":2,"c":1}],"z":{"x":2,"y":1}}`},
		{"no-html-escape", `"<a>&\u2028"`, "\"<a>&\u2028\""},
		{"controls", `"\u0000\u001f\b\f\t"`, `"\u0000\u001f\b\f\t"`},
		{"neg-zero", `-0.0`, `0`},
		{"empty", `[]`, `[]`},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := CanonicalizeJSON([]byte(c.in))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Fatalf("got  %s\nwant %s", got, c.want)
			}
		})
	}
}

func TestCanonicalizeRefuses(t *testing.T) {
	for _, in := range []string{
		`{"a":1,"a":2}`,
		`{"a":{"b":1,"b":1}}`,
		`"\ud800"`,
		`"\udc00\ud800"`,
		`"\ud800\u0041"`,
		"\"\xff\"",
		`1e400`,
		`-1e400`,
		`{"a":1} x`,
		`{"a":1}{}`,
		`01`,
		`1.`,
		`.5`,
		`+1`,
		`[1,]`,
		`{"a":1,}`,
		`"tab	"`,
		`nul`,
		``,
		`"\x"`,
		`9007199254740993`,
		`-9007199254740993`,
		`[123456789012345678901234567890]`,
	} {
		if _, err := CanonicalizeJSON([]byte(in)); !errors.Is(err, ErrNotCanonicalizable) {
			t.Errorf("%q: got %v, want ErrNotCanonicalizable", in, err)
		}
	}
	deep := ""
	for range maxDepth + 2 {
		deep += "["
	}
	if _, err := CanonicalizeJSON([]byte(deep)); err == nil {
		t.Error("deep nesting accepted")
	}
}

// ES Number::toString outputs (RFC 8785 Appendix B and ECMA-262).
func TestFormatNumber(t *testing.T) {
	for _, c := range []struct {
		f    float64
		want string
	}{
		{0, "0"}, {math.Copysign(0, -1), "0"}, {1, "1"}, {-1, "-1"},
		{4.5, "4.5"}, {0.002, "0.002"}, {1e-7, "1e-7"}, {0.000001, "0.000001"},
		{1e21, "1e+21"}, {1e20, "100000000000000000000"}, {123456789012345680000, "123456789012345680000"},
		{1e30, "1e+30"}, {1e-27, "1e-27"}, {333333333.33333329, "333333333.3333333"},
		{9007199254740992, "9007199254740992"}, {math.MaxFloat64, "1.7976931348623157e+308"},
		{5e-324, "5e-324"}, {-1.5e-10, "-1.5e-10"}, {295147905179352830000, "295147905179352830000"},
	} {
		if got := formatNumber(c.f); got != c.want {
			t.Errorf("formatNumber(%v) = %s, want %s", c.f, got, c.want)
		}
	}
	r := rand.New(rand.NewPCG(1, 2))
	for range 100000 {
		f := math.Float64frombits(r.Uint64())
		if math.IsNaN(f) || math.IsInf(f, 0) {
			continue
		}
		s := formatNumber(f)
		back, err := strconv.ParseFloat(s, 64)
		if err != nil || back != f && !(f == 0 && back == 0) {
			t.Fatalf("formatNumber(%v) = %s does not round-trip (%v, %v)", f, s, back, err)
		}
	}
}

func FuzzCanonicalizeJSON(f *testing.F) {
	for _, s := range []string{
		`{"b":1,"a":[true,null,"x"]}`, `1e30`, `"\ud83d\ude00"`, `{"\u20ac":1,"\r":2}`,
		`[0.1,-0,1E-7,123456789012345678901234567890]`, `{"a":{"a":{}}}`, `"\u0000"`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		out, err := CanonicalizeJSON(in)
		if err != nil {
			return
		}
		if !json.Valid(in) {
			t.Fatalf("accepted invalid JSON %q", in)
		}
		if !json.Valid(out) {
			t.Fatalf("produced invalid JSON %q from %q", out, in)
		}
		again, err := CanonicalizeJSON(out)
		if err != nil || string(again) != string(out) {
			t.Fatalf("not idempotent: %q → %q (%v)", out, again, err)
		}
		var a, b any
		if json.Unmarshal(in, &a) != nil || json.Unmarshal(out, &b) != nil {
			t.Fatal("unmarshal")
		}
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("value changed: %q → %q", in, out)
		}
	})
}

// Canonical refuses what json.Marshal would encode with a loss, so two
// different values never hash alike.
func TestCanonicalLossless(t *testing.T) {
	for _, v := range []any{
		map[string]any{"p": "a\xffb"},
		[]int64{1<<53 + 1},
		[]uint64{1<<64 - 1},
		json.Number("9007199254740993"),
	} {
		if _, err := Canonical(v); !errors.Is(err, ErrNotCanonicalizable) {
			t.Errorf("%#v: got %v, want ErrNotCanonicalizable", v, err)
		}
		if _, err := HashOf(v); err == nil {
			t.Errorf("HashOf(%#v) accepted", v)
		}
	}
	for _, v := range []any{
		[]int64{1 << 53, -(1 << 53), 1 << 62}, // exact in a double
		"\ufffd is fine when it is the real character",
		json.RawMessage(`18446744073709551616`),
	} {
		if _, err := Canonical(v); err != nil {
			t.Errorf("%#v: %v", v, err)
		}
	}
	a, _ := HashOf([]int64{1 << 53})
	if b, err := HashOf([]int64{1<<53 + 1}); err == nil && a == b {
		t.Fatal("2^53 and 2^53+1 hash alike")
	}
}
