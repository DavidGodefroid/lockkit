package refusal

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// Codes of a test product, registered once.
const (
	NoLimit           Code = "E_TEST_NO_LIMIT"
	MaskedOrder       Code = "E_TEST_MASKED_ORDER"
	Forbidden         Code = "E_TEST_FORBIDDEN"
	Cost              Code = "E_TEST_COST"
	UnsupportedSyntax Code = "E_TEST_UNSUPPORTED"
	Retired           Code = "E_TEST_RETIRED"
)

func init() {
	Register(NoLimit, RetryRewrite, "no limit", "add a limit")
	Register(MaskedOrder, RetryRewrite, "masked order", "order by another column")
	Register(Forbidden, RetryStop, "forbidden", "tell the user")
	Register(Cost, RetryRewrite, "cost", "make it cheaper")
	Register(UnsupportedSyntax, RetryRewrite, "unsupported", "rewrite it")
	Register(Retired, RetryStop, "retired", "none")
	Retire(Retired)
}

func TestRegisteredCodes(t *testing.T) {
	codes := Codes()
	if !slices.IsSorted(codes) {
		t.Error("Codes is not sorted")
	}
	for _, c := range []Code{Policy, NoLimit, MaskedOrder, Forbidden, Cost, UnsupportedSyntax} {
		if !slices.Contains(codes, c) || !c.Known() || c.Title() == "" || c.Hint() == "" {
			t.Errorf("%s: not listed or not described", c)
		}
	}
	if Forbidden.Retry() != RetryStop || NoLimit.Retry() != RetryRewrite {
		t.Error("retry rules lost")
	}
	if Code("E_NOPE").Known() || Code("").Known() || Code("E_NOPE").Retry() != RetryStop {
		t.Error("unknown codes reported known, or not final")
	}
}

// A retired code stays known, for the audit records that carry it, but is
// no longer listed among the codes a refusal may carry.
func TestRetiredCodeStaysKnown(t *testing.T) {
	if !Retired.Known() || Retired.Hint() == "" {
		t.Fatal("retired code no longer known")
	}
	if slices.Contains(Codes(), Retired) {
		t.Fatal("retired code listed")
	}
}

// A code is registered once; a malformed one is a programming error.
func TestRegisterRefusesDuplicatesAndBadNames(t *testing.T) {
	for name, f := range map[string]func(){
		"duplicate":  func() { Register(NoLimit, RetryStop, "t", "h") },
		"policy":     func() { Register(Policy, RetryStop, "t", "h") },
		"bad name":   func() { Register("no_prefix", RetryStop, "t", "h") },
		"no hint":    func() { Register("E_TEST_NO_HINT", RetryStop, "t", "") },
		"bad retry":  func() { Register("E_TEST_BAD_RETRY", "later", "t", "h") },
		"retire unk": func() { Retire("E_TEST_UNKNOWN") },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: accepted", name)
				}
			}()
			f()
		}()
	}
}

func TestNewAndError(t *testing.T) {
	e := Newf(NoLimit, "a top-level %s is required", "LIMIT")
	if e.Error() != "a top-level LIMIT is required" || e.Code != NoLimit || e.Pos != -1 {
		t.Fatalf("%+v", e)
	}
	var r *Error
	if !errors.As(fmt.Errorf("wrapped: %w", e), &r) || r != e {
		t.Fatal("errors.As")
	}
	if e.WithHint("x").Hint != "x" {
		t.Fatal("hint")
	}
}

func TestInfoLocatesTheSpan(t *testing.T) {
	src := "  SELECT id\n  FROM users\n  ORDER BY émail LIMIT 5"
	pos := strings.Index(src, "émail")
	e := New(MaskedOrder, "x").At(pos-2, "émail") // positions of the trimmed text
	in := e.Info(src, 2)
	if in.Span == nil || in.Span.Line != 3 || in.Span.Col != 12 || in.Span.Token != "émail" {
		t.Fatalf("%+v", in.Span)
	}
	if in.Code != MaskedOrder || in.Retry != MaskedOrder.Retry() || in.Hint != MaskedOrder.Hint() {
		t.Fatalf("%+v", in)
	}
}

// A token folded by the lexer comes back as the agent wrote it.
func TestInfoKeepsTheSpelling(t *testing.T) {
	in := New(Forbidden, "x").At(7, "SLEEP").Info("SELECT sleep(1)", 0)
	if in.Span == nil || in.Span.Token != "sleep" {
		t.Fatalf("%+v", in.Span)
	}
}

func TestInfoWithoutPosition(t *testing.T) {
	in := New(Cost, "weight").Info("SELECT 1", 0)
	if in.Span != nil {
		t.Fatalf("span %+v", in.Span)
	}
	b, _ := json.Marshal(in)
	if strings.Contains(string(b), "span") {
		t.Fatalf("%s", b)
	}
}

// A position outside the text, or inside a character, gives no span:
// a wrong span is worse than none.
func TestInfoDropsABadPosition(t *testing.T) {
	for _, pos := range []int{-5, 100, 1} {
		if in := New(Cost, "x").At(pos, "").Info("é", 0); in.Span != nil {
			t.Errorf("pos %d: %+v", pos, in.Span)
		}
	}
}

// A token is kept only when it is printable and short: it comes from the
// agent's own statement, but it must not carry a whole literal.
func TestTokenIsBounded(t *testing.T) {
	long := strings.Repeat("a", 100)
	in := New(UnsupportedSyntax, "x").At(0, long).Info(long, 0)
	if in.Span == nil || len(in.Span.Token) > MaxToken {
		t.Fatalf("%+v", in.Span)
	}
	in = New(UnsupportedSyntax, "x").At(0, "a\x1bb").Info("a\x1bb", 0)
	if in.Span == nil || in.Span.Token != "" {
		t.Fatalf("control character kept: %+v", in.Span)
	}
}

func TestShift(t *testing.T) {
	e := New(NoLimit, "x").At(3, "LIMIT")
	e.Shift(4)
	if e.Pos != 7 {
		t.Fatal(e.Pos)
	}
	n := New(NoLimit, "x")
	n.Shift(4)
	if n.Pos != -1 {
		t.Fatal("an unknown position moved")
	}
}

func TestFromFallsBackClosed(t *testing.T) {
	if r := From(errors.New("plain")); r.Code != Policy || r.Reason != "plain" {
		t.Fatalf("%+v", r)
	}
	if r := From(&Error{Reason: "no code", Pos: -1}); r.Code != Policy {
		t.Fatalf("%+v", r)
	}
	e := New(NoLimit, "k")
	if From(e) != e {
		t.Fatal("a coded refusal was replaced")
	}
}
