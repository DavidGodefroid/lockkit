package pii

import (
	"strings"
	"testing"
	"time"
)

// The outputs locksql 0.8 gives for each mode.
func TestMaskValueModes(t *testing.T) {
	ts := time.Date(2026, 10, 19, 10, 42, 0, 0, time.UTC)
	for _, c := range []struct {
		mode string
		in   any
		want any
	}{
		{ModeRedact, "alice@example.com", "<redacted>"},
		{ModePartial, "alice@example.com", "a***(17)"},
		{ModeEmail, "alice@example.com", "a***@example.com"},
		{ModeEmail, "not an address", "n***(14)"},
		{ModeEmail, "@example.com", "@***(12)"},
		{ModePartial, []byte{1, 2, 3}, "<masked bytes:3>"},
		{ModePartial, 1234, "1***(4)"},
		{ModePartial, ts, "2***(20)"},
		{ModePartial, "", "***(0)"},
		{"unknown", "abc", "a***(3)"},
	} {
		if got := MaskValue(c.in, c.mode); got != c.want {
			t.Errorf("MaskValue(%v, %s) = %v, want %v", c.in, c.mode, got, c.want)
		}
	}
	if got := Mask(ModeEmail, "bob@example.org"); got != "b***@example.org" {
		t.Errorf("Mask = %q", got)
	}
	for _, m := range []string{ModeRedact, ModePartial, ModeEmail} {
		if !ValidMode(m) {
			t.Errorf("%s not valid", m)
		}
	}
	if ValidMode("hash") || ValidMode("") {
		t.Error("unknown mode valid")
	}
}

func TestDetectKeepsTypeWhenUnchanged(t *testing.T) {
	ds, err := Detectors([]string{"email"})
	if err != nil {
		t.Fatal(err)
	}
	if got := Detect(42, ds); got != 42 {
		t.Errorf("Detect(42) = %#v", got)
	}
	if got := Detect("write to bob@example.org", ds); got == "write to bob@example.org" {
		t.Errorf("email not masked: %v", got)
	}
	if !Detects("bob@example.org", ds) || Detects("nothing here", ds) {
		t.Error("Detects")
	}
	if got := Detect("a@b.example", nil); got != "a@b.example" {
		t.Error("no detectors changed the value")
	}
	// Past DetectLimit nothing is scanned: the text is cut, marked, and
	// what is left still goes through the detectors.
	long := strings.Repeat("x", DetectLimit) + " bob@example.org"
	out, _ := Detect(long, ds).(string)
	if strings.Contains(out, "bob@example.org") || !strings.HasSuffix(out, "…") || len(out) > DetectLimit+len("…") {
		t.Errorf("long value: len %d, tail %q", len(out), out[len(out)-10:])
	}
}

func TestCellText(t *testing.T) {
	ts := time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC)
	for in, want := range map[any]string{"s": "s", 12: "12", ts: "2026-01-02T03:04:05.000000006Z"} {
		if got := CellText(in); got != want {
			t.Errorf("CellText(%v) = %q", in, got)
		}
	}
	if CellText([]byte("b")) != "b" {
		t.Error("bytes")
	}
	if RedactedRef("r1.2.3") != "<redacted:r1.2.3>" {
		t.Error(RedactedRef("r1.2.3"))
	}
}
