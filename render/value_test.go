package render

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type answer struct {
	Plugin string            `json:"plugin"`
	Value  int               `json:"value"`
	Note   string            `json:"note,omitempty"`
	Tags   []string          `json:"tags"`
	Extra  map[string]any    `json:"extra,omitempty"`
	Large  json.Number       `json:"large,omitempty"`
	Nested map[string]answer `json:"nested,omitempty"`
}

// A typed result is written as JSON with every string capped and escaped;
// numbers, booleans and nulls keep their JSON type.
func TestValueCapsStrings(t *testing.T) {
	v := []answer{{
		Plugin: "pdf.blank", Value: 1, Note: strings.Repeat("x", 50) + "\x1b[2J", Tags: []string{"a<b>", "c&d"},
		Extra: map[string]any{"ok": true, "n": nil, "f": 1.5}, Large: "18446744073709551615",
		Nested: map[string]answer{"k": {Plugin: strings.Repeat("é", 30)}},
	}}
	var b bytes.Buffer
	if err := Value(&b, v, Caps{MaxCellChars: 20, MaxOutputBytes: 4096}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{`"note":"xxxxxxxxxxxxxxxxxxx…"`, `"tags":["a<b>","c&d"]`, `"value":1`, `"ok":true`, `"n":null`,
		`"f":1.5`, `"large":18446744073709551615`, `"plugin":"` + strings.Repeat("é", 19) + `…"`} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %s:\n%s", want, out)
		}
	}
	if !json.Valid(b.Bytes()) || strings.ContainsRune(out, 0x1b) {
		t.Fatalf("output: %s", out)
	}
}

func TestValueEscapesControls(t *testing.T) {
	var b bytes.Buffer
	if err := Value(&b, map[string]string{"k\x1b": "a\x00b\xffc"}, Caps{}); err != nil {
		t.Fatal(err)
	}
	if out := b.String(); !strings.Contains(out, `"k\\x1b":"a\\x00b�c"`) {
		t.Fatalf("out = %s", out)
	}
}

func TestValueOverOutputCap(t *testing.T) {
	big := make([]string, 1000)
	for i := range big {
		big[i] = "abcdefgh"
	}
	var b bytes.Buffer
	err := Value(&b, big, Caps{MaxOutputBytes: 500})
	if !errors.Is(err, ErrOutputCap) || b.Len() != 0 {
		t.Fatalf("err = %v, wrote %d bytes", err, b.Len())
	}
}

func TestValueRefusesUnencodable(t *testing.T) {
	if err := Value(&bytes.Buffer{}, map[string]any{"f": func() {}}, Caps{}); err == nil {
		t.Fatal("a func was encoded")
	}
}
