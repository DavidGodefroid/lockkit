// Package pii is the product-neutral half of personal-data masking: value
// detectors (email, phone, IBAN, card, national ids), mask modes, the
// multilingual name heuristics that propose mask rules, and the store of
// the clear values behind redacted references. Which value is personal
// (column provenance, JSON paths, headers) is the product's.
package pii

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Mask modes.
const (
	// ModeRedact replaces the whole value: "<redacted>" (the default).
	ModeRedact = "redact"
	// ModePartial keeps the first character and the length: "j***(12)".
	ModePartial = "partial"
	// ModeEmail keeps the first character and the domain of an address:
	// "j***@example.com" (other values are masked as partial).
	ModeEmail = "email"
)

// ValidMode reports whether m is a mask mode.
func ValidMode(m string) bool {
	return m == ModeRedact || m == ModePartial || m == ModeEmail
}

// Redacted is a value masked in mode redact.
const Redacted = "<redacted>"

// MaskValue masks one non-nil value in mode. Bytes become
// "<masked bytes:N>" in modes partial and email; an unknown mode masks as
// partial.
func MaskValue(v any, mode string) any {
	switch mode {
	case ModeRedact:
		return Redacted
	case ModeEmail:
		if s, ok := v.(string); ok {
			if at := strings.LastIndexByte(s, '@'); at > 0 && at < len(s)-1 && utf8.ValidString(s) {
				first, _ := utf8.DecodeRuneInString(s)
				return string(first) + "***@" + s[at+1:]
			}
		}
	}
	return maskCell(v)
}

// Mask masks the text value in mode.
func Mask(mode, value string) string { return MaskValue(value, mode).(string) }

// MaskText is the partial mask format: first character + "***" + "(length
// in characters)". An invalid UTF-8 byte counts as one U+FFFD character.
func MaskText(s string) string {
	first := ""
	for _, r := range s {
		first = string(r)
		break
	}
	return first + "***(" + strconv.Itoa(utf8.RuneCountInString(s)) + ")"
}

func maskCell(v any) any {
	switch x := v.(type) {
	case []byte:
		return "<masked bytes:" + strconv.Itoa(len(x)) + ">"
	case string:
		return MaskText(x)
	case time.Time:
		return MaskText(x.Format(time.RFC3339Nano))
	default:
		return MaskText(fmt.Sprint(x))
	}
}

// CellText is the text of a value, as compared and substituted.
func CellText(v any) string {
	switch x := v.(type) {
	case []byte:
		return string(x)
	case string:
		return x
	case time.Time:
		return x.Format(time.RFC3339Nano)
	}
	return fmt.Sprint(v)
}

// RedactedRef is a redacted value that carries a reference to it, which
// the console alone resolves (see RefStore).
func RedactedRef(name string) string { return "<redacted:" + name + ">" }

// Detects reports whether a detector would mask something in s.
func Detects(s string, ds []Detector) bool {
	out, ok := Detect(s, ds).(string)
	return ok && out != s
}

// Detect runs the detectors over a text or integer value (a national
// number or a card can be stored as one), or an integral float (the same
// number in a double column), and returns the masked text, or v itself,
// with its type, when nothing was found. Other values pass.
func Detect(v any, ds []Detector) any {
	if len(ds) == 0 {
		return v
	}
	var in string
	switch x := v.(type) {
	case string:
		in = x
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		in = fmt.Sprint(x) // drivers use every width (pgx: int4 is int32)
	case float32:
		if in = integralText(float64(x)); in == "" {
			return v
		}
	case float64:
		if in = integralText(x); in == "" {
			return v
		}
	default:
		return v
	}
	out := cutForDetection(in)
	for _, d := range ds {
		out = d.Mask(out)
	}
	if out == in {
		return v // unchanged: keep the original type
	}
	return out
}

// integralText is f written as an integer when it is one that fits the
// integer path (|f| < 1e19), else "": 4111111111111111.0 is a card number,
// 1.5 is not scanned.
func integralText(f float64) string {
	if f != math.Trunc(f) || math.Abs(f) >= 1e19 {
		return ""
	}
	return strconv.FormatFloat(f, 'f', 0, 64)
}

// DetectLimit is how much of a text value the detectors scan. A longer
// value is cut there, and ends with CutMark, before detection: nothing past
// the scanned part can reach the output. Renderers cut values much
// earlier, so the cut is normally invisible; it bounds the time a huge
// value can cost.
const DetectLimit = 64 << 10

func cutForDetection(s string) string {
	if len(s) <= DetectLimit {
		return s
	}
	return CutAt(s, DetectLimit)
}

// CutMark ends a text value that was cut.
const CutMark = "…"

// cutTail is how far back a cut retreats over value-like characters, so that
// a value split by the cut (a partial number or address) is dropped whole.
const cutTail = 64

// valueChars may belong to a value the detectors recognise.
const valueChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz@._%+-/() "

// valueRune reports whether r may belong to such a value: valueChars, any
// letter, mark or digit (a Unicode address) and the spaces digits are
// grouped with.
func valueRune(r rune) bool {
	if r < utf8.RuneSelf {
		return strings.IndexByte(valueChars, byte(r)) >= 0
	}
	_, folded := foldRune(r)
	return folded || unicode.IsLetter(r) || unicode.IsMark(r) || unicode.IsNumber(r)
}

// CutAt cuts s, which must be longer than n bytes, to at most n bytes
// followed by CutMark: at a rune boundary, then back over up to cutTail
// value-like characters (valueRune), so that a value the cut splits (a partial e-mail
// address or number, which no detector would recognise) is dropped
// rather than shown in part.
func CutAt(s string, n int) string {
	end := n
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	for back := 0; back < cutTail && end > 0; back++ {
		r, size := utf8.DecodeLastRuneInString(s[:end])
		if !valueRune(r) {
			break
		}
		end -= size
	}
	return s[:end] + CutMark
}
