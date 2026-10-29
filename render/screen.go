package render

import (
	"encoding/json"
	"errors"
	"slices"

	"github.com/DavidGodefroid/lockkit/pii"
	"github.com/DavidGodefroid/lockkit/ticket"
)

// A Part is one piece of a line of an approval screen: structure (keywords,
// identifiers, operators, which stay visible) or a value (a literal, a
// parameter, a field of a message), with the column or field it belongs to
// when the product knows it.
type Part struct {
	Text string
	// Value marks a value; structure is masked only where a detector finds
	// personal data in it.
	Value bool
	// Column and ColumnType name where the value goes or comes from ("email",
	// "varchar"); "" when unknown.
	Column, ColumnType string
}

// Line is one line of an approval screen, in parts.
type Line []Part

// Structure is a line with no value in it.
func Structure(text string) Line { return Line{{Text: text}} }

// ScreenSource is an approval screen as a product draws it, before masking.
type ScreenSource struct {
	// Header names the request ("db / shop · tier read").
	Header string
	// Note is the agent's one-line reason (untrusted).
	Note string
	// Body are the lines of the request; Warnings are shown in red.
	Body     []Line
	Warnings []string
	// Red frames the screen in red outside production too.
	Red bool
}

// Masking says what is personal on a screen.
type Masking struct {
	// Detectors find personal values in any text (pii.Detectors); none
	// is every detector (pii.AllDetectors), never no detection.
	Detectors []pii.Detector
	// Personal reports a personal column; nil is pii.LooksPersonalColumn.
	Personal func(column, typ string) bool
}

// TouchedColumn is the kind of personal data reported for a value masked
// because its column looks personal.
const TouchedColumn = "personal_column"

// MaskedScreen is an approval screen that went through MaskScreen: the
// only form in which a screen may leave the lock (to the hub, in a ticket).
// It has no exported field and no other constructor; its zero value is not
// a screen (Valid is false and it does not encode).
type MaskedScreen struct {
	s       ticket.Screen
	touched []string
	ok      bool
}

// ErrUnmasked is the error of a MaskedScreen that MaskScreen did not build.
var ErrUnmasked = errors.New("render: screen not built by MaskScreen")

// MaskScreen masks src: every value whose column looks personal is masked
// whole, and the detectors mask what they find in values, structure,
// header, note and warnings alike. The structure of the request stays
// visible.
func MaskScreen(src ScreenSource, m Masking) MaskedScreen {
	if len(m.Detectors) == 0 {
		m.Detectors = pii.AllDetectors()
	}
	personal := m.Personal
	if personal == nil {
		personal = pii.LooksPersonalColumn
	}
	touched := map[string]bool{}
	detect := func(s string) string {
		if len(m.Detectors) > 0 && len(s) > pii.DetectLimit {
			s = pii.CutAt(s, pii.DetectLimit) // nothing past the scanned part shows
		}
		for _, d := range m.Detectors {
			if out := d.Mask(s); out != s {
				touched[d.Name()] = true
				s = out
			}
		}
		return s
	}
	out := MaskedScreen{ok: true, s: ticket.Screen{
		Header: detect(src.Header), Note: detect(src.Note), Red: src.Red,
		Body: []string{}, Warnings: []string{},
	}}
	for _, line := range src.Body {
		var b []byte
		for _, p := range line {
			text := p.Text
			if p.Value && personal(p.Column, p.ColumnType) {
				touched[TouchedColumn] = true
				text = pii.MaskText(text)
			} else {
				text = detect(text)
			}
			b = append(b, text...)
		}
		// Once more over the whole line: a value split across parts
		// ("jean" + "@example.com") is found only there.
		out.s.Body = append(out.s.Body, detect(string(b)))
	}
	for _, w := range src.Warnings {
		out.s.Warnings = append(out.s.Warnings, detect(w))
	}
	for k := range touched {
		out.touched = append(out.touched, k)
	}
	slices.Sort(out.touched)
	return out
}

// Valid reports whether MaskScreen built m.
func (m MaskedScreen) Valid() bool { return m.ok }

// Screen is the masked screen, for a ticket (a copy).
func (m MaskedScreen) Screen() ticket.Screen {
	s := m.s
	s.Body, s.Warnings = slices.Clone(m.s.Body), slices.Clone(m.s.Warnings)
	return s
}

// Touched names the kinds of personal data masked (ticket.PII.Touched):
// detector names and TouchedColumn, sorted.
func (m MaskedScreen) Touched() []string { return slices.Clone(m.touched) }

// MarshalJSON encodes the masked screen as a ticket.Screen; a screen
// MaskScreen did not build does not encode.
func (m MaskedScreen) MarshalJSON() ([]byte, error) {
	if !m.ok {
		return nil, ErrUnmasked
	}
	return json.Marshal(m.s)
}
