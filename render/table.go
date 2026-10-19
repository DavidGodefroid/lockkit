// Package render turns a (masked) product result into the text an agent
// sees, within the caps of a profile: a table (TSV or JSON) or any typed
// JSON value. Control and bidirectional characters are escaped, invalid
// UTF-8 is replaced, NULL is "NULL" (null in JSON), binary values are
// "<bytes:N>" and times ISO 8601.
//
// Cells are cut while they are converted, so a huge value never costs more
// than its cap in output.
package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Formats.
const (
	FormatTSV  = "tsv"
	FormatJSON = "json"
)

// Caps bound an output. Zero or negative fields take the defaults
// (DefaultCaps).
type Caps struct {
	MaxRows        int
	MaxCellChars   int
	MaxOutputBytes int
	// CutNote is the footer line that tells how many cells were cut; nil
	// gives the default wording.
	CutNote func(cells, maxChars int) string
}

// DefaultCaps are the caps of an unset field.
var DefaultCaps = Caps{MaxRows: 200, MaxCellChars: 200, MaxOutputBytes: 65_536}

func effective(l Caps) Caps {
	if l.MaxRows <= 0 {
		l.MaxRows = DefaultCaps.MaxRows
	}
	if l.MaxCellChars <= 0 {
		l.MaxCellChars = DefaultCaps.MaxCellChars
	}
	if l.MaxOutputBytes <= 0 {
		l.MaxOutputBytes = DefaultCaps.MaxOutputBytes
	}
	return l
}

// Table is a tabular result: column labels and rows of values. A table
// without columns reports Affected rows instead (a write).
type Table struct {
	Columns   []string
	Rows      [][]any
	Truncated bool // more rows exist beyond the producer's own cap
	Affected  int64
	// Cut marks the cells (row, column) the producer already cut while
	// reading them; they count in the cut-cells note.
	Cut map[[2]int]bool
}

// MarkCut records that the producer cut cell (row, col).
func (t *Table) MarkCut(row, col int) {
	if t.Cut == nil {
		t.Cut = map[[2]int]bool{}
	}
	t.Cut[[2]int{row, col}] = true
}

// Render writes t to w in format "tsv" (the default when empty) or
// "json". Rows beyond MaxRows are dropped and reported as truncated; rows
// that would push the output past MaxOutputBytes are dropped with a marker.
func Render(w io.Writer, t Table, l Caps, format string) error {
	l = effective(l)
	rows, truncated := t.Rows, t.Truncated
	if len(rows) > l.MaxRows {
		rows, truncated = rows[:l.MaxRows], true
	}
	switch format {
	case "", FormatTSV:
		return renderTSV(w, t, rows, truncated, l)
	case FormatJSON:
		return renderJSON(w, t, rows, truncated, l)
	}
	return fmt.Errorf("render: unknown format %q (want tsv or json)", format)
}

func renderTSV(w io.Writer, res Table, rows [][]any, truncated bool, l Caps) error {
	var b bytes.Buffer
	if len(res.Columns) == 0 {
		fmt.Fprintf(&b, "(%d rows affected)\n", res.Affected)
		_, err := w.Write(b.Bytes())
		return err
	}
	t := tsvCells(res, rows, truncated, l)
	b.WriteString(strings.Join(t.Header, "\t"))
	b.WriteByte('\n')
	for _, r := range t.Rows {
		b.WriteString(strings.Join(r, "\t"))
		b.WriteByte('\n')
	}
	for _, f := range t.Footer {
		b.WriteString(f)
		b.WriteByte('\n')
	}
	_, err := w.Write(b.Bytes())
	return err
}

// Cells is the TSV rendering of a table split into cells, with the same
// caps as Render: the header labels, the rows shown and the lines after
// them (cut marker, row count).
type Cells struct {
	Header []string
	Rows   [][]string
	Footer []string
}

// TSVCells is what Render writes in format tsv for a table with columns,
// before the cells are joined.
func TSVCells(t Table, l Caps) Cells {
	l = effective(l)
	rows, truncated := t.Rows, t.Truncated
	if len(rows) > l.MaxRows {
		rows, truncated = rows[:l.MaxRows], true
	}
	return tsvCells(t, rows, truncated, l)
}

func tsvCells(res Table, rows [][]any, truncated bool, l Caps) Cells {
	var t Cells
	cells := make([]string, len(res.Columns))
	for i, c := range res.Columns {
		cells[i] = capText(c, l.MaxCellChars, false)
	}
	header := cutBytes(strings.Join(cells, "\t"), l.MaxOutputBytes-1)
	t.Header = strings.Split(header, "\t")
	size := len(header) + 1
	cut := false
	cutN := 0 // cells cut, in the rows shown
	for ri, row := range rows {
		line := make([]string, len(row))
		n, rowCut := 0, 0
		for i, v := range row {
			var c bool
			line[i], c = tsvCell(v, l.MaxCellChars)
			if c || res.Cut[[2]int{ri, i}] {
				rowCut++
			}
			n += len(line[i])
		}
		if len(row) > 1 {
			n += len(row) - 1
		}
		if size+n+1 > l.MaxOutputBytes {
			cut = true
			break
		}
		t.Rows = append(t.Rows, line)
		size += n + 1
		cutN += rowCut
	}
	if cutN > 0 {
		note := l.CutNote
		if note == nil {
			note = defaultCutNote
		}
		t.Footer = append(t.Footer, note(cutN, l.MaxCellChars))
	}
	if cut {
		t.Footer = append(t.Footer, fmt.Sprintf("[output cut at %d bytes: %d of %d rows shown]", l.MaxOutputBytes, len(t.Rows), len(rows)))
	}
	count := fmt.Sprintf("(%d rows)", len(t.Rows))
	if truncated {
		count += " — more rows exist beyond the row cap"
	}
	t.Footer = append(t.Footer, count)
	return t
}

// cutBytes cuts s to at most n bytes, ending it with "…" when it was cut,
// without splitting a UTF-8 sequence. Each label is capped, but a wide
// header line as a whole must also stay under the output cap.
func cutBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	end := n - len("…")
	if end <= 0 {
		return ""
	}
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end] + "…"
}

// tsvCell is the TSV text of a value, and whether it was cut.
func tsvCell(v any, maxChars int) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "NULL", false
	case string:
		return capTextCut(x, maxChars, false)
	}
	return capTextCut(Text(v), maxChars, false)
}

func defaultCutNote(n, maxChars int) string {
	cells := "cells"
	if n == 1 {
		cells = "cell"
	}
	return fmt.Sprintf("[%d %s cut: a value longer than %d characters ends with …]", n, cells, maxChars)
}

type jsonResult struct {
	Columns   []string          `json:"columns"`
	Rows      []json.RawMessage `json:"rows"`
	Truncated bool              `json:"truncated"`
	Affected  *int64            `json:"affected,omitempty"`
	// OutputCutAt is set when rows were dropped to stay under the byte cap.
	OutputCutAt int `json:"output_cut_at_bytes,omitempty"`
	// CutCells counts the cells of the rows shown whose value was cut (it
	// ends with "…"), by the cell cap or by the producer.
	CutCells int `json:"cut_cells,omitempty"`
}

func renderJSON(w io.Writer, res Table, rows [][]any, truncated bool, l Caps) error {
	out := jsonResult{Columns: make([]string, len(res.Columns)), Rows: []json.RawMessage{}, Truncated: truncated}
	for i, c := range res.Columns {
		out.Columns[i] = capText(c, l.MaxCellChars, true)
	}
	if len(res.Columns) == 0 {
		a := res.Affected
		out.Affected = &a
	}
	// Measure the envelope as it is when rows are cut, so that adding the
	// cut fields never pushes the output past the cap.
	worst := out
	worst.Truncated, worst.OutputCutAt, worst.CutCells = true, l.MaxOutputBytes, len(rows)*len(res.Columns)
	base, err := encode(worst)
	if err != nil {
		return err
	}
	if len(base) > l.MaxOutputBytes {
		// The header alone is over the cap: keep the leading labels that
		// fit, end the list with "…" and show no rows.
		out.Columns, err = fitColumns(worst, l.MaxOutputBytes)
		if err != nil {
			return err
		}
		out.Truncated, out.OutputCutAt = true, l.MaxOutputBytes
		rows = nil
	}
	size := len(base)
	for ri, row := range rows {
		cells := make([]any, len(row))
		rowCut := 0
		for i, v := range row {
			var c bool
			cells[i], c = jsonCell(v, l.MaxCellChars)
			if c || res.Cut[[2]int{ri, i}] {
				rowCut++
			}
		}
		raw, err := encode(cells)
		if err != nil {
			return err
		}
		raw = bytes.TrimSuffix(raw, []byte("\n"))
		if size+len(raw)+1 > l.MaxOutputBytes {
			out.Truncated = true
			out.OutputCutAt = l.MaxOutputBytes
			break
		}
		out.Rows = append(out.Rows, raw)
		size += len(raw) + 1
		out.CutCells += rowCut
	}
	final, err := encode(out)
	if err != nil {
		return err
	}
	_, err = w.Write(final)
	return err
}

// fitColumns returns the longest prefix of r.Columns, followed by "…", whose
// encoding of r stays within limit (only "…" when none does; a cap smaller
// than the bare envelope cannot be met).
func fitColumns(r jsonResult, limit int) ([]string, error) {
	labels := r.Columns
	with := func(k int) []string { return append(labels[:k:k], "…") }
	lo, hi := 0, len(labels) // the answer lies in [lo, hi]
	for lo < hi {
		mid := (lo + hi + 1) / 2
		r.Columns = with(mid)
		b, err := encode(r)
		if err != nil {
			return nil, err
		}
		if len(b) <= limit {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return with(lo), nil
}

func encode(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("render: %w", err)
	}
	return b.Bytes(), nil
}

// jsonCell is the JSON value of a cell, and whether it was cut.
func jsonCell(v any, maxChars int) (any, bool) {
	switch x := v.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return x, false
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return Text(x), false
		}
		return x, false
	case float32:
		if math.IsNaN(float64(x)) || math.IsInf(float64(x), 0) {
			return Text(x), false
		}
		return x, false
	case string:
		return capTextCut(x, maxChars, true)
	}
	return capTextCut(Text(v), maxChars, true)
}

// Text is the display form of a non-nil value: bytes as <bytes:N>, times
// in RFC 3339, floats with NaN and ±Infinity spelled out.
func Text(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return "<bytes:" + strconv.Itoa(len(x)) + ">"
	case time.Time:
		return x.Format(time.RFC3339Nano)
	case int64:
		return strconv.FormatInt(x, 10)
	case uint64:
		return strconv.FormatUint(x, 10)
	case int:
		return strconv.Itoa(x)
	case float64:
		return formatFloat(x, 64)
	case float32:
		return formatFloat(float64(x), 32)
	case bool:
		return strconv.FormatBool(x)
	}
	return fmt.Sprint(v)
}

func formatFloat(f float64, bits int) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	return strconv.FormatFloat(f, 'g', -1, bits)
}

// capText escapes s and cuts it to maxChars characters, the last one being
// "…" when it was cut. It reads no more of s than the cap needs. In JSON
// mode tab, newline, carriage return and backslash are kept, since the JSON
// encoding escapes them.
func capText(s string, maxChars int, jsonMode bool) string {
	out, _ := capTextCut(s, maxChars, jsonMode)
	return out
}

// CapText is capText in JSON mode (true) or TSV mode, and whether it cut s.
func CapText(s string, maxChars int, jsonMode bool) (string, bool) {
	return capTextCut(s, maxChars, jsonMode)
}

// capTextCut is capText, and whether it cut s.
func capTextCut(s string, maxChars int, jsonMode bool) (string, bool) {
	var b strings.Builder
	n := 0      // characters written
	fitLen := 0 // byte length of b when it last held at most maxChars-1 characters
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		piece, chars := escape(r, size, jsonMode)
		if n+chars > maxChars {
			return b.String()[:fitLen] + "…", true
		}
		b.WriteString(piece)
		n += chars
		if n <= maxChars-1 {
			fitLen = b.Len()
		}
	}
	return b.String(), false
}

// escape returns the output for one decoded rune and its length in
// characters. An invalid byte (RuneError of size 1) becomes U+FFFD.
func escape(r rune, size int, jsonMode bool) (string, int) {
	switch {
	case r == utf8.RuneError && size == 1:
		return "�", 1
	case r == '\t' || r == '\n' || r == '\r' || r == '\\':
		if jsonMode {
			return string(r), 1
		}
		return `\` + string("tnr\\"[strings.IndexRune("\t\n\r\\", r)]), 2
	case r < 0x20 || r == 0x7f:
		return fmt.Sprintf(`\x%02x`, r), 4
	case r >= 0x80 && r <= 0x9f, // C1 controls
		r == 0x200e || r == 0x200f || r == 0x2028 || r == 0x2029 || r == 0xfeff,
		r >= 0x202a && r <= 0x202e, // bidi embeddings and overrides
		r >= 0x2066 && r <= 0x2069: // bidi isolates
		return fmt.Sprintf(`\u%04x`, r), 6
	}
	return string(r), 1
}
