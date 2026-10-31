package pii

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Match is a value a detector recognised: the byte range [Start, End) of
// the text it was found in, and the name of the detector (its kind:
// "email", "iban", ...).
type Match struct {
	Start, End int
	Kind       string
}

// Find returns the values that Detect(s, ds) masks, as byte ranges of s:
// sorted, non-overlapping, each with the kind of the detector that found
// it. The detectors run in the order given (Detectors returns their fixed
// run order), each on the text the previous ones masked, exactly as Detect
// runs them, so replacing every match with MaskText of its text gives
// Detect's output. Two exceptions, where Find masks more: a later detector
// whose match overlaps an earlier mask makes one match of both (Detect
// would mask the mask), and a Detector that is not one of this package's
// cannot say where it found a value, so anything it masks makes the whole
// text one match of its kind.
//
// Past DetectLimit, the rest of s is one more match, of kind CutKind,
// starting earlier where a value runs across the limit (the detectors scan
// a little past it to find such values whole): the matches are always
// safe to apply to s itself.
func Find(s string, ds []Detector) []Match {
	if len(ds) == 0 {
		return nil
	}
	t, rest := scanned(s)
	return finish(find(t, ds, nil), rest, s)
}

// CutKind is the kind of the match that covers the end of a text past
// DetectLimit (or past where a view reached its cap), masked whole.
const CutKind = "cut"

// scanOverlap is how far past a cut the detectors still scan, so that a
// value written across the cut is found whole (and the unscanned rest
// starts where it starts): longer than any value in any encoding the
// views decode.
const scanOverlap = 4 << 10

// scanned returns the part of s the detectors scan and where the
// unscanned rest begins at the latest (-1: nowhere): DetectLimit, at a
// rune boundary, with scanOverlap more bytes scanned past it.
func scanned(s string) (string, int) {
	if len(s) <= DetectLimit {
		return s, -1
	}
	cut := runeStart(s, DetectLimit)
	return s[:runeStart(s, min(len(s), cut+scanOverlap))], cut
}

func runeStart(s string, i int) int {
	for i > 0 && i < len(s) && !utf8.RuneStart(s[i]) {
		i--
	}
	return i
}

// finish merges matches and, when there is a cut (rest >= 0), makes the
// rest of the source one CutKind match, starting earlier where a match
// runs across the cut: no value is left in part.
func finish(ms []rankedMatch, rest int, src string) []Match {
	merged := mergeMatches(ms)
	if rest < 0 || rest >= len(src) {
		return merged
	}
	rest = backOverWord(src, rest)
	for k, m := range merged {
		if m.End > rest {
			rest = min(rest, m.Start)
			return append(merged[:k], Match{rest, len(src), CutKind})
		}
	}
	return append(merged, Match{rest, len(src), CutKind})
}

// backOverWord returns where the unscanned rest of s must start for a cut
// at i: back over the word the cut is in, however long (a value padded
// with invisible characters, marks or escapes is one word), and over
// single blanks between digit groups ("+32 475 12 34 56"). It stops at
// other whitespace.
func backOverWord(s string, i int) int {
	for i > 0 {
		r, n := utf8.DecodeLastRuneInString(s[:i])
		if droppedInView(r) || !unicode.IsSpace(r) {
			i -= n // part of the word, or invisible to the detectors
			continue
		}
		// A blank between digit groups (or after a group separator) does
		// not end a number: look at the nearest kept runes on both sides.
		if numberSide(s[:i-n], true) && numberSide(s[i:], false) {
			i -= n
			continue
		}
		break
	}
	return i
}

// numberSide reports whether the nearest rune of t that the view keeps
// (the last one when last, else the first) is a digit or a group
// separator ('.', '-', '/', ')').
func numberSide(t string, last bool) bool {
	for t != "" {
		var r rune
		var n int
		if last {
			r, n = utf8.DecodeLastRuneInString(t)
			t = t[:len(t)-n]
		} else {
			r, n = utf8.DecodeRuneInString(t)
			t = t[n:]
		}
		if droppedInView(r) {
			continue
		}
		return r >= '0' && r <= '9' || r == '.' || r == '-' || r == '/' || r == ')' || r == '(' || r == '+'
	}
	return false
}

// rankedMatch is a match with the position of its detector in the list it
// came from: when matches overlap, the earliest detector names the kind.
type rankedMatch struct {
	Match
	rank int
}

// find runs the detectors over s as Detect does and returns their matches,
// mapped through src (nil: s is the source itself) to the source text.
func find(s string, ds []Detector, src *View) []rankedMatch {
	var out []rankedMatch
	cur := View{Text: s}
	for rank, d := range ds {
		var spans []span
		if fd, ok := d.(finderDetector); ok {
			spans = fd.spans(cur.Text)
		} else if d.Mask(cur.Text) != cur.Text {
			// Fail closed: a foreign detector cannot say where.
			spans = []span{{0, len(cur.Text)}}
		}
		if len(spans) == 0 {
			continue
		}
		for _, sp := range spans {
			a, b := cur.Source(sp.start, sp.end)
			if src != nil {
				a, b = src.Source(a, b)
			}
			out = append(out, rankedMatch{Match{a, b, d.Name()}, rank})
		}
		cur = maskSpans(cur, spans)
	}
	return out
}

// maskSpans returns v with each span replaced by MaskText of its text, as
// finderDetector.Mask does, keeping the map to v's source: every byte of a
// mask comes from the whole span it replaced.
func maskSpans(v View, spans []span) View {
	var b strings.Builder
	b.Grow(len(v.Text))
	lo := make([]int32, 0, len(v.Text))
	hi := make([]int32, 0, len(v.Text))
	keep := func(from, to int) {
		b.WriteString(v.Text[from:to])
		for i := from; i < to; i++ {
			l, h := v.Source(i, i+1)
			lo, hi = append(lo, int32(l)), append(hi, int32(h))
		}
	}
	last := 0
	for _, sp := range spans {
		keep(last, sp.start)
		m := MaskText(v.Text[sp.start:sp.end])
		l, h := v.Source(sp.start, sp.end)
		b.WriteString(m)
		for range len(m) {
			lo, hi = append(lo, int32(l)), append(hi, int32(h))
		}
		last = sp.end
	}
	keep(last, len(v.Text))
	return View{Text: b.String(), lo: lo, hi: hi, srcLen: v.sourceLen()}
}

// FindInViews returns the values found in s and in each of its detection
// views (DetectionViews), as byte ranges of s: sorted, non-overlapping. A
// value found only in a view (behind an escape, a look-alike or a
// zero-width character) is the range of s it was written with, whole.
// Where matches of different kinds overlap, they make one match, of the
// kind of the earliest detector in ds (an encoded value next to a plain one
// may so take a neighbour's kind). Long texts are cut as by Find. Match
// boundaries are not moved to escape boundaries: a raw match may start
// inside an escape (the "n" of "\\n" before an address).
func FindInViews(s string, ds []Detector) []Match {
	if len(ds) == 0 {
		return nil
	}
	src := s
	s, rest := scanned(s)
	out := find(s, ds, nil)
	for _, v := range DetectionViews(s) {
		if v.lo == nil && v.Text == s {
			continue // s itself: already searched
		}
		if v.cut && (rest < 0 || v.cutAt < rest) {
			rest = v.cutAt // what the cut view does not show is masked whole
		}
		out = append(out, find(v.Text, ds, &v)...)
	}
	return finish(out, rest, src)
}

// mergeMatches sorts matches and joins those that overlap; a joined match
// takes the kind of its lowest-ranked part.
func mergeMatches(ms []rankedMatch) []Match {
	if len(ms) == 0 {
		return nil
	}
	sort.SliceStable(ms, func(i, j int) bool { return ms[i].Start < ms[j].Start })
	merged := ms[:0]
	for _, m := range ms {
		if n := len(merged); n > 0 && m.Start < merged[n-1].End {
			p := &merged[n-1]
			p.End = max(p.End, m.End)
			if m.rank < p.rank {
				p.rank, p.Kind = m.rank, m.Kind
			}
			continue
		}
		merged = append(merged, m)
	}
	out := make([]Match, len(merged))
	for i, m := range merged {
		out[i] = m.Match
	}
	return out
}
