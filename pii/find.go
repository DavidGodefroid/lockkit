package pii

import (
	"sort"
	"strings"
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
// A text longer than DetectLimit is scanned as Detect scans it, cut by
// CutAt(s, DetectLimit), and the matches are ranges of that cut text,
// which the caller must show instead of s.
func Find(s string, ds []Detector) []Match {
	return mergeMatches(find(cutForDetection(s), ds, nil))
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
// kind of the earliest detector in ds. Long texts are cut as by Find.
func FindInViews(s string, ds []Detector) []Match {
	s = cutForDetection(s)
	out := find(s, ds, nil)
	for _, v := range DetectionViews(s) {
		if v.lo == nil && v.Text == s {
			continue // s itself: already searched
		}
		out = append(out, find(v.Text, ds, &v)...)
	}
	return mergeMatches(out)
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
