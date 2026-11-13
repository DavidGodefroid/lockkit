package pii

import "sort"

// Confidence is how sure a detector is that a match is the personal value
// of its kind. It is a field of Match only: masked text and every value an
// agent sees stay the same whatever the confidence, or it would tell an
// agent which masks hide a verified number.
type Confidence uint8

const (
	// ConfidenceLow: a gazetteer word (person_name) or a candidate a
	// context word or field name raised to a match.
	ConfidenceLow Confidence = iota + 1
	// ConfidenceMedium: a pattern without a checksum (phone, email, ip,
	// secret, us_ssn).
	ConfidenceMedium
	// ConfidenceHigh: a checksum verified (iban, card, national numbers,
	// VAT and company numbers).
	ConfidenceHigh
)

func (c Confidence) String() string {
	switch c {
	case ConfidenceLow:
		return "low"
	case ConfidenceMedium:
		return "medium"
	case ConfidenceHigh:
		return "high"
	}
	return "unknown"
}

// detectorConfidence is the confidence of a detector's matches unless its
// finder grades a match itself (gspan.conf).
var detectorConfidence = map[string]Confidence{
	"secret":      ConfidenceMedium,
	"email":       ConfidenceMedium,
	"iban":        ConfidenceHigh,
	"eu_vat":      ConfidenceHigh,
	"be_company":  ConfidenceHigh,
	"card":        ConfidenceHigh,
	"be_niss":     ConfidenceHigh,
	"fr_nir":      ConfidenceHigh,
	"nl_bsn":      ConfidenceHigh,
	"us_ssn":      ConfidenceMedium,
	"person_name": ConfidenceLow,
	"ip":          ConfidenceMedium,
	"phone":       ConfidenceMedium,
	"phone_loose": ConfidenceMedium,
}

// gspan is a span with the confidence its finder gives it; 0 means the
// detector's.
type gspan struct {
	span
	conf Confidence
}

// mergeGSpans sorts spans and joins those that overlap, keeping the
// highest confidence.
func mergeGSpans(spans []gspan) []gspan {
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	out := spans[:0]
	for _, sp := range spans {
		if n := len(out); n > 0 && sp.start < out[n-1].end {
			out[n-1].end = max(out[n-1].end, sp.end)
			out[n-1].conf = max(out[n-1].conf, sp.conf)
			continue
		}
		out = append(out, sp)
	}
	return out
}

// graded wraps a finder whose matches all have the detector's confidence.
func graded(find func(string) []span, conf Confidence) func(string) []gspan {
	return func(s string) []gspan {
		spans := find(s)
		if spans == nil {
			return nil
		}
		out := make([]gspan, len(spans))
		for i, sp := range spans {
			out[i] = gspan{sp, conf}
		}
		return out
	}
}
