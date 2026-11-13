// Package gen builds the PII detection bench corpus: synthetic text cases
// in English, French, Dutch and German with the byte span and kind of
// every personal value they hold, hard negatives that look like personal
// data without being any, and field names labelled personal or
// quasi-identifying.
//
// Every value is generated: checksummed numbers have valid checksums in
// positives and invalid ones in hard negatives, e-mail addresses use the
// example.* domains, IP addresses come from the documentation ranges and
// a few public resolvers, names are drawn from short lists and syllables
// (a third of them outside the detector's gazetteer). No real personal
// data.
//
// The corpus is deterministic: each block (one kind in one language) has
// its own random source, seeded from the block's name, so adding a kind
// or a language leaves the other blocks unchanged.
package gen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
)

// Span is a personal value in a text case: the byte range [Start, End)
// of Text and the detector kind that should find it.
type Span struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	Kind  string `json:"kind"`
}

// TextCase is one text of the corpus.
type TextCase struct {
	ID    string   `json:"id"`
	Lang  string   `json:"lang"`
	Text  string   `json:"text"`
	Spans []Span   `json:"spans"`
	Tags  []string `json:"tags,omitempty"`
}

// FieldCase is one field name, labelled.
type FieldCase struct {
	ID       string `json:"id"`
	Lang     string `json:"lang"`
	Field    string `json:"field"`
	Personal bool   `json:"personal"`
	Quasi    bool   `json:"quasi"`
}

// Tags.
const (
	HardPositive = "hard_positive"
	HardNegative = "hard_negative"
)

// Langs are the languages of the corpus, one file each.
var Langs = []string{"en", "fr", "nl", "de"}

// Kinds are the detector kinds with corpus entries, in file order. A new
// detector appends its kind here, its value generator in values.go, its
// frames in frames.go, its languages in Claims and, optionally, its hard
// negatives in laterNegatives.
var Kinds = []string{"secret", "email", "iban", "card", "be_niss", "fr_nir", "nl_bsn", "us_ssn",
	"person_name", "ip", "phone", "phone_loose",
	"eu_vat", "be_company"}

// firstKinds is how many of Kinds the first corpus had: they come before
// the mixed lines and the hard negatives, the later ones after, each with
// its own hard negatives, so that a new kind only appends lines.
const firstKinds = 12

// Claims lists, per kind, the languages whose texts it is meant to cover:
// a national number belongs to its country's languages.
var Claims = map[string][]string{
	"secret":      Langs,
	"email":       Langs,
	"iban":        Langs,
	"card":        Langs,
	"be_niss":     {"fr", "nl", "de"},
	"fr_nir":      {"fr"},
	"nl_bsn":      {"nl"},
	"us_ssn":      {"en"},
	"person_name": Langs,
	"ip":          Langs,
	"phone":       Langs,
	"phone_loose": Langs,
	"eu_vat":      Langs,
	"be_company":  {"fr", "nl", "de"},
}

// Sizes of the blocks: comfortably above the bench's minimums (50
// positives per kind and language, 200 hard negatives per language).
const (
	positivesPerBlock = 60
	negativesPerLang  = 240
	mixedPerLang      = 20
	// Hard negatives of each kind written after the first corpus.
	laterNegativesPerBlock = 30
)

// seed is the fixed seed every block's source is derived from.
const seed = 0x10c4_1290

func rng(block string) *rand.Rand {
	h := fnv.New64a()
	h.Write([]byte(block))
	return rand.New(rand.NewPCG(seed, h.Sum64()))
}

// Texts returns the text cases of lang.
func Texts(lang string) []TextCase {
	var out []TextCase
	positives := func(kind string) {
		if !claims(kind, lang) {
			return
		}
		r := rng(lang + "/" + kind)
		for i := range positivesPerBlock {
			out = append(out, positive(r, lang, kind, fmt.Sprintf("%s-%s-%04d", lang, kind, i+1)))
		}
	}
	for _, kind := range Kinds[:firstKinds] {
		positives(kind)
	}
	r := rng(lang + "/mixed")
	for i := range mixedPerLang {
		out = append(out, mixed(r, lang, fmt.Sprintf("%s-mixed-%04d", lang, i+1)))
	}
	r = rng(lang + "/negative")
	for i := range negativesPerLang {
		out = append(out, negative(r, lang, fmt.Sprintf("%s-neg-%04d", lang, i+1)))
	}
	for _, kind := range Kinds[firstKinds:] {
		positives(kind)
		frames := laterNegatives[kind][lang]
		if len(frames) == 0 {
			continue
		}
		r := rng(lang + "/negative/" + kind)
		for i := range laterNegativesPerBlock {
			f := frames[r.IntN(len(frames))]
			text := strings.Replace(f.frame, "{v}", negValues[f.kind](r, lang), 1)
			out = append(out, TextCase{ID: fmt.Sprintf("%s-neg-%s-%04d", lang, kind, i+1), Lang: lang, Text: text,
				Spans: []Span{}, Tags: []string{HardNegative}})
		}
	}
	return out
}

func claims(kind, lang string) bool {
	for _, l := range Claims[kind] {
		if l == lang {
			return true
		}
	}
	return false
}

// builder assembles a text and the spans of the values written in it.
type builder struct {
	b     strings.Builder
	spans []Span
}

func (c *builder) text(s string) { c.b.WriteString(s) }

func (c *builder) value(v, kind string) {
	if prefix, rest, ok := strings.Cut(v, unspanned); ok {
		c.text(prefix)
		v = rest
	}
	start := c.b.Len()
	c.b.WriteString(v)
	c.spans = append(c.spans, Span{start, c.b.Len(), kind})
}

// fill writes frame with its {v} replaced by the value v of kind.
func (c *builder) fill(frame, v, kind string) {
	before, after, ok := strings.Cut(frame, "{v}")
	if !ok {
		panic("gen: frame without {v}: " + frame)
	}
	c.text(before)
	c.value(v, kind)
	c.text(after)
}

func positive(r *rand.Rand, lang, kind, id string) TextCase {
	v, hard := values[kind](r, lang)
	if !hard && (digitKinds[kind] || kind == "email" || kind == "person_name") {
		// One value in five is written the way a careless export or an
		// evasive writer would: full-width digits, a zero-width
		// character inside, no-break spaces between digit groups.
		if w, ok := disguise(r, kind, v); ok {
			v, hard = w, true
		}
	}
	frame := pick(r, framesFor(lang, kind))
	if f, ok := strings.CutPrefix(frame, "!"); ok {
		// A context the detectors are known to miss.
		frame, hard = f, true
	}
	var c builder
	c.fill(frame, v, kind)
	tc := TextCase{ID: id, Lang: lang, Text: c.b.String(), Spans: c.spans}
	if hard {
		tc.Tags = []string{HardPositive}
	}
	return tc
}

// mixed is a contact line with a name, an e-mail address and a phone
// number.
func mixed(r *rand.Rand, lang, id string) TextCase {
	frame := pick(r, mixedFrames[lang])
	var c builder
	for frame != "" {
		i := strings.Index(frame, "[[")
		if i < 0 {
			c.text(frame)
			break
		}
		j := strings.Index(frame, "]]")
		c.text(frame[:i])
		kind := frame[i+2 : j]
		v, _ := values[kind](r, lang)
		if kind == "person_name" {
			v = knownName(r, lang)
		}
		c.value(v, kind)
		frame = frame[j+2:]
	}
	return TextCase{ID: id, Lang: lang, Text: c.b.String(), Spans: c.spans}
}

func negative(r *rand.Rand, lang, id string) TextCase {
	f := negFrames[lang][r.IntN(len(negFrames[lang]))]
	v := negValues[f.kind](r, lang)
	text := strings.Replace(f.frame, "{v}", v, 1)
	return TextCase{ID: id, Lang: lang, Text: text, Spans: []Span{}, Tags: []string{HardNegative}}
}

func pick(r *rand.Rand, xs []string) string { return xs[r.IntN(len(xs))] }

// Files returns every corpus file by name: one JSON Lines file per
// language and fields.jsonl.
func Files() map[string][]byte {
	out := map[string][]byte{}
	for _, lang := range Langs {
		var b bytes.Buffer
		for _, tc := range Texts(lang) {
			writeLine(&b, tc)
		}
		out[lang+".jsonl"] = b.Bytes()
	}
	var b bytes.Buffer
	for _, fc := range Fields() {
		writeLine(&b, fc)
	}
	out["fields.jsonl"] = b.Bytes()
	return out
}

func writeLine(b *bytes.Buffer, v any) {
	enc := json.NewEncoder(b) // one line, newline-terminated
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic("gen: " + err.Error())
	}
}

// Write writes the corpus files into dir.
func Write(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, data := range Files() {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}
