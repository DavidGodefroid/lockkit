package pii

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/DavidGodefroid/lockkit/pii/internal/benchgen/gen"
)

// The PII detection bench: precision and recall of every detector per
// language on a synthetic corpus (pii/testdata/bench, written by
// go run ./pii/internal/benchgen), held to a checked-in baseline. A metric
// below its baseline fails; LOCKKIT_PII_BENCH_UPDATE=1 rewrites
// baseline.json and RESULTS.md, which only such a commit moves.

const benchDir = "testdata/bench"

// Minimum corpus sizes: positives per (detector, language it claims) and
// hard negatives per language; field cases per language.
const (
	benchMinPositives = 50
	benchMinNegatives = 200
	benchMinPersonal  = 20
	benchMinQuasi     = 10
	benchMinNeither   = 15
	benchOutsideShare = 0.30
)

// benchTolerance absorbs the rounding of the baseline to 3 decimals.
const benchTolerance = 0.0005

// benchFilter, when set, drops the matches it returns false for: a test
// hook that weakens a detector.
var benchFilter func(Match) bool

type kindStats struct {
	Gold, Found        int // gold spans, and those a match of their kind covers whole
	Predicted, Correct int // matches, and those overlapping a gold span of their kind
}

func (k kindStats) recall() float64 { return ratio(k.Found, k.Gold) }

// precision is 1 when the detector found nothing: no false positive.
func (k kindStats) precision() float64 {
	if k.Predicted == 0 {
		return 1
	}
	return ratio(k.Correct, k.Predicted)
}

func (k kindStats) f1() float64 { return f1(k.precision(), k.recall()) }

type maskedStats struct{ Gold, Masked int }

// benchReport is the score of a corpus: per kind and language, and the
// masked share per language ("all": overall).
type benchReport struct {
	Kinds  map[string]map[string]*kindStats
	Masked map[string]*maskedStats
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func f1(p, r float64) float64 {
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

func round3(x float64) float64 { return math.Round(x*1000) / 1000 }

// scoreBench runs ds over every case with FindInViews and scores the
// matches against the gold spans.
func scoreBench(cases []gen.TextCase, ds []Detector) benchReport {
	rep := benchReport{Kinds: map[string]map[string]*kindStats{}, Masked: map[string]*maskedStats{"all": {}}}
	stats := func(kind, lang string) *kindStats {
		if rep.Kinds[kind] == nil {
			rep.Kinds[kind] = map[string]*kindStats{}
		}
		if rep.Kinds[kind][lang] == nil {
			rep.Kinds[kind][lang] = &kindStats{}
		}
		return rep.Kinds[kind][lang]
	}
	for _, c := range cases {
		// Every detector gets a precision in every language, found or not.
		for _, d := range ds {
			stats(d.Name(), c.Lang)
		}
		if rep.Masked[c.Lang] == nil {
			rep.Masked[c.Lang] = &maskedStats{}
		}
		var ms []Match
		for _, m := range FindInViews(c.Text, ds) {
			if m.Kind != CutKind && (benchFilter == nil || benchFilter(m)) {
				ms = append(ms, m)
			}
		}
		for _, g := range c.Spans {
			st := stats(g.Kind, c.Lang)
			st.Gold++
			covered, found := false, false
			for _, m := range ms {
				if m.Start <= g.Start && m.End >= g.End {
					covered = true
					found = found || m.Kind == g.Kind
				}
			}
			if found {
				st.Found++
			}
			for _, k := range []string{c.Lang, "all"} {
				rep.Masked[k].Gold++
				if covered {
					rep.Masked[k].Masked++
				}
			}
		}
		for _, m := range ms {
			st := stats(m.Kind, c.Lang)
			st.Predicted++
			if slices.ContainsFunc(c.Spans, func(g gen.Span) bool {
				return g.Kind == m.Kind && m.Start < g.End && g.Start < m.End
			}) {
				st.Correct++
			}
		}
	}
	return rep
}

// metrics flattens the report into the baseline's names, rounded to 3
// decimals: kind/lang/recall, kind/lang/precision, kind/lang/f1,
// masked/lang.
func (r benchReport) metrics() map[string]float64 {
	out := map[string]float64{}
	for kind, langs := range r.Kinds {
		for lang, st := range langs {
			out[kind+"/"+lang+"/precision"] = round3(st.precision())
			if st.Gold > 0 {
				out[kind+"/"+lang+"/recall"] = round3(st.recall())
				out[kind+"/"+lang+"/f1"] = round3(st.f1())
			}
		}
	}
	for lang, st := range r.Masked {
		out["masked/"+lang] = round3(ratio(st.Masked, st.Gold))
	}
	return out
}

type confusion struct{ TP, FP, FN int }

func (c confusion) precision() float64 {
	if c.TP+c.FP == 0 {
		return 1
	}
	return ratio(c.TP, c.TP+c.FP)
}

func (c confusion) recall() float64 { return ratio(c.TP, c.TP+c.FN) }

// scoreFields scores LooksPersonal and LooksQuasi on the field cases, per
// language and overall: fields/heuristic/lang/precision and /recall.
func scoreFields(cases []gen.FieldCase) (map[string]map[string]*confusion, map[string]float64) {
	rep := map[string]map[string]*confusion{"personal": {"all": {}}, "quasi": {"all": {}}}
	add := func(h, lang string, got, want bool) {
		for _, k := range []string{lang, "all"} {
			if rep[h][k] == nil {
				rep[h][k] = &confusion{}
			}
			c := rep[h][k]
			switch {
			case got && want:
				c.TP++
			case got:
				c.FP++
			case want:
				c.FN++
			}
		}
	}
	for _, f := range cases {
		add("personal", f.Lang, LooksPersonal(f.Field), f.Personal)
		add("quasi", f.Lang, LooksQuasi(f.Field), f.Quasi)
	}
	out := map[string]float64{}
	for h, langs := range rep {
		for lang, c := range langs {
			out["fields/"+h+"/"+lang+"/precision"] = round3(c.precision())
			out["fields/"+h+"/"+lang+"/recall"] = round3(c.recall())
		}
	}
	return rep, out
}

// compareBaseline returns the metrics below their baseline, missing or
// not in it (failures), and those above it (rises).
func compareBaseline(cur, base map[string]float64) (fails, rises []string) {
	for _, k := range sortedKeys(base) {
		v, ok := cur[k]
		switch {
		case !ok:
			fails = append(fails, fmt.Sprintf("%s: no longer measured (baseline %.3f)", k, base[k]))
		case v < base[k]-benchTolerance:
			fails = append(fails, fmt.Sprintf("%s: %.3f, below its baseline %.3f", k, v, base[k]))
		case v > base[k]+benchTolerance:
			rises = append(rises, fmt.Sprintf("%s: %.3f, above its baseline %.3f", k, v, base[k]))
		}
	}
	for _, k := range sortedKeys(cur) {
		if _, ok := base[k]; !ok {
			fails = append(fails, fmt.Sprintf("%s: %.3f, not in the baseline", k, cur[k]))
		}
	}
	return fails, rises
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

func readJSONL[T any](t *testing.T, path string) []T {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []T
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for n := 1; sc.Scan(); n++ {
		var v T
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			t.Fatalf("%s:%d: %v", path, n, err)
		}
		out = append(out, v)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func benchTexts(t *testing.T) []gen.TextCase {
	t.Helper()
	var out []gen.TextCase
	for _, lang := range gen.Langs {
		out = append(out, readJSONL[gen.TextCase](t, filepath.Join(benchDir, lang+".jsonl"))...)
	}
	return out
}

func benchDetectors(t *testing.T) []Detector {
	t.Helper()
	ds, err := Detectors(detectorOrder)
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

type benchRun struct {
	texts   benchReport
	fields  map[string]map[string]*confusion
	metrics map[string]float64
}

func runBench(t *testing.T) benchRun {
	t.Helper()
	texts := scoreBench(benchTexts(t), benchDetectors(t))
	fields, fm := scoreFields(readJSONL[gen.FieldCase](t, filepath.Join(benchDir, "fields.jsonl")))
	m := texts.metrics()
	for k, v := range fm {
		m[k] = v
	}
	return benchRun{texts, fields, m}
}

func readBaseline(t *testing.T) map[string]float64 {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(benchDir, "baseline.json"))
	if err != nil {
		t.Fatalf("%v (write it with LOCKKIT_PII_BENCH_UPDATE=1 go test -run '^TestBench$' ./pii/)", err)
	}
	var base map[string]float64
	if err := json.Unmarshal(b, &base); err != nil {
		t.Fatal(err)
	}
	return base
}

func TestBench(t *testing.T) {
	run := runBench(t)
	t.Log("\n" + run.results())
	if os.Getenv("LOCKKIT_PII_BENCH_UPDATE") == "1" {
		b, err := json.MarshalIndent(run.metrics, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(benchDir, "baseline.json"), append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(benchDir, "RESULTS.md"), []byte(run.results()), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("baseline.json and RESULTS.md rewritten")
		return
	}
	fails, rises := compareBaseline(run.metrics, readBaseline(t))
	for _, r := range rises {
		t.Log("rise (update the baseline to keep it): " + r)
	}
	for _, f := range fails {
		t.Error(f)
	}
	if len(fails) > 0 {
		t.Log("a detector change that lowers a metric needs an explicit baseline commit: LOCKKIT_PII_BENCH_UPDATE=1 go test -run '^TestBench$' ./pii/")
	}
}

// results is RESULTS.md: the tables and the known gaps.
func (run benchRun) results() string {
	var b strings.Builder
	b.WriteString("# PII detection bench\n\n")
	b.WriteString("Generated by `LOCKKIT_PII_BENCH_UPDATE=1 go test -run '^TestBench$' ./pii/`; do not edit.\n\n")
	b.WriteString("Masking is best effort. These are the figures of every detector (all enabled, opt-in ones included, ")
	b.WriteString("matched with `pii.FindInViews`) on a synthetic corpus: `pii/testdata/bench/*.jsonl`, written by ")
	b.WriteString("`go run ./pii/internal/benchgen -out pii/testdata/bench`. No real personal data.\n\n")
	b.WriteString("- **Recall**: share of gold values a match of the same kind covers whole.\n")
	b.WriteString("- **Precision**: share of matches overlapping a gold value of their kind (1 when the detector matched nothing).\n")
	b.WriteString("- **Masked**: share of gold values covered whole by any match, whatever its kind: what an agent does not see.\n\n")
	b.WriteString("`TestBench` fails when a metric falls below `baseline.json`.\n\n")
	b.WriteString("## Detectors\n\n| Detector | Lang | Values | Recall | Matches | Precision | F1 |\n|---|---|--:|--:|--:|--:|--:|\n")
	var gaps []string
	for _, kind := range detectorOrder {
		langs := run.texts.Kinds[kind]
		for _, lang := range gen.Langs {
			st := langs[lang]
			if st == nil || st.Gold == 0 && st.Predicted == 0 {
				continue
			}
			rec, f := "-", "-"
			if st.Gold > 0 {
				rec, f = fmt.Sprintf("%.3f", st.recall()), fmt.Sprintf("%.3f", st.f1())
				if st.recall() < 0.9 {
					gaps = append(gaps, fmt.Sprintf("- `%s` / %s: recall %.3f", kind, lang, st.recall()))
				}
			}
			fmt.Fprintf(&b, "| `%s` | %s | %d | %s | %d | %.3f | %s |\n", kind, lang, st.Gold, rec, st.Predicted, st.precision(), f)
		}
	}
	b.WriteString("\n## Masked share\n\n| Lang | Values | Masked |\n|---|--:|--:|\n")
	for _, lang := range append(slices.Clone(gen.Langs), "all") {
		st := run.texts.Masked[lang]
		fmt.Fprintf(&b, "| %s | %d | %.3f |\n", lang, st.Gold, ratio(st.Masked, st.Gold))
	}
	b.WriteString("\n## Field heuristics\n\n| Heuristic | Lang | Precision | Recall |\n|---|---|--:|--:|\n")
	for _, h := range []string{"personal", "quasi"} {
		fn := map[string]string{"personal": "LooksPersonal", "quasi": "LooksQuasi"}[h]
		for _, lang := range append(slices.Clone(gen.Langs), "all") {
			c := run.fields[h][lang]
			fmt.Fprintf(&b, "| `%s` | %s | %.3f | %.3f |\n", fn, lang, c.precision(), c.recall())
		}
	}
	b.WriteString("\n## Known gaps\n\nEvery detector and language with a recall below 0.9:\n\n")
	if len(gaps) == 0 {
		b.WriteString("None.\n")
	} else {
		b.WriteString(strings.Join(gaps, "\n") + "\n")
	}
	return b.String()
}

func TestBenchCorpusUpToDate(t *testing.T) {
	fresh := t.TempDir()
	if err := gen.Write(fresh); err != nil {
		t.Fatal(err)
	}
	if err := sameCorpus(benchDir, fresh); err != nil {
		t.Fatalf("%v: run go run ./pii/internal/benchgen -out pii/testdata/bench", err)
	}

	t.Run("hand edit", func(t *testing.T) {
		edited := t.TempDir()
		files, err := readCorpus(benchDir)
		if err != nil {
			t.Fatal(err)
		}
		for name, data := range files {
			if name == "fr.jsonl" {
				data = bytes.Replace(data, []byte(`"lang":"fr"`), []byte(`"lang":"fr" `), 1)
			}
			if err := os.WriteFile(filepath.Join(edited, name), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		err = sameCorpus(edited, fresh)
		if err == nil || !strings.Contains(err.Error(), "fr.jsonl:1") {
			t.Fatalf("an edited line is not reported: %v", err)
		}
	})
}

// readCorpus returns the .jsonl files of dir by name.
func readCorpus(dir string) (map[string][]byte, error) {
	names, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err != nil {
			return nil, err
		}
		out[filepath.Base(n)] = b
	}
	return out, nil
}

// sameCorpus reports the first difference between the .jsonl files of two
// directories.
func sameCorpus(dir, want string) error {
	got, err := readCorpus(dir)
	if err != nil {
		return err
	}
	exp, err := readCorpus(want)
	if err != nil {
		return err
	}
	for _, name := range sortedKeys(exp) {
		g, ok := got[name]
		if !ok {
			return fmt.Errorf("%s missing", name)
		}
		gl, el := strings.Split(string(g), "\n"), strings.Split(string(exp[name]), "\n")
		for i := 0; i < max(len(gl), len(el)); i++ {
			if i >= len(gl) || i >= len(el) || gl[i] != el[i] {
				return fmt.Errorf("%s:%d differs from the generated corpus", name, i+1)
			}
		}
	}
	for _, name := range sortedKeys(got) {
		if _, ok := exp[name]; !ok {
			return fmt.Errorf("%s is not generated", name)
		}
	}
	return nil
}

func TestBenchCorpusCoverage(t *testing.T) {
	texts := benchTexts(t)
	gold := map[string]map[string]int{} // kind → lang → spans
	negatives := map[string]int{}
	var names, outside int
	for _, c := range texts {
		for _, g := range c.Spans {
			if g.Start < 0 || g.End > len(c.Text) || g.Start >= g.End || !utf8.RuneStart(c.Text[g.Start]) ||
				g.End < len(c.Text) && !utf8.RuneStart(c.Text[g.End]) {
				t.Errorf("%s: span %+v is not a range of runes of its text", c.ID, g)
				continue
			}
			if gold[g.Kind] == nil {
				gold[g.Kind] = map[string]int{}
			}
			gold[g.Kind][c.Lang]++
			if g.Kind == "person_name" {
				names++
				if !hasKnownGivenName(c.Text[g.Start:g.End]) {
					outside++
				}
			}
		}
		if slices.Contains(c.Tags, gen.HardNegative) {
			if len(c.Spans) > 0 {
				t.Errorf("%s: a hard negative with gold spans", c.ID)
			}
			negatives[c.Lang]++
		}
	}
	for _, d := range detectorOrder {
		langs := gen.Claims[d]
		if len(langs) == 0 {
			t.Errorf("detector %s has no corpus entries: add it to pii/internal/benchgen", d)
		}
		for _, lang := range langs {
			if n := gold[d][lang]; n < benchMinPositives {
				t.Errorf("%s/%s: %d positives, want at least %d", d, lang, n, benchMinPositives)
			}
		}
	}
	for _, lang := range gen.Langs {
		if negatives[lang] < benchMinNegatives {
			t.Errorf("%s: %d hard negatives, want at least %d", lang, negatives[lang], benchMinNegatives)
		}
	}
	if share := ratio(outside, names); share < benchOutsideShare {
		t.Errorf("%.2f of the names have a given name outside the gazetteer, want at least %.2f", share, benchOutsideShare)
	}

	fields := map[string][3]int{}
	for _, f := range readJSONL[gen.FieldCase](t, filepath.Join(benchDir, "fields.jsonl")) {
		n := fields[f.Lang]
		switch {
		case f.Personal:
			n[0]++
		case f.Quasi:
			n[1]++
		default:
			n[2]++
		}
		fields[f.Lang] = n
	}
	for _, lang := range gen.Langs {
		if n := fields[lang]; n[0] < benchMinPersonal || n[1] < benchMinQuasi || n[2] < benchMinNeither {
			t.Errorf("%s fields: %d personal, %d quasi, %d neither; want at least %d, %d, %d",
				lang, n[0], n[1], n[2], benchMinPersonal, benchMinQuasi, benchMinNeither)
		}
	}
}

// hasKnownGivenName reports a name with a word the gazetteer knows as a
// given name.
func hasKnownGivenName(name string) bool {
	for _, w := range words(DetectionView(name).Text) {
		if givenNames[w.key] || ambiguousNames[w.key] {
			return true
		}
	}
	return false
}

func TestScoreBench(t *testing.T) {
	cases := []gen.TextCase{
		// Found: an email match covers the gold span.
		{ID: "1", Lang: "en", Text: "mail a@example.com now", Spans: []gen.Span{{Start: 5, End: 18, Kind: "email"}}},
		// Partial: the match covers part of the gold span only.
		{ID: "2", Lang: "en", Text: "to a@example.com and more", Spans: []gen.Span{{Start: 3, End: 20, Kind: "email"}}},
		// Wrong kind: masked, but not a phone found.
		{ID: "3", Lang: "en", Text: "see b@example.org", Spans: []gen.Span{{Start: 4, End: 17, Kind: "phone"}}},
		// A hard negative left alone.
		{ID: "4", Lang: "en", Text: "order 12345 shipped", Spans: []gen.Span{}, Tags: []string{gen.HardNegative}},
		// A false positive.
		{ID: "5", Lang: "en", Text: "cc c@example.net", Spans: []gen.Span{}},
	}
	ds, err := Detectors([]string{"email", "phone"})
	if err != nil {
		t.Fatal(err)
	}
	rep := scoreBench(cases, ds)
	if got, want := *rep.Kinds["email"]["en"], (kindStats{Gold: 2, Found: 1, Predicted: 4, Correct: 2}); got != want {
		t.Errorf("email: %+v, want %+v", got, want)
	}
	if got, want := *rep.Kinds["phone"]["en"], (kindStats{Gold: 1}); got != want {
		t.Errorf("phone: %+v, want %+v", got, want)
	}
	want := map[string]float64{
		"email/en/recall": 0.5, "email/en/precision": 0.5, "email/en/f1": 0.5,
		"phone/en/recall": 0, "phone/en/precision": 1, "phone/en/f1": 0,
		"masked/en": 0.667, "masked/all": 0.667,
	}
	got := rep.metrics()
	if len(got) != len(want) {
		t.Errorf("metrics %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}

	fails, rises := compareBaseline(map[string]float64{"a": 0.5, "b": 0.9, "c": 0.3}, map[string]float64{"a": 0.5004, "b": 0.8, "d": 1})
	if want := []string{"d: no longer measured (baseline 1.000)", "c: 0.300, not in the baseline"}; !slices.Equal(fails, want) {
		t.Errorf("fails %q, want %q", fails, want)
	}
	if len(rises) != 1 || !strings.HasPrefix(rises[0], "b: ") {
		t.Errorf("rises %q", rises)
	}
}

func TestScoreFields(t *testing.T) {
	rep, m := scoreFields([]gen.FieldCase{
		{Lang: "en", Field: "email", Personal: true},
		{Lang: "en", Field: "order_id"},
		{Lang: "en", Field: "birth_date", Quasi: true},
		{Lang: "fr", Field: "file_name", Personal: true}, // labelled personal, not found
	})
	if got, want := *rep["personal"]["all"], (confusion{TP: 1, FN: 1}); got != want {
		t.Errorf("personal: %+v, want %+v", got, want)
	}
	if m["fields/personal/all/recall"] != 0.5 || m["fields/personal/all/precision"] != 1 || m["fields/quasi/en/recall"] != 1 {
		t.Errorf("metrics %v", m)
	}
}

// A detector weakened in a test (every iban match dropped) fails the
// bench, naming the iban recalls.
func TestBenchFailsOnWeakDetector(t *testing.T) {
	benchFilter = func(m Match) bool { return m.Kind != "iban" }
	t.Cleanup(func() { benchFilter = nil })
	fails, _ := compareBaseline(runBench(t).metrics, readBaseline(t))
	for _, lang := range gen.Claims["iban"] {
		key := "iban/" + lang + "/recall: "
		if !slices.ContainsFunc(fails, func(f string) bool { return strings.HasPrefix(f, key) }) {
			t.Errorf("no failure for %s in %q", key, fails)
		}
	}
}
