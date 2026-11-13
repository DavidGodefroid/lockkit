package pii

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// valuePrefiltered are the value finders with a prefilter: find is the
// finder, scan the same without its prefilter, pass the prefilter itself.
// under is a text one step short of the prefilter's condition, at a match
// that just meets it.
var valuePrefiltered = []struct {
	name       string
	find, scan func(string) []span
	pass       func(string) bool
	under, at  string
}{
	{"email", findEmails, scanEmails, func(s string) bool { return strings.IndexByte(s, '@') >= 0 }, "to jean.dupont at example.com", "to a@b.co"},
	{"card", findCards, scanCards, func(s string) bool { return hasDigits(s, cardMinDigits) }, "card 4222 2222 2222", "card 4222 2222 2222 2."},
	{"be_niss", findNISS, scanNISS, func(s string) bool { return hasDigits(s, nissMinDigits) }, "ref 8507300332 ok", "ref 85073003328 ok"},
	{"fr_nir", findNIR, scanNIR, func(s string) bool { return hasDigits(s, nirMinDigits) }, "nir 2 69 05 2A 001 123 0", "nir 2 69 05 2A 001 123 07"},
	{"nl_bsn", findBSN, scanBSN, func(s string) bool { return hasDigits(s, bsnMinDigits) }, "bsn 11122233", "bsn 111222333"},
	{"us_ssn", findSSN, scanSSN, func(s string) bool { return hasDigits(s, ssnMinDigits) }, "ssn 123-45-678", "ssn 123-45-6789"},
	{"iban", findIBANs, scanIBANs, hasIBANPrefix, "pay BE6 85390 0754 7034", "pay BE68539007547034"},
	{"ip", findIPs, scanIPs, func(s string) bool { return strings.Count(s, ":") >= 2 || strings.Count(s, ".") >= 3 }, "from 8.8.8 and 2606:4700", "from 8.8.8.8"},
}

func TestValuePrefilterThresholds(t *testing.T) {
	for _, p := range valuePrefiltered {
		if p.pass(p.under) {
			t.Errorf("%s: prefilter passes %q, one step short of its condition", p.name, p.under)
		}
		if got := p.find(p.under); got != nil {
			t.Errorf("%s(%q) = %v, want nil", p.name, p.under, got)
		}
		if !p.pass(p.at) {
			t.Errorf("%s: prefilter rejects %q", p.name, p.at)
		}
		if got := p.find(p.at); len(got) == 0 {
			t.Errorf("%s(%q) = nil, want a match", p.name, p.at)
		}
	}
}

func checkValuePrefilters(t *testing.T, s string) {
	t.Helper()
	for _, p := range valuePrefiltered {
		got, want := p.find(s), p.scan(s)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s(%q) = %v with its prefilter, %v without", p.name, s, got, want)
		}
		if !p.pass(s) && want != nil {
			t.Errorf("%s: prefilter rejects %q, which holds %v", p.name, s, want)
		}
	}
}

// valuePrefilterCorpus is the secret prefilters' corpus, the bench corpus,
// the short log messages and the threshold examples, each with its
// detection views (the finders are handed those too).
func valuePrefilterCorpus(t testing.TB) []string {
	in := prefilterCorpus(t)
	in = append(in, shortLogMessages...)
	for _, p := range valuePrefiltered {
		in = append(in, p.under, p.at)
	}
	in = append(in,
		"toK68539007547034", "ſe68539007547034", "BE68 5390 0754 7034", "nir 1 84 03 76 451 089 96",
		"4111-1111-1111-1111", "2606:4700:4700::1111", "::ffff:8.8.8.8", `'8.8.8.8'`, "a＠b.com",
	)
	files, err := filepath.Glob(filepath.Join(benchDir, "*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			var c struct{ Text, Field string }
			if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			in = append(in, c.Text, c.Field)
		}
		f.Close()
		if err := sc.Err(); err != nil {
			t.Fatal(err)
		}
	}
	out := in
	for _, s := range in {
		for _, v := range DetectionViews(s) {
			if v.Text != s {
				out = append(out, v.Text)
			}
		}
	}
	return out
}

func TestValuePrefiltersAreExact(t *testing.T) {
	for _, s := range valuePrefilterCorpus(t) {
		checkValuePrefilters(t, s)
	}
}

func FuzzValuePrefiltersAreExact(f *testing.F) {
	for _, s := range valuePrefilterCorpus(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			return
		}
		checkValuePrefilters(t, s)
		for _, v := range DetectionViews(s) {
			checkValuePrefilters(t, v.Text)
		}
	})
}
