package pii

import (
	"os"
	"reflect"
	"regexp/syntax"
	"strings"
	"testing"
)

var prefiltered = []struct {
	name       string
	find, scan func(string) []span
}{
	{"tokenShapes", findTokenShapes, scanTokenShapes},
	{"authSchemes", findAuthSchemes, scanAuthSchemes},
	{"userinfo", findUserinfo, scanUserinfo},
	{"mysql", findMySQLPasswords, scanMySQLPasswords},
}

func checkPrefilters(t *testing.T, s string) {
	t.Helper()
	for _, p := range prefiltered {
		if got, want := p.find(s), p.scan(s); !reflect.DeepEqual(got, want) {
			t.Errorf("%s(%q) = %v with its prefilter, %v without", p.name, s, got, want)
		}
	}
}

// prefilterCorpus is every input of the secret tests and the benign
// corpus, plus the inputs that only a case fold reaches.
func prefilterCorpus(t testing.TB) []string {
	data, err := os.ReadFile("testdata/benign-log-lines.txt")
	if err != nil {
		t.Fatal(err)
	}
	in := strings.Split(string(data), "\n")
	in = append(in, tokenShapeExamples(t)...)
	return append(in,
		"Authorization: BEARER abcdef123456", "toKen abcdef123456", "baſic dXNlcjpwYXNz",
		"curl -ubob:pw https://x", "mysql -uroot -phunter2", "https://bob:pw@example.com/",
		"x "+fakeGH, "AccountKey="+strings.Repeat("A", 44), "123456789:AA"+strings.Repeat("b", 33),
	)
}

func TestSecretPrefiltersAreExact(t *testing.T) {
	for _, s := range prefilterCorpus(t) {
		checkPrefilters(t, s)
	}
}

// TestTokenShapeLitsCoverEveryAlternative checks that every branch of
// tokenShapeRe (each alternative, each member of a small class) yields a
// match that contains one of tokenShapeLits: a shape added without its
// literal fails here.
func TestTokenShapeLitsCoverEveryAlternative(t *testing.T) {
	ex := tokenShapeExamples(t)
	if len(ex) < 60 {
		t.Fatalf("only %d examples", len(ex))
	}
	for _, s := range ex {
		if !tokenShapeRe.MatchString(s) {
			t.Errorf("example %q does not match tokenShapeRe", s)
		}
		if !containsAny(s, tokenShapeLits) {
			t.Errorf("tokenShapeRe matches %q, which holds none of tokenShapeLits", s)
		}
	}
}

// tokenShapeExamples enumerates one shortest match of tokenShapeRe per
// branch: every alternative and every member of a class of at most eight
// runes; a larger class contributes its first rune.
func tokenShapeExamples(t testing.TB) []string {
	re, err := syntax.Parse(tokenShapeRe.String(), syntax.Perl)
	if err != nil {
		t.Fatal(err)
	}
	return examples(re)
}

func examples(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		return []string{string(re.Rune)}
	case syntax.OpCharClass:
		var out []string
		n := 0
		for i := 0; i+1 < len(re.Rune); i += 2 {
			n += int(re.Rune[i+1]-re.Rune[i]) + 1
		}
		for i := 0; i+1 < len(re.Rune); i += 2 {
			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				out = append(out, string(r))
				if n > 8 {
					return out
				}
			}
		}
		return out
	case syntax.OpAlternate:
		var out []string
		for _, s := range re.Sub {
			out = append(out, examples(s)...)
		}
		return out
	case syntax.OpConcat:
		out := []string{""}
		for _, s := range re.Sub {
			var next []string
			for _, a := range out {
				for _, b := range examples(s) {
					next = append(next, a+b)
				}
			}
			out = next
		}
		return out
	case syntax.OpCapture, syntax.OpPlus:
		return examples(re.Sub[0])
	case syntax.OpRepeat:
		var out []string
		for _, e := range examples(re.Sub[0]) {
			out = append(out, strings.Repeat(e, re.Min))
		}
		return out
	case syntax.OpStar, syntax.OpQuest, syntax.OpEmptyMatch:
		return []string{""}
	}
	panic("examples: unhandled op " + re.Op.String())
}

func FuzzSecretPrefiltersAreExact(f *testing.F) {
	for _, s := range prefilterCorpus(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			return
		}
		checkPrefilters(t, s)
	})
}

// BenchmarkSecretBenignCorpus is the secret detector on benign log lines,
// the common case (locklog masks every record it reads).
func BenchmarkSecretBenignCorpus(b *testing.B) {
	data, err := os.ReadFile("testdata/benign-log-lines.txt")
	if err != nil {
		b.Fatal(err)
	}
	ls := strings.Split(string(data), "\n")
	n := 0
	for _, l := range ls {
		n += len(l)
	}
	d := mustDetectorsB(b, "secret")
	b.SetBytes(int64(n))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, l := range ls {
			Detect(l, d)
		}
	}
}

func mustDetectorsB(b *testing.B, names ...string) []Detector {
	ds, err := Detectors(names)
	if err != nil {
		b.Fatal(err)
	}
	return ds
}
