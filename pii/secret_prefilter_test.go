package pii

import (
	"os"
	"reflect"
	"regexp/syntax"
	"strconv"
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
	{"pairs", findSecretPairs, func(s string) []span { return secretPairs(s, nil) }},
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
		"Authorization: BEARER abcdef123456", "to\u212aen abcdef123456", "\u212aEY toKen abcdef123456", "ba\u017fic dXNlcjpwYXNz", "Authorization: Bearer abcdef123456",
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
func TestAuthSchemeFoldRunes(t *testing.T) {
	for _, r := range "\u212a\u017f" {
		if !strings.ContainsRune(authSchemeFold, r) {
			t.Errorf("authSchemeFold lacks %U", r)
		}
	}
	if !authSchemeRe.MatchString("to\u212aen ") || findAuthSchemes("Authorization: to\u212aen abcdef123456") == nil {
		t.Error("the Kelvin sign in token is not found")
	}
}

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

// TestSecretThroughputFloor fails when the secret detector masks the benign
// corpus slower than LOCKKIT_PII_FLOOR_MBPS (MB/s on one goroutine). CI
// sets it well under the measured speed (about 7 MB/s per core), so that
// only a regression, not a noisy runner, fails it; locklog needs at least
// 4 MiB/s per core for an approved scan to fit its approval.
func TestSecretThroughputFloor(t *testing.T) {
	floor, err := strconv.ParseFloat(os.Getenv("LOCKKIT_PII_FLOOR_MBPS"), 64)
	if err != nil {
		t.Skip("LOCKKIT_PII_FLOOR_MBPS not set")
	}
	best := 0.0
	for range 3 { // the best of three runs, against scheduler noise
		r := testing.Benchmark(BenchmarkSecretBenignCorpus)
		if mbps := float64(r.Bytes) * float64(r.N) / r.T.Seconds() / 1e6; mbps > best {
			best = mbps
		}
	}
	t.Logf("secret: %.2f MB/s", best)
	if best < floor {
		t.Fatalf("secret masks %.2f MB/s, under the floor of %.2f MB/s", best, floor)
	}
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
