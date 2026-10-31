package pii

import (
	"embed"
	"strings"
	"unicode"
	"unicode/utf8"
)

// --- person names (gazetteer)
//
// person_name finds a person's full name in free text: a known given name
// followed by a surname ("Jean Dupont", "Will Smith", "Ludwig van
// Beethoven", "JOHN SMITH", "john smith", "john.smith"), or a title
// followed by a capitalised name ("Mr. Smith", "Mme Lefebvre", "Dr
// Janssens"). A surname is a known family name, or, after an unambiguous
// given name in title case, any capitalised word that is not a common
// word. A given name alone, a surname alone, a name written "Smith, John"
// and names outside the gazetteer without a title are not found.

//go:embed gazetteer/*.txt
var gazetteerFS embed.FS

var (
	givenNames     = loadGazetteer("gazetteer/first-names.txt")
	ambiguousNames = loadGazetteer("gazetteer/ambiguous-first-names.txt")
	familyNames    = loadGazetteer("gazetteer/surnames.txt")
	commonWords    = loadGazetteer("gazetteer/common-words.txt")
	honorifics     = loadGazetteer("gazetteer/honorifics.txt")
)

// nameParticles join a given name to a surname ("van der", "de la").
var nameParticles = set("van", "der", "den", "de", "von", "da", "di", "del", "della", "le", "la", "du",
	"des", "ten", "ter", "bin", "ben", "al", "el", "dos", "das", "zu", "vom")

func loadGazetteer(name string) map[string]bool {
	b, err := gazetteerFS.ReadFile(name)
	if err != nil {
		panic("pii: " + err.Error())
	}
	m := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		for _, w := range strings.Fields(line) {
			m[nameKey(w)] = true
		}
	}
	return m
}

// nameKey is a word lowered, with accents removed from common Latin
// letters and the typographic apostrophe made plain: what the gazetteer
// is keyed by.
func nameKey(w string) string {
	var b strings.Builder
	b.Grow(len(w))
	for _, r := range w {
		if r == '’' {
			r = '\''
		}
		b.WriteRune(unaccent(unicode.ToLower(r)))
	}
	return b.String()
}

// word is a run of letters (with marks, inner apostrophes and hyphens)
// at s[start:end].
type word struct {
	start, end int
	key        string
	shape      wordShape
}

type wordShape uint8

const (
	shapeLower wordShape = iota // "smith"
	shapeTitle                  // "Smith", "McDonald", "O'Brien"
	shapeUpper                  // "SMITH"
	shapeOther                  // "sMITH", "x"
)

// maxNameWord bounds a word tried as a name: longer runs of letters are
// not names (and are skipped whole).
const maxNameWord = 40

func words(s string) []word {
	var out []word
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if !unicode.IsLetter(r) {
			i += n
			continue
		}
		start := i
		for i < len(s) {
			r, n := utf8.DecodeRuneInString(s[i:])
			if unicode.IsLetter(r) || unicode.IsMark(r) {
				i += n
				continue
			}
			// An apostrophe or a hyphen between letters stays inside
			// the word ("O'Brien", "Jean-Pierre").
			if r == '\'' || r == '’' || r == '-' {
				if r2, _ := utf8.DecodeRuneInString(s[i+n:]); unicode.IsLetter(r2) {
					i += n
					continue
				}
			}
			break
		}
		if i-start <= maxNameWord {
			w := s[start:i]
			out = append(out, word{start: start, end: i, key: nameKey(w), shape: shapeOf(w)})
		}
	}
	return out
}

func shapeOf(w string) wordShape {
	upper, lower := 0, 0
	first := true
	firstUpper := false
	for _, r := range w {
		switch {
		case unicode.IsUpper(r):
			upper++
			if first {
				firstUpper = true
			}
		case unicode.IsLower(r):
			lower++
		}
		if unicode.IsLetter(r) {
			first = false
		}
	}
	switch {
	case upper == 0:
		return shapeLower
	case lower == 0 && upper >= 2:
		return shapeUpper
	case firstUpper && lower > 0:
		return shapeTitle
	}
	return shapeOther
}

// gap returns the text between two words.
func gap(s string, a, b word) string { return s[a.end:b.start] }

func blankGap(g string) bool { return g == " " || g == "  " || g == " " }

func capitalised(w word) bool { return w.shape == shapeTitle || w.shape == shapeUpper }

// isInitial reports a middle initial: one capital letter followed by a dot.
func isInitial(s string, w word) bool {
	r, n := utf8.DecodeRuneInString(s[w.start:])
	return n == w.end-w.start && unicode.IsUpper(r) && after(s, w.end) == '.'
}

// compoundGiven reports a hyphenated given name made of given names
// ("jean-pierre", "anne-sophie").
func compoundGiven(key string) bool {
	parts := strings.Split(key, "-")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if !givenNames[p] && !ambiguousNames[p] {
			return false
		}
	}
	return true
}

func findPersonNames(s string) []span {
	ws := words(s)
	var out []span
	for i := 0; i < len(ws); i++ {
		if end, ok := titledName(s, ws, i); ok {
			out = append(out, span{ws[i+1].start, ws[end].end})
			i = end
			continue
		}
		if end, ok := givenAndSurname(s, ws, i); ok {
			out = append(out, span{ws[i].start, ws[end].end})
			i = end
		}
	}
	return out
}

// titledName reads "Mr. Smith", "Mme Lefebvre-Durand", "Dr. Jan de Vries":
// a capitalised title, then up to three capitalised words or particles
// ending on a capitalised one. It returns the index of the last word.
func titledName(s string, ws []word, i int) (int, bool) {
	t := ws[i]
	if !capitalised(t) && !(t.end-t.start == 1 && unicode.IsUpper(rune(s[t.start]))) || !honorifics[t.key] {
		return 0, false
	}
	if i+1 >= len(ws) {
		return 0, false
	}
	g := gap(s, t, ws[i+1])
	dotted := strings.HasPrefix(g, ".")
	if t.key == "m" && !dotted {
		return 0, false // "M" alone is a letter, "M." a title
	}
	if g = strings.TrimPrefix(g, "."); !blankGap(g) {
		return 0, false
	}
	last := -1
	for j := i + 1; j < len(ws) && j <= i+4; j++ {
		w := ws[j]
		if j > i+1 && !blankGap(gap(s, ws[j-1], w)) {
			break
		}
		switch {
		case capitalised(w) && !commonWords[w.key] && !honorifics[w.key]:
			last = j
			continue
		case nameParticles[w.key] && last >= 0 || nameParticles[w.key] && j == i+1:
			continue
		}
		break
	}
	if last < 0 {
		return 0, false
	}
	return last, true
}

// givenAndSurname reads a given name, an optional middle name or initial,
// optional particles and a surname. It returns the index of the surname.
func givenAndSurname(s string, ws []word, i int) (int, bool) {
	g := ws[i]
	ambiguous := ambiguousNames[g.key]
	if !givenNames[g.key] && !ambiguous && !compoundGiven(g.key) {
		return 0, false
	}
	if g.shape == shapeOther {
		return 0, false
	}
	j := i + 1
	if j >= len(ws) {
		return 0, false
	}
	sep := gap(s, g, ws[j])
	joined := sep == "." || sep == "_"
	if !blankGap(sep) && !joined {
		return 0, false
	}
	if joined {
		// "john.smith", "John_Smith": both names known, same case.
		u := ws[j]
		if familyNames[u.key] && u.shape == g.shape && g.shape != shapeOther {
			return j, true
		}
		return 0, false
	}
	// A middle initial ("John F. Kennedy") or given name ("Anne Marie Dupont").
	if capitalised(g) && j+1 < len(ws) {
		m := ws[j]
		gm := gap(s, m, ws[j+1])
		if isInitial(s, m) && blankGap(strings.TrimPrefix(gm, ".")) ||
			givenNames[m.key] && m.shape == g.shape && blankGap(gm) && !familyNames[m.key] {
			j++
		}
	}
	// Particles ("van der", "de la"), at most two.
	for k := 0; k < 2 && j+1 < len(ws) && nameParticles[ws[j].key] && blankGap(gap(s, ws[j], ws[j+1])); k++ {
		j++
	}
	u := ws[j]
	if j > i+1 && !blankGap(strings.TrimPrefix(gap(s, ws[j-1], u), ".")) {
		return 0, false
	}
	known := familyNames[u.key]
	switch {
	case known && u.shape == g.shape && (g.shape != shapeLower || !commonWords[u.key] && !ambiguous):
		// "Will Smith", "JOHN SMITH", "john smith" (both known).
		return j, true
	case known && capitalised(g) && capitalised(u):
		return j, true
	case !ambiguous && g.shape == shapeTitle && u.shape == shapeTitle && !commonWords[u.key] &&
		!honorifics[u.key] && utf8.RuneCountInString(s[u.start:u.end]) >= 2:
		// "Kevin Vandeputte": an unknown capitalised surname.
		return j, true
	}
	return 0, false
}
