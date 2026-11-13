package pii

import (
	"regexp"
	"strings"
)

// --- Belgian identity card number (eID, mod 97)

var beEIDRe = regexp.MustCompile(`[0-9]{3}-[0-9]{7}-[0-9]{2}`)

// findBEEID finds ddd-ddddddd-dd whose last 2 digits are the first 10
// mod 97 (97 for 0).
func findBEEID(s string) []gspan {
	return graded(func(s string) []span {
		return scan(s, beEIDRe, 14, func(s string, start, end int) (int, bool) {
			if b := before(s, start); isAlnum(b) || b == '-' || b == '.' {
				return 0, false
			}
			if !numberEnds(s, end) {
				return 0, false
			}
			d := digitsOf(s[start:end])
			check := mod97(d[:10])
			if check == 0 {
				check = 97
			}
			return end, check == int(d[10]-'0')*10+int(d[11]-'0')
		})
	}, ConfidenceHigh)(s)
}

// --- Belgian passport number (context only)

var passportRe = regexp.MustCompile(`[A-Z]{2}[0-9]{6}`)

// raisePassport: two upper-case letters and six digits after a passport
// word: the shape alone is a product code as often as a passport.
func raisePassport(s string, near func(int) bool) []gspan {
	return raised(scan(s, passportRe, 8, func(s string, start, end int) (int, bool) {
		if isAlnum(before(s, start)) || isAlnum(after(s, end)) {
			return 0, false
		}
		return end, near(start)
	}), near)
}

// --- birth date (context only)

// monthNames are the month names a written date may use, in lower case,
// en/fr/nl/de, with their common abbreviations.
var monthNames = []string{
	"january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december",
	"jan", "feb", "mar", "apr", "jun", "jul", "aug", "sep", "sept", "oct", "nov", "dec",
	"janvier", "février", "fevrier", "mars", "avril", "mai", "juin", "juillet", "août", "aout", "septembre", "octobre", "novembre", "décembre", "decembre",
	"januari", "februari", "maart", "mei", "juni", "juli", "augustus", "oktober",
	"januar", "februar", "märz", "maerz", "dezember",
}

var monthIndex = func() map[string]int {
	full := [][]string{
		{"january", "jan", "janvier", "januari", "januar"},
		{"february", "feb", "février", "fevrier", "februari", "februar"},
		{"march", "mar", "mars", "maart", "märz", "maerz"},
		{"april", "apr", "avril"},
		{"may", "mai", "mei"},
		{"june", "jun", "juin", "juni"},
		{"july", "jul", "juillet", "juli"},
		{"august", "aug", "août", "aout", "augustus"},
		{"september", "sep", "sept", "septembre"},
		{"october", "oct", "octobre", "oktober"},
		{"november", "nov", "novembre"},
		{"december", "dec", "décembre", "decembre", "dezember"},
	}
	m := map[string]int{}
	for i, names := range full {
		for _, n := range names {
			m[n] = i + 1
		}
	}
	return m
}()

// birthDateRe is DD/MM/YYYY, DD-MM-YYYY, DD.MM.YYYY, YYYY-MM-DD, or a day,
// a month name and a year ("3 March 1985", "1er mars 1985", "3. März
// 1985", "March 3, 1985").
var birthDateRe = regexp.MustCompile(`(?i)[0-9]{1,2}[./-][0-9]{1,2}[./-][0-9]{4}` +
	`|[0-9]{4}-[0-9]{2}-[0-9]{2}` +
	`|[0-9]{1,2}(?:er|st|nd|rd|th)?\.? (?:` + strings.Join(monthNames, "|") + `)\.? [0-9]{4}` +
	`|(?:` + strings.Join(monthNames, "|") + `)\.? [0-9]{1,2}(?:st|nd|rd|th)?,? [0-9]{4}`)

// raiseBirthDates: a date after a birth word ("né le", "geboren",
// "DOB"); never a date alone.
func raiseBirthDates(s string, near func(int) bool) []gspan {
	return raised(scan(s, birthDateRe, 48, func(s string, start, end int) (int, bool) {
		if isAlnum(before(s, start)) || isAlnum(after(s, end)) || !near(start) {
			return 0, false
		}
		return end, plausibleDate(s[start:end])
	}), near)
}

// plausibleDate checks the day, month and year (1900 to 2099) of a date
// birthDateRe matched.
func plausibleDate(v string) bool {
	_, _, _, ok := parseDate(v)
	return ok
}

// parseDate reads a date birthDateRe matched: day first unless the year
// is (or the second number cannot be a month: MM/DD/YYYY).
func parseDate(v string) (year, month, day int, ok bool) {
	var nums []int
	for _, f := range strings.FieldsFunc(strings.ToLower(v), func(r rune) bool {
		return r == ' ' || r == '.' || r == '/' || r == '-' || r == ','
	}) {
		if m, ok := monthIndex[f]; ok {
			month = m
			continue
		}
		d := strings.TrimRight(f, "erstndh")
		if d == "" || digitsOf(d) != d {
			return 0, 0, 0, false
		}
		nums = append(nums, atoi(d))
	}
	switch {
	case month > 0 && len(nums) == 2:
		day, year = nums[0], nums[1]
	case len(nums) == 3 && nums[0] > 31:
		year, month, day = nums[0], nums[1], nums[2]
	case len(nums) == 3:
		day, month, year = nums[0], nums[1], nums[2]
		if month > 12 && day <= 12 {
			day, month = month, day // MM/DD/YYYY
		}
	default:
		return 0, 0, 0, false
	}
	return year, month, day, year >= 1900 && year <= 2099 && month >= 1 && month <= 12 && day >= 1 && day <= 31
}

func noFinder(string) []gspan { return nil }
