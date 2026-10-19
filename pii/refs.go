package pii

import (
	"regexp"
	"strconv"
	"strings"
)

// Bounds of the reference store: the oldest results are forgotten first.
const (
	MaxRefResults = 50
	MaxRefBytes   = 16 << 20
)

// RefStore keeps the clear values behind the redacted references of the
// last results, so that an agent can name a value ('${rN.K}') without
// seeing it. It lives in the console's memory and dies with it. The zero
// value is ready; it is not safe for concurrent use.
//
// A reference is "r<result>.<key>", where key is positive integers
// separated by dots chosen by the product: locksql uses "<row>.<column>",
// PutDistinct numbers the distinct values of a result. A key never holds
// the value.
type RefStore struct {
	next    int
	results []refResult // oldest first
	bytes   int
}

type refResult struct {
	n        int
	cells    map[string]string
	distinct map[string]string // value -> key, for PutDistinct
	bytes    int
}

var refKeyRe = regexp.MustCompile(`^[1-9][0-9]*(\.[1-9][0-9]*)*$`)

// Begin opens the next result and returns its number.
func (r *RefStore) Begin() int {
	r.next++
	r.results = append(r.results, refResult{n: r.next, cells: map[string]string{}})
	for len(r.results) > MaxRefResults {
		r.Evict()
	}
	return r.next
}

// Put stores value under key in result n and returns its reference, or ""
// when the key is malformed, the result unknown or the store cannot hold
// the value.
func (r *RefStore) Put(n int, key, value string) string {
	if !refKeyRe.MatchString(key) || len(value) > MaxRefBytes {
		return ""
	}
	for r.bytes+len(value) > MaxRefBytes && len(r.results) > 1 {
		r.Evict()
	}
	res := r.find(n)
	if res == nil || r.bytes+len(value) > MaxRefBytes {
		return ""
	}
	res.cells[key] = value
	res.bytes += len(value)
	r.bytes += len(value)
	return "r" + strconv.Itoa(n) + "." + key
}

// PutDistinct stores value in result n under the next number, or returns
// the reference it already has in that result: the same value gets the
// same reference across the records of one result.
func (r *RefStore) PutDistinct(n int, value string) string {
	res := r.find(n)
	if res == nil {
		return ""
	}
	if key, ok := res.distinct[value]; ok {
		return "r" + strconv.Itoa(n) + "." + key
	}
	key := strconv.Itoa(len(res.distinct) + 1)
	ref := r.Put(n, key, value)
	if ref == "" {
		return ""
	}
	if res = r.find(n); res != nil {
		if res.distinct == nil {
			res.distinct = map[string]string{}
		}
		res.distinct[value] = key
	}
	return ref
}

// Get resolves a reference.
func (r *RefStore) Get(ref string) (string, bool) {
	rest, ok := strings.CutPrefix(ref, "r")
	if !ok {
		return "", false
	}
	num, key, ok := strings.Cut(rest, ".")
	if !ok || !refKeyRe.MatchString(num) || !refKeyRe.MatchString(key) {
		return "", false
	}
	n, err := strconv.Atoi(num)
	if err != nil {
		return "", false
	}
	res := r.find(n)
	if res == nil {
		return "", false
	}
	v, ok := res.cells[key]
	return v, ok
}

func (r *RefStore) find(n int) *refResult {
	for i := range r.results {
		if r.results[i].n == n {
			return &r.results[i]
		}
	}
	return nil
}

// Evict forgets the oldest result.
func (r *RefStore) Evict() {
	if len(r.results) == 0 {
		return
	}
	r.bytes -= r.results[0].bytes
	r.results = r.results[1:]
}
