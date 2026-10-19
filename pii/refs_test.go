package pii

import (
	"strings"
	"testing"
)

func TestRefStorePutGet(t *testing.T) {
	var s RefStore
	n := s.Begin()
	ref := s.Put(n, "2.3", "alice@example.com")
	if ref != "r1.2.3" {
		t.Fatalf("ref = %q", ref)
	}
	if v, ok := s.Get(ref); !ok || v != "alice@example.com" {
		t.Fatalf("Get = %q, %v", v, ok)
	}
	for _, bad := range []string{"", "r", "r1", "r1.2", "r0.2.3", "r1.0.3", "rx.2.3", "1.2.3", "r1.2.3.4", "r2.2.3", "r1.2.4"} {
		if _, ok := s.Get(bad); ok {
			t.Errorf("Get(%q) resolved", bad)
		}
	}
	// A key is positive integers separated by dots: never text that could
	// carry the value into the reference.
	for _, bad := range []string{"", "a", "1.x", "0", "1..2", "-1", "alice@example.com"} {
		if s.Put(n, bad, "v") != "" {
			t.Errorf("key %q accepted", bad)
		}
	}
	if s.Put(n+1, "1.1", "v") != "" {
		t.Error("put into a result that was never begun")
	}
}

// The same value in one result gets one reference; the numbering says
// nothing of the value.
func TestRefStorePutDistinct(t *testing.T) {
	var s RefStore
	n := s.Begin()
	a := s.PutDistinct(n, "alice@example.com")
	b := s.PutDistinct(n, "bob@example.com")
	if a != "r1.1" || b != "r1.2" || s.PutDistinct(n, "alice@example.com") != a {
		t.Fatalf("refs %q %q", a, b)
	}
	if v, ok := s.Get(b); !ok || v != "bob@example.com" {
		t.Fatalf("Get = %q %v", v, ok)
	}
	m := s.Begin()
	if s.PutDistinct(m, "alice@example.com") != "r2.1" {
		t.Error("numbering is per result")
	}
}

func TestRefStoreEvictsOldestResults(t *testing.T) {
	var s RefStore
	first := s.Begin()
	ref := s.Put(first, "1.1", "x")
	for i := 0; i < MaxRefResults; i++ {
		s.Begin()
	}
	if _, ok := s.Get(ref); ok {
		t.Fatal("the oldest result was kept past MaxRefResults")
	}
	// A value too large for the store is not kept.
	n := s.Begin()
	if s.Put(n, "1.1", strings.Repeat("v", MaxRefBytes+1)) != "" {
		t.Fatal("oversized value stored")
	}
	// Byte pressure evicts older results, never the current one.
	old := s.Put(n, "1.1", strings.Repeat("a", MaxRefBytes/2))
	cur := s.Begin()
	newer := s.Put(cur, "1.1", strings.Repeat("b", MaxRefBytes/2+1))
	if newer == "" {
		t.Fatal("current result refused")
	}
	if _, ok := s.Get(old); ok {
		t.Fatal("older result kept over the byte bound")
	}
	s.Evict()
	if _, ok := s.Get(newer); ok {
		t.Fatal("Evict kept the oldest result")
	}
}
