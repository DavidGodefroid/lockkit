package pii

import (
	"os"
	"strings"
	"testing"
)

// shortLogMessages are short log messages and field values with no
// personal data, the common case of a log scan (locklog hands every
// message and field value to FindInViews).
var shortLogMessages = []string{
	"order confirmed in 123ms",
	"GET /api/orders/4812 200",
	"cache miss for key product:991",
	"retrying request (attempt 2 of 5)",
	"user logged in",
	"payment accepted",
	"worker 7 started",
	"processed 1042 events in 3.2s",
	"connection pool size=20 idle=4",
	"INFO",
	"checkout",
	"2026-11-13T09:12:44.512Z",
	"shipment 88123 dispatched to warehouse BRU-2",
	"invoice 2026-0042 generated",
	"job nightly-export finished with status ok",
	"timeout after 30000 ms, giving up",
	"feature flag new-cart enabled for 25% of traffic",
	"request_id=7f3c2a91",
	"queue depth 0",
	"rendered template emails/welcome.html",
}

func benchLines(b *testing.B) []string {
	data, err := os.ReadFile("testdata/benign-log-lines.txt")
	if err != nil {
		b.Fatal(err)
	}
	var ls []string
	for _, l := range strings.Split(string(data), "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			ls = append(ls, l)
		}
	}
	return ls
}

func benchFindInViews(b *testing.B, ls []string, ds []Detector) {
	n := 0
	for _, l := range ls {
		n += len(l)
	}
	b.SetBytes(int64(n))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, l := range ls {
			FindInViews(l, ds)
		}
	}
}

// BenchmarkFindInViewsShortMessages is FindInViews on short log messages,
// with AllDetectors and with locklog's set (AllDetectors, ip, person_name
// and secret).
func BenchmarkFindInViewsShortMessages(b *testing.B) {
	b.Run("all", func(b *testing.B) { benchFindInViews(b, shortLogMessages, AllDetectors()) })
	b.Run("locklog", func(b *testing.B) { benchFindInViews(b, shortLogMessages, locklogDetectors(b)) })
}

// BenchmarkFindInViewsBenignLines is FindInViews on the benign corpus
// (access logs, versions, hashes, ids).
func BenchmarkFindInViewsBenignLines(b *testing.B) {
	ls := benchLines(b)
	b.Run("all", func(b *testing.B) { benchFindInViews(b, ls, AllDetectors()) })
	b.Run("locklog", func(b *testing.B) { benchFindInViews(b, ls, locklogDetectors(b)) })
}

func locklogDetectors(b *testing.B) []Detector {
	return append(AllDetectors(), mustDetectorsB(b, "ip", "person_name", "secret")...)
}
