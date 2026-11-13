package plans

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInputKeyInMemoryWhilePending(t *testing.T) {
	s, dir, _ := newStore(t)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Create(bind(agent3), json.RawMessage(`{}`), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.KeepInputKey(p.ID, tk1, key); !errors.Is(err, ErrState) {
		t.Fatalf("planned: %v", err)
	}
	if err := s.MarkPending(p.ID, agent3, tkt(t, p, nil)); err != nil {
		t.Fatal(err)
	}
	if err := s.KeepInputKey(p.ID, "01JBDN0Z0000000000000000ZZ", key); !errors.Is(err, ErrState) {
		t.Fatalf("another ticket: %v", err)
	}
	if err := s.KeepInputKey(p.ID, tk1, key); err != nil {
		t.Fatal(err)
	}
	if s.InputKey(p.ID, tk1) != key || s.InputKey(p.ID, "01JBDN0Z0000000000000000ZZ") != nil {
		t.Fatal("InputKey")
	}
	// Never on disk.
	raw := key.Bytes()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if bytes.Contains(b, raw) || bytes.Contains(b, []byte(base64.RawURLEncoding.EncodeToString(raw))) ||
			bytes.Contains(b, []byte(base64.StdEncoding.EncodeToString(raw))) {
			t.Fatalf("%s holds the key", e.Name())
		}
	}
	// Gone once the plan runs.
	if err := s.Begin(p.ID, agent3, "nonce-1"); err != nil {
		t.Fatal(err)
	}
	if s.InputKey(p.ID, tk1) != nil {
		t.Fatal("key kept after Begin")
	}
	// Gone once the plan ends.
	q, _ := s.Create(Binding{UID: agent3.UID, TokenHash: HashToken(agent3.Token), PolicyFP: fpA, PlanHash: hashB}, json.RawMessage(`{}`), 0)
	tq := tkt(t, q, nil)
	if err := s.MarkPending(q.ID, agent3, tq); err != nil {
		t.Fatal(err)
	}
	if err := s.KeepInputKey(q.ID, tq.ID, key); err != nil {
		t.Fatal(err)
	}
	if err := s.End(q.ID, agent3, Denied, "no"); err != nil {
		t.Fatal(err)
	}
	if s.InputKey(q.ID, tq.ID) != nil {
		t.Fatal("key kept after End")
	}
	if err := s.KeepInputKey(q.ID, tq.ID, nil); err == nil {
		t.Fatal("nil key kept")
	}
}
