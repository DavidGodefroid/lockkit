package pii

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

func fixedPseudonymizer(t *testing.T) *Pseudonymizer {
	t.Helper()
	key := bytes.Repeat([]byte{0x42}, KeyLen)
	p, err := NewPseudonymizer("E7Q2M9ZD", t0, key)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A golden vector: the ID scheme is a contract (references and cursors
// minted under an epoch must stay readable by the next release).
func TestPseudonymGolden(t *testing.T) {
	p := fixedPseudonymizer(t)
	got := p.ID("email", "Jean.Dupont@Example.com")
	if got != goldenEmailID {
		t.Errorf("ID = %s, want %s", got, goldenEmailID)
	}
	if !ValidID(got) || len(got) != PseudonymLen {
		t.Errorf("ID %q is not a valid pseudonym", got)
	}
	for _, c := range got {
		if !strings.ContainsRune(crockford, c) {
			t.Errorf("ID %q has %q outside Crockford base32", got, c)
		}
	}
	for _, bad := range []string{"", "7F3KQ2M9ZD4", "7F3KQ2M9ZD4XX", "7F3KQ2M9ZD4I", "7f3kq2m9zd4x"} {
		if ValidID(bad) {
			t.Errorf("ValidID(%q) = true", bad)
		}
	}
}

// goldenEmailID was computed independently (Python hmac + Crockford).
const goldenEmailID = "BJYSN2C98Y4R"

func TestPseudonymsStableAcrossCalls(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "epochs")
	s, err := OpenEpochStore(dir, true, t0)
	if err != nil {
		t.Fatal(err)
	}
	p := s.Current()
	same := [][]string{
		{"email", "jean.dupont@example.com", "Jean.Dupont@EXAMPLE.com", " jean.dupont@example.com ", "jean.dupont%40example.com", `jean.dupont@example.com`, "jean.dupont&#64;example.com", "ｊｅａｎ.dupont@example.com", "jean\u200b.dupont@example.com"},
		{"phone", "+32 475 12 34 56", "+32475123456", "0032 475 12 34 56", "+32.475.12.34.56", "+32 475 12 34 56"},
		{"phone", "0475 12 34 56", "0475/12.34.56", "0475123456"},
		{"iban", "BE68 5390 0754 7034", "be68539007547034", "BE68539007547034"},
		{"card", "4111 1111 1111 1111", "4111-1111-1111-1111", "４１１１１１１１１１１１１１１１"},
		{"be_niss", "85.07.30-033.28", "85073003328"},
		{"fr_nir", "2 69 05 2A 001 123 07", "269052a00112307"},
		{"ip", "2001:db8::1", "2001:DB8:0:0:0:0:0:1", "[2001:db8::1]"},
		{"ip", "192.0.2.1", "::ffff:192.0.2.1"},
	}
	for _, group := range same {
		kind, want := group[0], p.ID(group[0], group[1])
		for _, v := range group[2:] {
			if got := p.ID(kind, v); got != want {
				t.Errorf("ID(%s, %q) = %s, want %s (as %q): Normalise %q vs %q", kind, v, got, want, group[1], Normalise(kind, v), Normalise(kind, group[1]))
			}
		}
		if again := p.ID(kind, group[1]); again != want {
			t.Errorf("ID not stable: %s then %s", want, again)
		}
	}
	// Different values, different kinds: different IDs.
	ids := map[string]string{}
	for _, kv := range [][2]string{{"email", "a@example.com"}, {"email", "b@example.com"}, {"phone", "+32475123456"}, {"phone", "+32475123457"}, {"card", "4111111111111111"}, {"be_niss", "4111111111111111"}, {"ip", "192.0.2.1"}, {"ip", "192.0.2.2"}} {
		id := p.ID(kv[0], kv[1])
		if prev, dup := ids[id]; dup {
			t.Errorf("ID collision: %v and %s", kv, prev)
		}
		ids[id] = fmt.Sprint(kv)
	}
	// A reopened store gives the same IDs.
	s2, err := OpenEpochStore(dir, false, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if s2.Current().Epoch() != p.Epoch() || s2.Current().ID("email", "jean.dupont@example.com") != p.ID("email", "jean.dupont@example.com") {
		t.Error("a reopened store gives other pseudonyms")
	}
	// Another epoch, other IDs.
	q, _ := NewEpoch(t0)
	if q.ID("email", "jean.dupont@example.com") == p.ID("email", "jean.dupont@example.com") || q.Epoch() == p.Epoch() {
		t.Error("two epochs give the same pseudonym")
	}
}

func TestEpochRotationAndDeletion(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "epochs")
	s, err := OpenEpochStore(dir, true, t0)
	if err != nil {
		t.Fatal(err)
	}
	old := s.Current()
	oldID := old.ID("email", "a@example.com")
	if s.RotationDue(t0.Add(6*24*time.Hour), 7*24*time.Hour) || !s.RotationDue(t0.Add(7*24*time.Hour), 7*24*time.Hour) {
		t.Error("RotationDue wrong around 7 days")
	}
	rotated := t0.Add(7 * 24 * time.Hour)
	cur, err := s.Rotate(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if s.Current() != cur || cur.Epoch() == old.Epoch() || cur.ID("email", "a@example.com") == oldID {
		t.Fatal("rotation kept the epoch or the pseudonyms")
	}
	// The previous epoch is still readable, here and after a reopen.
	if g, err := s.Get(old.Epoch()); err != nil || g.ID("email", "a@example.com") != oldID {
		t.Errorf("Get(previous) = %v, %v", g, err)
	}
	s2, err := OpenEpochStore(dir, false, rotated)
	if err != nil || s2.Current().Epoch() != cur.Epoch() || len(s2.Epochs()) != 2 {
		t.Fatalf("reopen after rotation: %v, %v", s2, err)
	}
	// Not yet 24 h: nothing pruned.
	if gone, err := s.Prune(rotated.Add(23*time.Hour), 24*time.Hour); err != nil || len(gone) != 0 {
		t.Errorf("Prune before 24 h = %v, %v", gone, err)
	}
	gone, err := s.Prune(rotated.Add(24*time.Hour), 24*time.Hour)
	if err != nil || len(gone) != 1 || gone[0] != old.Epoch() {
		t.Fatalf("Prune = %v, %v", gone, err)
	}
	if _, err := s.Get(old.Epoch()); !errors.Is(err, ErrUnknownEpoch) {
		t.Errorf("Get(pruned) = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, old.Epoch()+keyFileSuffix)); !os.IsNotExist(err) {
		t.Errorf("pruned key file still there: %v", err)
	}
	if !bytes.Equal(old.key, make([]byte, KeyLen)) {
		t.Error("pruned key not cleared from memory")
	}
	// The current epoch is never pruned.
	if gone, _ := s.Prune(rotated.Add(1000*24*time.Hour), time.Nanosecond); len(gone) != 0 || s.Current() != cur {
		t.Errorf("Prune deleted the current epoch: %v", gone)
	}
	s3, err := OpenEpochStore(dir, false, rotated.Add(25*time.Hour))
	if err != nil || len(s3.Epochs()) != 1 {
		t.Errorf("reopen after prune: %v, %v", s3, err)
	}
	// Rotations in the same second keep their order.
	a, _ := s.Rotate(rotated)
	b, _ := s.Rotate(rotated)
	if s.Current() != b || !b.Created().After(a.Created()) {
		t.Error("same-second rotations out of order")
	}
	s4, _ := OpenEpochStore(dir, false, rotated)
	if s4.Current().Epoch() != b.Epoch() {
		t.Error("reopen picked another current epoch")
	}
}

func TestEpochStoreRefusals(t *testing.T) {
	if _, err := OpenEpochStore(filepath.Join(t.TempDir(), "none"), false, t0); !errors.Is(err, ErrNoEpoch) {
		t.Errorf("missing dir: %v", err)
	}
	empty := filepath.Join(t.TempDir(), "empty")
	os.Mkdir(empty, 0o700)
	if _, err := OpenEpochStore(empty, false, t0); !errors.Is(err, ErrNoEpoch) {
		t.Errorf("empty dir: %v", err)
	}
	fresh := func(t *testing.T) (string, string) {
		dir := filepath.Join(t.TempDir(), "epochs")
		s, err := OpenEpochStore(dir, true, t0)
		if err != nil {
			t.Fatal(err)
		}
		return dir, filepath.Join(dir, s.Current().Epoch()+keyFileSuffix)
	}
	corrupt := map[string]func(string) []byte{
		"truncated": func(b string) []byte { return []byte(b[:len(b)-10]) },
		"no magic":  func(b string) []byte { return []byte(strings.TrimPrefix(b, keyFileMagic)) },
		"short key": func(b string) []byte { return []byte(b[:strings.Index(b, "key=")] + "key=AAAA\n") },
		"bad time":  func(b string) []byte { return []byte(strings.Replace(b, "created=2026", "created=x026", 1)) },
		"extra":     func(b string) []byte { return []byte(b + "key=AAAA\n") },
		"empty":     func(string) []byte { return nil },
	}
	for name, f := range corrupt {
		dir, file := fresh(t)
		b, _ := os.ReadFile(file)
		os.WriteFile(file, f(string(b)), 0o600)
		if _, err := OpenEpochStore(dir, true, t0); err == nil {
			t.Errorf("%s key file accepted", name)
		}
	}
	// Another epoch's file under this epoch's name.
	dir, file := fresh(t)
	b, _ := os.ReadFile(file)
	os.WriteFile(file, bytes.Replace(b, []byte("epoch="), []byte("epoch=X"), 1), 0o600)
	if _, err := OpenEpochStore(dir, false, t0); err == nil {
		t.Error("mismatched epoch accepted")
	}
	if runtime.GOOS == "windows" {
		return
	}
	dir, file = fresh(t)
	os.Chmod(file, 0o640)
	if _, err := OpenEpochStore(dir, false, t0); err == nil || !strings.Contains(err.Error(), "group or others") {
		t.Errorf("group-readable key file: %v", err)
	}
	dir, _ = fresh(t)
	os.Chmod(dir, 0o750)
	if _, err := OpenEpochStore(dir, false, t0); err == nil {
		t.Error("group-readable directory accepted")
	}
	dir, file = fresh(t)
	elsewhere := filepath.Join(t.TempDir(), "k")
	os.Rename(file, elsewhere)
	os.Symlink(elsewhere, file)
	if _, err := OpenEpochStore(dir, false, t0); err == nil {
		t.Error("symlinked key file accepted")
	}
	dir, _ = fresh(t)
	link := dir + "-link"
	os.Symlink(dir, link)
	if _, err := OpenEpochStore(link, false, t0); err == nil {
		t.Error("symlinked directory accepted")
	}
	// Created files and directory are private.
	dir, file = fresh(t)
	for path, want := range map[string]os.FileMode{dir: 0o700, file: 0o600} {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != want {
			t.Errorf("%s mode %04o, want %04o", path, fi.Mode().Perm(), want)
		}
	}
}

func TestPseudonymKeyNeverPrinted(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "epochs")
	s, err := OpenEpochStore(dir, true, t0)
	if err != nil {
		t.Fatal(err)
	}
	p := s.Current()
	raw := string(p.key)
	b64 := strings.TrimSuffix(strings.SplitAfter(mustRead(t, filepath.Join(dir, p.Epoch()+keyFileSuffix)), "key=")[1], "\n")
	hexKey := fmt.Sprintf("%x", p.key)
	j1, _ := json.Marshal(p)
	j2, _ := json.Marshal(s)
	j3, _ := json.Marshal(struct{ P *Pseudonymizer }{p})
	outs := []string{fmt.Sprint(p), fmt.Sprintf("%v %+v %#v %s", p, p, p, p), fmt.Sprintf("%v %+v %#v", s, s, s), string(j1), string(j2), string(j3), fmt.Sprintf("%v", *p)}
	for _, o := range outs {
		if strings.Contains(o, raw) || strings.Contains(o, b64) || strings.Contains(o, hexKey) {
			t.Errorf("key printed: %s", o)
		}
	}
	if !strings.Contains(string(j1), p.Epoch()) {
		t.Errorf("JSON = %s, want the epoch", j1)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestNewPseudonymizerValidates(t *testing.T) {
	if _, err := NewPseudonymizer("E7Q2M9ZD", t0, make([]byte, 31)); err == nil {
		t.Error("short key accepted")
	}
	if _, err := NewPseudonymizer("e7q2m9zd", t0, make([]byte, KeyLen)); err == nil {
		t.Error("lower-case epoch accepted")
	}
	key := bytes.Repeat([]byte{1}, KeyLen)
	p, _ := NewPseudonymizer("E7Q2M9ZD", t0, key)
	key[0] = 2
	if p.key[0] != 1 {
		t.Error("NewPseudonymizer keeps the caller's slice")
	}
}
