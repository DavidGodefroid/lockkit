package pii

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

// mustID is p.ID for a live epoch.
func mustID(t testing.TB, p *Pseudonymizer, kind, value string) string {
	t.Helper()
	id, err := p.ID(kind, value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

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
	got := mustID(t, p, "email", "Jean.Dupont@Example.com")
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
const goldenEmailID = "MMEHXXJMBQJ0"

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
		kind, want := group[0], mustID(t, p, group[0], group[1])
		for _, v := range group[2:] {
			if got := mustID(t, p, kind, v); got != want {
				t.Errorf("ID(%s, %q) = %s, want %s (as %q): Normalise %q vs %q", kind, v, got, want, group[1], Normalise(kind, v), Normalise(kind, group[1]))
			}
		}
		if again := mustID(t, p, kind, group[1]); again != want {
			t.Errorf("ID not stable: %s then %s", want, again)
		}
	}
	// Different values, different kinds: different IDs.
	ids := map[string]string{}
	for _, kv := range [][2]string{{"email", "a@example.com"}, {"email", "b@example.com"}, {"phone", "+32475123456"}, {"phone", "+32475123457"}, {"card", "4111111111111111"}, {"be_niss", "4111111111111111"}, {"ip", "192.0.2.1"}, {"ip", "192.0.2.2"}} {
		id := mustID(t, p, kv[0], kv[1])
		if prev, dup := ids[id]; dup {
			t.Errorf("ID collision: %v and %s", kv, prev)
		}
		ids[id] = fmt.Sprint(kv)
	}
	// A reopened store gives the same IDs.
	before := mustID(t, p, "email", "jean.dupont@example.com")
	s.Close()
	s2, err := OpenEpochStore(dir, false, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if s2.Current().Epoch() != p.Epoch() || mustID(t, s2.Current(), "email", "jean.dupont@example.com") != before {
		t.Error("a reopened store gives other pseudonyms")
	}
	// Another epoch, other IDs.
	q, _ := NewEpoch(t0)
	if mustID(t, q, "email", "jean.dupont@example.com") == before || q.Epoch() == p.Epoch() {
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
	oldID := mustID(t, old, "email", "a@example.com")
	if s.RotationDue(t0.Add(6*24*time.Hour), 7*24*time.Hour) || !s.RotationDue(t0.Add(7*24*time.Hour), 7*24*time.Hour) {
		t.Error("RotationDue wrong around 7 days")
	}
	rotated := t0.Add(7 * 24 * time.Hour)
	cur, err := s.Rotate(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if s.Current() != cur || cur.Epoch() == old.Epoch() || mustID(t, cur, "email", "a@example.com") == oldID {
		t.Fatal("rotation kept the epoch or the pseudonyms")
	}
	// The previous epoch is still readable, here and after a reopen.
	if g, err := s.Get(old.Epoch()); err != nil || mustID(t, g, "email", "a@example.com") != oldID {
		t.Errorf("Get(previous) = %v, %v", g, err)
	}
	s.Close()
	s2, err := OpenEpochStore(dir, false, rotated)
	if err != nil || s2.Current().Epoch() != cur.Epoch() || len(s2.Epochs()) != 2 {
		t.Fatalf("reopen after rotation: %v, %v", s2, err)
	}
	old, _ = s2.Get(old.Epoch()) // the handle this store will forget
	// Not yet 24 h: nothing pruned.
	if gone, err := s2.Prune(rotated.Add(23*time.Hour), 24*time.Hour); err != nil || len(gone) != 0 {
		t.Errorf("Prune before 24 h = %v, %v", gone, err)
	}
	gone, err := s2.Prune(rotated.Add(24*time.Hour), 24*time.Hour)
	if err != nil || len(gone) != 1 || gone[0] != old.Epoch() {
		t.Fatalf("Prune = %v, %v", gone, err)
	}
	if _, err := s2.Get(old.Epoch()); !errors.Is(err, ErrUnknownEpoch) {
		t.Errorf("Get(pruned) = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, old.Epoch()+keyFileSuffix)); !os.IsNotExist(err) {
		t.Errorf("pruned key file still there: %v", err)
	}
	// The pruned epoch is forgotten: no ID with a cleared key.
	if id, err := old.ID("email", "a@example.com"); !errors.Is(err, ErrForgottenEpoch) || id != "" || !old.Forgotten() || old.key.b != nil {
		t.Errorf("ID after prune = %q, %v (want ErrForgottenEpoch)", id, err)
	}
	// The current epoch is never pruned.
	if gone, _ := s2.Prune(rotated.Add(1000*24*time.Hour), time.Nanosecond); len(gone) != 0 || s2.Current().Epoch() != cur.Epoch() {
		t.Errorf("Prune deleted the current epoch: %v", gone)
	}
	s2.Close()
	s3, err := OpenEpochStore(dir, false, rotated.Add(25*time.Hour))
	if s3 != nil {
		defer s3.Close()
	}
	if err != nil || len(s3.Epochs()) != 1 {
		t.Errorf("reopen after prune: %v, %v", s3, err)
	}
	// Rotations in the same second keep their order.
	a, _ := s3.Rotate(rotated)
	b, _ := s3.Rotate(rotated)
	if s3.Current() != b || b.seq != a.seq+1 {
		t.Error("same-second rotations out of order")
	}
	s3.Close()
	s4, _ := OpenEpochStore(dir, false, rotated)
	defer s4.Close()
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
		s.Close()
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
	raw := string(p.key.b)
	b64 := strings.TrimSuffix(strings.SplitAfter(mustRead(t, filepath.Join(dir, p.Epoch()+keyFileSuffix)), "key=")[1], "\n")
	hexKey := fmt.Sprintf("%x", p.key.b)
	decimal := strings.Trim(fmt.Sprint(p.key.b), "[]")
	held := struct{ P Pseudonymizer }{*p} // a value copy, as a careless caller would hold it
	j1, _ := json.Marshal(p)
	j2, _ := json.Marshal(s)
	j3, _ := json.Marshal(struct{ P *Pseudonymizer }{p})
	outs := []string{fmt.Sprint(p), fmt.Sprintf("%v %+v %#v %s", p, p, p, p), fmt.Sprintf("%v %+v %#v", s, s, s), string(j1), string(j2), string(j3)}
	outs = append(outs, fmt.Sprintf("%v %+v %#v", held, held, held), fmt.Sprint(*p))
	for _, o := range outs {
		if strings.Contains(o, raw) || strings.Contains(o, b64) || strings.Contains(o, hexKey) || strings.Contains(o, decimal) {
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
	if p.key.b[0] != 1 {
		t.Error("NewPseudonymizer keeps the caller's slice")
	}
}

// ID and forget race: every ID is either the live one or refused, never an
// ID computed with a cleared key (run with -race).
func TestPseudonymForgetConcurrent(t *testing.T) {
	for range 20 {
		p := fixedPseudonymizer(t)
		want := mustID(t, p, "email", "a@example.com")
		var wg sync.WaitGroup
		errs := make(chan string, 400)
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 100 {
					id, err := p.ID("email", "a@example.com")
					if err == nil && id != want || err != nil && (id != "" || !errors.Is(err, ErrForgottenEpoch)) {
						errs <- id
					}
				}
			}()
		}
		p.forget()
		wg.Wait()
		close(errs)
		for id := range errs {
			t.Fatalf("ID during forget = %q", id)
		}
		if _, err := p.ID("email", "a@example.com"); !errors.Is(err, ErrForgottenEpoch) {
			t.Fatalf("ID after forget: %v", err)
		}
	}
}

// A copy of a Pseudonymizer taken before Prune is forgotten with it: no
// ID from a cleared key, through any copy.
func TestPseudonymCopyForgotten(t *testing.T) {
	p := fixedPseudonymizer(t)
	cp := *p
	p.forget()
	if _, err := cp.ID("email", "a@example.com"); !errors.Is(err, ErrForgottenEpoch) {
		t.Errorf("copy ID after forget: %v", err)
	}
	var zero Pseudonymizer
	if _, err := zero.ID("email", "a@example.com"); !errors.Is(err, ErrForgottenEpoch) {
		t.Errorf("zero Pseudonymizer ID: %v", err)
	}
}

func TestPseudonymZeroKeyRefused(t *testing.T) {
	if _, err := NewPseudonymizer("E7Q2M9ZD", t0, make([]byte, KeyLen)); err == nil {
		t.Error("all-zero key accepted")
	}
	dir := filepath.Join(t.TempDir(), "epochs")
	s, _ := OpenEpochStore(dir, true, t0)
	file := filepath.Join(dir, s.Current().Epoch()+keyFileSuffix)
	s.Close()
	b, _ := os.ReadFile(file)
	k := strings.Index(string(b), "key=")
	os.WriteFile(file, []byte(string(b[:k])+"key="+strings.Repeat("A", 43)+"=\n"), 0o600)
	if _, err := OpenEpochStore(dir, false, t0); err == nil {
		t.Error("a key file with an all-zero key accepted")
	}
}

// Kinds are 1 to 32 of [a-z0-9_]: a NUL cannot shift bytes between kind
// and value.
func TestPseudonymKindValidated(t *testing.T) {
	p := fixedPseudonymizer(t)
	for _, k := range []string{"", "x\x00y", "Email", "e-mail", strings.Repeat("a", 33), "⟦x⟧"} {
		if _, err := p.ID(k, "z"); !errors.Is(err, ErrInvalidKind) {
			t.Errorf("ID(%q) = %v, want ErrInvalidKind", k, err)
		}
	}
	if _, err := p.ID("person_name", "x"); err != nil {
		t.Error(err)
	}
}

// A clock that was ahead neither keeps an epoch alive nor keeps an old
// key past its time.
func TestEpochClockAhead(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "epochs")
	future := t0.Add(365 * 24 * time.Hour)
	s, err := OpenEpochStore(dir, true, future)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	old := s.Current()
	if !s.RotationDue(t0, 7*24*time.Hour) {
		t.Error("an epoch created in the future is not due for rotation")
	}
	cur, _ := s.Rotate(t0)
	if s.Current() != cur || !cur.Created().Equal(t0) {
		t.Errorf("rotation chained off the future: %v", cur.Created())
	}
	if gone, _ := s.Prune(t0.Add(25*time.Hour), 24*time.Hour); len(gone) != 1 || gone[0] != old.Epoch() {
		t.Errorf("Prune = %v, want the future epoch deleted", gone)
	}
	s.Close()
	s2, err := OpenEpochStore(dir, false, t0)
	if err != nil || s2.Current().Epoch() != cur.Epoch() {
		t.Errorf("reopen: %v", err)
	}
	s2.Close()
}

// Leftover temporary files (a crash before a rename) are removed; a
// second store on the same directory is refused while the first is open.
func TestEpochStoreTempFilesAndLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "epochs")
	s, _ := OpenEpochStore(dir, true, t0)
	tmp := filepath.Join(dir, ".tmp-ABCDEFGH.key-123")
	os.WriteFile(tmp, []byte("key material"), 0o600)
	if runtime.GOOS != "windows" {
		if _, err := OpenEpochStore(dir, false, t0); err == nil {
			t.Error("a second store on a locked directory opened")
		}
	}
	s.Prune(t0, time.Hour)
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error("Prune left a temporary key file")
	}
	os.WriteFile(tmp, []byte("key material"), 0o600)
	s.Close()
	s2, err := OpenEpochStore(dir, false, t0)
	if err != nil {
		t.Fatal(err)
	}
	s2.Close()
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error("open left a temporary key file")
	}
}

func TestNormalisePhoneTrunk(t *testing.T) {
	for in, want := range map[string]string{"+32 (0)475 12 34 56": "+32475123456", "+0032475123456": "+32475123456", "0032 (0)475 12 34 56": "+32475123456", "0032 475 12 34 56": "+32475123456"} {
		if got := Normalise("phone", in); got != want {
			t.Errorf("Normalise(phone, %q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("a", DetectLimit) + "x"
	if Normalise("person_name", long) == Normalise("person_name", strings.Repeat("a", DetectLimit)+"y") {
		t.Error("long values sharing a prefix normalise alike")
	}
}

// A closed store no longer writes: two handles on one directory cannot
// both rotate.
func TestEpochStoreClosedRefusesWrites(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "epochs")
	s, _ := OpenEpochStore(dir, true, t0)
	cur := s.Current()
	s.Close()
	if _, err := s.Rotate(t0); !errors.Is(err, ErrClosed) {
		t.Errorf("Rotate after Close: %v", err)
	}
	if _, err := s.Prune(t0, time.Hour); !errors.Is(err, ErrClosed) {
		t.Errorf("Prune after Close: %v", err)
	}
	if _, err := cur.ID("email", "a@example.com"); !errors.Is(err, ErrForgottenEpoch) {
		t.Errorf("ID after Close = %v, want ErrForgottenEpoch (another process may prune the key)", err)
	}
	if _, err := s.Get("ZZZZZZZZ"); !errors.Is(err, ErrUnknownEpoch) {
		t.Errorf("Get(never existed) = %v", err)
	}
	var nilP *Pseudonymizer
	_ = fmt.Sprint(nilP)
}

// A store dropped without Close keeps its lock while a handle on one of
// its epochs lives: another open cannot prune the key from under it.
func TestEpochStoreLockOutlivesDroppedStore(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no directory lock on Windows")
	}
	dir := filepath.Join(t.TempDir(), "epochs")
	open := func() *Pseudonymizer {
		s, err := OpenEpochStore(dir, true, t0)
		if err != nil {
			t.Fatal(err)
		}
		return s.Current() // the store itself is dropped
	}
	p := open()
	for range 3 {
		runtime.GC()
	}
	if s2, err := OpenEpochStore(dir, false, t0); err == nil {
		s2.Close()
		t.Fatal("a second store opened while a handle of the first lives")
	}
	if _, err := p.ID("email", "a@example.com"); err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(p)
}

func TestNormaliseNamesAndIBANIdempotent(t *testing.T) {
	if a, b := Normalise("person_name", "Jean  Dupont"), Normalise("person_name", "jean dupont"); a != b {
		t.Errorf("person_name spellings split: %q vs %q", a, b)
	}
	for _, in := range []string{"BE68 5390 0754 7034", "be68-5390-0754-7034", "ϐE68539007547034", "ＢＥ68 5390 0754 7034"} {
		n := Normalise("iban", in)
		if Normalise("iban", n) != n {
			t.Errorf("Normalise(iban) not idempotent on %q: %q", in, n)
		}
	}
}

func TestEpochSequenceExhausted(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "epochs")
	s, err := OpenEpochStore(dir, true, t0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.epochs[len(s.epochs)-1].seq = math.MaxUint64
	if _, err := s.Rotate(t0.Add(time.Hour)); err == nil {
		t.Fatal("Rotate wrapped the sequence number")
	}
	if len(s.Epochs()) != 1 {
		t.Error("a refused rotation left an epoch behind")
	}
}

// A Rotate that fails after its key file was renamed into place leaves
// that file behind: a retry must not reuse its sequence number.
func TestEpochRotateFailedSyncKeepsStoreOpenable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "epochs")
	s, err := OpenEpochStore(dir, true, t0)
	if err != nil {
		t.Fatal(err)
	}
	syncDirHook = func(string) error { return errors.New("injected sync failure") }
	_, err = s.Rotate(t0.Add(time.Hour))
	syncDirHook = syncDir
	if err == nil {
		t.Fatal("Rotate ignored the sync failure")
	}
	cur, err := s.Rotate(t0.Add(2 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, err := OpenEpochStore(dir, false, t0.Add(3*time.Hour))
	if err != nil {
		t.Fatalf("store no longer opens: %v", err)
	}
	defer s2.Close()
	if s2.Current().Epoch() != cur.Epoch() {
		t.Error("the retried rotation is not current after reopening")
	}
}
