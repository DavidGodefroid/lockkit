package pii

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Errors of the epoch store.
var (
	// ErrNoEpoch: the store holds no epoch and was not asked to create one.
	ErrNoEpoch = errors.New("pii: no pseudonym epoch key")
	// ErrClosed: Rotate or Prune on a closed store (it no longer holds the
	// directory's lock).
	ErrClosed = errors.New("pii: epoch store closed")
	// ErrUnknownEpoch: the epoch was never kept here, or was pruned.
	ErrUnknownEpoch = errors.New("pii: unknown or deleted pseudonym epoch")
)

// keyFileSuffix ends an epoch key file: "<epoch>.key".
const keyFileSuffix = ".key"

// keyFileMagic starts an epoch key file.
const keyFileMagic = "lockkit pseudonym epoch v1\n"

// EpochStore keeps pseudonym epochs in a directory of their own: one file
// per epoch ("<epoch>.key", 0600, written once, atomically), the directory
// 0700, both owned by the process's user. The current epoch is the newest;
// an epoch is replaced when a newer one is created, and its key is deleted
// by Prune once it has been replaced for long enough (references minted
// under it can be re-read until then). A corrupt or exposed key file
// refuses the store: nothing is repaired silently. Epochs are ordered by
// a sequence number, not by the clock. The store locks its directory
// (one process at a time; Close releases it) and is safe for concurrent
// use within that process.
type EpochStore struct {
	dir  string
	lock io.Closer // the directory's lock, held until Close

	mu     sync.Mutex
	closed bool
	epochs []*Pseudonymizer // oldest first; the last is current
	// lastSeq is the highest sequence number used or attempted: a Rotate
	// that failed after its file was renamed into place must not hand
	// that number out again (the store would no longer open).
	lastSeq uint64
}

// OpenEpochStore opens the epochs kept in dir. When dir holds none, it
// creates the directory (0700) and a first epoch if create is set, and
// fails with ErrNoEpoch otherwise.
func OpenEpochStore(dir string, create bool, now time.Time) (*EpochStore, error) {
	s := &EpochStore{dir: dir}
	if create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("pii: epoch store: %w", err)
		}
	}
	if err := checkPrivate(dir, true); err != nil {
		return nil, err
	}
	lock, err := lockDir(dir)
	if err != nil {
		return nil, err
	}
	s.lock = lock
	ok := false
	defer func() {
		if !ok {
			lock.Close()
		}
	}()
	names, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("pii: epoch store: %w", err)
	}
	for _, e := range names {
		name := e.Name()
		if strings.HasPrefix(name, ".tmp-") {
			// A write that crashed before its rename: it may hold a key.
			os.Remove(filepath.Join(dir, name))
			continue
		}
		epoch, isKey := strings.CutSuffix(name, keyFileSuffix)
		if !isKey || !validEpochID(epoch) {
			continue // a foreign file
		}
		p, err := readKeyFile(filepath.Join(dir, name), epoch)
		if err != nil {
			return nil, err
		}
		p.store = s
		s.epochs = append(s.epochs, p)
	}
	sort.Slice(s.epochs, func(i, j int) bool { return s.epochs[i].seq < s.epochs[j].seq })
	for i := 1; i < len(s.epochs); i++ {
		if s.epochs[i].seq == s.epochs[i-1].seq {
			return nil, fmt.Errorf("pii: epochs %s and %s have the same sequence number", s.epochs[i-1].epoch, s.epochs[i].epoch)
		}
	}
	if len(s.epochs) == 0 {
		if !create {
			return nil, ErrNoEpoch
		}
		if _, err := s.Rotate(now); err != nil {
			return nil, err
		}
	}
	ok = true
	return s, nil
}

func readKeyFile(path, epoch string) (*Pseudonymizer, error) {
	if err := checkPrivate(path, false); err != nil {
		return nil, err
	}
	b, err := readNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("pii: epoch %s: %w", epoch, err)
	}
	defer clear(b)
	bad := fmt.Errorf("pii: epoch key file %s is corrupt", filepath.Base(path))
	rest, ok := bytes.CutPrefix(b, []byte(keyFileMagic))
	if !ok {
		return nil, bad
	}
	var gotEpoch, created, seq, key []byte
	for _, line := range bytes.Split(bytes.TrimSuffix(rest, []byte("\n")), []byte("\n")) {
		k, v, ok := bytes.Cut(line, []byte("="))
		switch {
		case !ok:
			return nil, bad
		case string(k) == "epoch" && gotEpoch == nil:
			gotEpoch = v
		case string(k) == "created" && created == nil:
			created = v
		case string(k) == "seq" && seq == nil:
			seq = v
		case string(k) == "key" && key == nil:
			key = v
		default:
			return nil, bad
		}
	}
	if string(gotEpoch) != epoch {
		return nil, bad
	}
	t, err := time.Parse(time.RFC3339, string(created))
	if err != nil {
		return nil, bad
	}
	n64, err := strconv.ParseUint(string(seq), 10, 64)
	if err != nil || n64 == 0 {
		return nil, bad
	}
	raw := make([]byte, base64.StdEncoding.DecodedLen(len(key)))
	n, err := base64.StdEncoding.Strict().Decode(raw, key)
	defer clear(raw)
	if err != nil || n != KeyLen {
		return nil, bad
	}
	p, err := NewPseudonymizer(epoch, t, raw[:n])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", bad, err)
	}
	p.seq = n64
	return p, nil
}

func (s *EpochStore) writeKeyFile(p *Pseudonymizer) error {
	var b bytes.Buffer
	b.WriteString(keyFileMagic)
	key := p.keyBytes()
	defer clear(key)
	fmt.Fprintf(&b, "epoch=%s\ncreated=%s\nseq=%d\nkey=%s\n", p.epoch, p.created.Format(time.RFC3339), p.seq, base64.StdEncoding.EncodeToString(key))
	defer func() { clear(b.Bytes()) }()
	return writeFileAtomic(s.dir, p.epoch+keyFileSuffix, b.Bytes())
}

// Current returns the current epoch.
func (s *EpochStore) Current() *Pseudonymizer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epochs[len(s.epochs)-1]
}

// Get returns a kept epoch, current or replaced but not yet pruned.
func (s *EpochStore) Get(epoch string) (*Pseudonymizer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.epochs {
		if p.epoch == epoch {
			return p, nil
		}
	}
	return nil, ErrUnknownEpoch
}

// Epochs returns the ids of the kept epochs, oldest first.
func (s *EpochStore) Epochs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.epochs))
	for i, p := range s.epochs {
		out[i] = p.epoch
	}
	return out
}

// Rotate creates a new epoch, which becomes current. The previous one is
// kept until Prune deletes it.
func (s *EpochStore) Rotate(now time.Time) (*Pseudonymizer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	var p *Pseudonymizer
	for {
		var err error
		if p, err = NewEpoch(now); err != nil {
			return nil, err
		}
		if !s.has(p.epoch) {
			break
		}
	}
	last := s.lastSeq
	if n := len(s.epochs); n > 0 && s.epochs[n-1].seq > last {
		last = s.epochs[n-1].seq
	}
	if last == math.MaxUint64 {
		p.forget()
		return nil, errors.New("pii: epoch sequence exhausted")
	}
	p.seq = last + 1
	s.lastSeq = p.seq
	if err := s.writeKeyFile(p); err != nil {
		p.forget()
		return nil, err
	}
	p.store = s
	s.epochs = append(s.epochs, p)
	return p, nil
}

func (s *EpochStore) has(epoch string) bool {
	for _, q := range s.epochs {
		if q.epoch == epoch {
			return true
		}
	}
	return false
}

// ClockSkew is how far in the future an epoch's creation time may be
// before the store treats it as wrong (a clock that was ahead).
const ClockSkew = time.Hour

// RotationDue reports whether the current epoch began at least every ago,
// or claims to begin more than ClockSkew in the future (a clock that was
// ahead must not keep an epoch alive).
func (s *EpochStore) RotationDue(now time.Time, every time.Duration) bool {
	c := s.Current().created
	return now.Sub(c) >= every || c.After(now.Add(ClockSkew))
}

// Prune deletes the keys of the epochs replaced at least keep ago (an
// epoch is replaced when the next one is created) and returns their ids.
// The current epoch is never deleted.
func (s *EpochStore) Prune(now time.Time, keep time.Duration) ([]string, error) {
	if keep <= 0 {
		return nil, errors.New("pii: Prune needs a positive keep")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	var gone []string
	kept := s.epochs[:0]
	for i, p := range s.epochs {
		if i < len(s.epochs)-1 && replacedLongAgo(now, s.epochs[i+1].created, keep) {
			if err := os.Remove(filepath.Join(s.dir, p.epoch+keyFileSuffix)); err != nil && !errors.Is(err, os.ErrNotExist) {
				s.epochs = append(kept, s.epochs[i:]...)
				return gone, fmt.Errorf("pii: delete epoch %s: %w", p.epoch, err)
			}
			p.forget()
			gone = append(gone, p.epoch)
			continue
		}
		kept = append(kept, p)
	}
	s.epochs = kept
	if names, err := os.ReadDir(s.dir); err == nil {
		for _, e := range names {
			if strings.HasPrefix(e.Name(), ".tmp-") {
				os.Remove(filepath.Join(s.dir, e.Name()))
			}
		}
	}
	if len(gone) > 0 {
		_ = syncDir(s.dir) // the deletion is done; a lost sync only delays it
	}
	return gone, nil
}

// replacedLongAgo reports whether an epoch replaced at replaced (its
// successor's creation) was replaced keep ago, a time in the future
// (a clock that was ahead) counting as long ago.
func replacedLongAgo(now, replaced time.Time, keep time.Duration) bool {
	return now.Sub(replaced) >= keep || replaced.After(now.Add(ClockSkew))
}

// Close releases the directory's lock and forgets every epoch's key in
// memory (another process may now prune them): ID then fails with
// ErrForgottenEpoch, Rotate and Prune with ErrClosed.
func (s *EpochStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	// Another process may now prune these keys: never mint under them.
	for _, p := range s.epochs {
		p.forget()
	}
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}

// String shows the directory and the epochs, never a key.
func (s *EpochStore) String() string {
	return fmt.Sprintf("pii.EpochStore{dir: %s, epochs: %v}", s.dir, s.Epochs())
}

// GoString shows the directory and the epochs, never a key.
func (s *EpochStore) GoString() string { return s.String() }

// MarshalJSON writes the epochs, never a key.
func (s *EpochStore) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Epochs []string `json:"epochs"`
	}{s.Epochs()})
}

// writeFileAtomic writes name in dir through a temporary file, fsynced,
// renamed over it, and the directory fsynced: name holds the old content
// or the new, never a part.
func writeFileAtomic(dir, name string, data []byte) error {
	f, err := os.CreateTemp(dir, ".tmp-"+name+"-*")
	if err != nil {
		return fmt.Errorf("pii: epoch store: %w", err)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("pii: epoch store: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("pii: epoch store: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("pii: epoch store: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("pii: epoch store: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("pii: epoch store: %w", err)
	}
	ok = true
	return syncDirHook(dir)
}

// syncDirHook is syncDir, replaced in tests to fail after a rename.
var syncDirHook = syncDir

// syncDir fsyncs dir: a new key file must survive a crash before any ID
// is minted under it. Only Unix reports the error (others cannot sync a
// directory).
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("pii: epoch store: sync %s: %w", dir, err)
	}
	return nil
}
