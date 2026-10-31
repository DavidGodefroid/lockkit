package pii

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Errors of the epoch store.
var (
	// ErrNoEpoch: the store holds no epoch and was not asked to create one.
	ErrNoEpoch = errors.New("pii: no pseudonym epoch key")
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
// refuses the store: nothing is repaired silently. It is safe for
// concurrent use within one process.
type EpochStore struct {
	dir string

	mu     sync.Mutex
	epochs []*Pseudonymizer // oldest first; the last is current
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
	names, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("pii: epoch store: %w", err)
	}
	for _, e := range names {
		name := e.Name()
		epoch, ok := strings.CutSuffix(name, keyFileSuffix)
		if !ok || !validEpochID(epoch) {
			continue // temporary or foreign file
		}
		p, err := readKeyFile(filepath.Join(dir, name), epoch)
		if err != nil {
			return nil, err
		}
		s.epochs = append(s.epochs, p)
	}
	sort.SliceStable(s.epochs, func(i, j int) bool { return s.epochs[i].created.Before(s.epochs[j].created) })
	if len(s.epochs) == 0 {
		if !create {
			return nil, ErrNoEpoch
		}
		if _, err := s.Rotate(now); err != nil {
			return nil, err
		}
	}
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
	var gotEpoch, created, key []byte
	for _, line := range bytes.Split(bytes.TrimSuffix(rest, []byte("\n")), []byte("\n")) {
		k, v, ok := bytes.Cut(line, []byte("="))
		switch {
		case !ok:
			return nil, bad
		case string(k) == "epoch" && gotEpoch == nil:
			gotEpoch = v
		case string(k) == "created" && created == nil:
			created = v
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
	raw := make([]byte, base64.StdEncoding.DecodedLen(len(key)))
	n, err := base64.StdEncoding.Decode(raw, key)
	defer clear(raw)
	if err != nil || n != KeyLen {
		return nil, bad
	}
	return NewPseudonymizer(epoch, t, raw[:n])
}

func (s *EpochStore) writeKeyFile(p *Pseudonymizer) error {
	var b bytes.Buffer
	b.WriteString(keyFileMagic)
	fmt.Fprintf(&b, "epoch=%s\ncreated=%s\nkey=%s\n", p.epoch, p.created.Format(time.RFC3339), base64.StdEncoding.EncodeToString(p.key)) // p is new: not shared yet
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
	if n := len(s.epochs); n > 0 && !p.created.After(s.epochs[n-1].created) {
		// Keep the order by creation time even when the clock went back or
		// two rotations fall in the same second.
		p.created = s.epochs[n-1].created.Add(time.Second)
	}
	if err := s.writeKeyFile(p); err != nil {
		return nil, err
	}
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

// RotationDue reports whether the current epoch began at least every ago.
func (s *EpochStore) RotationDue(now time.Time, every time.Duration) bool {
	return now.Sub(s.Current().created) >= every
}

// Prune deletes the keys of the epochs replaced at least keep ago (an
// epoch is replaced when the next one is created) and returns their ids.
// The current epoch is never deleted.
func (s *EpochStore) Prune(now time.Time, keep time.Duration) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var gone []string
	kept := s.epochs[:0]
	for i, p := range s.epochs {
		if i < len(s.epochs)-1 && now.Sub(s.epochs[i+1].created) >= keep {
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
	if len(gone) > 0 {
		syncDir(s.dir)
	}
	return gone, nil
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
	syncDir(dir)
	return nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync() // best effort: not supported everywhere
		d.Close()
	}
}
