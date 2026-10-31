//go:build unix

package pii

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO named like a key file refuses the store, without blocking.
func TestEpochStoreRefusesFIFOKeyFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "epochs")
	s, err := OpenEpochStore(dir, true, t0)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := syscall.Mkfifo(filepath.Join(dir, "ABCDEFGH.key"), 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() {
		s2, err := OpenEpochStore(dir, false, t0)
		if err == nil {
			s2.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a FIFO key file is accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("opening a store with a FIFO key file blocks")
	}
}
