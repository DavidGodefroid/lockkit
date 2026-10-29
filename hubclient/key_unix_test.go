//go:build unix

package hubclient_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
)

// A hub key "file" that is a FIFO or a directory is refused at once: a
// FIFO nobody writes must not block the console's start-up.
func TestReadHubKeyNotRegular(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "hub.pub")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan error, 1)
	go func() { _, err := hubclient.ReadHubKey(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO was read as the hub key")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadHubKey blocked on a FIFO")
	}
	if _, err := hubclient.ReadHubKey(dir); err == nil {
		t.Fatal("a directory was read as the hub key")
	}
	big := filepath.Join(dir, "big.pub")
	if err := os.WriteFile(big, make([]byte, 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := hubclient.ReadHubKey(big); err == nil {
		t.Fatal("a 1 MiB file was read as the hub key")
	}
}

// An instance key that is a FIFO is refused, never read (nor replaced).
func TestInstanceKeyNotRegular(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "hub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(home, "hub", "crm-test.key"), 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan error, 1)
	go func() { _, err := hubclient.InstanceKey(home, "crm-test"); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO was used as the instance key")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("InstanceKey blocked on a FIFO")
	}
}
