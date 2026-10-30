//go:build unix

package plans

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestHelperHoldStore is not a test: run by TestLockReleasedWhenHolderKilled
// as another process, it opens the store, says so, and waits to be killed.
func TestHelperHoldStore(t *testing.T) {
	dir := os.Getenv("PLANS_HOLD_DIR")
	if dir == "" {
		t.Skip("helper process")
	}
	if _, err := Open(dir); err != nil {
		os.Stdout.WriteString("error: " + err.Error() + "\n")
		os.Exit(1)
	}
	os.Stdout.WriteString("holding\n")
	time.Sleep(time.Minute)
	os.Exit(2)
}

// The directory lock dies with its holder: a console killed with SIGKILL
// (no Close) does not lock its plans away from the next one.
func TestLockReleasedWhenHolderKilled(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "plans")
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHoldStore$")
	cmd.Env = append(os.Environ(), "PLANS_HOLD_DIR="+dir)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line := make(chan string, 1)
	go func() {
		s := bufio.NewScanner(out)
		for s.Scan() {
			if l := s.Text(); l == "holding" || strings.HasPrefix(l, "error:") {
				line <- l
				return
			}
		}
		line <- "helper ended"
	}()
	select {
	case l := <-line:
		if l != "holding" {
			t.Fatalf("helper: %s", l)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the helper never opened the store")
	}
	// Held by the other process: refused.
	if _, err := Open(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("Open while held: %v, want ErrLocked", err)
	}
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open after the holder was killed: %v", err)
	}
	s.Close()
}
