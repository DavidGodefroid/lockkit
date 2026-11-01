//go:build unix

package client

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/sysconf"
)

// separated points the system setup at a file of the separated setup with
// the default socket directory, and returns a project directory.
func separated(t *testing.T) string {
	t.Helper()
	return separatedIn(t, "")
}

// separatedIn is separated with the socket directory socketDir ("" for
// the default).
func separatedIn(t *testing.T, socketDir string) string {
	t.Helper()
	d := t.TempDir()
	path := filepath.Join(d, "system.toml")
	conf := "service_user = \"root\"\n"
	if socketDir != "" {
		conf += "socket_dir = \"" + socketDir + "\"\n"
	}
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	oldPath, oldSkip := sysconf.Path, sysconf.SkipOwnerCheck
	sysconf.Path, sysconf.SkipOwnerCheck = path, true
	t.Cleanup(func() { sysconf.Path, sysconf.SkipOwnerCheck = oldPath, oldSkip })
	cwd := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cwd, ".lockmq"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, ".lockmq", "config.toml"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return cwd
}

// noInstanceEnv clears the instance variables of testProduct.
func noInstanceEnv(t *testing.T) {
	t.Helper()
	t.Setenv("LOCKMQ_INSTANCE", "")
	t.Setenv("LEA_LOCKMQ_INSTANCES", "")
}

func TestSocketPathInstanceNoneIsToday(t *testing.T) {
	cwd := separated(t)
	today, err := SocketPath(testProduct, cwd, "uat")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(testProduct.SharedSocketDir(), config.ProjectKey(testProduct, cwd)+"-uat.sock"); today != want {
		t.Fatalf("SocketPath = %q, want %q", today, want)
	}
	got, err := SocketPathInstance(testProduct, cwd, "uat", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != today {
		t.Fatalf("SocketPathInstance without instance = %q, want %q", got, today)
	}
}

func TestSocketPathInstanceIsASubdirectory(t *testing.T) {
	cwd := separated(t)
	got, err := SocketPathInstance(testProduct, cwd, "uat", "orders")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(testProduct.SharedSocketDir(), "orders", config.ProjectKey(testProduct, cwd)+"-uat.sock"); got != want {
		t.Fatalf("SocketPathInstance = %q, want %q", got, want)
	}
}

func TestSocketPathInstanceNeedsTheSeparatedSetup(t *testing.T) {
	runtimeDir(t)
	if _, err := SocketPathInstance(testProduct, t.TempDir(), "uat", "orders"); err == nil ||
		!strings.Contains(err.Error(), "separated setup") {
		t.Fatalf("err = %v, want the separated setup named", err)
	}
	if _, err := SocketDirInstance(testProduct, "orders"); err == nil || !strings.Contains(err.Error(), "separated setup") {
		t.Fatalf("SocketDirInstance err = %v, want the separated setup named", err)
	}
}

func TestSocketDirInstance(t *testing.T) {
	d := runtimeDir(t)
	if got, err := SocketDirInstance(testProduct, ""); err != nil || got != filepath.Join(d, "lockmq") {
		t.Fatalf("same-user SocketDirInstance = %q, %v, want %q", got, err, filepath.Join(d, "lockmq"))
	}
	separated(t)
	if got, err := SocketDirInstance(testProduct, ""); err != nil || got != testProduct.SharedSocketDir() {
		t.Fatalf("SocketDirInstance = %q, %v, want %q", got, err, testProduct.SharedSocketDir())
	}
	want := filepath.Join(testProduct.SharedSocketDir(), "orders")
	if got, err := SocketDirInstance(testProduct, "orders"); err != nil || got != want {
		t.Fatalf("SocketDirInstance(orders) = %q, %v, want %q", got, err, want)
	}
	if _, err := SocketDirInstance(testProduct, "../x"); !errors.Is(err, ErrBadInstance) {
		t.Fatalf("SocketDirInstance(../x) err = %v, want ErrBadInstance", err)
	}
}

func TestSocketPathInstanceRefusesBadName(t *testing.T) {
	cwd := separated(t)
	for _, name := range []string{"../x", "..", "a/b", "/abs", "Orders", "-x", "o rders", strings.Repeat("a", 64)} {
		_, err := SocketPathInstance(testProduct, cwd, "uat", name)
		if !errors.Is(err, ErrBadInstance) {
			t.Errorf("SocketPathInstance(%q) err = %v, want ErrBadInstance", name, err)
		}
		if _, err := DialInstance(testProduct, cwd, "uat", name); !errors.Is(err, ErrBadInstance) {
			t.Errorf("DialInstance(%q) err = %v, want ErrBadInstance", name, err)
		}
	}
}

// A leftover LOCKMQ_INSTANCE or --instance with a single lock in lea (no
// LEA_LOCKMQ_INSTANCES) points at a directory that does not exist: the
// error says so and names the source, never "run lox up".
func TestDialInstanceMissingDirectoryIsNamed(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "lkin")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cwd := separatedIn(t, dir)
	_, err = DialInstance(testProduct, cwd, "uat", "orders")
	if err == nil || errors.Is(err, ErrNoConsole) {
		t.Fatalf("err = %v, want a missing instance directory, not ErrNoConsole", err)
	}
	msg := err.Error()
	for _, want := range []string{"--instance", "LOCKMQ_INSTANCE", "no lockmq lock directory for the instance set by"} {
		if !strings.Contains(msg, want) {
			t.Errorf("err = %q, want %q in it", msg, want)
		}
	}
	if strings.Contains(msg, "orders") {
		t.Errorf("err = %q, must not echo the instance value", msg)
	}
	if strings.Contains(msg, "lox up") {
		t.Errorf("err = %q, must not give the lox up hint", msg)
	}
	// The directory is there, no console listens: the usual NoConsoleError.
	if err := os.Mkdir(filepath.Join(dir, "orders"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := DialInstance(testProduct, cwd, "uat", "orders"); !errors.Is(err, ErrNoConsole) {
		t.Fatalf("err = %v, want ErrNoConsole once the directory exists", err)
	}
}

func TestResolveInstanceNoneListedIsToday(t *testing.T) {
	noInstanceEnv(t)
	got, err := ResolveInstance(testProduct, "")
	if err != nil || got != "" {
		t.Fatalf("ResolveInstance = %q, %v, want \"\", nil", got, err)
	}
}

func TestResolveInstanceSingleListed(t *testing.T) {
	noInstanceEnv(t)
	t.Setenv("LEA_LOCKMQ_INSTANCES", "orders")
	got, err := ResolveInstance(testProduct, "")
	if err != nil || got != "orders" {
		t.Fatalf("ResolveInstance = %q, %v, want orders", got, err)
	}
}

func TestResolveInstanceSeveralNoneChosen(t *testing.T) {
	noInstanceEnv(t)
	t.Setenv("LEA_LOCKMQ_INSTANCES", "audit events")
	_, err := ResolveInstance(testProduct, "")
	want := "several lockmq locks: audit events; pass --instance NAME (or set LOCKMQ_INSTANCE)"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
}

func TestResolveInstanceUnknown(t *testing.T) {
	noInstanceEnv(t)
	t.Setenv("LEA_LOCKMQ_INSTANCES", "audit events")
	_, err := ResolveInstance(testProduct, "shop")
	want := "no lockmq lock shop: audit events"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
	t.Setenv("LOCKMQ_INSTANCE", "shop")
	if _, err := ResolveInstance(testProduct, ""); err == nil || err.Error() != want {
		t.Fatalf("env: err = %v, want %q", err, want)
	}
}

func TestResolveInstanceBadName(t *testing.T) {
	for _, c := range []struct{ flag, env, list, key string }{
		{flag: "../x", key: "--instance"},
		{env: "../x", key: "LOCKMQ_INSTANCE"},
		{list: "orders ../x", key: "LEA_LOCKMQ_INSTANCES"},
		{flag: "../x", list: "orders stock", key: "--instance"},
	} {
		noInstanceEnv(t)
		t.Setenv("LOCKMQ_INSTANCE", c.env)
		t.Setenv("LEA_LOCKMQ_INSTANCES", c.list)
		_, err := ResolveInstance(testProduct, c.flag)
		if !errors.Is(err, ErrBadInstance) {
			t.Fatalf("%+v: err = %v, want ErrBadInstance", c, err)
		}
		if !strings.Contains(err.Error(), c.key) || strings.Contains(err.Error(), "../x") {
			t.Errorf("%+v: err = %q, want %s named and the value not echoed", c, err, c.key)
		}
	}
}

func TestResolveInstancePrecedence(t *testing.T) {
	noInstanceEnv(t)
	t.Setenv("LEA_LOCKMQ_INSTANCES", "audit events")
	t.Setenv("LOCKMQ_INSTANCE", "events")
	if got, err := ResolveInstance(testProduct, "audit"); err != nil || got != "audit" {
		t.Fatalf("flag over env: %q, %v, want audit", got, err)
	}
	if got, err := ResolveInstance(testProduct, ""); err != nil || got != "events" {
		t.Fatalf("env over the list: %q, %v, want events", got, err)
	}
	t.Setenv("LEA_LOCKMQ_INSTANCES", "audit")
	if got, err := ResolveInstance(testProduct, "events"); err == nil {
		t.Fatalf("flag not in a one-name list: %q, nil, want an error", got)
	}
	t.Setenv("LOCKMQ_INSTANCE", "")
	t.Setenv("LEA_LOCKMQ_INSTANCES", "")
	if got, err := ResolveInstance(testProduct, "audit"); err != nil || got != "audit" {
		t.Fatalf("flag without a list: %q, %v, want audit", got, err)
	}
}
