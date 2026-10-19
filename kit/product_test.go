package kit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var sql = Product{Name: "locksql", Account: "locksql", ClientsGroup: "locksql-clients",
	KeychainService: "locksql", EnvPrefix: "LOCKSQL_", Version: "0.8.0"}

var mq = Product{Name: "lockmq", Account: "lockmq", ClientsGroup: "lockmq-clients",
	KeychainService: "lockmq", EnvPrefix: "LOCKMQ_", Version: "0.1.0"}

// The paths locksql computed before lockkit existed (its config and ipc
// tests): a product named locksql keeps every one of them.
func TestProductPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "cfg"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(home, "run"))
	t.Setenv("TMPDIR", filepath.Join(home, "tmp"))
	t.Setenv("LOCKSQL_RUNTIME_DIR", "")
	t.Setenv("LOCKMQ_RUNTIME_DIR", "")

	if got := sql.ProjectDir(); got != ".locksql" {
		t.Errorf("ProjectDir = %q", got)
	}
	ucd, _ := os.UserConfigDir()
	if got, err := sql.UserConfigDir(); err != nil || got != filepath.Join(ucd, "locksql") {
		t.Errorf("UserConfigDir = %q, %v", got, err)
	}
	wantState := filepath.Join(home, "state", "locksql")
	if runtime.GOOS == "darwin" {
		wantState = filepath.Join(ucd, "locksql")
	}
	if got, err := sql.StateDir(); err != nil || got != wantState {
		t.Errorf("StateDir = %q, %v; want %q", got, err, wantState)
	}
	wantRun := filepath.Join(home, "run", "locksql")
	if runtime.GOOS == "darwin" {
		wantRun = filepath.Join(home, "tmp", "locksql")
	}
	if got, err := sql.RuntimeDir(); err != nil || got != wantRun {
		t.Errorf("RuntimeDir = %q, %v; want %q", got, err, wantRun)
	}
	t.Setenv("LOCKSQL_RUNTIME_DIR", filepath.Join(home, "override"))
	if got, _ := sql.RuntimeDir(); got != filepath.Join(home, "override", "locksql") {
		t.Errorf("RuntimeDir with LOCKSQL_RUNTIME_DIR = %q", got)
	}
	if got := sql.SystemConfigPath(); got != "/etc/locksql/system.toml" {
		t.Errorf("SystemConfigPath = %q", got)
	}
	wantShared := "/run/locksql"
	if runtime.GOOS == "darwin" {
		wantShared = "/usr/local/var/run/locksql"
	}
	if got := sql.SharedSocketDir(); got != wantShared {
		t.Errorf("SharedSocketDir = %q", got)
	}
}

// Another product never reaches locksql's directories, socket or
// environment.
func TestProductPathsDoNotLeak(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("TMPDIR", "")
	t.Setenv("LOCKSQL_RUNTIME_DIR", filepath.Join(home, "sql"))
	t.Setenv("LOCKMQ_RUNTIME_DIR", "")
	paths := []string{mq.ProjectDir(), mq.SystemConfigPath(), mq.SharedSocketDir(), mq.Account, mq.ClientsGroup, mq.KeychainService, mq.EnvPrefix}
	for _, f := range []func() (string, error){mq.UserConfigDir, mq.StateDir, mq.RuntimeDir} {
		p, err := f()
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	for _, p := range paths {
		if strings.Contains(strings.ToLower(p), "locksql") {
			t.Errorf("lockmq path %q names locksql", p)
		}
	}
}

func TestProductValidate(t *testing.T) {
	if err := sql.Validate(); err != nil {
		t.Errorf("locksql: %v", err)
	}
	for name, p := range map[string]Product{
		"empty name": {},
		"bad name":   {Name: "Lock SQL", Account: "a", ClientsGroup: "g", KeychainService: "k", EnvPrefix: "A_"},
		"no account": {Name: "x", ClientsGroup: "g", KeychainService: "k", EnvPrefix: "X_"},
		"bad prefix": {Name: "x", Account: "a", ClientsGroup: "g", KeychainService: "k", EnvPrefix: "x"},
	} {
		if p.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
