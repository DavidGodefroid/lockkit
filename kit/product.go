// Package kit names a product built on lockkit. Every lockkit package that
// needs a name, an account, a directory or an environment variable takes a
// Product instead of a literal, so two products on one machine never share
// a socket, a config directory or a keychain service.
package kit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
)

// Product is the identity of a product: its names on the machine.
type Product struct {
	// Name is the binary name and the directory name under every config,
	// state and runtime directory ("locksql").
	Name string
	// Tagline is the line under the name in the banner.
	Tagline string
	// Account is the dedicated console account ("locksql").
	Account string
	// ClientsGroup's members may reach the console ("locksql-clients").
	ClientsGroup string
	// KeychainService names every OS keychain item of the product.
	KeychainService string
	// EnvPrefix prefixes the product's environment variables ("LOCKSQL_").
	EnvPrefix string
	// Version is the product's version, without a leading v.
	Version string
}

var (
	nameRe   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	prefixRe = regexp.MustCompile(`^[A-Z][A-Z0-9]*_$`)
)

// Validate reports a product whose names cannot be used safely.
func (p Product) Validate() error {
	if !nameRe.MatchString(p.Name) {
		return fmt.Errorf("kit: invalid product name %q", p.Name)
	}
	if p.Account == "" || p.ClientsGroup == "" || p.KeychainService == "" {
		return fmt.Errorf("kit: product %s: account, clients group and keychain service are required", p.Name)
	}
	if !prefixRe.MatchString(p.EnvPrefix) {
		return fmt.Errorf("kit: product %s: invalid environment prefix %q", p.Name, p.EnvPrefix)
	}
	return nil
}

// Env is the name of the product's environment variable suffix
// ("RUNTIME_DIR" → "LOCKSQL_RUNTIME_DIR").
func (p Product) Env(suffix string) string { return p.EnvPrefix + suffix }

// ProjectDir is the project directory name: "." + Name.
func (p Product) ProjectDir() string { return "." + p.Name }

// UserConfigDir is <user config dir>/Name.
func (p Product) UserConfigDir() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, p.Name), nil
}

// StateBase is the per-user state directory every product's StateDir is
// under: $XDG_STATE_HOME or ~/.local/state on Linux, the user config dir
// on macOS.
func StateBase() (string, error) {
	if runtime.GOOS == "darwin" {
		return os.UserConfigDir()
	}
	if d := os.Getenv("XDG_STATE_HOME"); d != "" && filepath.IsAbs(d) {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if home == "" {
		return "", errors.New("kit: no home directory for the state dir")
	}
	return filepath.Join(home, ".local", "state"), nil
}

// StateDir is StateBase()/Name: approved policies, audit log, caches.
func (p Product) StateDir() (string, error) {
	b, err := StateBase()
	if err != nil {
		return "", err
	}
	return filepath.Join(b, p.Name), nil
}

// RuntimeDirEnv is the variable that overrides the runtime dir on every OS
// when set to an absolute path: the sockets then live in $<prefix>RUNTIME_DIR/Name.
func (p Product) RuntimeDirEnv() string { return p.Env("RUNTIME_DIR") }

// RuntimeDir is the private directory of the user's console sockets:
// $<prefix>RUNTIME_DIR/Name when set, else $XDG_RUNTIME_DIR/Name (Linux) or
// $TMPDIR/Name (macOS), else /tmp/Name-<uid>.
func (p Product) RuntimeDir() (string, error) {
	if d := os.Getenv(p.RuntimeDirEnv()); d != "" && filepath.IsAbs(d) {
		return filepath.Join(d, p.Name), nil
	}
	switch runtime.GOOS {
	case "darwin":
		if d := os.Getenv("TMPDIR"); d != "" && filepath.IsAbs(d) && d != "/tmp" && d != "/tmp/" {
			return filepath.Join(d, p.Name), nil
		}
	default:
		if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" && filepath.IsAbs(d) {
			return filepath.Join(d, p.Name), nil
		}
	}
	// Shared temp dir fallback: the per-user directory itself is the private
	// one, so the listener checks its owner and mode (the sticky /tmp keeps
	// others from renaming it).
	uid := os.Getuid()
	if uid < 0 {
		return "", errors.New("kit: no runtime dir")
	}
	return filepath.Join("/tmp", fmt.Sprintf("%s-%d", p.Name, uid)), nil
}

// SystemConfigPath is the machine-wide setup file: /etc/Name/system.toml.
func (p Product) SystemConfigPath() string { return "/etc/" + p.Name + "/system.toml" }

// SharedSocketDir is the default socket directory of a separated setup.
func (p Product) SharedSocketDir() string {
	if runtime.GOOS == "darwin" {
		return "/usr/local/var/run/" + p.Name
	}
	return "/run/" + p.Name
}

// LauncherHint tells how to get the separated setup of p: the product runs
// in its image, which the launcher on the host sets up; the image refuses
// the former host install.
func (p Product) LauncherHint() string {
	return "run " + p.Name + " through the launcher, which runs it in its image (scripts/install.sh, docs/docker.md)"
}
