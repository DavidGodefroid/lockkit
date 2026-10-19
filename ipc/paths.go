// Package ipc is the console's local transport: a Unix domain socket in a
// directory private to the user (on Linux and macOS),
// newline-delimited JSON-RPC 2.0 framing capped at 1 MiB, and a peer check.
package ipc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/DavidGodefroid/lockkit/kit"
)

// maxSocketPath is the longest socket path the OS accepts: sizeof(sun_path)
// minus the terminating NUL (104 on macOS, 108 on Linux).
var maxSocketPath = func() int {
	if runtime.GOOS == "darwin" {
		return 103
	}
	return 107
}()

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

func checkName(what, s string) error {
	if !nameRe.MatchString(s) || strings.Contains(s, "..") {
		return fmt.Errorf("ipc: invalid %s %q", what, s)
	}
	return nil
}

// SocketPath returns the console socket of a project and profile of p:
// <p.RuntimeDir()>/<project-hash>-<profile>.sock (kit.Product.RuntimeDir:
// $<PREFIX>RUNTIME_DIR/<name> when set, else $XDG_RUNTIME_DIR/<name> on
// Linux or $TMPDIR/<name> on macOS, else /tmp/<name>-<uid>). A name that
// would exceed the OS socket path limit is replaced by
// <project-hash>-~<sha256(profile)[:16]>.sock, which is still stable, so
// the client and the console agree on it.
func SocketPath(p kit.Product, projectHash, profile string) (string, error) {
	if err := checkName("project hash", projectHash); err != nil {
		return "", err
	}
	if err := checkName("profile", profile); err != nil {
		return "", err
	}
	dir, err := p.RuntimeDir()
	if err != nil {
		return "", fmt.Errorf("ipc: %w", err)
	}
	return socketIn(dir, projectHash, profile)
}

// SharedSocketPath is SocketPath in the shared socket directory of a
// separated setup.
func SharedSocketPath(dir, projectHash, profile string) (string, error) {
	if err := checkName("project hash", projectHash); err != nil {
		return "", err
	}
	if err := checkName("profile", profile); err != nil {
		return "", err
	}
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("ipc: shared socket dir %q is not absolute", dir)
	}
	return socketIn(dir, projectHash, profile)
}

func socketIn(dir, projectHash, profile string) (string, error) {
	p := filepath.Join(dir, projectHash+"-"+profile+".sock")
	if len(p) <= maxSocketPath {
		return p, nil
	}
	sum := sha256.Sum256([]byte(profile))
	p = filepath.Join(dir, projectHash+"-~"+hex.EncodeToString(sum[:])[:16]+".sock")
	if len(p) > maxSocketPath {
		return "", fmt.Errorf("ipc: socket path %s is longer than %d bytes", p, maxSocketPath)
	}
	return p, nil
}
