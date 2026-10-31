//go:build unix

package ipc

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/kit"
)

// A product's sockets never sit in another product's directory, nor follow
// its environment.
func TestSocketPathIsPerProduct(t *testing.T) {
	base := shortDir(t)
	t.Setenv("LOCKSQL_RUNTIME_DIR", base)
	t.Setenv("LOCKMQ_RUNTIME_DIR", "")
	t.Setenv("XDG_RUNTIME_DIR", base)
	t.Setenv("TMPDIR", base)
	mq := kit.Product{Name: "lockmq", EnvPrefix: "LOCKMQ_"}
	p, err := SocketPath(mq, "abcd1234", "uat")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(base, "lockmq", "abcd1234-uat.sock"); p != want {
		t.Fatalf("SocketPath = %q, want %q", p, want)
	}
}

func TestSocketPath(t *testing.T) {
	base := shortDir(t)
	switch runtime.GOOS {
	case "linux":
		t.Setenv("XDG_RUNTIME_DIR", base)
	case "darwin":
		t.Setenv("TMPDIR", base)
	}
	p, err := SocketPath(testProduct, "abcd1234", "uat")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(base, "locksql", "abcd1234-uat.sock")
	if p != want {
		t.Fatalf("SocketPath = %q, want %q", p, want)
	}
	other, _ := SocketPath(testProduct, "ffff0000", "uat")
	if other == p {
		t.Fatal("two projects share a socket")
	}
}

func TestSocketPathRefusesBadNames(t *testing.T) {
	for _, c := range [][2]string{{"", "uat"}, {"abcd", ""}, {"../x", "uat"}, {"abcd", "a/b"}, {"abcd", `a\b`}, {"abcd", ".."}, {"abcd", "-x"}} {
		if _, err := SocketPath(testProduct, c[0], c[1]); err == nil {
			t.Errorf("SocketPath(%q, %q) accepted", c[0], c[1])
		}
	}
}

func TestSocketPathLongNameIsShortened(t *testing.T) {
	base := shortDir(t)
	t.Setenv("XDG_RUNTIME_DIR", base)
	t.Setenv("TMPDIR", base)
	t.Setenv("LOCALAPPDATA", base)
	long := strings.Repeat("p", 64)
	p, err := SocketPath(testProduct, "abcd1234", long)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) > maxSocketPath {
		t.Fatalf("path too long (%d): %s", len(p), p)
	}
	p2, _ := SocketPath(testProduct, "abcd1234", long)
	p3, _ := SocketPath(testProduct, "abcd1234", strings.Repeat("p", 63)+"q")
	if p != p2 || p == p3 {
		t.Fatal("shortened names must be stable and distinct")
	}
}

func TestRuntimeDirFallbackLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	t.Setenv("XDG_RUNTIME_DIR", "relative/dir")
	p, err := SocketPath(testProduct, "abcd1234", "uat")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(p) || strings.Contains(p, "relative") {
		t.Fatalf("relative XDG_RUNTIME_DIR used: %q", p)
	}
}

func TestSocketPathRuntimeDirOverride(t *testing.T) {
	base := shortDir(t)
	t.Setenv("LOCKSQL_RUNTIME_DIR", base)
	t.Setenv("XDG_RUNTIME_DIR", "/nonexistent-xdg")
	t.Setenv("TMPDIR", "/nonexistent-tmp")
	t.Setenv("LOCALAPPDATA", `C:\nonexistent`)
	p, err := SocketPath(testProduct, "abcd1234", "uat")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(base, "locksql", "abcd1234-uat.sock"); p != want {
		t.Fatalf("SocketPath = %q, want %q", p, want)
	}
	// A relative override is ignored.
	t.Setenv("LOCKSQL_RUNTIME_DIR", "relative/dir")
	if p, err := SocketPath(testProduct, "abcd1234", "uat"); err == nil && strings.HasPrefix(p, "relative") {
		t.Fatalf("relative override used: %q", p)
	}
}

// An invalid profile or project hash is named, never quoted back.
func TestSocketPathNeverEchoesNames(t *testing.T) {
	p := kit.Product{Name: "lockdemo"}
	for _, v := range []string{"glsa_CanarySecretToken123/x", "https://user:glsa_Canary@h/path?token=glsa_Canary"} {
		if _, err := SocketPath(p, "abcd", v); err == nil || strings.Contains(err.Error(), "glsa_Canary") || !strings.Contains(err.Error(), "invalid profile") {
			t.Errorf("SocketPath profile: %v", err)
		}
		if _, err := SocketPath(p, v, "prod"); err == nil || strings.Contains(err.Error(), "glsa_Canary") || !strings.Contains(err.Error(), "invalid project hash") {
			t.Errorf("SocketPath project hash: %v", err)
		}
	}
}
