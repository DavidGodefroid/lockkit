//go:build unix

package client

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/sysconf"
)

var testProduct = kit.Product{Name: "lockmq", Account: "lockmq", ClientsGroup: "lockmq-clients",
	KeychainService: "lockmq", EnvPrefix: "LOCKMQ_"}

// runtimeDir points the socket paths at a short private temp dir, and the
// system setup at a file that does not exist (same-user mode).
func runtimeDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "lkcl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	t.Setenv("LOCKMQ_RUNTIME_DIR", d)
	old := sysconf.Path
	sysconf.Path = filepath.Join(d, "no-system.toml")
	t.Cleanup(func() { sysconf.Path = old })
	return d
}

// fakeConsole answers requests on the profile's socket with handler.
type fakeConsole struct {
	mu      sync.Mutex
	methods []string
	clients []string
}

func (f *fakeConsole) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.methods...)
}

func startFake(t *testing.T, cwd, profile string, handler func(req ipc.Request) ipc.Response) *fakeConsole {
	t.Helper()
	path, err := ipc.SocketPath(testProduct, config.ProjectKey(testProduct, cwd), profile)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := ipc.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeConsole{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					var req ipc.Request
					if err := ipc.ReadMsg(r, &req); err != nil {
						return
					}
					f.mu.Lock()
					f.methods = append(f.methods, req.Method)
					f.mu.Unlock()
					var resp ipc.Response
					if req.Method == ipc.MethodHello {
						var hp ipc.HelloParams
						_ = json.Unmarshal(req.Params, &hp)
						f.mu.Lock()
						f.clients = append(f.clients, hp.Client)
						f.mu.Unlock()
						resp = result(req.ID, ipc.HelloResult{ProtocolMajor: ipc.ProtocolMajor, ConsoleVersion: "9.9.9", Profile: profile})
					} else {
						resp = handler(req)
					}
					if err := ipc.WriteMsg(c, resp); err != nil {
						return
					}
				}
			}()
		}
	}()
	return f
}

func result(id int64, v any) ipc.Response {
	b, _ := json.Marshal(v)
	return ipc.Response{JSONRPC: "2.0", ID: id, Result: b}
}

func rpcErr(id int64, code int, msg string) ipc.Response {
	return ipc.Response{JSONRPC: "2.0", ID: id, Error: &ipc.RPCError{Code: code, Message: msg}}
}

func TestDialWithoutConsoleNamesTheProduct(t *testing.T) {
	runtimeDir(t)
	_, err := Dial(testProduct, t.TempDir(), "uat")
	var nc *NoConsoleError
	if !errors.Is(err, ErrNoConsole) || !errors.As(err, &nc) || nc.Profile != "uat" || nc.Project != "" {
		t.Fatalf("err = %#v", err)
	}
	msg := err.Error()
	for _, want := range []string{"no lockmq console is running for profile uat", "the lockmq account's own session",
		".lockmq/config.toml", "`lockmq doctor`", "lockmq console --profile uat --project DIR"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, "locksql") {
		t.Errorf("another product named: %s", msg)
	}
	if got := StartCommand(testProduct, "uat", "/a b/it's"); got != `lockmq console --profile uat --project '/a b/it'\''s'` {
		t.Fatalf("quoting: %s", got)
	}
}

func TestDialWithoutConsoleInProjectNamesProject(t *testing.T) {
	runtimeDir(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".lockmq"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".lockmq", "config.toml"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "pkg")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Dial(testProduct, sub, "uat")
	var nc *NoConsoleError
	if !errors.As(err, &nc) || nc.Project != root {
		t.Fatalf("err = %#v", err)
	}
	want := "lockmq console --profile uat --project " + root
	if nc.Command() != want || !strings.Contains(err.Error(), want) {
		t.Fatalf("hint %q / command %q", err.Error(), nc.Command())
	}
}

func TestDialStaleSocketIsErrNoConsole(t *testing.T) {
	runtimeDir(t)
	cwd := t.TempDir()
	path, err := ipc.SocketPath(testProduct, config.ProjectKey(testProduct, cwd), "uat")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := ipc.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	if _, err := Dial(testProduct, cwd, "uat"); !errors.Is(err, ErrNoConsole) {
		t.Fatalf("err = %v, want ErrNoConsole", err)
	}
}

func TestDialRefusesBadProfile(t *testing.T) {
	runtimeDir(t)
	if _, err := Dial(testProduct, t.TempDir(), "../x"); err == nil || errors.Is(err, ErrNoConsole) {
		t.Fatalf("err = %v, want a plain error", err)
	}
}

func TestCallSendsHelloFirstAndDecodes(t *testing.T) {
	runtimeDir(t)
	cwd := t.TempDir()
	fake := startFake(t, cwd, "uat", func(req ipc.Request) ipc.Response {
		return result(req.ID, ipc.PIIListResult{Mask: []string{"orders/*:$.email"}})
	})
	c, err := Dial(testProduct, cwd, "uat")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var got ipc.PIIListResult
	if err := c.Call(context.Background(), ipc.MethodPIIList, nil, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Mask) != 1 || c.ConsoleVersion != "9.9.9" || c.Profile() != "uat" {
		t.Fatalf("got %+v, console %q", got, c.ConsoleVersion)
	}
	if err := c.Call(context.Background(), ipc.MethodPIIList, nil, nil); err != nil {
		t.Fatal(err)
	}
	want := []string{ipc.MethodHello, ipc.MethodPIIList, ipc.MethodPIIList}
	if s := fake.seen(); strings.Join(s, ",") != strings.Join(want, ",") {
		t.Fatalf("methods = %v, want %v", s, want)
	}
	// The client names itself after the product unless told otherwise.
	if fake.clients[0] != "lockmq" {
		t.Fatalf("hello client = %q", fake.clients[0])
	}
}

func TestCallReturnsRPCError(t *testing.T) {
	runtimeDir(t)
	cwd := t.TempDir()
	startFake(t, cwd, "uat", func(req ipc.Request) ipc.Response {
		return rpcErr(req.ID, ipc.CodeDenied, "denied by the human")
	})
	c, err := Dial(testProduct, cwd, "uat")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	err = c.Call(context.Background(), "op.run", map[string]string{"op": "read"}, nil)
	var re *ipc.RPCError
	if !errors.As(err, &re) || re.Code != ipc.CodeDenied {
		t.Fatalf("err = %v, want RPCError %d", err, ipc.CodeDenied)
	}
}

func helloOnly(t *testing.T, cwd string, hr ipc.HelloResult) {
	t.Helper()
	path, _ := ipc.SocketPath(testProduct, config.ProjectKey(testProduct, cwd), "uat")
	ln, err := ipc.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var req ipc.Request
		if ipc.ReadMsg(bufio.NewReader(c), &req) == nil {
			_ = ipc.WriteMsg(c, result(req.ID, hr))
		}
	}()
}

func TestHelloProtocolMismatch(t *testing.T) {
	runtimeDir(t)
	cwd := t.TempDir()
	helloOnly(t, cwd, ipc.HelloResult{ProtocolMajor: ipc.ProtocolMajor + 1, Profile: "uat"})
	c, err := Dial(testProduct, cwd, "uat")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	err = c.Call(context.Background(), ipc.MethodStatus, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "protocol mismatch") || !strings.Contains(err.Error(), "same lockmq version") {
		t.Fatalf("err = %v, want a protocol mismatch", err)
	}
}

func TestHelloProfileMismatch(t *testing.T) {
	runtimeDir(t)
	cwd := t.TempDir()
	helloOnly(t, cwd, ipc.HelloResult{ProtocolMajor: ipc.ProtocolMajor, Profile: "prod"})
	c, err := Dial(testProduct, cwd, "uat")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Call(context.Background(), ipc.MethodStatus, nil, nil); err == nil || !strings.Contains(err.Error(), "prod") {
		t.Fatalf("err = %v, want a profile mismatch", err)
	}
}

// spyConn records every deadline set on the connection.
type spyConn struct {
	net.Conn
	mu        sync.Mutex
	deadlines []time.Time
}

func (s *spyConn) record(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deadlines = append(s.deadlines, t)
}
func (s *spyConn) SetDeadline(t time.Time) error      { s.record(t); return s.Conn.SetDeadline(t) }
func (s *spyConn) SetReadDeadline(t time.Time) error  { s.record(t); return s.Conn.SetReadDeadline(t) }
func (s *spyConn) SetWriteDeadline(t time.Time) error { s.record(t); return s.Conn.SetWriteDeadline(t) }

// A call carries no client-side timeout: neither the call context nor the
// connection gets a deadline, so an approval may take as long as the
// console allows.
func TestCallWaitsWithoutClientTimeout(t *testing.T) {
	runtimeDir(t)
	cwd := t.TempDir()
	release := make(chan struct{})
	startFake(t, cwd, "uat", func(req ipc.Request) ipc.Response {
		<-release // the human takes their time
		return result(req.ID, map[string]int{"n": 1})
	})
	var spy *spyConn
	old := dialUnix
	dialUnix = func(path string) (net.Conn, error) {
		c, err := old(path)
		if err != nil {
			return nil, err
		}
		spy = &spyConn{Conn: c}
		return spy, nil
	}
	t.Cleanup(func() { dialUnix = old })

	c, err := Dial(testProduct, cwd, "uat")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	done := make(chan error, 1)
	go func() { done <- c.Call(context.Background(), "op.read", nil, nil) }()
	select {
	case err := <-done:
		t.Fatalf("Call returned before the human answered: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Call did not return after the answer")
	}
	spy.mu.Lock()
	defer spy.mu.Unlock()
	for _, d := range spy.deadlines {
		if !d.IsZero() {
			t.Fatalf("a deadline was set on the call: %v", d)
		}
	}
	if c.LastDeadline() != nil {
		t.Fatalf("the call context carried a deadline: %v", *c.LastDeadline())
	}
}

func TestCallHonoursContextCancel(t *testing.T) {
	runtimeDir(t)
	cwd := t.TempDir()
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	startFake(t, cwd, "uat", func(req ipc.Request) ipc.Response {
		<-block
		return result(req.ID, map[string]bool{"ok": true})
	})
	c, err := Dial(testProduct, cwd, "uat")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	if err := c.Call(ctx, ipc.MethodLogout, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestConsoleClosingMidCallIsAnError(t *testing.T) {
	runtimeDir(t)
	cwd := t.TempDir()
	path, _ := ipc.SocketPath(testProduct, config.ProjectKey(testProduct, cwd), "uat")
	ln, err := ipc.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		r := bufio.NewReader(c)
		var req ipc.Request
		if ipc.ReadMsg(r, &req) == nil {
			_ = ipc.WriteMsg(c, result(req.ID, ipc.HelloResult{ProtocolMajor: ipc.ProtocolMajor, Profile: "uat"}))
		}
		_ = ipc.ReadMsg(r, &req)
		c.Close()
	}()
	c, err := Dial(testProduct, cwd, "uat")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Call(context.Background(), ipc.MethodStatus, nil, nil); !errors.Is(err, ErrConsoleClosed) {
		t.Fatalf("err = %v, want ErrConsoleClosed", err)
	}
}

func TestSocketPathUsesProjectKey(t *testing.T) {
	d := runtimeDir(t)
	cwd := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cwd, ".lockmq"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, ".lockmq", "config.toml"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := SocketPath(testProduct, cwd, "uat")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(d, "lockmq", config.ProjectHash(cwd)+"-uat.sock"); p != want {
		t.Fatalf("SocketPath = %q, want %q", p, want)
	}
}
