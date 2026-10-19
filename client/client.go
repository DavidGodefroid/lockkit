// Package client is the secret-free side of a product: it dials the
// console socket of a project and profile and calls the console's
// JSON-RPC methods. A product's CLI client commands and MCP server are
// built on it.
//
// A call carries no client-side timeout: a request waits for the human as
// long as the console allows. The caller's context is the only way to
// abandon a call, and abandoning one closes the connection, which the
// console sees as "client gone".
package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/sysconf"
)

// ErrNoConsole means no console listens for the profile.
// Errors that match it are *NoConsoleError values carrying the command the
// human must run.
var ErrNoConsole = errors.New("no console is running")

// ErrConsoleClosed means the console closed the connection before
// answering (the session ended, or the console stopped).
var ErrConsoleClosed = errors.New("the console closed the connection")

// NoConsoleError reports a missing console and how to start it.
type NoConsoleError struct {
	Product kit.Product
	Profile string
	// Project is the project root of the client's directory, "" outside
	// any project. The console must serve the same project.
	Project string
	Socket  string
	Err     error
}

func (e *NoConsoleError) Error() string {
	return fmt.Sprintf("no %s console is running for profile %s: %s", e.Product.Name, e.Profile, e.Hint())
}

// Command is the exact command that starts the missing console.
func (e *NoConsoleError) Command() string { return StartCommand(e.Product, e.Profile, e.Project) }

// Hint tells the agent what to ask of the user. Inside a project, only a
// console started on that project serves the agent, so the hint names it;
// outside one, the hint asks for the project's directory, since the
// console runs in the product's account and reads the profiles from the
// project's config.
func (e *NoConsoleError) Hint() string {
	if e.Project != "" {
		return fmt.Sprintf("ask the user to run this command in the %s account's own session (the console must serve the project %s):\n  %s", e.Product.Account, e.Project, e.Command())
	}
	return fmt.Sprintf("ask the user to start the console in the %s account's own session, on the project that holds %s/%s (`%s doctor` checks the setup):\n  %s",
		e.Product.Account, e.Product.ProjectDir(), config.ConfigFile, e.Product.Name, StartCommand(e.Product, e.Profile, "DIR"))
}

// Is makes errors.Is(err, ErrNoConsole) true.
func (e *NoConsoleError) Is(target error) bool { return target == ErrNoConsole }

func (e *NoConsoleError) Unwrap() error { return e.Err }

// StartCommand is the exact command that starts p's console for profile
// (left out when empty) on project (left out when "": the user config).
func StartCommand(p kit.Product, profile, project string) string {
	c := p.Name + " console"
	if profile != "" {
		c += " --profile " + ShellQuote(profile)
	}
	if project != "" {
		c += " --project " + ShellQuote(project)
	}
	return c
}

// ShellQuote quotes s for a POSIX shell when it holds anything beyond
// letters, digits and ./_-+:,@%=.
func ShellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("./_-+:,@%=", r)))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// SocketPath is p's console socket of profile for the project of cwd. The
// console computes the same path: in the shared socket directory when the
// machine separates the console from the agent (sysconf), in the user's
// runtime directory otherwise.
func SocketPath(p kit.Product, cwd, profile string) (string, error) {
	sys, err := sysconf.Load(p)
	if err != nil {
		return "", err
	}
	if sys != nil {
		return ipc.SharedSocketPath(sys.SocketDir, config.ProjectKey(p, cwd), profile)
	}
	return ipc.SocketPath(p, config.ProjectKey(p, cwd), profile)
}

// dialUnix opens the socket; tests replace it to watch the connection.
var dialUnix = func(path string) (net.Conn, error) { return net.Dial("unix", path) }

// Client is one connection to a console. Calls are serialised.
type Client struct {
	// Name identifies the client in the hello handshake (the product's
	// name when empty).
	Name string
	// ConsoleVersion is the console's version, known after the first call.
	ConsoleVersion string

	product kit.Product
	profile string
	conn    net.Conn
	r       *bufio.Reader

	mu     sync.Mutex
	nextID int64
	hello  bool
	broken error
	// lastDeadline records the deadline of the last call's context, nil
	// when it had none.
	lastDeadline *time.Time
}

// Dial connects to p's console of profile for the project of cwd. It
// returns a *NoConsoleError (matching ErrNoConsole) when none is running.
// The hello handshake happens on the first call, under that call's context.
func Dial(p kit.Product, cwd, profile string) (*Client, error) {
	path, err := SocketPath(p, cwd, profile)
	if err != nil {
		return nil, err
	}
	conn, err := dialUnix(path)
	if err != nil {
		if noListener(err) {
			root, _ := config.FindProjectRoot(p, cwd)
			return nil, &NoConsoleError{Product: p, Profile: profile, Project: root, Socket: path, Err: err}
		}
		return nil, fmt.Errorf("client: connecting to the console: %w", err)
	}
	if err := checkConsole(p, conn); err != nil {
		conn.Close()
		return nil, err
	}
	return &Client{product: p, profile: profile, conn: conn, r: bufio.NewReader(conn)}, nil
}

// checkConsole verifies, in a separated setup, that the process behind the
// socket runs as the console account: the kernel reports the server's
// credentials to the client too.
func checkConsole(p kit.Product, conn net.Conn) error {
	sys, err := sysconf.Load(p)
	if err != nil || sys == nil {
		return err
	}
	want, err := sys.ServiceUID()
	if err != nil {
		return err
	}
	cred, err := ipc.PeerCred(conn)
	if err != nil {
		return fmt.Errorf("client: %w", err)
	}
	if cred.UID != want {
		return fmt.Errorf("client: the socket is served by uid %d, not by the console account %q", cred.UID, sys.ServiceUser)
	}
	return nil
}

// noListener reports a dial error meaning nobody listens at the path: no
// socket file, or a socket left by a console that died.
func noListener(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ENOTDIR)
}

// Profile is the profile this client talks to.
func (c *Client) Profile() string { return c.profile }

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// LastDeadline is the deadline of the last call's context, nil when it had
// none (tests check that approval calls carry none).
func (c *Client) LastDeadline() *time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastDeadline
}

// Call sends one request and decodes its result into result (nil to
// ignore it). A console error is returned as *ipc.RPCError. Numbers in
// result decode as json.Number when result holds interface values.
func (c *Client) Call(ctx context.Context, method string, params, result any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.hello && method != ipc.MethodHello {
		if err := c.handshake(ctx); err != nil {
			return err
		}
	}
	return c.call(ctx, method, params, result)
}

func (c *Client) handshake(ctx context.Context) error {
	name := c.Name
	if name == "" {
		name = c.product.Name
	}
	var hr ipc.HelloResult
	if err := c.call(ctx, ipc.MethodHello, ipc.HelloParams{ProtocolMajor: ipc.ProtocolMajor, Client: name}, &hr); err != nil {
		return err
	}
	if !ipc.Compatible(hr.ProtocolMajor) {
		return fmt.Errorf("protocol mismatch: the console speaks %d, this client speaks %d; use the same %s version on both sides",
			hr.ProtocolMajor, ipc.ProtocolMajor, c.product.Name)
	}
	if hr.Profile != c.profile {
		return fmt.Errorf("the console on this socket serves profile %s, not %s", hr.Profile, c.profile)
	}
	c.ConsoleVersion = hr.ConsoleVersion
	c.hello = true
	return nil
}

func (c *Client) call(ctx context.Context, method string, params, result any) error {
	if dl, ok := ctx.Deadline(); ok {
		c.lastDeadline = &dl
	} else {
		c.lastDeadline = nil
	}
	if c.broken != nil {
		return c.broken
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("client: encode params: %w", err)
		}
		raw = b
	}
	c.nextID++
	req := ipc.Request{JSONRPC: "2.0", ID: c.nextID, Method: method, Params: raw}

	// Abandoning the call closes the connection: the console cancels a
	// pending approval prompt when it sees the client gone.
	stop := context.AfterFunc(ctx, func() { c.conn.Close() })
	defer stop()

	if err := ipc.WriteMsg(c.conn, req); err != nil {
		return c.fail(ctx, err)
	}
	var resp ipc.Response
	if err := ipc.ReadMsg(c.r, &resp); err != nil {
		return c.fail(ctx, err)
	}
	if resp.ID != req.ID {
		c.broken = fmt.Errorf("client: response id %d for request %d", resp.ID, req.ID)
		return c.broken
	}
	if resp.Error != nil {
		return resp.Error
	}
	if result == nil || len(resp.Result) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(resp.Result))
	dec.UseNumber()
	if err := dec.Decode(result); err != nil {
		return fmt.Errorf("client: decode %s result: %w", method, err)
	}
	return nil
}

// fail marks the connection unusable after a transport error.
func (c *Client) fail(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		c.broken = ctx.Err()
		return ctx.Err()
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		c.broken = ErrConsoleClosed
		return ErrConsoleClosed
	}
	c.broken = fmt.Errorf("client: %w", err)
	return c.broken
}
