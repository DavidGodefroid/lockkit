package console

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/DavidGodefroid/lockkit/ipc"
)

// Loop is the console's request loop: it accepts clients, checks their
// peer credentials and serves their requests one at a time on one
// goroutine, between the lines and control keys the human types and the
// periodic ticks. A request whose client goes away has its context
// cancelled, which cancels a pending approval prompt.
type Loop struct {
	IO IO
	// Handle serves one request (required).
	Handle func(ctx context.Context, req ipc.Request) ipc.Response
	// Command runs a line typed by the human between requests.
	Command func(ctx context.Context, line string)
	// Key handles a control key pressed between prompts; with a KeySource
	// IO it also handles the keys pressed during a prompt.
	Key func(Key)
	// Tick runs every second (session timeouts).
	Tick func()
	// Poll runs every PolicyPoll (config file changes).
	Poll func()
	// Ended reports the end of the session (required); End ends it.
	Ended func() bool
	End   func(reason string)
	// Refresh runs after every event (the status row); Clear on return.
	Refresh func()
	Clear   func()
	// PeerAllowed decides which clients are served, from the kernel's
	// credentials of the peer. Nil serves the console's own account only.
	PeerAllowed func(ipc.Cred) bool
}

// job is one request handed from a connection to the console goroutine.
type job struct {
	ctx  context.Context
	req  ipc.Request
	resp chan ipc.Response
}

// flushWait bounds how long an ending session waits for the last responses
// (such as the answer to logout) to reach their clients.
const flushWait = 2 * time.Second

func (l *Loop) refresh() {
	if l.Refresh != nil {
		l.Refresh()
	}
}

// Serve accepts clients on ln and serves their requests one at a time until
// ctx ends or the session ends (logout, timeouts, :quit). lines are the
// console commands typed by the human (nil for none); the control keys
// come from the IO when it is a KeySource. ln is closed on return, which
// removes the socket.
func (l *Loop) Serve(ctx context.Context, ln net.Listener, lines <-chan string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var keys <-chan Key
	if ks, ok := l.IO.(KeySource); ok && l.Key != nil {
		keys = ks.Keys()
		ks.SetKeyHandler(l.Key)
	}
	l.refresh()
	if l.Clear != nil {
		defer l.Clear()
	}
	jobs := make(chan job)
	// inflight counts responses handed to connections but not yet written.
	var wg, inflight sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		l.accept(ctx, ln, jobs, &wg, &inflight)
	}()
	defer func() {
		ln.Close()
		waitFor(&inflight, flushWait)
		cancel()
		wg.Wait()
	}()

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	lastPoll := time.Now()
	for {
		if l.Ended() {
			return nil
		}
		select {
		case <-ctx.Done():
			if l.End != nil {
				l.End("interrupted")
			}
			return nil
		case j := <-jobs:
			inflight.Add(1)
			if j.ctx.Err() != nil {
				j.resp <- ErrResp(j.req.ID, ipc.CodeDenied, "client gone")
				continue
			}
			j.resp <- l.Handle(j.ctx, j.req)
		case line, ok := <-lines:
			if !ok {
				lines = nil
				continue
			}
			if l.Command != nil {
				l.Command(ctx, line)
			}
		case k := <-keys:
			l.Key(k)
		case <-tick.C:
			if time.Since(lastPoll) >= PolicyPoll {
				lastPoll = time.Now()
				if l.Poll != nil {
					l.Poll()
				}
			}
			if l.Tick != nil {
				l.Tick()
			}
		}
		l.refresh()
	}
}

// waitFor waits for wg, at most d.
func waitFor(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
	}
}

func (l *Loop) accept(ctx context.Context, ln net.Listener, jobs chan<- job, wg, inflight *sync.WaitGroup) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient accept errors: back off briefly.
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		cred, err := ipc.PeerCred(c)
		if err != nil || !l.peerAllowed(cred) {
			c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			serveConn(WithPeer(ctx, cred), c, jobs, inflight)
		}()
	}
}

// peerAllowed applies the peer check: the configured one, or the console's
// own account.
func (l *Loop) peerAllowed(c ipc.Cred) bool {
	if l.PeerAllowed != nil {
		return l.PeerAllowed(c)
	}
	return c.UID == os.Getuid()
}

// maxQueued bounds the requests a client may pipeline behind the one being
// served.
const maxQueued = 32

type readResult struct {
	req ipc.Request
	err error
}

// serveConn reads requests from c and hands them to the console goroutine
// one by one. While a request is being served, the next read doubles as a
// probe: a closed connection cancels the request's context, which cancels
// a pending approval prompt. Every response received from the console
// goroutine is marked done on inflight once written (or dropped).
func serveConn(ctx context.Context, c net.Conn, jobs chan<- job, inflight *sync.WaitGroup) {
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	msgs := make(chan readResult, 1)
	done := make(chan struct{}) // ends the reader when serveConn returns
	defer close(done)
	go func() {
		r := bufio.NewReader(c)
		for {
			var req ipc.Request
			err := ipc.ReadMsg(r, &req)
			select {
			case msgs <- readResult{req, err}:
			case <-done:
				return
			}
			if err != nil {
				return
			}
		}
	}()

	var queue []readResult
	next := func() (readResult, bool) {
		if len(queue) > 0 {
			m := queue[0]
			queue = queue[1:]
			return m, true
		}
		select {
		case m := <-msgs:
			return m, true
		case <-ctx.Done():
			return readResult{}, false
		}
	}
	gone := false
	for !gone {
		m, ok := next()
		if !ok {
			return
		}
		if m.err != nil {
			if !errors.Is(m.err, io.EOF) && !errors.Is(m.err, net.ErrClosed) {
				_ = ipc.WriteMsg(c, ErrResp(0, ipc.CodeParseError, "invalid message"))
			}
			return
		}
		jctx, jcancel := context.WithCancel(ctx)
		j := job{ctx: jctx, req: m.req, resp: make(chan ipc.Response, 1)}
		// While the job waits for the console (another client's approval
		// may be pending), keep reading: a client that leaves meanwhile
		// never gets its request run.
	handoff:
		for {
			select {
			case jobs <- j:
				break handoff
			case m2 := <-msgs:
				if m2.err != nil {
					jcancel()
					return
				}
				if len(queue) >= maxQueued {
					jcancel()
					_ = ipc.WriteMsg(c, ErrResp(m2.req.ID, ipc.CodeInvalidRequest, "too many pipelined requests"))
					return
				}
				queue = append(queue, m2)
			case <-ctx.Done():
				jcancel()
				return
			}
		}
		var resp ipc.Response
	wait:
		for {
			select {
			case resp = <-j.resp:
				break wait
			case m2 := <-msgs:
				if m2.err != nil {
					// The client is gone: cancel the request, then still
					// wait for the console to finish with it.
					gone = true
					jcancel()
					continue
				}
				if len(queue) >= maxQueued {
					// Too many pipelined requests: drop the client once
					// the console is done with the current one.
					gone = true
					jcancel()
					continue
				}
				queue = append(queue, m2)
			}
		}
		jcancel()
		if gone {
			inflight.Done()
			return
		}
		err := ipc.WriteMsg(c, resp)
		if errors.Is(err, ipc.ErrTooLarge) {
			err = ipc.WriteMsg(c, ErrResp(resp.ID, ipc.CodeInternal,
				"result larger than 1 MiB: lower limits.max_output_bytes or select fewer columns"))
		}
		inflight.Done()
		if err != nil {
			return
		}
	}
}

// ErrResp is an error response.
func ErrResp(id int64, code int, msg string) ipc.Response {
	return ipc.Response{JSONRPC: "2.0", ID: id, Error: &ipc.RPCError{Code: code, Message: msg}}
}

// OKResp is a result response; a value that does not encode gives an
// internal error.
func OKResp(id int64, v any) ipc.Response {
	b, err := json.Marshal(v)
	if err != nil {
		return ErrResp(id, ipc.CodeInternal, fmt.Sprintf("encode result: %v", err))
	}
	return ipc.Response{JSONRPC: "2.0", ID: id, Result: b}
}

// Level waits until the next multiple of quantum since start, so that the
// response time tells nothing finer than quantum (0 or less: no wait).
func Level(ctx context.Context, quantum time.Duration, start time.Time) {
	if quantum <= 0 {
		return
	}
	el := time.Since(start)
	wait := quantum - el%quantum
	if wait == quantum && el > 0 {
		return
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}
