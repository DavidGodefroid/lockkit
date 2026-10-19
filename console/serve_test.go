package console

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ipc"
)

// A client that leaves while its request waits for the console (busy with
// another client's approval) must not have that request served.
func TestServeConnDropsRequestOfClientGoneBeforeHandoff(t *testing.T) {
	srv, cli := net.Pipe()
	jobs := make(chan job)
	var inflight sync.WaitGroup
	done := make(chan struct{})
	go func() {
		serveConn(context.Background(), srv, jobs, &inflight)
		close(done)
	}()
	if err := ipc.WriteMsg(cli, ipc.Request{JSONRPC: "2.0", ID: 1, Method: ipc.MethodStatus}); err != nil {
		t.Fatal(err)
	}
	cli.Close()
	// Nobody serves jobs (the console is busy): serveConn must notice the
	// client left and return without handing the request over.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveConn still waits to hand over the request of a gone client")
	}
}

// Level rounds a response time up to the quantum, and returns at once when
// the context ends or no quantum is set.
func TestLevel(t *testing.T) {
	start := time.Now()
	Level(context.Background(), 60*time.Millisecond, start)
	if el := time.Since(start); el < 55*time.Millisecond || el > 500*time.Millisecond {
		t.Errorf("levelled to %v", el)
	}
	start = time.Now()
	Level(context.Background(), 0, start)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	Level(ctx, time.Hour, start)
	if time.Since(start) > 100*time.Millisecond {
		t.Error("waited without a quantum or with an ended context")
	}
}

func TestResponses(t *testing.T) {
	if r := OKResp(3, map[string]int{"a": 1}); r.Error != nil || string(r.Result) != `{"a":1}` || r.ID != 3 {
		t.Fatalf("%+v", r)
	}
	if r := OKResp(3, func() {}); r.Error == nil || r.Error.Code != ipc.CodeInternal {
		t.Fatalf("%+v", r)
	}
	if r := ErrResp(4, ipc.CodeDenied, "no"); r.Error.Code != ipc.CodeDenied || r.Error.Message != "no" || r.Result != nil {
		t.Fatalf("%+v", r)
	}
}
