package mcpkit

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type limitIn struct {
	Limit int `json:"limit"`
}

// rawClient speaks JSON-RPC lines to a server run by Serve, so a test sees
// the answer as the client gets it, before any client-side decoding.
type rawClient struct {
	t    *testing.T
	w    io.Writer
	r    *bufio.Scanner
	meta string // the _meta of every call: the sessionless revision, if any
	id   int
}

// call sends method with params (a JSON object without _meta) and returns
// the decoded answer.
func (c *rawClient) call(method, params string) map[string]any {
	c.t.Helper()
	c.id++
	if c.meta != "" {
		sep := ","
		if params == "{}" {
			sep = ""
		}
		params = strings.TrimSuffix(params, "}") + sep + `"_meta":` + c.meta + "}"
	}
	line, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.id, "method": method, "params": json.RawMessage(params)})
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := c.w.Write(append(line, '\n')); err != nil {
		c.t.Fatal(err)
	}
	if !c.r.Scan() {
		c.t.Fatalf("%s: no answer: %v", method, c.r.Err())
	}
	var m map[string]any
	if err := json.Unmarshal(c.r.Bytes(), &m); err != nil {
		c.t.Fatalf("%s: %v: %s", method, err, c.r.Bytes())
	}
	return m
}

// serveLimitTool serves a product server with one tool taking limit in
// 1..200 and no other property. middleware, when set, is the product's own
// receiving middleware.
func serveLimitTool(t *testing.T, middleware mcp.Middleware) (*mcp.Server, *rawClient) {
	t.Helper()
	s := New(testProduct, "1.2.3", "")
	schema, err := jsonschema.For[limitIn](nil)
	if err != nil {
		t.Fatal(err)
	}
	lo, hi := 1.0, 200.0
	schema.Properties["limit"].Minimum, schema.Properties["limit"].Maximum = &lo, &hi
	mcp.AddTool(s, &mcp.Tool{Name: "search", InputSchema: schema}, func(context.Context, *mcp.CallToolRequest, limitIn) (*mcp.CallToolResult, any, error) {
		return Text("ok"), nil, nil
	})
	if middleware != nil {
		s.AddReceivingMiddleware(middleware)
	}
	return s, startRaw(t, s)
}

func startRaw(t *testing.T, s *mcp.Server) *rawClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, s, inR, outW) }()
	t.Cleanup(func() {
		cancel()
		inW.Close()
		outR.Close()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return &rawClient{t: t, w: inW, r: bufio.NewScanner(outR)}
}

// initialize opens a session at revision v with the initialize handshake.
func (c *rawClient) initialize(v string) map[string]any {
	c.t.Helper()
	res := c.call("initialize", `{"protocolVersion":"`+v+`","capabilities":{},"clientInfo":{"name":"agent","version":"1"}}`)
	if _, err := c.w.Write([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")); err != nil {
		c.t.Fatal(err)
	}
	return res
}

// sessionless makes every call carry revision v in its _meta.
func (c *rawClient) sessionless(v string) {
	c.meta = `{"io.modelcontextprotocol/protocolVersion":"` + v + `","io.modelcontextprotocol/clientCapabilities":{}}`
}

// badArgs is a product middleware rewriting the SDK's argument errors as a
// refusal of its own, in a new result, as locklog does.
func badArgs(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		res, err := next(ctx, method, req)
		r, ok := res.(*mcp.CallToolResult)
		if method != "tools/call" || !ok || !r.IsError || r.GetError() == nil {
			return res, err
		}
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "refused [E_BAD_ARGS]: invalid arguments: limit; see the tool's input schema"}}}, err
	}
}

var badCalls = []struct{ name, args, text string }{
	{"out of range", `{"limit":201}`, "/properties/limit: maximum"},
	{"unknown property", `{"limit":5,"source":"e2e"}`, `unexpected additional properties ["source"]`},
}

func toolCall(args string) string { return `{"name":"search","arguments":` + args + `}` }

// errorResult checks that answer is a tool error result with resultType
// complete and a text holding want, and returns that text.
func errorResult(t *testing.T, answer map[string]any, want string) {
	t.Helper()
	res, ok := answer["result"].(map[string]any)
	if !ok {
		t.Fatalf("not a result: %v", answer)
	}
	if res["resultType"] != "complete" || res["isError"] != true {
		t.Fatalf("resultType %v, isError %v: %v", res["resultType"], res["isError"], res)
	}
	content, _ := res["content"].([]any)
	if len(content) != 1 || !strings.Contains(content[0].(map[string]any)["text"].(string), want) {
		t.Fatalf("content %v, want %q", content, want)
	}
}

func TestArgumentErrorsCarryResultType(t *testing.T) {
	for _, mode := range []string{"initialize", "sessionless"} {
		for _, mw := range []struct {
			name string
			m    mcp.Middleware
			text func(sdk string) string
		}{
			{"SDK text", nil, func(sdk string) string { return sdk }},
			{"product middleware", badArgs, func(string) string { return "refused [E_BAD_ARGS]: invalid arguments: limit" }},
		} {
			t.Run(mode+"/"+mw.name, func(t *testing.T) {
				_, c := serveLimitTool(t, mw.m)
				if mode == "initialize" {
					c.initialize("2026-07-28")
				} else {
					c.sessionless("2026-07-28")
				}
				for _, bc := range badCalls {
					errorResult(t, c.call("tools/call", toolCall(bc.args)), mw.text(bc.text))
				}
				ok := c.call("tools/call", toolCall(`{"limit":5}`))["result"].(map[string]any)
				if ok["resultType"] != "complete" || ok["isError"] != nil {
					t.Fatalf("valid call: %v", ok)
				}
			})
		}
	}
}

func TestOlderRevisionGetsNoResultType(t *testing.T) {
	_, c := serveLimitTool(t, badArgs)
	c.initialize("2025-06-18")
	res := c.call("tools/call", toolCall(`{"limit":201}`))["result"].(map[string]any)
	if _, has := res["resultType"]; has || res["isError"] != true {
		t.Fatalf("2025-06-18: %v", res)
	}
}

func TestCompleteResultsKeepsTheError(t *testing.T) {
	boom := errors.New("boom")
	s, c := serveLimitTool(t, func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			res, err := next(ctx, method, req)
			if r, ok := res.(*mcp.CallToolResult); ok && r.IsError {
				out := Text("refused [E_BAD_ARGS]: limit")
				out.SetError(boom)
				return out, err
			}
			return res, err
		}
	})
	var seen error
	// Added after Serve's own, so it runs outside completeResults.
	s.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			res, err := next(ctx, method, req)
			if r, ok := res.(*mcp.CallToolResult); ok {
				seen = r.GetError()
			}
			return res, err
		}
	})
	c.initialize("2026-07-28")
	errorResult(t, c.call("tools/call", toolCall(`{"limit":5,"x":1}`)), "refused [E_BAD_ARGS]: limit")
	if seen != boom {
		t.Fatalf("error after completeResults: %v", seen)
	}

	// An error a result keeps for the server only never reaches the wire:
	// the content stays empty and isError false.
	hidden := errors.New("secret backend text")
	s2, c2 := serveLimitTool(t, func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			res, err := next(ctx, method, req)
			if _, ok := res.(*mcp.CallToolResult); ok {
				out := &mcp.CallToolResult{}
				out.SetError(hidden)
				out.Content, out.IsError = nil, false
				return out, err
			}
			return res, err
		}
	})
	seen = nil
	s2.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			res, err := next(ctx, method, req)
			if r, ok := res.(*mcp.CallToolResult); ok {
				seen = r.GetError()
			}
			return res, err
		}
	})
	c2.initialize("2026-07-28")
	res := c2.call("tools/call", toolCall(`{"limit":5}`))["result"].(map[string]any)
	if content, _ := res["content"].([]any); res["resultType"] != "complete" || res["isError"] != nil || content == nil || len(content) != 0 {
		t.Fatalf("hidden error: %v", res)
	}
	if seen != hidden {
		t.Fatalf("hidden error after completeResults: %v", seen)
	}

	// Without a session there is no revision: the result is left as is.
	r := Text("x")
	out, err := completeResults(func(context.Context, string, mcp.Request) (mcp.Result, error) { return r, nil })(context.Background(), "tools/call", &mcp.CallToolRequest{})
	if err != nil || out != r {
		t.Fatalf("no session: %v %v", out, err)
	}
}

func TestServeTwiceStampsOnce(t *testing.T) {
	s, c := serveLimitTool(t, nil)
	c.initialize("2026-07-28")
	c.call("tools/call", toolCall(`{"limit":5}`))
	c2 := startRaw(t, s)
	c2.initialize("2026-07-28")
	errorResult(t, c2.call("tools/call", toolCall(`{"limit":0}`)), "minimum")
}

func TestProtocolVersionsPinned(t *testing.T) {
	want := []string{"2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}
	if got := ProtocolVersions(); !slices.Equal(got, want) {
		t.Fatalf("ProtocolVersions %v, want %v: a change of revision is deliberate and tested", got, want)
	}
	for _, v := range want {
		if !slices.Contains(mcp.SupportedProtocolVersions(), v) {
			t.Fatalf("the SDK no longer supports %s", v)
		}
	}
	ProtocolVersions()[0] = "x"
	if protocolVersions[0] != "2026-07-28" {
		t.Fatal("ProtocolVersions returns the pinned slice itself")
	}

	// The initialize handshake negotiates the newest pre-2026-07-28
	// revision (the handshake's last), whatever the client asks.
	for ask, negotiated := range map[string]string{"2026-07-28": "2025-11-25", "2025-06-18": "2025-06-18", "2099-01-01": "2025-11-25"} {
		_, c := serveLimitTool(t, nil)
		if got := c.initialize(ask)["result"].(map[string]any)["protocolVersion"]; got != negotiated {
			t.Errorf("initialize %s: negotiated %v, want %s", ask, got, negotiated)
		}
	}

	// A sessionless call names its revision: a pinned one is served, any
	// other refused with the pinned list.
	_, c := serveLimitTool(t, nil)
	c.sessionless("2026-07-28")
	if c.call("tools/list", `{}`)["result"] == nil {
		t.Fatal("2026-07-28 sessionless call refused")
	}
	c.sessionless("2099-01-01")
	e, ok := c.call("tools/list", `{}`)["error"].(map[string]any)
	if !ok || !strings.Contains(e["message"].(string), "unsupported protocol version") {
		t.Fatalf("2099-01-01: %v", e)
	}
	if data, _ := json.Marshal(e["data"]); !strings.Contains(string(data), `"supported":["2026-07-28","2025-11-25","2025-06-18","2025-03-26","2024-11-05"]`) {
		t.Fatalf("supported list %s", data)
	}
}
