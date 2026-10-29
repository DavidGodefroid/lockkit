package mcpkit

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/DavidGodefroid/lockkit/ipc"
)

func TestPending(t *testing.T) {
	res, out := Pending("locksql", "01JBDN0Z0000000000000000AB")
	if res.IsError {
		t.Fatal("pending is not an error")
	}
	want := "Pending human approval: ticket 01JBDN0Z0000000000000000AB on locksql. Do not retry. End your turn; you will be told when it is decided."
	if len(res.Content) != 1 || res.Content[0].(*mcp.TextContent).Text != want {
		t.Fatalf("content %#v", res.Content)
	}
	b, _ := json.Marshal(res.StructuredContent)
	if string(b) != `{"status":"pending","ticket":"01JBDN0Z0000000000000000AB","lock":"locksql"}` {
		t.Fatalf("structured %s", b)
	}
	if out != (PendingResult{Status: "pending", Ticket: "01JBDN0Z0000000000000000AB", Lock: "locksql"}) {
		t.Fatalf("out %+v", out)
	}
}

// In hub mode the pending answer names the lock instance too; outside it
// (no instance) the answer is unchanged.
func TestPendingOnInstance(t *testing.T) {
	res, out := PendingOn("locksql", "crm-prod", "01JBDN0Z0000000000000000AB")
	b, _ := json.Marshal(res.StructuredContent)
	if string(b) != `{"status":"pending","ticket":"01JBDN0Z0000000000000000AB","lock":"locksql","instance":"crm-prod"}` {
		t.Fatalf("structured %s", b)
	}
	if out.Instance != "crm-prod" || res.IsError {
		t.Fatalf("out %+v", out)
	}
	res, _ = PendingOn("locksql", "", "01JBDN0Z0000000000000000AB")
	if b, _ := json.Marshal(res.StructuredContent); string(b) != `{"status":"pending","ticket":"01JBDN0Z0000000000000000AB","lock":"locksql"}` {
		t.Fatalf("no instance: %s", b)
	}
}

// Through the SDK: a typed tool returning Pending reaches the client as a
// non-error result whose structured content has the pending fields.
func TestPendingOverMCP(t *testing.T) {
	s := New(testProduct, "1", "")
	mcp.AddTool(s, &mcp.Tool{Name: "lockmq_run"}, func(ctx context.Context, req *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, PendingResult, error) {
		res, out := Pending("lockmq", "01JBDN0Z0000000000000000AB")
		return res, out, nil
	})
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := s.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	c := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil)
	cs, err := c.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "lockmq_run", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatal("isError")
	}
	b, _ := json.Marshal(res.StructuredContent)
	var got PendingResult
	if err := json.Unmarshal(b, &got); err != nil || got.Status != StatusPending || got.Ticket != "01JBDN0Z0000000000000000AB" || got.Lock != "lockmq" {
		t.Fatalf("structured %s %v", b, err)
	}
}

func TestRequesterFromEnv(t *testing.T) {
	env := map[string]string{"LEA_AGENT": "dev-3", "LEA_AGENT_TOKEN": "tok"}
	if got := requesterFrom(func(k string) string { return env[k] }); got != (ipc.Requester{Agent: "dev-3", Token: "tok"}) {
		t.Fatalf("%+v", got)
	}
	if got := requesterFrom(func(string) string { return "" }); got != (ipc.Requester{}) {
		t.Fatalf("outside lea: %+v", got)
	}
	b, _ := json.Marshal(ipc.Requester{})
	if string(b) != `{}` {
		t.Fatalf("empty requester encodes as %s", b)
	}
	t.Setenv("LEA_AGENT", "dev-9")
	t.Setenv("LEA_AGENT_TOKEN", "t9")
	if got := RequesterFromEnv(); got.Agent != "dev-9" || got.Token != "t9" {
		t.Fatalf("%+v", got)
	}
}
