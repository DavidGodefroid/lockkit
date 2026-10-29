package mcpkit

import (
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/plans"
)

// StatusPending is the status of a request waiting for the human on the
// approval hub.
const StatusPending = "pending"

// PendingResult is the structured content of a pending answer, shared by
// every lock: a hook of the agent's harness reads status, ticket and lock
// to suspend the agent until the ticket is decided. A tool with a typed
// output embeds it (its fields at the top level of the output).
type PendingResult struct {
	Status string `json:"status"` // StatusPending
	Ticket string `json:"ticket"`
	Lock   string `json:"lock"`
	// Instance is the lock instance the ticket is on (the console's
	// --instance), set in hub mode.
	Instance string `json:"instance,omitempty"`
}

// PendingText is the fixed text of a pending answer.
func PendingText(lock, ticket string) string {
	return "Pending human approval: ticket " + ticket + " on " + lock +
		". Do not retry. End your turn; you will be told when it is decided."
}

// Pending is the answer of a run that waits for the human on the hub:
// not an error, the fixed text, and the structured PendingResult (also
// returned, for a tool with a typed output, whose output the SDK puts in
// the structured content).
func Pending(lock, ticket string) (*mcp.CallToolResult, PendingResult) {
	return PendingOn(lock, "", ticket)
}

// PendingOn is Pending for a ticket on lock instance instance ("" none:
// the answer of Pending).
func PendingOn(lock, instance, ticket string) (*mcp.CallToolResult, PendingResult) {
	out := PendingResult{Status: StatusPending, Ticket: ticket, Lock: lock, Instance: instance}
	res := Text(PendingText(lock, ticket))
	res.StructuredContent = out
	return res, out
}

// Environment variables lea sets in every agent it starts.
const (
	EnvAgent      = "LEA_AGENT"
	EnvAgentToken = "LEA_AGENT_TOKEN"
)

// RequesterFromEnv is the requester the MCP server reports in its plan and
// run requests: the agent's name from lea's environment and the hash of its
// token (plans.HashToken), empty outside lea. The raw token never leaves the
// agent's process: the console only compares tokens, and a hash compares the
// same (it is just as replayable; the binding is no security boundary).
func RequesterFromEnv() ipc.Requester { return requesterFrom(os.Getenv) }

func requesterFrom(getenv func(string) string) ipc.Requester {
	return ipc.Requester{Agent: getenv(EnvAgent), Token: plans.HashToken(getenv(EnvAgentToken))}
}
