package ipc

// lockkit's own methods, served by every console. A product adds its own
// (its Backend's Methods). None of them loosens policy: change.request
// only queues a proposal that the console shows to the human.
const (
	MethodHello         = "hello"
	MethodStatus        = "status"
	MethodPIIList       = "pii.list"
	MethodPIIAdd        = "pii.add"
	MethodChangeRequest = "change.request"
	MethodLogout        = "logout"
)

// Error codes. The -320xx range is reserved by JSON-RPC for implementation
// errors; the standard codes are kept for protocol faults.
const (
	CodeRefused       = -32001 // the policy refused the request
	CodeDenied        = -32002 // the human denied
	CodeTimeout       = -32003 // no answer within the approval timeout
	CodeNoSuchPlan    = -32004 // unknown, used or expired plan id
	CodeConnLost      = -32005 // the backend connection was lost
	CodePolicyPending = -32006 // a policy change awaits the human
	// CodeWrongRequester: in hub mode, a plan or ticket presented by
	// another agent than the one that made it (Requester.Token).
	CodeWrongRequester = -32007

	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603
)

// Requester is the agent behind a request, as its MCP server reports it
// (mcpkit.RequesterFromEnv): the agent's name and its lea token. A product
// carries it in the params of its plan and run methods; in hub mode the
// console binds a plan to the token (stored hashed) and refuses it to
// another token with CodeWrongRequester. Agents of one UID can read each
// other's token: this catches mistakes, it is no security boundary.
type Requester struct {
	Agent string `json:"agent,omitempty"`
	Token string `json:"token,omitempty"`
}

// HelloParams opens a session; Client is a free-form name and version.
type HelloParams struct {
	ProtocolMajor int    `json:"protocol_major"`
	Client        string `json:"client,omitempty"`
}

// HelloResult answers hello.
type HelloResult struct {
	ProtocolMajor  int    `json:"protocol_major"`
	ConsoleVersion string `json:"console_version,omitempty"`
	Profile        string `json:"profile"`
}

// PIIListResult answers pii.list with the mask and allow rules in force.
type PIIListResult struct {
	Mask  []string `json:"mask"`
	Allow []string `json:"allow"`
}

// PIIAddParams proposes a mask rule (its syntax is the product's).
type PIIAddParams struct {
	Pattern string `json:"pattern"`
}

// ChangeParams queues a policy change proposal for the human.
type ChangeParams struct {
	Change string `json:"change"`
}

// ChangeResult answers change.request.
type ChangeResult struct {
	Queued bool `json:"queued"`
}
