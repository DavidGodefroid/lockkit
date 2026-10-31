package console

// The rollback of hub mode, from when a console could start without its
// hub (standalone). A console is now hub-attached only (ErrNoHub); these
// stay for the products with their own console lifecycle that still call
// them, and go in the next minor release.

import (
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/ticket"
)

// StandaloneReason is the reason of the plans a standalone start
// withdraws, as the hub and the plans store record it.
//
// Deprecated: there is no standalone start any more.
const StandaloneReason = "the lock was restarted without its hub (standalone)"

// Withdrawn is what a standalone start withdrew from the hub mode of one
// instance.
//
// Deprecated: there is no standalone start any more.
type Withdrawn struct {
	Instance string
	// Tickets are the tickets withdrawn now.
	Tickets []string
}

// WithdrawStandalone was the rollback of hub mode (a console started
// without --hub after running with it). It is inert now: it withdraws
// nothing, touches no file and returns nil, nil. A console is hub-attached
// only (or policy-only, without plans), so there is no standalone start
// whose withdrawals it would do, and a call left in a product must not end
// the pending plans of a hub instance whose console is merely stopped.
//
// Deprecated: there is no standalone start any more; Run no longer calls
// it. It goes in the next minor release.
func WithdrawStandalone(kit.Product, string) ([]Withdrawn, error) { return nil, nil }

// WithdrawnResp is the explicit answer of a standalone console to a run
// of hub ticket tk: the ticket was withdrawn, plan again.
//
// Deprecated: there is no standalone console any more.
func WithdrawnResp(id int64, tk string) ipc.Response {
	if !ticket.ValidID(tk) {
		tk = "(not a ticket id)"
	}
	return ErrResp(id, ipc.CodeWithdrawn, "ticket "+tk+" was withdrawn: this lock now runs without its hub; "+
		"plan the request again, the human approves it on the lock's own terminal")
}
