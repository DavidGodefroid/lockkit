package console

// The rollback of hub mode, from when a console could start without its
// hub (standalone). A console is now hub-attached only (ErrNoHub); these
// stay for the products with their own console lifecycle that still call
// them, and go in the next minor release.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/plans"
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

// WithdrawStandalone is the rollback of hub mode (a console started
// without --hub after running with it): every pending plan of every hub
// instance under stateDir (as Options.StateDir) ends Withdrawn, marked for
// the hub to hear of at the next start in hub mode
// (hubclient.Client.Sync). An instance whose plans another console holds
// open (plans.ErrLocked: it runs in hub mode now) is left alone.
//
// Deprecated: there is no standalone start any more; Run no longer calls
// it.
func WithdrawStandalone(p kit.Product, stateDir string) ([]Withdrawn, error) {
	dirs, err := filepath.Glob(filepath.Join(stateDir, p.Name, "hub", "*", "plans"))
	if err != nil {
		return nil, err
	}
	sort.Strings(dirs)
	var out []Withdrawn
	var errs []error
	for _, d := range dirs {
		if fi, err := os.Lstat(d); err != nil || !fi.IsDir() {
			continue
		}
		inst := filepath.Base(filepath.Dir(d))
		st, err := plans.Open(d)
		if errors.Is(err, plans.ErrLocked) {
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("hub plans of %s: %w", inst, err))
			continue
		}
		ws, err := st.WithdrawAll(StandaloneReason)
		_ = st.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("hub plans of %s: %w", inst, err))
		}
		if len(ws) == 0 {
			continue
		}
		w := Withdrawn{Instance: inst}
		for _, pl := range ws {
			w.Tickets = append(w.Tickets, pl.Ticket)
		}
		out = append(out, w)
	}
	return out, errors.Join(errs...)
}

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
