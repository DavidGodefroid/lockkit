package ipc

import (
	"fmt"
	"net"

	"github.com/DavidGodefroid/lockkit/kit"
)

// On Windows the console's socket is not served: it would need a named
// pipe ACL'd to a dedicated account, which lockkit does not implement.
// Every entry point refuses, so a console never listens without its peer
// checks.

func privateDir(string) error { return fmt.Errorf("ipc: console socket %w", ErrUnsupported) }

func restrictSocket(string) error { return fmt.Errorf("ipc: console socket %w", ErrUnsupported) }

// ListenShared refuses on Windows.
func ListenShared(kit.Product, string, int) (net.Listener, error) {
	return nil, fmt.Errorf("ipc: console socket %w", ErrUnsupported)
}
