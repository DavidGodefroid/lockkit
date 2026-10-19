package ipc

import "errors"

// ErrUnsupported is returned on a platform where the console's socket and
// its peer checks do not exist (Windows): products run there inside WSL2.
var ErrUnsupported = errors.New("not supported on Windows: run it inside WSL2")
