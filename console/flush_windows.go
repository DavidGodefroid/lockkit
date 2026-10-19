package console

import (
	"errors"
	"os"
)

var errNoTerminal = errors.New("console: terminal control is not supported on Windows: run it inside WSL2")

// flushInput refuses on Windows: type-ahead could not be discarded before
// a prompt.
func flushInput(*os.File) error { return errNoTerminal }

// echoOff refuses on Windows.
func echoOff(*os.File) (func(), error) { return nil, errNoTerminal }
