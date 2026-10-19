package console

import "errors"

// Harden cannot disable core dumps on Windows: a production profile is
// refused, as on a failed Harden elsewhere.
func Harden() error {
	return errors.New("process hardening is not supported on Windows")
}
