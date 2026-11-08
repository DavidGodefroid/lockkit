package hubclient

// SetBeforeDenialEnd runs f in Begin between its read of a pending plan
// and its End of the plan on a denial: a test injects EndDenied there.
func SetBeforeDenialEnd(f func()) (restore func()) {
	old := beforeDenialEnd
	beforeDenialEnd = f
	return func() { beforeDenialEnd = old }
}
