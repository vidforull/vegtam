//go:build !linux && !darwin

package keeper

import "os"

// waitReadable returns at once, unless quit is closed: here a file is
// read as it is, and the keeper does not run (see Listen).
func waitReadable(_ *os.File, quit <-chan struct{}) error {
	select {
	case <-quit:
		return errStopped
	default:
		return nil
	}
}
