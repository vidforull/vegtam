//go:build !linux && !darwin

package keeper

import "errors"

// Protect does nothing here, and says so: the keeper runs on Linux and
// macOS (see Listen).
func Protect() []string {
	return []string{"the keeper cannot protect its memory from the other processes of its user on this system"}
}

// Lock does nothing here: memory is not locked.
func Lock([]byte) error { return errors.New("memory is not locked on this system") }

// Unlock wipes b.
func Unlock(b []byte) error {
	Wipe(b)
	return nil
}
