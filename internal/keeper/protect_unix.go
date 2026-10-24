//go:build linux || darwin

package keeper

import "golang.org/x/sys/unix"

// privateUmask is the umask of the keeper: what it makes is its user's
// alone.
const privateUmask = 0o077

// Lock keeps b in memory, out of swap, as far as the system lets it: the
// memory a process may lock is limited (RLIMIT_MEMLOCK), so an error is
// to be expected, and the keeper goes on without. b must be one that make
// allocated, which stays where it is.
func Lock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Mlock(b)
}

// Unlock wipes b, then lets it go to swap again.
func Unlock(b []byte) error {
	Wipe(b)
	if len(b) == 0 {
		return nil
	}
	return unix.Munlock(b)
}
