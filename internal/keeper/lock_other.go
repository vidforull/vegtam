//go:build !linux && !darwin

package keeper

import "errors"

// maxSocketPath is the longest path a unix socket may have, as Linux has
// it: the keeper does not listen here (see Listen).
const maxSocketPath = 107

// lockFile is an error: the keeper does not listen here.
func lockFile(string) (int, error) { return -1, errors.New("the keeper runs on Linux and macOS") }

// unlockFile does nothing: no lock is taken here.
func unlockFile(int, string) error { return nil }
