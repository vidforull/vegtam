//go:build !linux && !darwin

package keeper

import (
	"errors"
	"syscall"
)

// peerSupported is set where the keeper can tell which process is at the
// other end of its socket: not here, so it does not listen (see Listen).
const peerSupported = false

// peerOf returns an unknown Peer: this system does not say.
func peerOf(syscall.Conn) (Peer, error) {
	return Peer{UID: -1, PID: -1}, errors.New("this system does not say which process is at the other end of a unix socket")
}

// procName returns "": the name of a process is not known here.
func procName(int) string { return "" }

func procParent(int) int { return 0 }
