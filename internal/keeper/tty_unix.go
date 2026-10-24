//go:build linux || darwin

package keeper

import (
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// pollInterval is how long waitReadable waits at a time before it looks
// at quit again.
const pollInterval = 100 * time.Millisecond

// waitReadable waits until f has something to read, or its end, or quit
// is closed: errStopped then. It asks select(2), which, unlike poll(2) on
// macOS, takes a terminal, and leaves the file's mode as it is: a terminal
// that the keeper's shell shares stays blocking.
func waitReadable(f *os.File, quit <-chan struct{}) error {
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	for {
		select {
		case <-quit:
			return errStopped
		default:
		}
		ready := false
		var serr error
		err := raw.Control(func(fd uintptr) {
			if fd >= unix.FD_SETSIZE {
				serr = fmt.Errorf("descriptor %d is beyond what select takes", fd)
				return
			}
			var set unix.FdSet
			set.Set(int(fd))
			tv := unix.NsecToTimeval(pollInterval.Nanoseconds())
			n, err := unix.Select(int(fd)+1, &set, nil, nil, &tv)
			switch {
			case errors.Is(err, unix.EINTR):
			case err != nil:
				serr = err
			default:
				ready = n > 0
			}
		})
		switch {
		case err != nil:
			return err
		case serr != nil:
			return serr
		case ready:
			return nil
		}
	}
}
