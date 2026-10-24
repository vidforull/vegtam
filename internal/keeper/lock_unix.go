//go:build linux || darwin

package keeper

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// maxSocketPath is the longest path a unix socket may have here, its
// terminating NUL aside.
const maxSocketPath = len(unix.RawSockaddrUnix{}.Path) - 1

// lockFile takes the lock of the file at path, made if it is missing, and
// writes the process's pid in it; it returns its descriptor, which holds
// the lock until unlockFile, or until the process ends. The file is
// written in place, not renamed over: the lock is the file's, and a new
// one would hold none. A lock that another process holds is an error that
// names its pid.
func lockFile(path string) (int, error) {
	// A keeper that stops removes the file, and one that starts then makes
	// another: the file locked must still be the one at path.
	for range 3 {
		fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err != nil {
			return -1, err
		}
		if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); errors.Is(err, unix.EWOULDBLOCK) {
			running := errors.New("a keeper already runs on this socket")
			if pid := lockPID(fd); pid > 0 {
				running = fmt.Errorf("a keeper already runs on this socket, pid %d", pid)
			}
			return -1, errors.Join(running, unix.Close(fd))
		} else if err != nil {
			return -1, errors.Join(err, unix.Close(fd))
		}
		var held, now unix.Stat_t
		if unix.Fstat(fd, &held) == nil && unix.Lstat(path, &now) == nil && held.Dev == now.Dev && held.Ino == now.Ino {
			pid := []byte(strconv.Itoa(os.Getpid()) + "\n")
			err := unix.Ftruncate(fd, 0)
			if err == nil {
				_, err = unix.Pwrite(fd, pid, 0)
			}
			if err != nil {
				return -1, errors.Join(err, unix.Close(fd))
			}
			return fd, nil
		}
		if err := unix.Close(fd); err != nil {
			return -1, err
		}
	}
	return -1, fmt.Errorf("%s changes as it is locked: is another keeper starting?", path)
}

// lockPID returns the pid written in the lock file fd; 0 if there is none.
func lockPID(fd int) int {
	var b [32]byte
	n, err := unix.Pread(fd, b[:], 0)
	if err != nil || n <= 0 {
		return 0
	}
	pid, err := strconv.Atoi(string(bytes.TrimSpace(b[:n])))
	if err != nil {
		return 0
	}
	return pid
}

// unlockFile removes the lock file at path, held at fd, then lets the
// lock go.
func unlockFile(fd int, path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return errors.Join(err, unix.Close(fd))
}
