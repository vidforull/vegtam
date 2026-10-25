//go:build unix

package policy

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// openFile opens name, a file of the directory of root, to read it. A
// named pipe put in its place after the check of its name opens at once,
// rather than wait for a writer, and the check of the open file refuses
// it; a symbolic link does not open.
func openFile(root *os.Root, name string) (*os.File, error) {
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	fd, oerr := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err = dir.Close(); err != nil && oerr == nil {
		return nil, errors.Join(err, unix.Close(fd))
	}
	if oerr != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: oerr}
	}
	return os.NewFile(uintptr(fd), name), nil
}
