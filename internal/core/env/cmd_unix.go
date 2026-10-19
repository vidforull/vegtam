//go:build unix

package env

import (
	"errors"
	"os"
	"syscall"
)

// detached starts a command in a session of its own, which has no
// controlling terminal.
func detached() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true} }

// kill kills p and the processes it started that are still in its
// process group: in a session of its own, they no longer get the
// terminal's Ctrl-C.
func kill(p *os.Process) error {
	err := syscall.Kill(-p.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}
