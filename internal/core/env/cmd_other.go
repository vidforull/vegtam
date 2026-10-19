//go:build !unix

package env

import (
	"os"
	"syscall"
)

// detached starts a command as any other: without Unix sessions there is
// no controlling terminal to take away.
func detached() *syscall.SysProcAttr { return nil }

// kill kills p.
func kill(p *os.Process) error { return p.Kill() }
