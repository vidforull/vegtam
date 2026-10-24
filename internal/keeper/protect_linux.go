//go:build linux

package keeper

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Protect protects the keeper's process from the other processes of its
// user, such as the agent whose requests it sends, and returns what it
// could not do. What it makes is its user's alone (umask 077), and the
// process is not dumpable (PR_SET_DUMPABLE): another process of the user
// cannot attach to it with ptrace or read its memory in /proc/pid/mem,
// and it leaves no core dump. Root can still do both.
func Protect() []string {
	unix.Umask(privateUmask)
	var warnings []string
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		warnings = append(warnings, fmt.Sprintf("other processes of the user may read the keeper's memory: prctl(PR_SET_DUMPABLE): %v", err))
	}
	return warnings
}
