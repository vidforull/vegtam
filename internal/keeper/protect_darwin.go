//go:build darwin

package keeper

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Protect protects the keeper's process from the other processes of its
// user, such as the agent whose requests it sends, and returns what it
// could not do. What it makes is its user's alone (umask 077); no
// debugger may attach to it (ptrace PT_DENY_ATTACH), nor read its memory
// through one; and it leaves no core dump (RLIMIT_CORE 0, which it cannot
// raise again). Root can still read its memory.
//
// No test runs this: the tests run on Linux. PT_DENY_ATTACH is also why a
// keeper cannot be debugged on macOS.
func Protect() []string {
	unix.Umask(privateUmask)
	var warnings []string
	if err := unix.PtraceDenyAttach(); err != nil {
		warnings = append(warnings, fmt.Sprintf("a debugger may attach to the keeper: ptrace(PT_DENY_ATTACH): %v", err))
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		warnings = append(warnings, fmt.Sprintf("the keeper may leave a core dump: setrlimit(RLIMIT_CORE): %v", err))
	}
	return warnings
}
