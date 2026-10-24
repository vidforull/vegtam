package keeper

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// The tests of Protect run on Linux. Those of macOS are not run: whether
// PT_DENY_ATTACH keeps a debugger out, and RLIMIT_CORE a core dump. Nor
// is what Lock does under a small RLIMIT_MEMLOCK, which the test does not
// lower: the keeper goes on without the lock.

func TestProtect(t *testing.T) {
	// Tests share the process: what Protect changes is put back.
	old := unix.Umask(0o022)
	unix.Umask(old)
	t.Cleanup(func() {
		unix.Umask(old)
		if err := unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0); err != nil {
			t.Error(err)
		}
	})
	if warnings := Protect(); len(warnings) != 0 {
		t.Errorf("warnings: %q", warnings)
	}
	if mask := unix.Umask(old); mask != privateUmask {
		t.Errorf("umask %#o, want %#o", mask, privateUmask)
	}
	// Not dumpable: other processes of the user cannot attach to it, nor
	// read /proc/pid/mem.
	if d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err != nil || d != 0 {
		t.Errorf("dumpable %d, %v; want 0", d, err)
	}
}

func TestLock(t *testing.T) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4096)
	err := Lock(b)
	// A page is locked wherever the limit allows one.
	if lim.Cur >= 2*4096 && err != nil {
		t.Errorf("Lock: %v (RLIMIT_MEMLOCK %d)", err, lim.Cur)
	}
	if err == nil {
		if err := Unlock(b); err != nil {
			t.Error(err)
		}
	}
}

// TestProcParent checks that the keeper finds the parent of a process, as
// it walks its ancestors for a multiplexer: its own is its parent's.
func TestProcParent(t *testing.T) {
	if got := procParent(os.Getpid()); got != os.Getppid() {
		t.Errorf("procParent = %d, want %d", got, os.Getppid())
	}
	if got := procParent(-1); got != 0 {
		t.Errorf("procParent(-1) = %d", got)
	}
}
