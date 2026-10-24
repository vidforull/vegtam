//go:build darwin

package keeper

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// peerSupported is set where the keeper can tell which process is at the
// other end of its socket.
const peerSupported = true

// peerOf returns the process at the other end of c: its user as
// LOCAL_PEERCRED gives it, its pid as LOCAL_PEERPID does.
func peerOf(c syscall.Conn) (Peer, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Peer{UID: -1, PID: -1}, err
	}
	var (
		cred *unix.Xucred
		pid  int
	)
	cerr := raw.Control(func(fd uintptr) {
		cred, err = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err == nil {
			pid, err = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		}
	})
	if err == nil {
		err = cerr
	}
	if err != nil {
		return Peer{UID: -1, PID: -1}, err
	}
	p := Peer{UID: int(cred.Uid), PID: pid, Name: procName(pid)}
	if p.PID <= 0 {
		p.PID = -1
	}
	return p, nil
}

// procName returns the name of the process pid, as the kernel keeps it
// (kern.proc.pid); "" if it cannot be had.
func procName(pid int) string {
	if pid <= 0 {
		return ""
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return ""
	}
	return processName([]byte(unix.ByteSliceToString(kp.Proc.P_comm[:])))
}

// procParent returns the pid of the parent of the process pid, or 0 if it
// cannot be told.
func procParent(pid int) int {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0
	}
	return int(kp.Eproc.Ppid)
}
