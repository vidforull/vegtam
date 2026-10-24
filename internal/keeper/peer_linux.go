//go:build linux

package keeper

import (
	"bytes"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// peerSupported is set where the keeper can tell which process is at the
// other end of its socket.
const peerSupported = true

// peerOf returns the process at the other end of c, as SO_PEERCRED gives
// it: the one that connected, as it was when it did.
func peerOf(c syscall.Conn) (Peer, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Peer{UID: -1, PID: -1}, err
	}
	var cred *unix.Ucred
	cerr := raw.Control(func(fd uintptr) {
		cred, err = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err == nil {
		err = cerr
	}
	if err != nil {
		return Peer{UID: -1, PID: -1}, err
	}
	// A pid of 0 is a process that the keeper's pid namespace does not see.
	p := Peer{UID: int(cred.Uid), PID: int(cred.Pid), Name: procName(int(cred.Pid))}
	if p.PID <= 0 {
		p.PID = -1
	}
	return p, nil
}

// procName returns the name of the process pid, from /proc/pid/comm; ""
// if it cannot be read.
func procName(pid int) string {
	if pid <= 0 {
		return ""
	}
	f, err := os.OpenInRoot("/proc", strconv.Itoa(pid)+"/comm")
	if err != nil {
		return ""
	}
	b, err := io.ReadAll(io.LimitReader(f, maxName))
	if cerr := f.Close(); err != nil || cerr != nil {
		return ""
	}
	return processName(bytes.TrimSuffix(b, []byte("\n")))
}

// procParent returns the pid of the parent of the process pid, from
// /proc/pid/stat, or 0 if it cannot be read. The name in parentheses may
// hold spaces and parentheses itself: the fields after it are read from
// its last ")".
func procParent(pid int) int {
	f, err := os.OpenInRoot("/proc", strconv.Itoa(pid)+"/stat")
	if err != nil {
		return 0
	}
	b, err := io.ReadAll(io.LimitReader(f, 4096))
	if cerr := f.Close(); err != nil || cerr != nil {
		return 0
	}
	_, rest, ok := bytes.CutLast(b, []byte(")"))
	if !ok {
		return 0
	}
	fields := strings.Fields(string(rest)) // state, ppid, ...
	if len(fields) < 2 {
		return 0
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return ppid
}
