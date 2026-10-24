package keeper

import (
	"strconv"
	"strings"
)

// Peer is the process at the other end of a connection to the keeper, as
// the kernel says, and not as the process says of itself: its user and
// its pid, -1 where they are not known, and its name, "" if it is not.
// The name is the one the process gave itself, which says little: the
// uid and the pid are what tell one process from another.
type Peer struct {
	UID  int
	PID  int
	Name string
}

// String returns p as the keeper shows it to its person, such as
// "pid 4242 (agent) uid 501".
func (p Peer) String() string {
	var b strings.Builder
	if p.PID >= 0 {
		b.WriteString("pid " + strconv.Itoa(p.PID))
	} else {
		b.WriteString("pid unknown")
	}
	if p.Name != "" {
		b.WriteString(" (" + p.Name + ")")
	}
	if p.UID >= 0 {
		b.WriteString(" uid " + strconv.Itoa(p.UID))
	} else {
		b.WriteString(" uid unknown")
	}
	return b.String()
}
