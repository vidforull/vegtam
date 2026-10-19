//go:build unix

package policy

import (
	"os"
	"syscall"
)

// ownedByUser reports whether fi belongs to the user vegtam runs as.
func ownedByUser(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return !ok || int(st.Uid) == os.Geteuid()
}
