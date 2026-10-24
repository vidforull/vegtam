//go:build unix

package policy

import (
	"os"
	"syscall"
)

// Owner returns the user that fi belongs to, by uid; false where the
// system does not say.
func Owner(fi os.FileInfo) (uid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

// OwnedByUser reports whether fi belongs to the user vegtam runs as.
func OwnedByUser(fi os.FileInfo) bool {
	uid, ok := Owner(fi)
	return !ok || uid == os.Geteuid()
}
