//go:build !unix

package policy

import "os"

// Owner returns the user that fi belongs to: without Unix owners, none.
func Owner(os.FileInfo) (uid int, ok bool) { return 0, false }

// OwnedByUser reports whether fi belongs to the user vegtam runs as.
// Without Unix owners, permission bits are all the store checks.
func OwnedByUser(os.FileInfo) bool { return true }
