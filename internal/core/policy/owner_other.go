//go:build !unix

package policy

import "os"

// ownedByUser reports whether fi belongs to the user vegtam runs as.
// Without Unix owners, permission bits are all the store checks.
func ownedByUser(os.FileInfo) bool { return true }
