//go:build !unix

package policy

import "os"

// openFile opens name, a file of the directory of root, to read it.
// Without named pipes, nothing can block the open.
func openFile(root *os.Root, name string) (*os.File, error) { return root.Open(name) }
