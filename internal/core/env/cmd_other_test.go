//go:build !unix || aix || solaris

package env

// leadsGroup reports true: there is nothing to check.
func leadsGroup() bool { return true }
