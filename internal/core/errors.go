package core

import "fmt"

// Kind classifies an Error. The CLI maps kinds to exit codes, and they
// appear as is in JSON output.
type Kind string

const (
	KindUsage    Kind = "usage"    // bad arguments or paths
	KindParse    Kind = "parse"    // a .http or environment file does not parse
	KindVariable Kind = "variable" // a placeholder cannot be resolved
	KindRequest  Kind = "request"  // the resolved request is invalid: URL, header, body file
	KindNetwork  Kind = "network"  // DNS, connection, TLS, redirects
	KindTimeout  Kind = "timeout"  // no complete response within the timeout
)

// Error is an error of a known kind, tied to a place in a file when there
// is one.
type Error struct {
	Kind      Kind
	Source    Source
	Msg       string
	Variables []string // unresolved names, for KindVariable
}

// Errorf returns an *Error of kind k at src.
func Errorf(k Kind, src Source, format string, args ...any) *Error {
	return &Error{Kind: k, Source: src, Msg: fmt.Sprintf(format, args...)}
}

func (e *Error) Error() string {
	if e.Source.File == "" {
		return e.Msg
	}
	return e.Source.String() + ": " + e.Msg
}
