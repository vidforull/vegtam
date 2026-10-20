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
	KindStatus   Kind = "status"   // the response status is 400 or above, and the caller counts that as failure
	KindImport   Kind = "import"   // an export from another tool cannot be read
	KindAssert   Kind = "assert"   // an @assert check on the response failed
	KindCapture  Kind = "capture"  // an @capture found no value in the response
	KindPolicy   Kind = "policy"   // policy does not allow it: a command file that is not trusted, an address the network guard refuses, a policy file that cannot be read
	KindCanceled Kind = "canceled" // the run was interrupted before the request or its command finished
)

// Error is an error of a known kind, tied to a place in a file when there
// is one.
type Error struct {
	Kind      Kind
	Source    Source
	Msg       string
	Variables []string // unresolved names, for KindVariable
	Phase     string   // what a KindTimeout ended: PhaseConnect, PhaseRead or PhaseTotal; "" if not known
}

// Errorf returns an *Error of kind k at src.
func Errorf(k Kind, src Source, format string, args ...any) *Error {
	return &Error{Kind: k, Source: src, Msg: fmt.Sprintf(format, args...)}
}

// Warning is something to know of a request or a file, which does not
// stop it.
type Warning struct {
	Source Source
	Msg    string
}

func (w Warning) String() string {
	if w.Source.File == "" {
		return w.Msg
	}
	return w.Source.String() + ": " + w.Msg
}

func (e *Error) Error() string {
	if e.Source.File == "" {
		return e.Msg
	}
	return e.Source.String() + ": " + e.Msg
}
