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
	KindConfirm  Kind = "confirm"  // the request needs a confirmation that the run does not give
	KindPolicy   Kind = "policy"   // policy does not allow it: a command file that is not trusted, an address the network guard refuses, a policy file that cannot be read
	KindCanceled Kind = "canceled" // the run was interrupted before the request or its command finished
)

// Error is an error of a known kind, tied to a place in a file when there
// is one.
type Error struct {
	Kind      Kind
	Source    Source
	Msg       string
	Variables []string      // unresolved names, for KindVariable
	Phase     string        // what a KindTimeout ended: PhaseConnect, PhaseRead or PhaseTotal; "" if not known
	Confirm   *Confirmation // what a KindConfirm asks for
	// Secret is the first secret that the request would send to an origin
	// it is not bound to, for the KindPolicy or KindConfirm of that; or
	// the first that a run without a person holds no value of.
	Secret *Bound
	// PersonCommand is the command a person at a terminal runs to send
	// the request, for the KindPolicy of a run without a person that holds
	// no value of its Secret.
	PersonCommand string
}

// Confirmation is what a request that is not sent without a confirmation
// asks for.
type Confirmation struct {
	Reason string // ReasonMethod, ReasonNote or ReasonSecret
	Method string
	URL    string  // as written, its placeholders unresolved
	Note   *string // the text of its @note, which may be empty; nil if it has none
	Flag   string  // what confirms it, such as --confirm=api.http#create
	// Secret is the first secret that the request would send to an origin
	// it is not bound to, whatever the reason; nil for none.
	Secret *Bound
}

// Why a request needs a confirmation.
const (
	ReasonMethod = "method" // its method may change something, and no person is at a terminal
	ReasonNote   = "note"   // it has an @note, which asks a person to confirm it
	// ReasonSecret: it would send a secret to an origin the secret is not
	// bound to, and a person at a terminal may confirm that; without one,
	// nothing does.
	ReasonSecret = "secret"
)

// Errorf returns an *Error of kind k at src.
func Errorf(k Kind, src Source, format string, args ...any) *Error {
	return &Error{Kind: k, Source: src, Msg: fmt.Sprintf(format, args...)}
}

// Warning is something to know of a request or a file, which does not
// stop it.
type Warning struct {
	Source Source `json:"source"`
	Msg    string `json:"message"`
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
