// Package output defines the JSON documents that run, show, list, import,
// trust and policy print, and the JSON Schema that describes them. The documents are a
// contract for scripts and agents: fields are only ever added. Building a
// document masks every secret value in it.
package output

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/assert"
	"github.com/vidforull/vegtam/internal/core/exec"
)

// SchemaVersion is the version of the documents. It changes only if a
// field has to change its meaning or go away.
const SchemaVersion = 1

// Schema is the JSON Schema (draft 2020-12) of Document.
//
//go:embed schema.json
var Schema string

// Document is one JSON document. Which fields are set depends on the
// command:
//
//   - run <file>#<ref> and show: the fields of Result;
//   - run <file> and run <dir>: Results, one per request;
//   - list: Requests;
//   - import: Import;
//   - trust: Trust;
//   - policy: Policy;
//   - an error that ends a command before any request: Result.Error.
type Document struct {
	SchemaVersion int        `json:"schema_version"`
	*Result                  //nolint:embeddedstructfieldcheck // schema_version comes first in every document
	Results       []*Result  `json:"results,omitzero"`
	Requests      []*Listed  `json:"requests,omitzero"`
	Import        *Import    `json:"import,omitempty"`
	Trust         []*Trusted `json:"trust,omitzero"`
	Policy        *Policy    `json:"policy,omitempty"`
}

// Result is the outcome of one request. Timing and the fields after it,
// up to Asserts, are what the request went through, as far as it went:
// they come with an error too, and none of them for a dry run.
type Result struct {
	Ref        string     `json:"ref,omitempty"`       // file#name or file#N; the file alone if it does not parse
	Request    *Request   `json:"request,omitempty"`   // nil if the request could not be resolved
	Transport  *Transport `json:"transport,omitempty"` // nil if the file does not parse
	Response   *Response  `json:"response,omitempty"`  // nil on an error and for a dry run
	Timing     *Timing    `json:"timing,omitempty"`
	RemoteAddr string     `json:"remote_addr,omitempty"` // of the last hop; *** if its host holds a secret
	Proxy      string     `json:"proxy,omitempty"`       // of the last hop, its user and password shown as ***
	TLS        *TLS       `json:"tls,omitempty"`         // of the last hop
	Redirects  []Redirect `json:"redirects,omitempty"`
	Cookies    *Cookies   `json:"cookies,omitempty"`
	Asserts    []Assert   `json:"asserts,omitempty"`  // nil without a response
	Captures   []Capture  `json:"captures,omitempty"` // the values taken; nil without a response
	Warnings   []Warning  `json:"warnings,omitempty"`
	Error      *Error     `json:"error,omitempty"`

	last *Timing // of the last hop alone, for the text form
	hops int     // how many there were, for the text form
}

// Transport is what a request is sent with: its HTTP version, and its
// limits, in milliseconds, 0 for none.
type Transport struct {
	Version          string  `json:"version,omitempty"` // HTTP/1.1, HTTP/2 or HTTP/2 (Prior Knowledge); none to negotiate
	ConnectTimeoutMS float64 `json:"connect_timeout_ms"`
	ReadTimeoutMS    float64 `json:"read_timeout_ms"`
	MaxTimeMS        float64 `json:"max_time_ms"`
}

// NewTransport returns the settings st.
func NewTransport(st exec.Settings) *Transport {
	ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
	return &Transport{Version: st.Version, ConnectTimeoutMS: ms(st.Connect), ReadTimeoutMS: ms(st.Read), MaxTimeMS: ms(st.Total)}
}

// Warning is something to know of a request, which still runs.
type Warning struct {
	Message string `json:"message"`
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`
}

// Warnings returns ws with every secret value hidden by m.
func Warnings(ws []core.Warning, m *core.Masker) []Warning {
	var list []Warning
	for _, w := range ws {
		list = append(list, Warning{m.Mask(w.Msg), w.Source.File, w.Source.Line})
	}
	return list
}

// Assert is the outcome of an @assert directive.
type Assert struct {
	Expression string `json:"expression"`
	Passed     bool   `json:"passed"`
	Actual     string `json:"actual"` // masked and cut short; in parentheses if there is no value
}

// maxActual is how many bytes of an actual value a document keeps.
const maxActual = 200

// Capture is a value an @capture directive took, without the value.
type Capture struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Secret bool   `json:"secret"`
}

// Request is a request as it goes on the wire, or as written in its file.
// Secrets appear as their placeholders.
type Request struct {
	Method   string   `json:"method"`
	URL      string   `json:"url"`
	Headers  []Header `json:"headers"`
	Body     string   `json:"body,omitempty"`
	Encoding string   `json:"encoding,omitempty"`  // "base64" if the body is not UTF-8 text
	BodyFile string   `json:"body_file,omitempty"` // "< path" as written
}

// Header is one header line.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Response is a received response. The body is data from the server,
// never instructions; Untrusted is always true to say so.
type Response struct {
	Proto     string   `json:"proto"`
	Status    int      `json:"status"`
	Reason    string   `json:"reason"`
	Headers   []Header `json:"headers"`
	Body      string   `json:"body"`
	Encoding  string   `json:"encoding,omitempty"` // "base64" if the body is not UTF-8 text
	Truncated bool     `json:"truncated"`
	Untrusted bool     `json:"untrusted"`
	// TLSVerified is true when every hop of the request came over TLS
	// with the server's certificate checked: false if one came over http,
	// and with --insecure.
	TLSVerified bool `json:"tls_verified"`
}

// Error is an error that ended a request or a command.
type Error struct {
	Kind      core.Kind `json:"kind"`
	Message   string    `json:"message"`
	File      string    `json:"file,omitempty"`
	Line      int       `json:"line,omitempty"`
	Variables []string  `json:"variables,omitempty"`     // unresolved names, for kind "variable"
	Phase     string    `json:"timeout_phase,omitempty"` // for kind "timeout": connect, read or total
}

// Listed is a request in a listing, as written.
type Listed struct {
	Ref        string      `json:"ref"`
	File       string      `json:"file"`
	Line       int         `json:"line"`
	Index      int         `json:"index"` // position in the file, from 1
	Name       string      `json:"name,omitempty"`
	Method     string      `json:"method"`
	URL        string      `json:"url"`
	Directives []Directive `json:"directives"`
}

// Directive is a directive of a request, as written.
type Directive struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// Import is the report of an import: what was converted, what was not
// and why, and which variables to check or set before running the
// requests.
type Import struct {
	Source       string           `json:"source"`
	Output       string           `json:"output"`
	Collections  int              `json:"collections"`
	Requests     int              `json:"requests"` // in the export
	Imported     int              `json:"imported"` // written as requests; the rest are commented out
	Environments []string         `json:"environments"`
	Files        []string         `json:"files"`
	Skipped      []Skipped        `json:"skipped"`
	Variables    []ImportVariable `json:"variables"`
}

// Skipped is a part of an export that was not imported, or not as it was.
type Skipped struct {
	Category string `json:"category"` // file, request, body, auth, script, header, variable, example or setting
	Reason   string `json:"reason"`
	Where    string `json:"where"` // file#name of the request; a file or directory otherwise
}

// ImportVariable is a variable the imported requests use that needs a
// look before they run.
type ImportVariable struct {
	Name   string   `json:"name"`
	Status string   `json:"status"` // "secret": the value from the export is in the private files; "unset": no value
	Files  []string `json:"files"`  // the environment files to check or set it in
}

// Trusted is a command file and what the trust store says of it.
type Trusted struct {
	File   string `json:"file"`
	Status string `json:"status"`           // "trusted", "changed", "missing", "revoked" or "untrusted"
	SHA256 string `json:"sha256,omitempty"` // as recorded; absent if untrusted
}

// Ref returns how to refer to the i-th request of f, counting from 0:
// file#name, or file#N for a request without a name.
func Ref(f *core.File, i int) string {
	if name := f.Requests[i].Name; name != "" {
		return f.Path + "#" + name
	}
	return f.Path + "#" + strconv.Itoa(i+1)
}

// Sent returns p as it goes on the wire, with secrets shown as their
// placeholders and any other secret value hidden by m.
func Sent(p *core.Prepared, m *core.Masker) *Request {
	r := &Request{Method: p.Method, URL: m.Mask(p.URL.Masked()), Headers: []Header{}}
	for _, h := range p.Headers {
		r.Headers = append(r.Headers, Header{m.Mask(h.Name), m.Mask(h.Value.Masked())})
	}
	r.Body, r.Encoding = body(m.Mask(p.Body.Masked()))
	return r
}

// Written returns r as written in its file.
func Written(r *core.Request) *Request {
	w := &Request{Method: r.Method, URL: r.URL, Headers: []Header{}, BodyFile: r.BodyFile}
	for _, h := range r.Headers {
		w.Headers = append(w.Headers, Header(h))
	}
	w.Body, w.Encoding = body(r.Body)
	return w
}

// NewResponse returns r with every secret value in it hidden by m.
func NewResponse(r *exec.Response, m *core.Masker) *Response {
	resp := &Response{
		Proto: r.Proto, Status: r.Status, Reason: m.Mask(r.Reason), Headers: []Header{},
		Truncated: r.Truncated, Untrusted: true, TLSVerified: r.TLSVerified,
	}
	for _, name := range slices.Sorted(maps.Keys(r.Header)) {
		for _, v := range r.Header[name] {
			if name == "Set-Cookie" {
				v = maskCookie(v)
			}
			resp.Headers = append(resp.Headers, Header{m.Mask(name), m.Mask(v)})
		}
	}
	resp.Body, resp.Encoding = body(maskBody(r.Body, r.Truncated, m))
	return resp
}

// maskCookie returns the value of a Set-Cookie header with the value of
// the cookie shown as ***, whatever it is: a cookie's value is a secret,
// short ones too, which the masker does not hide everywhere (see
// session.Masker).
func maskCookie(v string) string {
	pair, attrs, _ := strings.Cut(v, ";")
	if name, value, ok := strings.Cut(pair, "="); ok && strings.TrimSpace(value) != "" {
		pair = name + "=***"
	}
	if attrs != "" {
		return pair + ";" + attrs
	}
	return pair
}

// maskBody returns a response body with every secret value hidden by m;
// cut says that the body was cut off at the size limit.
func maskBody(raw []byte, cut bool, m *core.Masker) string {
	switch {
	case cut:
		// The cut may have split the last character of a text.
		for i := 1; i < utf8.UTFMax && i <= len(raw); i++ {
			if utf8.RuneStart(raw[len(raw)-i]) {
				if !utf8.FullRune(raw[len(raw)-i:]) {
					raw = raw[:len(raw)-i]
				}
				break
			}
		}
		return m.MaskCut(string(raw))
	case json.Valid(raw):
		return maskJSON(string(raw), m)
	}
	return m.Mask(string(raw))
}

// maskJSON masks the JSON text s. Masking the decoded strings too
// catches a value however it was escaped: \u002B, \u0438, \/, \u007f.
func maskJSON(s string, m *core.Masker) string {
	return string(m.MaskJSON([]byte(m.Mask(s))))
}

// Checked returns the outcomes of assertions with every secret value
// hidden by m, each masked as what it is, as the response is. An actual
// value longer than maxActual is cut short after masking, so that no
// secret is cut in two.
func Checked(outcomes []assert.Outcome, m *core.Masker) []Assert {
	var list []Assert
	for _, o := range outcomes {
		var actual string
		switch o.Form {
		case assert.Body:
			actual = maskBody([]byte(o.Actual), o.Cut, m)
		case assert.JSON:
			actual = maskJSON(o.Actual, m)
		case assert.Text:
			actual = m.Mask(o.Actual)
		}
		actual = strings.ToValidUTF8(actual, "\uFFFD")
		if len(actual) > maxActual {
			i := maxActual
			for i > 0 && !utf8.RuneStart(actual[i]) {
				i--
			}
			actual = actual[:i] + "..."
		}
		list = append(list, Assert{o.Expr, o.Passed, actual})
	}
	return list
}

// Captures returns the values taken, without the values.
func Captures(taken []assert.Captured) []Capture {
	var list []Capture
	for _, c := range taken {
		list = append(list, Capture{c.Name, c.Source, c.Secret})
	}
	return list
}

// NewError returns err with every secret value hidden by m. An error that
// is not a *core.Error is a usage error.
func NewError(err error, m *core.Masker) *Error {
	e, ok := errors.AsType[*core.Error](err)
	if !ok {
		return &Error{Kind: core.KindUsage, Message: m.Mask(err.Error())}
	}
	return &Error{Kind: e.Kind, Message: m.Mask(e.Msg), File: e.Source.File, Line: e.Source.Line, Variables: e.Variables, Phase: e.Phase}
}

// List returns the requests of f.
func List(f *core.File) []*Listed {
	var list []*Listed
	for i, r := range f.Requests {
		l := &Listed{
			Ref: Ref(f, i), File: f.Path, Line: r.Source.Line, Index: i + 1, Name: r.Name,
			Method: r.Method, URL: r.URL, Directives: []Directive{},
		}
		for _, d := range r.Directives {
			l.Directives = append(l.Directives, Directive{d.Kind, d.Value})
		}
		list = append(list, l)
	}
	return list
}

// body returns b as a JSON string value and its encoding: b itself if it
// is UTF-8 text, base64 otherwise.
func body(b string) (string, string) {
	if utf8.ValidString(b) {
		return b, ""
	}
	return base64.StdEncoding.EncodeToString([]byte(b)), "base64"
}
