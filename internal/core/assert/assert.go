// Package assert checks responses against the @assert directives of their
// requests and takes values from them for @capture directives;
// docs/FORMAT.md describes both. httpfile parses the directives as it
// reads a file, so a directive that does not parse is an error in the
// file.
package assert

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/itchyny/gojq"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/exec"
)

// Assert is a parsed @assert directive.
type Assert struct {
	Expr  string // as written
	Line  int
	form  Form
	check func(*Response) (passed bool, actual string)
}

// Outcome is the result of one assertion.
type Outcome struct {
	Expr   string
	Line   int
	Passed bool
	// Actual is the value checked: the status, the duration, the values
	// of a header joined with ", ", the body, or the JSON of a path's
	// value. It is in parentheses when there is no value: "(absent)", or
	// why the body has none.
	Actual string
	Form   Form
	Cut    bool // Actual is a body cut off at the size limit
}

// Form is what the actual value of an outcome holds, so that it can be
// masked as what it is.
type Form int

const (
	Text Form = iota // a status, a duration, header values, or why there is no value
	JSON             // a JSON value from the body, or why there is none
	Body             // the body
)

var (
	headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
	statusCode = regexp.MustCompile(`^[1-9][0-9][0-9]$`)
)

// comparisons maps an operator to the cmp.Compare results it accepts.
var comparisons = map[string]func(int) bool{
	"==": func(c int) bool { return c == 0 },
	"!=": func(c int) bool { return c != 0 },
	"<":  func(c int) bool { return c < 0 },
	"<=": func(c int) bool { return c <= 0 },
	">":  func(c int) bool { return c > 0 },
	">=": func(c int) bool { return c >= 0 },
}

// Parse parses the expression of an @assert directive.
func Parse(expr string) (*Assert, error) {
	subject, rest := splitWord(expr)
	var check func(*Response) (bool, string)
	var err error
	switch subject {
	case "status":
		check, err = statusCheck(rest)
	case "header":
		check, err = headerCheck(rest)
	case "body":
		check, err = bodyCheck(rest)
	case "jsonpath":
		check, err = pathCheck(rest)
	case "duration":
		check, err = durationCheck(rest)
	default:
		return nil, fmt.Errorf("unknown check %q (supported: status, header, body, jsonpath, duration)", subject)
	}
	if err != nil {
		return nil, err
	}
	form := map[string]Form{"body": Body, "jsonpath": JSON}[subject]
	return &Assert{Expr: expr, form: form, check: check}, nil
}

func statusCheck(s string) (func(*Response) (bool, string), error) {
	op, arg := splitWord(s)
	actual := func(r *Response) string { return strconv.Itoa(r.Status) }
	if lo, hi, ok := strings.Cut(arg, ".."); op == "in" && ok && statusCode.MatchString(lo) && statusCode.MatchString(hi) && lo <= hi {
		from, _ := strconv.Atoi(lo)
		to, _ := strconv.Atoi(hi)
		return func(r *Response) (bool, string) { return from <= r.Status && r.Status <= to, actual(r) }, nil
	}
	is, ok := comparisons[op]
	if !ok || !statusCode.MatchString(arg) {
		return nil, errors.New("want status <op> <code> with ==, !=, <, <=, > or >=, or status in <from>..<to>, such as 200..299")
	}
	n, _ := strconv.Atoi(arg)
	return func(r *Response) (bool, string) { return is(cmp.Compare(r.Status, n)), actual(r) }, nil
}

func headerCheck(s string) (func(*Response) (bool, string), error) {
	name, rest := splitWord(s)
	op, arg := splitWord(rest)
	var text string
	var err error
	switch op {
	case "exists":
		if arg != "" {
			err = errors.New("exists takes no value")
		}
	case "==", "contains":
		text, err = quoted(arg)
	default:
		err = errors.New("unknown operator")
	}
	if err != nil || !headerName.MatchString(name) {
		return nil, errors.New(`want header <Name> == "value", header <Name> contains "text" or header <Name> exists`)
	}
	return func(r *Response) (bool, string) {
		values := r.Header.Values(name)
		if len(values) == 0 {
			return false, "(absent)"
		}
		passed := op == "exists" || slices.ContainsFunc(values, func(v string) bool {
			return v == text || op == "contains" && strings.Contains(v, text)
		})
		return passed, strings.Join(values, ", ")
	}, nil
}

func bodyCheck(s string) (func(*Response) (bool, string), error) {
	op, arg := splitWord(s)
	text, err := quoted(arg)
	if op != "contains" || err != nil {
		return nil, errors.New(`want body contains "text"`)
	}
	return func(r *Response) (bool, string) {
		return strings.Contains(string(r.Body), text), string(r.Body)
	}, nil
}

func pathCheck(s string) (func(*Response) (bool, string), error) {
	src, rest := splitWord(s)
	p, err := compilePath(src)
	if err != nil {
		return nil, err
	}
	op, arg := splitWord(rest)
	var test func(any) bool
	switch op {
	case "exists":
		if arg == "" {
			test = func(any) bool { return true }
		}
	case "==":
		if want, err := literal(arg); err == nil {
			test = func(v any) bool { return gojq.Compare(v, want) == 0 }
		}
	case "contains":
		if text, err := quoted(arg); err == nil {
			test = func(v any) bool {
				s, ok := v.(string)
				return ok && strings.Contains(s, text)
			}
		}
	}
	if test == nil {
		return nil, errors.New(`want jsonpath <path> == <JSON value>, jsonpath <path> contains "text" or jsonpath <path> exists`)
	}
	return func(r *Response) (bool, string) {
		v, ok, err := p.value(r)
		switch {
		case err != nil:
			return false, "(" + err.Error() + ")"
		case !ok:
			return false, "(absent)"
		}
		return test(v), encode(v)
	}, nil
}

func durationCheck(s string) (func(*Response) (bool, string), error) {
	op, arg := splitWord(s)
	d, err := time.ParseDuration(arg)
	if op != "<" && op != "<=" || err != nil || d <= 0 {
		return nil, errors.New("want duration < <time> or duration <= <time>, such as duration < 500ms")
	}
	is := comparisons[op]
	return func(r *Response) (bool, string) {
		round := time.Millisecond
		if r.Duration < time.Millisecond {
			round = time.Microsecond
		}
		return is(cmp.Compare(r.Duration, d)), r.Duration.Round(round).String()
	}, nil
}

// quoted parses s as a JSON string: "text", escapes allowed.
func quoted(s string) (string, error) {
	var text string
	if !strings.HasPrefix(s, `"`) || json.Unmarshal([]byte(s), &text) != nil {
		return "", errors.New("want a quoted string")
	}
	return text, nil
}

// Directives returns the @assert and @capture directives of r, parsed.
// The error, of kind parse, names the line of the directive.
func Directives(r *core.Request) ([]*Assert, []*Capture, error) {
	var asserts []*Assert
	var captures []*Capture
	for _, d := range r.Directives {
		var err error
		switch d.Kind {
		case "assert":
			var a *Assert
			if a, err = Parse(d.Value); err == nil {
				a.Line = d.Line
				asserts = append(asserts, a)
			}
		case "capture":
			var c *Capture
			if c, err = ParseCapture(d.Value); err == nil {
				// One value per variable and request: two would leave which
				// one the next requests get to chance.
				if i := slices.IndexFunc(captures, func(o *Capture) bool { return o.Name == c.Name }); i >= 0 {
					err = fmt.Errorf("%s is captured on line %d already", c.Name, captures[i].Line)
					break
				}
				c.Line = d.Line
				captures = append(captures, c)
			}
		}
		if err != nil {
			return nil, nil, core.Errorf(core.KindParse, core.Source{File: r.Source.File, Line: d.Line}, "@%s %s: %v", d.Kind, d.Value, err)
		}
	}
	return asserts, captures, nil
}

// Result is what the directives of a request made of its response.
type Result struct {
	Outcomes []Outcome  // one per @assert
	Captured []Captured // one per @capture that found its value, in order
	// Err is for the captures that found none, of kind capture, or else
	// for the failed assertions, of kind assert: a failed capture has the
	// higher exit code.
	Err error
}

// Captured is a value an @capture took.
type Captured struct {
	*Capture
	Value string
}

// Evaluate checks resp against the @assert directives of req and takes
// the values of its @capture directives. Every directive is evaluated,
// whatever the others give.
func Evaluate(ctx context.Context, req *core.Request, resp *exec.Response) *Result {
	res := &Result{}
	_, captures, err := Directives(req)
	if err != nil {
		res.Err = err
		return res
	}
	res.Outcomes, res.Err = Check(ctx, req, resp)
	r := &Response{Response: resp, ctx: ctx}
	var failed []string
	line := 0
	for _, c := range captures {
		v, err := c.take(r)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s = %s: %v", c.Name, c.Source, err))
			line = cmp.Or(line, c.Line)
			continue
		}
		res.Captured = append(res.Captured, Captured{c, v})
	}
	if len(failed) > 0 {
		res.Err = failure(req, line, "capture", failed, len(captures))
	}
	return res
}

// Check checks resp against the @assert directives of req, each whatever
// the others give, and returns their outcomes, and the error of kind
// assert for those that failed. A run that is not shown a value checks
// them against the response as it is shown it: it must not learn the
// value, a character at a time, from what its assertions on it give.
func Check(ctx context.Context, req *core.Request, resp *exec.Response) ([]Outcome, error) {
	asserts, _, err := Directives(req)
	if err != nil {
		return nil, err
	}
	r := &Response{Response: resp, ctx: ctx}
	var outcomes []Outcome
	var failed []string
	line := 0
	for _, a := range asserts {
		passed, actual := a.check(r)
		outcomes = append(outcomes, Outcome{
			Expr: a.Expr, Line: a.Line, Passed: passed, Actual: actual,
			Form: a.form, Cut: a.form == Body && resp.Truncated,
		})
		if !passed {
			failed = append(failed, a.Expr)
			line = cmp.Or(line, a.Line)
		}
	}
	if len(failed) > 0 {
		// The actual values stay out of the message: a body cut short
		// for it could cut a secret in two, and then masking misses it.
		return outcomes, failure(req, line, "assertion", failed, len(asserts))
	}
	return outcomes, nil
}

// failure returns the error for the failed directives of one kind, of
// the n of req: assertion or capture.
func failure(req *core.Request, line int, what string, failed []string, n int) error {
	kind, msg := core.KindAssert, what+" failed: "+failed[0]
	if what == "capture" {
		kind = core.KindCapture
	}
	if len(failed) > 1 {
		msg = fmt.Sprintf("%d of %d %ss failed: %s", len(failed), n, what, strings.Join(failed, "; "))
	}
	return core.Errorf(kind, core.Source{File: req.Source.File, Line: line}, "%s", msg)
}

// splitWord splits s at its first run of spaces or tabs.
func splitWord(s string) (word, rest string) {
	s = strings.TrimSpace(s)
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimSpace(s[i:])
}
