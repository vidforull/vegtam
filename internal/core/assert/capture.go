package assert

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/vidforull/vegtam/internal/core"
)

// Capture is a parsed @capture directive: [plain] <name> = <source>.
type Capture struct {
	Name   string
	Source string // as written: $.token, header X-Session or status
	Secret bool   // not marked plain: the value is masked as any secret
	Line   int
	take   func(*Response) (string, error)
}

// ParseCapture parses the value of an @capture directive.
func ParseCapture(s string) (*Capture, error) {
	left, src, ok := strings.Cut(s, "=")
	words := strings.Fields(left)
	c := &Capture{Secret: true, Source: strings.TrimSpace(src)}
	if len(words) == 2 && words[0] == "plain" {
		c.Secret, words = false, words[1:]
	}
	if !ok || len(words) != 1 || c.Source == "" {
		return nil, errors.New("want [plain] <name> = <source>, such as token = $.token")
	}
	c.Name = words[0]
	if !core.IsVarName(c.Name) {
		return nil, fmt.Errorf("invalid variable name %q: start with a letter or _, then letters, digits, _, . and -", c.Name)
	}
	subject, rest := splitWord(c.Source)
	switch {
	case subject == "status" && rest == "":
		c.take = func(r *Response) (string, error) { return strconv.Itoa(r.Status), nil }
	case subject == "header" && headerName.MatchString(rest):
		c.take = func(r *Response) (string, error) {
			if v := r.Header.Values(rest); len(v) > 0 {
				return v[0], nil
			}
			return "", errors.New("the response has no such header")
		}
	case strings.HasPrefix(subject, "$") && rest == "":
		p, err := compilePath(subject)
		if err != nil {
			return nil, err
		}
		c.take = func(r *Response) (string, error) {
			v, ok, err := p.value(r)
			switch {
			case err != nil:
				return "", err
			case !ok:
				return "", errors.New("the body has no such value")
			case v == nil:
				return "", errors.New("the value is null")
			}
			switch s := v.(type) {
			case string:
				return s, nil
			case map[string]any, []any:
				// Masking knows the compact JSON, not the values inside it
				// as the body has them.
				if c.Secret {
					return "", errors.New("the value is an object or array, which a secret capture cannot mask; capture a value inside it, or mark the capture plain")
				}
			}
			return encode(v), nil
		}
	default:
		return nil, errors.New("want a source: $.path, header <Name> or status")
	}
	return c, nil
}
