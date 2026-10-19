package assert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/itchyny/gojq"

	"github.com/vidforull/vegtam/internal/core/exec"
)

// Response is a response as the directives see it. Its body is decoded as
// JSON once, when a directive first needs it.
type Response struct {
	*exec.Response
	ctx     context.Context
	decoded bool
	doc     any
	err     error // why the body has no JSON value
}

func (r *Response) json() (any, error) {
	if !r.decoded {
		r.decoded = true
		switch {
		case r.Truncated:
			r.err = errors.New("the body was cut off at the size limit")
		case !json.Valid(r.Body):
			r.err = errors.New("the body is not JSON")
		default:
			// Numbers stay exact, as gojq compares them.
			dec := json.NewDecoder(bytes.NewReader(r.Body))
			dec.UseNumber()
			r.err = dec.Decode(&r.doc)
		}
	}
	return r.doc, r.err
}

// path is a path into a JSON body: a gojq expression written with a
// leading $, as in JSONPath: $.items[0].id is .items[0].id. Only plain
// paths are allowed, with an optional |length at the end, and gojq only
// says which keys a path takes; the value is looked up here, in objects
// and arrays alone. So a path points into the body and cannot compute a
// new value from it, such as a slice, a character or the base64 of a
// secret, which masking would not recognise.
type path struct {
	keys   *gojq.Code // path(p), for p without its |length
	length bool
}

func compilePath(src string) (*path, error) {
	if src == "" || src[0] != '$' || len(src) > 1 && !strings.ContainsRune(".[|", rune(src[1])) {
		return nil, fmt.Errorf("want a path starting with $, such as $.items[0].id, got %q", src)
	}
	q := src[1:]
	if !strings.HasPrefix(q, ".") {
		q = "." + q
	}
	parsed, err := gojq.Parse(q)
	if err != nil {
		return nil, fmt.Errorf("path %s: %w", src, err)
	}
	p := &path{}
	if parsed.Op == gojq.OpPipe && isLength(parsed.Right) {
		parsed, p.length = parsed.Left, true
	}
	if !plainPath(parsed) {
		return nil, fmt.Errorf(`path %s: want a plain path of names, quoted keys and indexes, such as $.items[0].id or $["first-name"], optionally ending in |length`, src)
	}
	keys, err := gojq.Parse("path(" + parsed.String() + ")")
	if err == nil {
		p.keys, err = gojq.Compile(keys)
	}
	if err != nil {
		return nil, fmt.Errorf("path %s: %w", src, err)
	}
	return p, nil
}

// plainPath reports whether q is ., or a chain of .name, ."key", .["key"]
// and [N] with N an integer.
func plainPath(q *gojq.Query) bool {
	if q == nil || q.Op != 0 || q.Term == nil || len(q.FuncDefs) > 0 || len(q.Imports) > 0 || len(q.Patterns) > 0 {
		return false
	}
	t := q.Term
	switch {
	case t.Type == gojq.TermTypeIdentity:
	case t.Type == gojq.TermTypeIndex && plainIndex(t.Index):
	default:
		return false
	}
	for _, s := range t.SuffixList {
		if s.Iter || s.Optional || !plainIndex(s.Index) {
			return false
		}
	}
	return true
}

func plainIndex(ix *gojq.Index) bool {
	switch {
	case ix == nil || ix.IsSlice || ix.End != nil:
		return false
	case ix.Name != "":
		return true
	case ix.Str != nil:
		return len(ix.Str.Queries) == 0
	}
	// [N], [-N] or ["key"]
	q := ix.Start
	if q == nil || q.Op != 0 || q.Term == nil || len(q.Term.SuffixList) > 0 {
		return false
	}
	t := q.Term
	if t.Type == gojq.TermTypeUnary && t.Unary.Op == gojq.OpSub && len(t.Unary.Term.SuffixList) == 0 {
		t = t.Unary.Term
	}
	switch t.Type {
	case gojq.TermTypeNumber:
		_, err := strconv.Atoi(t.Number)
		return err == nil
	case gojq.TermTypeString:
		return t == q.Term && len(t.Str.Queries) == 0
	}
	return false
}

func isLength(q *gojq.Query) bool {
	return q != nil && q.Op == 0 && q.Term != nil && q.Term.Type == gojq.TermTypeFunc && q.Term.Func.Name == "length" &&
		len(q.Term.Func.Args) == 0 && len(q.Term.SuffixList) == 0
}

// errMisfit is for a path that goes into a value that is neither an
// object nor an array. gojq's own messages would quote part of that
// value, which could be the start of a secret that masking cannot
// recognise.
var errMisfit = errors.New("the path does not fit the body")

// value returns the value at p in the body of r. ok is false if the body
// has none there.
func (p *path) value(r *Response) (v any, ok bool, err error) {
	doc, err := r.json()
	if err != nil {
		return nil, false, err
	}
	keys, found := p.keys.RunWithContext(r.ctx, doc).Next()
	list, isList := keys.([]any)
	if !found || !isList {
		return nil, false, errMisfit
	}
	if v, ok, err = lookup(doc, list); err != nil || !ok || !p.length {
		return v, ok, err
	}
	switch v := v.(type) {
	case string:
		return utf8.RuneCountInString(v), true, nil
	case []any:
		return len(v), true, nil
	case map[string]any:
		return len(v), true, nil
	case nil:
		return 0, true, nil
	}
	return nil, false, errMisfit
}

// lookup returns the value at keys in doc: object keys and array
// indexes, as path() gives them.
func lookup(doc any, keys []any) (any, bool, error) {
	for _, k := range keys {
		switch c := doc.(type) {
		case nil: // as in jq, null has nothing at any key
			return nil, false, nil
		case map[string]any:
			s, isKey := k.(string)
			if !isKey {
				return nil, false, errMisfit
			}
			v, ok := c[s]
			if !ok {
				return nil, false, nil
			}
			doc = v
		case []any:
			i, isIndex := k.(int)
			if !isIndex {
				return nil, false, errMisfit
			}
			if i < 0 {
				i += len(c)
			}
			if i < 0 || i >= len(c) {
				return nil, false, nil
			}
			doc = c[i]
		default:
			return nil, false, errMisfit
		}
	}
	return doc, true, nil
}

// literal parses s as one JSON value.
func literal(s string) (any, error) {
	if !json.Valid([]byte(s)) {
		return nil, errors.New("not a JSON value")
	}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	err := dec.Decode(&v)
	return v, err
}

// encode returns v as compact JSON.
func encode(v any) string {
	b, err := gojq.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}
