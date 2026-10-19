package postman

import (
	"bytes"
	"encoding/json"
	"strings"
)

// The Postman formats, as far as the importer reads them. Postman writes
// several fields in more than one shape; these types accept each one.

// collection is a Postman Collection, v2.0 or v2.1.
type collection struct {
	Info struct {
		Name string `json:"name"`
	} `json:"info"`
	Item     []*item `json:"item"`
	Auth     *auth   `json:"auth"`
	Event    []event `json:"event"`
	Variable []param `json:"variable"`
}

// item is a folder if it has items, a request otherwise.
type item struct {
	Name     string            `json:"name"`
	Item     []*item           `json:"item"`
	Request  *request          `json:"request"`
	Response []json.RawMessage `json:"response"` // saved examples
	Auth     *auth             `json:"auth"`     // folders only
	Event    []event           `json:"event"`
	Behavior map[string]any    `json:"protocolProfileBehavior"`
}

func (it *item) isFolder() bool { return it.Item != nil || it.Request == nil }

// request is a request. Postman may write a GET request as its URL alone.
type request struct {
	Method string  `json:"method"`
	URL    pmURL   `json:"url"`
	Header headers `json:"header"`
	Body   *body   `json:"body"`
	Auth   *auth   `json:"auth"`
}

func (r *request) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*r = request{URL: pmURL{Raw: s}}
		return nil
	}
	type plain request
	return json.Unmarshal(b, (*plain)(r))
}

// pmURL is a URL: the raw text, its parts, or both.
type pmURL struct {
	Raw      string  `json:"raw"`
	Protocol string  `json:"protocol"`
	Host     parts   `json:"host"`
	Port     string  `json:"port"`
	Path     parts   `json:"path"`
	Query    []param `json:"query"`
	Hash     string  `json:"hash"`
	Variable []param `json:"variable"` // values of :name path segments
}

func (u *pmURL) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*u = pmURL{Raw: s}
		return nil
	}
	type plain pmURL
	return json.Unmarshal(b, (*plain)(u))
}

// String returns the raw URL or, without one, the URL built from its
// parts.
func (u pmURL) String() string {
	if u.Raw != "" {
		return u.Raw
	}
	var b strings.Builder
	if u.Protocol != "" {
		b.WriteString(u.Protocol + "://")
	}
	b.WriteString(strings.Join(u.Host, "."))
	if u.Port != "" {
		b.WriteString(":" + u.Port)
	}
	if len(u.Path) > 0 {
		b.WriteString("/" + strings.Join(u.Path, "/"))
	}
	var query []string
	for _, p := range u.Query {
		if !p.off() {
			query = append(query, string(p.Key)+"="+string(p.Value))
		}
	}
	if len(query) > 0 {
		b.WriteString("?" + strings.Join(query, "&"))
	}
	if u.Hash != "" {
		b.WriteString("#" + u.Hash)
	}
	return b.String()
}

// headers are header lines, which Postman may also write as one string.
type headers []param

func (h *headers) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		for line := range strings.Lines(s) {
			if k, v, ok := strings.Cut(line, ":"); ok {
				*h = append(*h, param{Key: text(strings.TrimSpace(k)), Value: text(strings.TrimSpace(v))})
			}
		}
		return nil
	}
	return json.Unmarshal(b, (*[]param)(h))
}

type body struct {
	Mode       string  `json:"mode"`
	Raw        text    `json:"raw"`
	URLEncoded []param `json:"urlencoded"`
	Disabled   bool    `json:"disabled"`
	Options    struct {
		Raw struct {
			Language string `json:"language"`
		} `json:"raw"`
	} `json:"options"`
}

// auth is an auth setting: its type and the parameters of that type,
// which v2.1 writes as [{"key", "value"}] and v2.0 as an object.
type auth struct {
	Type   string
	Params map[string]string
}

func (a *auth) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	json.Unmarshal(m["type"], &a.Type) // no type: inherit
	a.Params = map[string]string{}
	var list []param
	var obj map[string]text
	if json.Unmarshal(m[a.Type], &list) == nil {
		for _, p := range list {
			a.Params[string(p.Key)] = string(p.Value)
		}
	} else if json.Unmarshal(m[a.Type], &obj) == nil {
		for k, v := range obj {
			a.Params[k] = string(v)
		}
	}
	return nil
}

// inherits reports whether a request or folder with auth a takes the
// auth of its parent.
func (a *auth) inherits() bool { return a == nil || a.Type == "" || a.Type == "inherit" }

// event is a script: pre-request or test.
type event struct {
	Listen   string `json:"listen"`
	Disabled bool   `json:"disabled"`
	Script   struct {
		Exec parts `json:"exec"`
	} `json:"script"`
}

func (e event) code() string { return strings.TrimSpace(strings.Join(e.Script.Exec, "\n")) }

// param is a key and a value: a header, a query or form parameter, a
// path variable, or a variable.
type param struct {
	Key      text  `json:"key"`
	Value    text  `json:"value"`
	Type     text  `json:"type"`   // "secret" for a hidden variable
	Secret   bool  `json:"secret"` // another way to say the same
	Disabled bool  `json:"disabled"`
	Enabled  *bool `json:"enabled"` // environments say it this way
}

func (p param) off() bool { return p.Disabled || p.Enabled != nil && !*p.Enabled }

// vars is an environment or the globals.
type vars struct {
	Name   string  `json:"name"`
	Scope  string  `json:"_postman_variable_scope"`
	Values []param `json:"values"`
}

// text is a string that Postman may also write as a number, a boolean, an
// object or null. Anything but a string or null is kept as compact JSON.
type text string

func (t *text) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*t = text(s)
		return nil
	}
	var c bytes.Buffer
	if err := json.Compact(&c, b); err != nil {
		return err
	}
	if c.String() != "null" {
		*t = text(c.String())
	}
	return nil
}

// parts is a list of strings that Postman may also write as one string,
// or as objects with a "value".
type parts []string

func (p *parts) UnmarshalJSON(b []byte) error {
	var list []json.RawMessage
	if json.Unmarshal(b, &list) != nil {
		list = []json.RawMessage{b}
	}
	for _, raw := range list {
		var obj struct {
			Value text `json:"value"`
		}
		var one text
		if json.Unmarshal(raw, &obj) == nil {
			one = obj.Value
		} else if err := json.Unmarshal(raw, &one); err != nil {
			return err
		}
		*p = append(*p, string(one))
	}
	return nil
}
