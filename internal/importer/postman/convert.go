package postman

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/httpfile"
)

// converter converts the requests of one collection.
type converter struct {
	imp     *importer
	dir     string            // the collection's directory, relative to the output
	prefix  string            // of the variables it creates
	vars    []param           // collection variables
	created []param           // variables made for secret values found in requests
	byValue map[string]string // created variables by value
	unset   map[string]string // variables made for values the import cannot compute
	known   names             // variable names in use
	used    map[string]bool   // variables the requests use
	written []written         // the requests written as requests, not commented out
	files   []*httpFile
}

// httpFile is a .http file: the requests of one folder.
type httpFile struct {
	path   string // relative to the output
	names  names  // request names
	blocks []string
}

// collection converts col into a directory of its own.
func (imp *importer) collection(col *collection) {
	dir := imp.dirs.unique(slug(col.Info.Name, "collection"))
	prefix := strings.ReplaceAll(dir, "-", "_")
	if !varName.MatchString(prefix) {
		prefix = "_" + prefix
	}
	c := &converter{
		imp: imp, dir: dir, prefix: prefix, byValue: map[string]string{}, unset: map[string]string{},
		known: names{}, used: map[string]bool{},
	}
	c.vars = imp.variables(col.Variable)
	for _, ps := range [][]param{imp.globals, c.vars} {
		for _, p := range ps {
			c.known[string(p.Key)] = true
		}
	}
	for _, e := range imp.envs {
		for _, p := range e.vars {
			c.known[string(p.Key)] = true
		}
	}
	c.scripts(col.Event, "collection", imp.at(dir))
	c.folder(dir, dir+"/"+dir+".http", col.Item, col.Auth, names{dir: true})
	for _, f := range c.files {
		imp.write(f.path, []byte(strings.Join(f.blocks, "\n")), false)
	}
	imp.convs = append(imp.convs, c)
	imp.report.Collections++
}

// folder converts the items of a folder: its requests go to the file at
// path, its subfolders to directory dir, under names unique in stems.
func (c *converter) folder(dir, path string, items []*item, inherited *auth, stems names) {
	var f *httpFile
	for _, it := range items {
		if it.isFolder() {
			sub := dir + "/" + stems.unique(slug(it.Name, "folder"))
			a := inherited
			if !it.Auth.inherits() {
				a = it.Auth
			}
			where := sub
			if slices.ContainsFunc(it.Item, func(i *item) bool { return !i.isFolder() }) {
				where += ".http"
			}
			c.scripts(it.Event, "folder", c.imp.at(where))
			c.folder(sub, sub+".http", it.Item, a, names{})
			continue
		}
		if f == nil {
			f = &httpFile{path: path, names: names{}}
			c.files = append(c.files, f)
		}
		c.request(f, it, inherited)
	}
}

// scripts reports the scripts of a collection or a folder.
func (c *converter) scripts(events []event, of, where string) {
	for _, e := range events {
		if !e.Disabled && e.code() != "" {
			c.imp.skip("script", of+" "+scriptKind(e)+" script", where)
		}
	}
}

func scriptKind(e event) string {
	if e.Listen == "prerequest" {
		return "pre-request"
	}
	return e.Listen
}

// extract moves value, a secret, to a variable named from base and
// returns the variable's name. The same value gives the same variable.
func (c *converter) extract(base, value string) string {
	if name, ok := c.byValue[value]; ok {
		return name
	}
	name := c.known.unique(c.prefix + "_" + base)
	c.created = append(c.created, param{Key: text(name), Value: text(value)})
	c.byValue[value] = name
	c.imp.secret[name] = true
	c.used[name] = true
	return name
}

// rq is a request being converted.
type rq struct {
	c        *converter
	ref      string // file#name, for the report
	asserts  []string
	comments []string // before the request line
	method   string
	url      string
	lines    []string      // header lines, with disabled headers as comments
	headers  []core.Header // the headers the lines should parse to
	body     string
	dynamic  names // Postman dynamic variables reported
}

func (c *converter) request(f *httpFile, it *item, inherited *auth) {
	c.imp.report.Requests++
	name := slug(it.Name, "request")
	if _, err := strconv.Atoi(name); err == nil {
		name = "request-" + name
	}
	name = f.names.unique(name)
	q := &rq{c: c, ref: c.imp.at(f.path) + "#" + name, dynamic: names{}}
	r := it.Request
	q.method = strings.ToUpper(strings.TrimSpace(r.Method))
	if q.method == "" {
		q.method = "GET"
	}
	q.url = q.convertURL(r.URL)
	for _, h := range r.Header {
		q.header(h)
	}
	a := inherited
	if !r.Auth.inherits() {
		a = r.Auth
	}
	q.auth(a)
	q.convertBody(r.Body)
	q.scripts(it.Event)
	if n := len(it.Response); n > 0 {
		q.skip("example", fmt.Sprintf("%d saved response(s)", n))
	}
	if s := settings(it.Behavior); s != "" {
		q.skip("setting", "request settings: "+s)
	}

	lines := []string{"# @name " + name}
	for _, a := range q.asserts {
		lines = append(lines, "# @assert "+a)
	}
	for _, s := range q.comments {
		lines = append(lines, "# "+oneLine(s))
	}
	lines = append(lines, q.method+" "+q.url)
	lines = append(lines, q.lines...)
	if q.body != "" {
		lines = append(lines, "")
		lines = append(lines, strings.Split(q.body, "\n")...)
	}
	if reason := q.check(strings.Join(lines, "\n")); reason != "" {
		q.skip("request", reason)
		lines = commentOut(lines, reason)
	} else {
		c.imp.report.Imported++
		c.written = append(c.written, newWritten(q))
	}
	title := strings.TrimSpace("### " + oneLine(it.Name))
	f.blocks = append(f.blocks, title+"\n"+strings.Join(lines, "\n")+"\n")
}

func (q *rq) skip(category, reason string) { q.c.imp.skip(category, reason, q.ref) }

// check parses block as vegtam will and returns why it does not give
// back the request q means, or "" if it does.
func (q *rq) check(block string) string {
	switch {
	case q.url == "":
		return "the request has no URL"
	case !httpfile.IsMethod(q.method):
		return "method " + q.method + " is not supported"
	}
	for line := range strings.Lines(q.body) {
		if strings.HasPrefix(line, "###") {
			return "a line of the body starts with ###, which would end the request"
		}
	}
	f, err := httpfile.Parse("request.http", []byte(block))
	if err != nil {
		if e, ok := errors.AsType[*core.Error](err); ok {
			return e.Msg
		}
		return err.Error()
	}
	if len(f.Requests) != 1 {
		return "the body cannot be written in a .http file as it is"
	}
	r := f.Requests[0]
	switch {
	case r.Body != q.body, r.BodyFile != "":
		return "the body cannot be written in a .http file as it is"
	case r.Method != q.method, r.URL != q.url:
		return "the request line cannot be written in a .http file as it is"
	case !slices.Equal(r.Headers, q.headers):
		return "the headers cannot be written in a .http file as they are"
	case len(r.Directives) != len(q.asserts):
		return "a comment would be read as a directive"
	}
	return ""
}

// commentOut returns the lines of a request as comments, after a note
// that says why. They start with "## ", which no line read as a directive
// or a separator does; a line with a line break in it becomes several.
func commentOut(lines []string, reason string) []string {
	out := []string{"# Not imported: " + oneLine(reason)}
	for _, l := range lines {
		for l := range strings.SplitSeq(strings.ReplaceAll(l, "\r\n", "\n"), "\n") {
			out = append(out, strings.TrimRight("## "+l, " "))
		}
	}
	return out
}

var placeholder = regexp.MustCompile(`\{\{([^{}]*)\}\}`)

// text rewrites the placeholders of s for vegtam: variables get valid
// names, and Postman's dynamic variables, such as {{$guid}}, are reported.
func (q *rq) text(s string) string {
	return placeholder.ReplaceAllStringFunc(s, func(m string) string {
		inner := strings.TrimSpace(m[2 : len(m)-2])
		switch {
		case inner == "":
			return m
		case strings.HasPrefix(inner, "$"):
			if !q.dynamic[inner] {
				q.dynamic[inner] = true
				q.skip("variable", "Postman dynamic variable {{"+inner+"}} is not supported")
			}
			return "{{" + inner + "}}"
		}
		name := q.c.imp.rename(inner)
		q.c.used[name] = true
		return "{{" + name + "}}"
	})
}

// refs returns the names of the variables s refers to.
func refs(s string) []string {
	var names []string
	for _, m := range placeholder.FindAllStringSubmatch(s, -1) {
		names = append(names, strings.TrimSpace(m[1]))
	}
	return names
}

// secret returns value, which q.text has rewritten, for a place that
// holds a secret. Each run of literal text in it moves to a new variable
// named from base and is replaced by its placeholder; the variables value
// refers to become secrets.
func (q *rq) secret(value, base string) string {
	var b strings.Builder
	last := 0
	literal := func(s string) {
		if s != "" || value == "" {
			b.WriteString("{{" + q.c.extract(base, s) + "}}")
		}
	}
	for _, m := range placeholder.FindAllStringSubmatchIndex(value, -1) {
		literal(value[last:m[0]])
		if name := strings.TrimSpace(value[m[2]:m[3]]); !strings.HasPrefix(name, "$") {
			q.c.imp.secret[name] = true
		}
		b.WriteString(value[m[0]:m[1]])
		last = m[1]
	}
	literal(value[last:])
	return b.String()
}

// secretRefs makes the variables that s, a Postman value that is not
// imported, refers to secrets.
func (q *rq) secretRefs(s string) {
	for _, name := range refs(s) {
		if !strings.HasPrefix(name, "$") {
			q.c.imp.secret[q.c.imp.rename(name)] = true
		}
	}
}

var secretNameRE = regexp.MustCompile(`(?i)token|key|secret|passw|pwd|credential|cookie|session|authorization`)

// secretName reports whether a variable, header or parameter called name
// likely holds a secret.
func secretName(name string) bool { return secretNameRE.MatchString(name) }

// base returns a variable name suffix made from a header or parameter
// name.
func base(name string) string { return strings.ReplaceAll(slug(name, "secret"), "-", "_") }

func (q *rq) convertURL(u pmURL) string {
	s := pathVariables(strings.TrimSpace(u.String()), u.Variable)
	// Postman sends a space as %20; placeholders hold no spaces by now.
	s = strings.ReplaceAll(q.text(s), " ", "%20")
	// And it sends a URL without a scheme over http.
	if s != "" && !strings.Contains(s, "://") && !strings.HasPrefix(s, "{{") {
		s = "http://" + s
	}
	path, query, ok := strings.Cut(s, "?")
	if !ok {
		return s
	}
	query, fragment, hasFragment := strings.Cut(query, "#")
	pairs := strings.Split(query, "&")
	for i, p := range pairs {
		if k, v, ok := strings.Cut(p, "="); ok && v != "" && secretName(k) {
			pairs[i] = k + "=" + q.secret(v, base(k))
		}
	}
	s = path + "?" + strings.Join(pairs, "&")
	if hasFragment {
		s += "#" + fragment
	}
	return s
}

// pathVariables replaces the :name segments of the path of rawURL with
// the values of vars, as Postman does. A variable without a value becomes
// a placeholder.
func pathVariables(rawURL string, vars []param) string {
	if len(vars) == 0 {
		return rawURL
	}
	end := strings.IndexAny(rawURL, "?#")
	if end < 0 {
		end = len(rawURL)
	}
	segs := strings.Split(rawURL[:end], "/")
	for i, s := range segs {
		name, ok := strings.CutPrefix(s, ":")
		if !ok {
			continue
		}
		for _, v := range vars {
			if string(v.Key) == name {
				segs[i] = string(v.Value)
				if segs[i] == "" {
					segs[i] = "{{" + name + "}}"
				}
			}
		}
	}
	return strings.Join(segs, "/") + rawURL[end:]
}

func (q *rq) header(h param) {
	key := strings.TrimSpace(string(h.Key))
	if key == "" {
		return
	}
	if h.off() {
		value := oneLine(strings.TrimSpace(string(h.Value)))
		if secretName(key) && value != "" && len(refs(value)) == 0 {
			value = "(secret value not imported)"
		}
		q.lines = append(q.lines, strings.TrimSpace("# "+oneLine(key)+": "+value))
		q.skip("header", "disabled header "+oneLine(key))
		return
	}
	key, value := q.text(key), strings.TrimSpace(q.text(string(h.Value)))
	if value != "" && secretName(key) {
		scheme, cred, ok := strings.Cut(value, " ")
		if isAuthorization(key) && ok && len(refs(scheme)) == 0 {
			value = scheme + " " + q.secret(strings.TrimSpace(cred), schemeBase(scheme))
		} else {
			value = q.secret(value, base(key))
		}
	}
	q.headers = append(q.headers, core.Header{Name: key, Value: value})
	q.lines = append(q.lines, key+": "+value)
}

func isAuthorization(name string) bool {
	return strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Proxy-Authorization")
}

// schemeBase names the variable for the credentials of an auth scheme.
func schemeBase(scheme string) string {
	if strings.EqualFold(scheme, "Bearer") {
		return "token"
	}
	return base(scheme)
}

// addHeader adds a header that auth or the body type implies, unless the
// request sets it itself.
func (q *rq) addHeader(name, value string, from string) {
	for _, h := range q.headers {
		if strings.EqualFold(h.Name, name) {
			if from != "" {
				q.comments = append(q.comments, fmt.Sprintf("%s from the Postman %s is not added: the request sets its own", name, from))
			}
			return
		}
	}
	q.headers = append(q.headers, core.Header{Name: name, Value: value})
	q.lines = append(q.lines, name+": "+value)
}

func (q *rq) auth(a *auth) {
	if a.inherits() || a.Type == "noauth" {
		return
	}
	param := func(k string) string { return strings.TrimSpace(q.text(a.Params[k])) }
	switch a.Type {
	case "bearer":
		q.addHeader("Authorization", "Bearer "+q.secret(param("token"), "token"), "bearer auth")
	case "basic":
		user, pass := param("username"), param("password")
		if len(refs(user+pass)) == 0 {
			q.addHeader("Authorization", "Basic "+q.secret(base64.StdEncoding.EncodeToString([]byte(user+":"+pass)), "basic"), "basic auth")
			return
		}
		// vegtam does not encode placeholders, so the credentials have
		// to be set already encoded.
		key := user + ":" + pass
		name, ok := q.c.unset[key]
		if !ok {
			name = q.c.known.unique(q.c.prefix + "_basic")
			q.c.unset[key] = name
			q.c.imp.secret[name] = true
		}
		q.c.used[name] = true
		var from []string
		for _, n := range refs(key) {
			q.secretRefs("{{" + n + "}}")
			from = append(from, "{{"+n+"}}")
		}
		q.comments = append(q.comments, fmt.Sprintf("Basic auth: set %s to the base64 encoding of username:password (in Postman, from %s)",
			name, strings.Join(from, " and ")))
		q.addHeader("Authorization", "Basic {{"+name+"}}", "basic auth")
	case "apikey":
		key := param("key")
		if key == "" {
			q.skip("auth", "apikey auth without a key name")
			return
		}
		value := q.secret(param("value"), base(key))
		if a.Params["in"] != "query" {
			q.addHeader(key, value, "apikey auth")
			return
		}
		u, fragment, hasFragment := strings.Cut(q.url, "#")
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		q.url = u + sep + url.QueryEscape(key) + "=" + value
		if hasFragment {
			q.url += "#" + fragment
		}
	default:
		for _, v := range a.Params {
			q.secretRefs(v)
		}
		q.skip("auth", a.Type+" auth")
		q.comments = append(q.comments, "Postman "+a.Type+" auth is not imported: add the header it sends")
	}
}

// rawTypes are the Content-Type headers Postman sends for raw bodies, by
// the language chosen for them.
var rawTypes = map[string]string{
	"": "text/plain", "text": "text/plain", "json": "application/json",
	"xml": "application/xml", "html": "text/html", "javascript": "application/javascript",
}

func (q *rq) convertBody(b *body) {
	if b == nil || b.Disabled {
		return
	}
	switch b.Mode {
	case "", "none":
	case "raw":
		q.body = q.jsonSecrets(trimLines(q.text(string(b.Raw))))
		if t, ok := rawTypes[b.Options.Raw.Language]; ok && q.body != "" {
			q.addHeader("Content-Type", t, "")
		}
	case "urlencoded":
		var pairs []string
		for _, p := range b.URLEncoded {
			if p.off() {
				q.skip("body", "disabled form field "+oneLine(string(p.Key)))
				continue
			}
			k, v := q.text(string(p.Key)), formEscape(q.text(string(p.Value)))
			if v != "" && secretName(k) {
				v = q.secret(v, base(k))
			}
			pairs = append(pairs, formEscape(k)+"="+v)
		}
		q.body = strings.Join(pairs, "&")
		if q.body != "" {
			q.addHeader("Content-Type", "application/x-www-form-urlencoded", "")
		}
	default:
		q.skip("body", b.Mode+" body")
		q.comments = append(q.comments, "The "+b.Mode+" body is not imported")
	}
}

// jsonSecrets moves the literal values under keys named like secrets in
// body, if it looks like JSON, to variables: strings, numbers, and every
// value inside an array or object under such a key. It reads the body
// token by token instead of decoding it, so that bodies Postman sends as
// they are, with trailing commas, comments or unquoted placeholders, are
// covered too; every other byte stays as it was. A variable holds the
// value as written, escapes included, so that the request sends the same
// bytes.
func (q *rq) jsonSecrets(body string) string {
	if t := strings.TrimSpace(body); !strings.HasPrefix(t, "{") && !strings.HasPrefix(t, "[") {
		return body
	}
	s := &jsonScan{q: q, body: body}
	for i := 0; i < len(body); {
		i = s.step(i)
	}
	return s.out.String() + body[s.last:]
}

// jsonScan is how far jsonSecrets has read a body.
type jsonScan struct {
	q           *rq
	body        string
	out         strings.Builder // body[:last], with secret values moved to variables
	last        int
	depth       int
	secretDepth int    // the depth of the container under a secret key, or 0
	key         string // the last object key read
	afterColon  bool
}

// step reads the token at body[i] and returns where the next one starts.
func (s *jsonScan) step(i int) int {
	body, c := s.body, s.body[i]
	if strings.IndexByte(" \t\r\n", c) >= 0 {
		return i + 1
	}
	secret := s.secretDepth > 0 || s.afterColon && secretName(s.key)
	s.afterColon = false
	var m []int
	if c == '{' {
		m = placeholderAt.FindStringIndex(body[i:])
	}
	switch {
	case c == '"':
		return s.str(i, secret)
	case m != nil:
		if secret {
			s.q.secret(body[i:i+m[1]], "") // all placeholders: marks their variables
		}
		return i + m[1]
	case c == ':':
		s.afterColon = true
	case c == '{' || c == '[':
		s.depth++
		if secret && s.secretDepth == 0 {
			s.secretDepth = s.depth
		}
	case c == '}' || c == ']':
		if s.depth == s.secretDepth {
			s.secretDepth = 0
		}
		s.depth--
	case strings.HasPrefix(body[i:], "//"):
		return lineEnd(body, i)
	case strings.HasPrefix(body[i:], "/*"):
		return commentEnd(body, i)
	case secret && (c == '-' || '0' <= c && c <= '9'):
		j := numberEnd(body, i)
		s.out.WriteString(body[s.last:i] + "{{" + s.q.c.extract(base(s.key), body[i:j]) + "}}")
		s.last = j
		return j
	}
	return i + 1
}

// str reads the string at body[i]: an object key, or a value that moves to
// a variable if it is secret. A string that does not end ends the body.
func (s *jsonScan) str(i int, secret bool) int {
	body := s.body
	j := stringEnd(body, i)
	if j < 0 {
		return len(body)
	}
	if strings.HasPrefix(strings.TrimLeft(body[j:], " \t\r\n"), ":") {
		s.key = body[i+1 : j-1]
	} else if secret && j-i > 2 {
		s.out.WriteString(body[s.last:i+1] + s.q.secret(body[i+1:j-1], base(s.key)))
		s.last = j - 1
	}
	return j
}

// lineEnd returns the index of the line feed that ends the line at
// body[i], or len(body).
func lineEnd(body string, i int) int {
	if n := strings.IndexByte(body[i:], '\n'); n >= 0 {
		return i + n
	}
	return len(body)
}

// commentEnd returns the index after the /* comment */ at body[i], or
// len(body) if it does not end.
func commentEnd(body string, i int) int {
	if n := strings.Index(body[i+2:], "*/"); n >= 0 {
		return i + n + 4
	}
	return len(body)
}

// numberEnd returns the index after the number at body[i].
func numberEnd(body string, i int) int {
	j := i + 1
	for j < len(body) && strings.IndexByte("+-.0123456789eE", body[j]) >= 0 {
		j++
	}
	return j
}

var placeholderAt = regexp.MustCompile(`^\{\{[^{}]*\}\}`)

// stringEnd returns the index after the JSON string that starts at
// body[i], or -1 if it does not end.
func stringEnd(body string, i int) int {
	for j := i + 1; j < len(body); j++ {
		switch body[j] {
		case '\\':
			j++
		case '"':
			return j + 1
		}
	}
	return -1
}

// formEscape escapes s for a form body, leaving its placeholders as they
// are. vegtam inserts their values unescaped.
func formEscape(s string) string {
	var b strings.Builder
	last := 0
	for _, m := range placeholder.FindAllStringIndex(s, -1) {
		b.WriteString(url.QueryEscape(s[last:m[0]]) + s[m[0]:m[1]])
		last = m[1]
	}
	b.WriteString(url.QueryEscape(s[last:]))
	return b.String()
}

// trimLines returns s with LF line endings and without blank lines at its
// start and end, as the .http parser reads a body.
func trimLines(s string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		lines = lines[1:]
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	return strings.Join(lines, "\n")
}

// scripts reports the scripts of a request. A test that only checks the
// status becomes an @assert.
func (q *rq) scripts(events []event) {
	for _, e := range events {
		if e.Disabled || e.code() == "" {
			continue
		}
		q.skip("script", scriptKind(e)+" script")
		q.comments = append(q.comments, "The Postman "+scriptKind(e)+" script is not imported")
		if s := statusTest(e.code()); s != "" && e.Listen == "test" {
			q.asserts = append(q.asserts, "status == "+s)
		}
	}
}

var statusTestRE = regexp.MustCompile(`pm\.response\.to\.have\.status\(\s*(\d{3})\s*\)|` +
	`pm\.response\.code\)\.to\.(?:eql|equal|be)\(\s*(\d{3})\s*\)|responseCode\.code\s*===?\s*(\d{3})|pm\.response\.to\.be\.(ok)\b`)

// statusTest returns the status a test script checks for, if it checks
// for exactly one.
func statusTest(js string) string {
	var codes []string
	for _, m := range statusTestRE.FindAllStringSubmatch(js, -1) {
		code := m[1] + m[2] + m[3] + m[4]
		if code == "ok" {
			code = "200"
		}
		codes = append(codes, code)
	}
	slices.Sort(codes)
	if codes = slices.Compact(codes); len(codes) == 1 {
		return codes[0]
	}
	return ""
}

// settings lists the request settings that are not imported.
// disableBodyPruning only lets a GET request have a body, which vegtam
// always allows.
func settings(b map[string]any) string {
	var keys []string
	for k := range b {
		if k != "disableBodyPruning" {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return strings.Join(keys, ", ")
}

// oneLine returns s for a comment line: line breaks and other control
// characters become spaces.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.ReplaceAll(s, "\r\n", " "))
}
