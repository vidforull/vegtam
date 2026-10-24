package redact

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Limits of JSON, so that an untrusted body cannot make the list of paths
// grow with the square of its size, through deep nesting or long keys.
const (
	maxDepth = 1000 // levels of objects and arrays; one deeper is hidden whole
	maxPaths = 100  // paths listed; the rest are counted
	maxPath  = 256  // bytes of a path; a longer one is cut short with …
)

// JSON returns the JSON text doc with what commonly carries credentials in
// it replaced with the JSON string "***", and the paths of what it
// replaced. It replaces the value of each member whose key Key names,
// whatever its type, but null and "", which hold nothing; and in every
// other string value, keys aside, each JWT-shaped token as Text finds it,
// so that a value that is a token alone becomes "***". Keys are compared, and
// values searched, as JSON decodes them: a server may escape any
// character. A value that is "***" already is left alone and not listed,
// so that JSON of its own output changes nothing.
//
// The rest of doc is kept byte for byte: the order of keys, spacing,
// numbers and escapes. JSON is lenient: it reads invalid JSON as far as it
// can make sense of it, and never fails. A member whose key Key names and
// whose value is cut off, as at the end of a body cut at a size limit,
// has the rest of doc replaced with "***". The output of valid JSON is
// valid JSON.
//
// Paths are written as JSONPath writes them, such as $.data.items[0].token,
// with a key that is not a name JSON-quoted in brackets: $["api-key"].
// Each is listed once, in document order, at most 100 of them, each cut
// short with … after 256 bytes; when there are more, the last entry says
// how many: "and 12 more". An object or array nested deeper than 1000
// levels is replaced whole.
func JSON(doc []byte) (out []byte, paths []string) {
	s := &scanner{doc: doc, out: make([]byte, 0, len(doc)), seen: map[string]bool{}}
	for s.i < len(s.doc) {
		s.step()
	}
	if s.more > 0 {
		s.paths = append(s.paths, "and "+strconv.Itoa(s.more)+" more")
	}
	return s.out, s.paths
}

// state is what a scanner expects next in an object or array.
type state int

const (
	wantValue  state = iota // a value, or the end
	wantKey                 // a key, or the end of an object
	wantColon               // the colon after a key
	afterValue              // a comma, or the end
)

// frame is an object or array the scanner is in.
type frame struct {
	object bool
	state  state
	key    string // of the member being read, decoded
	index  int    // of the item being read
}

// scanner reads a JSON text a byte at a time, copying it to out as it
// goes, but for the values it replaces. A byte it does not expect is
// copied and read past: a value where a comma or a colon should be is
// read as if the comma or colon were there.
type scanner struct {
	doc   []byte
	i     int // the next byte to read
	out   []byte
	stack []frame
	paths []string
	seen  map[string]bool // paths listed
	more  int             // values replaced but not listed
}

// step reads one token, or one byte that is not one.
func (s *scanner) step() {
	c := s.doc[s.i]
	switch {
	case isSpace(c):
		s.copy(s.i + 1)
		return
	case len(s.stack) == 0:
		// Values may follow one another, as in JSON Lines.
		if strings.IndexByte(",:]}", c) >= 0 {
			s.copy(s.i + 1)
		} else {
			s.value(false)
		}
		return
	case c == '}' || c == ']':
		s.copy(s.i + 1)
		s.stack = s.stack[:len(s.stack)-1]
		return
	}
	f := &s.stack[len(s.stack)-1]
	switch f.state {
	case wantKey:
		s.key(f, c)
	case wantColon:
		f.state = wantValue
		if c == ':' {
			s.copy(s.i + 1)
		}
	case afterValue:
		f.state = wantKey
		if !f.object {
			f.state = wantValue
			f.index++
		}
		if c == ',' {
			s.copy(s.i + 1)
		}
	case wantValue:
		switch c {
		case ',':
			s.copy(s.i + 1)
			if f.object {
				f.state = wantKey
			}
		case ':':
			s.copy(s.i + 1)
		default:
			// The value may push a frame, and f with it.
			f.state = afterValue
			s.value(f.object && Key(f.key))
		}
	}
}

// key reads the key of a member, starting with c, into f.
func (s *scanner) key(f *frame, c byte) {
	switch c {
	case '"':
		end, _ := stringEnd(s.doc, s.i) // a key cut off ends the text
		f.key, f.state = decode(s.doc[s.i:end]), wantColon
		s.copy(end)
	case ',':
		s.copy(s.i + 1)
	case ':':
		s.copy(s.i + 1)
		f.key, f.state = "", wantValue
	case '{', '[':
		f.key, f.state = "", wantValue
	default: // a name without quotes
		end := bareEnd(s.doc, s.i)
		f.key, f.state = string(s.doc[s.i:end]), wantColon
		s.copy(end)
	}
}

// value reads a value; secret says that its key is one Key names.
func (s *scanner) value(secret bool) {
	switch c := s.doc[s.i]; {
	case secret:
		s.hide()
	case c == '"':
		end, cut := stringEnd(s.doc, s.i)
		raw := s.doc[s.i:end]
		s.i = end
		if t, ok := redactString(raw, cut); ok {
			s.out = append(s.out, t...)
			s.list()
		} else {
			s.out = append(s.out, raw...)
		}
	case c == '{' || c == '[':
		if len(s.stack) >= maxDepth {
			s.hide()
			return
		}
		s.copy(s.i + 1)
		f := frame{object: c == '{', state: wantValue}
		if f.object {
			f.state = wantKey
		}
		s.stack = append(s.stack, f)
	default: // a number, true, false, null, or a word that is not JSON
		end := bareEnd(s.doc, s.i)
		if t, ok := Text(string(s.doc[s.i:end])); ok {
			s.out = append(s.out, t...)
			s.list()
			s.i = end
		} else {
			s.copy(end)
		}
	}
}

// hide replaces the value that starts at s.i with "***", unless it holds
// nothing or is "***" already. A value cut off at the end of the text
// takes the rest of it.
func (s *scanner) hide() {
	var end int
	var cut bool
	switch s.doc[s.i] {
	case '"':
		end, cut = stringEnd(s.doc, s.i)
	case '{', '[':
		end, cut = containerEnd(s.doc, s.i)
	default:
		// Up to the end of the member: a value that is not JSON may hold
		// spaces, and is hidden whole.
		end = s.i
		for end < len(s.doc) && strings.IndexByte(",]}", s.doc[end]) < 0 {
			end++
		}
		for end > s.i && isSpace(s.doc[end-1]) {
			end--
		}
	}
	raw := s.doc[s.i:end]
	if !cut && (string(raw) == "null" || string(raw) == `""` || raw[0] == '"' && decode(raw) == "***") {
		s.copy(end)
		return
	}
	s.out = append(s.out, `"***"`...)
	s.list()
	s.i = end
}

// list lists the path of the value being read as replaced.
func (s *scanner) list() {
	p := s.path()
	switch {
	case s.seen[p]:
	case len(s.paths) >= maxPaths:
		s.more++
	default:
		s.seen[p] = true
		s.paths = append(s.paths, p)
	}
}

// path returns the path of the value being read, cut short after
// maxPath bytes.
func (s *scanner) path() string {
	b := []byte{'$'}
	for _, f := range s.stack {
		if len(b) > maxPath {
			break
		}
		switch k := f.key[:min(len(f.key), maxPath)]; {
		case !f.object:
			b = append(b, '[')
			b = strconv.AppendInt(b, int64(f.index), 10)
			b = append(b, ']')
		case isName(k):
			b = append(b, '.')
			b = append(b, k...)
		default:
			b = append(b, '[')
			b = append(b, quote(k)...)
			b = append(b, ']')
		}
	}
	if len(b) > maxPath {
		n := maxPath
		for n > 0 && !utf8.RuneStart(b[n]) {
			n--
		}
		b = append(b[:n], "…"...)
	}
	return string(b)
}

// copy copies the text up to end to the output.
func (s *scanner) copy(end int) {
	s.out = append(s.out, s.doc[s.i:end]...)
	s.i = end
}

// redactString returns the JSON string raw, which cut says has no closing
// quote, with each JWT-shaped token in it replaced, and whether there was
// one. The string is searched as JSON decodes it; one that does not decode
// is searched as it is.
func redactString(raw []byte, cut bool) ([]byte, bool) {
	if len(raw) < 3*minSegment+2 {
		return nil, false
	}
	if !cut && bytes.IndexByte(raw, '\\') >= 0 {
		var d string
		if json.Unmarshal(raw, &d) == nil {
			if t, ok := Text(d); ok {
				return []byte(quote(t)), true
			}
			return nil, false
		}
	}
	// Quotes and backslashes are not part of a word, so the quotes and
	// escapes stay as they are.
	t, ok := Text(string(raw))
	return []byte(t), ok
}

// stringEnd returns the index just past the JSON string that starts at
// doc[i], a quote, and whether the string is cut off: it has no closing
// quote.
func stringEnd(doc []byte, i int) (int, bool) {
	for j := i + 1; j < len(doc); j++ {
		switch doc[j] {
		case '\\':
			j++
		case '"':
			return j + 1, false
		}
	}
	return len(doc), true
}

// containerEnd returns the index just past the object or array that
// starts at doc[i], and whether it is cut off. Any closing bracket closes
// any opening one.
func containerEnd(doc []byte, i int) (int, bool) {
	depth := 0
	for j := i; j < len(doc); j++ {
		switch doc[j] {
		case '"':
			end, cut := stringEnd(doc, j)
			if cut {
				return len(doc), true
			}
			j = end - 1
		case '{', '[':
			depth++
		case '}', ']':
			if depth--; depth == 0 {
				return j + 1, false
			}
		}
	}
	return len(doc), true
}

// bareEnd returns the index just past the word that starts at doc[i]: a
// number, true, false, null, or text that is not JSON.
func bareEnd(doc []byte, i int) int {
	j := i
	for j < len(doc) && !isSpace(doc[j]) && strings.IndexByte(`,:[]{}"`, doc[j]) < 0 {
		j++
	}
	return j
}

// decode returns the JSON string raw decoded, or what is between its
// quotes if it does not decode.
func decode(raw []byte) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return strings.TrimSuffix(strings.TrimPrefix(string(raw), `"`), `"`)
}

// quote returns s as a JSON string, with <, > and & as they are.
func quote(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if enc.Encode(s) != nil { // a string always encodes
		return `"***"`
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// isName reports whether k may follow a dot in a path: a letter or '_',
// then letters, digits and '_'.
func isName(k string) bool {
	for i := range len(k) {
		switch c := k[i]; {
		case c == '_', 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z':
		case i > 0 && '0' <= c && c <= '9':
		default:
			return false
		}
	}
	return k != ""
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }
