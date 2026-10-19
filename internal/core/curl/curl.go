// Package curl writes a prepared request as a curl command line. No
// secret is in it in any form: each is a shell variable, which the
// command checks is set before curl runs.
package curl

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/vidforull/vegtam/internal/core"
)

// ErrSecret is the error for a request whose text holds a secret value
// outside a placeholder, such as a public variable whose value is also a
// private one: the command would hold the value.
var ErrSecret = errors.New("a secret value is in the request outside a placeholder")

// Command returns p as a curl command line for bash, zsh and other POSIX
// shells, an option to a line. curl sends what vegtam would: the method,
// the URL, the headers and the body, and nothing that curl adds to a body
// of its own accord, such as a Content-Type or an Expect; its default
// headers, such as User-Agent and Accept, are curl's. A body file is sent
// with --data-binary @path, its path as the .http file's was given.
//
// Each secret is "$name", a shell variable named after its placeholder:
// {{token}} is "$token", {{$env NAME}} and {{$cmd NAME}} are "$NAME".
// Prepared requests hold no secret values, so neither can the command. A
// comment first names the variables, and the command checks that they
// are set before curl runs. If m finds a secret value in the text of p,
// Command returns an error that wraps ErrSecret, and says where the
// value is, instead of a command that would hold it.
//
// Literal text is single-quoted or, if it holds a control character other
// than a line feed, an invisible format character (core.Invisible) or a
// byte that is not UTF-8, written as $'...' with those escaped: the
// command holds none of them, and shows on a terminal as it is.
func Command(p *core.Prepared, m *core.Masker) (string, error) {
	c := &command{masker: m, names: map[core.Secret]string{}, taken: map[string]bool{}}
	file := p.Request.BodyFile
	inline := !empty(p.Body) && file == ""
	// net/http sends these methods with Content-Length: 0 when there is
	// no body; curl sends it for an empty --data-raw only.
	none := !inline && file == "" && slices.Contains([]string{http.MethodPost, http.MethodPut, http.MethodPatch}, p.Method)
	body := inline || file != "" || none

	first := []string{"curl"}
	switch m := p.Method; {
	case m == http.MethodHead && !body:
		first = append(first, "--head")
	case m == http.MethodGet && !body, m == http.MethodPost && body:
	default:
		first = append(first, "-X", word(m))
	}
	if p.URL.HasSecret() || strings.ContainsAny(p.URL.Masked(), "[]{}") {
		first = append(first, "--globoff") // curl would read [1-3] and {a,b} as ranges and sets
	}
	// curl would remove /./ and /../, and %2e%2e too; vegtam sends the
	// path as it is.
	first = append(first, "--path-as-is", c.text(p.URL, "the URL"))
	lines := []string{strings.Join(first, " ")}

	contentType := false
	for _, h := range p.Headers {
		contentType = contentType || strings.EqualFold(h.Name, "Content-Type")
		t := append(core.Text{{Text: h.Name + ": "}}, h.Value...)
		if empty(h.Value) {
			t = core.Text{{Text: h.Name + ";"}} // "Name:" would remove the header, "Name;" sends it empty
		}
		lines = append(lines, "-H "+c.text(t, "header "+h.Name))
	}
	if body && !contentType {
		lines = append(lines, "-H 'Content-Type:'")
	}
	if size(p.Body) > 1<<20 {
		lines = append(lines, "-H 'Expect:'") // curl would wait for 100 Continue first
	}
	switch {
	case file != "":
		path := filepath.Join(filepath.Dir(p.Request.Source.File), filepath.FromSlash(file))
		if !filepath.IsAbs(path) {
			path = "." + string(filepath.Separator) + path // @- would read stdin
		}
		lines = append(lines, "--data-binary "+c.literal("@"+path, "the path of the body file"))
	case inline:
		lines = append(lines, "--data-raw "+c.text(p.Body, "the body")) // not --data-binary: a body that starts with @ is no file name
	case none:
		lines = append(lines, "--data-raw ''")
	}
	if c.err != nil {
		return "", c.err
	}
	cmd := strings.Join(lines, " \\\n  ") + "\n"
	if len(c.order) == 0 {
		return cmd, nil
	}
	return c.comment() + "\n" + c.guard() + cmd, nil
}

// command is a command line being written: the shell variables of its
// secrets, in the order they come, and whether its text held a secret.
type command struct {
	masker *core.Masker
	names  map[core.Secret]string
	order  []core.Secret
	taken  map[string]bool
	err    error
}

// text returns t, which is where, as one shell word.
func (c *command) text(t core.Text, where string) string {
	var b strings.Builder
	literal := ""
	for _, seg := range t {
		if seg.Secret == nil {
			literal += seg.Text
			continue
		}
		b.WriteString(c.literal(literal, where) + `"$` + c.variable(*seg.Secret) + `"`)
		literal = ""
	}
	b.WriteString(c.literal(literal, where))
	if b.Len() == 0 {
		return "''"
	}
	return b.String()
}

// literal returns s, which is in where, quoted. It looks for secret
// values in s first, as it is: quoted, a value with a ' or a control
// character in it would no longer be found.
func (c *command) literal(s, where string) string {
	if c.err == nil && c.masker.Mask(s) != s {
		c.err = fmt.Errorf("%w, in %s", ErrSecret, where)
	}
	return quote(s)
}

// variable returns the name of the shell variable for s.
func (c *command) variable(s core.Secret) string {
	if name, ok := c.names[s]; ok {
		return name
	}
	base := s.Name
	if _, arg, ok := strings.Cut(s.Name, " "); ok { // "$env NAME", "$cmd NAME"
		base = arg
	}
	base = strings.Map(func(r rune) rune {
		if r == '_' || r < utf8.RuneSelf && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
			return r
		}
		return '_'
	}, base)
	if base == "" || base[0] >= '0' && base[0] <= '9' {
		base = "_" + base
	}
	// The variable of {{$env NAME}} is NAME, whatever NAME is: it is the
	// one vegtam reads.
	env := strings.HasPrefix(s.Name, "$env ")
	name := base
	for i := 2; c.taken[name] || name == base && !env && reserved(base); i++ {
		name = base + "_" + strconv.Itoa(i)
	}
	c.names[s], c.taken[name] = name, true
	c.order = append(c.order, s)
	return name
}

// reserved reports whether bash or zsh give the variable name a meaning
// of their own: setting it would change the shell, not pass a value.
func reserved(name string) bool {
	return shellNames[name] || strings.HasPrefix(name, "BASH") || strings.HasPrefix(name, "ZSH_")
}

var shellNames = func() map[string]bool {
	names := map[string]bool{}
	for name := range strings.FieldsSeq(`_ CDPATH COLUMNS ENV EUID FCEDIT GROUPS HISTFILE HISTSIZE HOME HOSTNAME IFS
		LANG LC_ALL LINENO LINES MAIL MAILPATH OLDPWD OPTARG OPTIND PATH PPID PS1 PS2 PS3 PS4 PWD RANDOM SECONDS
		SHELL SHELLOPTS SHLVL TERM TMOUT UID USER PS0 PROMPT_COMMAND PROMPT PROMPT2 PROMPT3 PROMPT4 RPROMPT RPROMPT2
		RPS1 RPS2 aliases argv cdpath commands fpath functions histchars history
		manpath mailpath module_path options parameters path pipestatus prompt psvar signals status watch`) {
		names[name] = true
	}
	return names
}()

// comment names the shell variables to set, and what each stands for. It
// has no parentheses, for zsh, which without interactivecomments reads it
// as a command.
func (c *command) comment() string {
	var vars []string
	for _, s := range c.order {
		name := s.Name
		// The command holds no control or invisible character, its
		// comment included: shown with Go's escapes.
		if strings.ContainsFunc(name, func(r rune) bool { return !unicode.IsPrint(r) && r != ' ' || core.Invisible(r) }) {
			name = strconv.QuoteToASCII(name)
		}
		v := c.names[s] + " for {{" + name + "}}"
		if s.Capture {
			v += " from an @capture"
		}
		vars = append(vars, v)
	}
	return "# Set first: " + strings.Join(vars, ", ")
}

// guard starts the command with a check that each variable is set, so
// that curl does not run, pasted at once, with a secret left out.
func (c *command) guard() string {
	var b strings.Builder
	b.WriteString(":")
	for _, s := range c.order {
		b.WriteString(` "${` + c.names[s] + `?}"`)
	}
	return b.String() + " && "
}

// word returns s as a shell word, quoted only if it has to be.
func word(s string) string {
	if safe.MatchString(s) {
		return s
	}
	return quote(s)
}

var safe = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

// quote returns s quoted for a shell, or "" for "".
func quote(s string) string {
	switch {
	case s == "":
		return ""
	case utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) && r != '\n' || core.Invisible(r) }):
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	var b strings.Builder
	b.WriteString("$'")
	for s != "" {
		r, size := utf8.DecodeRuneInString(s)
		switch {
		case r == '\\', r == '\'':
			b.WriteString(`\` + string(r))
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == utf8.RuneError && size == 1, unicode.IsControl(r), core.Invisible(r):
			for _, c := range []byte(s[:size]) {
				fmt.Fprintf(&b, `\x%02x`, c)
			}
		default:
			b.WriteString(s[:size])
		}
		s = s[size:]
	}
	b.WriteString("'")
	return b.String()
}

// size returns how many bytes of t are literal text.
func size(t core.Text) int {
	n := 0
	for _, seg := range t {
		n += len(seg.Text)
	}
	return n
}

// empty reports whether t is no text at all.
func empty(t core.Text) bool {
	for _, seg := range t {
		if seg.Secret != nil || seg.Text != "" {
			return false
		}
	}
	return true
}
