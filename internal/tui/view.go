package tui

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"charm.land/bubbles/v2/help"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/env"
	"github.com/vidforull/vegtam/internal/core/output"
)

// The layouts: three columns from wideWidth on, the tree beside the
// request over the response from minWidth on, one column below that.
const (
	wideWidth = 140
	minWidth  = 80
)

var (
	accent = lipgloss.Color("6")
	faint  = lipgloss.Color("8")
)

// View renders the interface. Every text in it has been through clean
// before Lip Gloss lays it out. A panic in it ends the program.
func (m *Model) View() (v tea.View) {
	defer func() {
		if r := recover(); r != nil {
			v, m.panicked = tea.NewView(""), caught(r)
			m.stop()
		}
	}()
	v = tea.NewView(m.render())
	v.AltScreen = true
	return v
}

// resize fits the panes to the terminal.
func (m *Model) resize() {
	w, body := max(m.width, 1), max(m.height-1, 3) // the status line
	switch {
	case w >= wideWidth:
		tw := max(24, w*22/100)
		rw := (w - tw) / 2
		m.sizes = [panes]size{{tw, body}, {rw, body}, {w - tw - rw, body}}
	case w >= minWidth:
		tw, rh := max(24, w*28/100), body*2/5
		m.sizes = [panes]size{{tw, body}, {w - tw, rh}, {w - tw, body - rh}}
	default:
		th, rh := body/4, body/3
		m.sizes = [panes]size{{w, th}, {w, rh}, {w, body - th - rh}}
	}
	// Less the border, and the title.
	m.request.SetWidth(max(m.sizes[requestPane].w-2, 1))
	m.request.SetHeight(max(m.sizes[requestPane].h-3, 1))
	m.response.SetWidth(max(m.sizes[responsePane].w-2, 1))
	m.response.SetHeight(max(m.sizes[responsePane].h-3, 1))
	m.help.SetWidth(max(w-2, 1))
	m.help.SetHeight(max(body-3, 1))
	if m.mode == helping { // laid out anew for the width
		m.help.SetContent(m.helpText(m.help.Width()))
	}
}

func (m *Model) render() string {
	if m.width == 0 {
		return ""
	}
	treeTitle := "Requests"
	switch {
	case m.mode == choosingEnv:
		treeTitle = "Environment"
	case m.runsOpen:
		treeTitle = "History"
	}
	tree := m.box(treePane, treeTitle, m.treeText())
	request := m.box(requestPane, "Request "+m.ref(), m.request.View())
	title := "Response "
	if m.fold > 0 { // before the reference, which may be cut off
		title += "(folded from depth " + strconv.Itoa(m.fold) + ") "
	}
	title += m.resultRef()
	response := m.box(responsePane, title, m.response.View())
	switch {
	case m.runsOpen:
		response = m.box(responsePane, "Run", m.response.View())
	case m.curl != "":
		response = m.box(responsePane, "curl "+m.ref(), m.response.View())
	}
	switch m.mode {
	case browsing, searching, choosingEnv, helping:
	case confirming:
		r := m.rows[m.cursor]
		req := r.file.Requests[r.index]
		question := fmt.Sprintf("Send %s %s?\n\n", req.Method, output.Ref(r.file, r.index))
		// The text of its @note, from the file: clean masks it and shows
		// what would drive the terminal as escapes.
		if note, ok := req.Note(); ok && note != "" {
			question += note + "\n\n"
		}
		response = m.box(responsePane, "Send?", m.clean(question+"enter sends it, any other key does not."))
	}
	var panes string
	switch {
	case m.mode == helping: // over all three panes, so that it fits 80x24; scrolled if it does not
		title := "Keys"
		if m.help.TotalLineCount() > m.help.Height() {
			title += fmt.Sprintf(" (%d%%; j/k, f/b scroll)", int(m.help.ScrollPercent()*100))
		}
		panes = m.frame(m.width, max(m.height-1, 3), true, title, m.help.View())
	case m.width >= wideWidth:
		panes = lipgloss.JoinHorizontal(lipgloss.Top, tree, request, response)
	case m.width >= minWidth:
		panes = lipgloss.JoinHorizontal(lipgloss.Top, tree, lipgloss.JoinVertical(lipgloss.Left, request, response))
	default:
		panes = lipgloss.JoinVertical(lipgloss.Left, tree, request, response)
	}
	return lipgloss.JoinVertical(lipgloss.Left, panes, m.statusLine())
}

// box draws pane p with a title over content, which fits it already.
func (m *Model) box(p pane, title, content string) string {
	return m.frame(m.sizes[p].w, m.sizes[p].h, p == m.focus, title, content)
}

// frame draws a w by h box with a title over content.
func (m *Model) frame(w, h int, focused bool, title, content string) string {
	border := faint
	if focused {
		border = accent
	}
	head := lipgloss.NewStyle().Bold(true).MaxWidth(max(w-2, 1)).Render(m.line(title))
	return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(border).
		Width(w).Height(h).MaxHeight(h).Render(head + "\n" + content)
}

// line is clean for text that must stay on one line.
func (m *Model) line(s string) string { return strings.ReplaceAll(m.clean(s), "\n", `\n`) }

func (m *Model) ref() string {
	if m.preview == nil {
		return m.rows[m.cursor].path
	}
	return m.preview.Ref
}

func (m *Model) resultRef() string {
	switch {
	case m.flight != nil:
		return m.flight.ref
	case m.result != nil:
		return m.result.Ref
	}
	return ""
}

// treeText lists the files and their requests that match the search, or
// the environments to choose from, as many lines as fit around the
// selected one. The search, if there is one, stays on the first line.
func (m *Model) treeText() string {
	sz := m.sizes[treePane]
	w, h := max(sz.w-2, 1), max(sz.h-3, 1)
	// Without styles, as with TERM=dumb, a mark shows the selected line.
	item := func(s string, selected bool) string {
		st := lipgloss.NewStyle().MaxWidth(w)
		switch {
		case m.plain && selected:
			s = "> " + s
		case m.plain:
			s = "  " + s
		case selected:
			st = st.Reverse(true)
		}
		return st.Render(m.line(s))
	}
	var head string
	var lines []string
	at := 0
	if q, _, _ := m.searched(); m.mode != choosingEnv && (m.mode == searching || *q != "") {
		text := "/" + *q
		if m.mode == searching {
			text += "_"
		}
		head = lipgloss.NewStyle().Foreground(accent).MaxWidth(w).Render(m.line(text)) + "\n"
		h = max(h-1, 1)
	}
	switch {
	case m.mode == choosingEnv:
		for i, name := range m.envs {
			lines = append(lines, item(cmp.Or(name, "(none)"), i == m.choice))
		}
		at = m.choice
	case m.runsOpen:
		for _, i := range m.runShown {
			if i == m.run {
				at = len(lines)
			}
			lines = append(lines, item(m.runLabel(m.runs[i]), i == m.run))
		}
		switch {
		case len(m.runs) == 0:
			lines = append(lines, item("no runs yet", false))
		case len(lines) == 0:
			lines = append(lines, item("no run matches", false))
		}
	default:
		for _, i := range m.shown {
			r := m.rows[i]
			label := r.label
			switch {
			case r.index >= 0:
				label = "  " + label
			case r.err != nil:
				label += " ✗"
			}
			if i == m.cursor {
				at = len(lines)
			}
			lines = append(lines, item(label, i == m.cursor))
		}
		if len(lines) == 0 {
			lines = append(lines, item("no request matches", false))
		}
	}
	start := max(0, min(at-h/2, len(lines)-h))
	return head + strings.Join(lines[start:min(start+h, len(lines))], "\n")
}

// requestText is the selected request: its directives and the request as
// it would be sent or, if it cannot be resolved, as written, and what
// stops it from being sent.
func (m *Model) requestText() string {
	r := m.rows[m.cursor]
	var b strings.Builder
	if m.preview == nil {
		fmt.Fprintf(&b, "%s\n\n%d requests\n", r.path, len(r.file.Requests))
		return b.String()
	}
	if r.index >= 0 {
		req := r.file.Requests[r.index]
		for _, d := range req.Directives {
			b.WriteString(strings.TrimSpace("# @"+d.Kind+" "+d.Value) + "\n")
		}
		if m.preview.Request != nil {
			output.WriteRequest(&b, m.preview.Request)
		} else {
			output.WriteRequest(&b, output.Written(req))
		}
	}
	writeError(&b, m.preview.Error)
	return b.String()
}

// The colours of placeholders in the request pane, by what they stand
// for. Without colour, as with NO_COLOR, the text tells as much: a secret
// shows as its placeholder or as ***, and the error under the request
// names what is unresolved.
var placeholderStyles = map[env.Class]lipgloss.Style{
	env.Unresolved: lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Bold(true),
	env.Plain:      lipgloss.NewStyle().Foreground(lipgloss.Color("2")),
	env.Secret:     lipgloss.NewStyle().Foreground(lipgloss.Color("5")),
	env.Captured:   lipgloss.NewStyle().Foreground(lipgloss.Color("3")),
}

// placeholder matches a placeholder, and a value masked as ***.
var placeholder = regexp.MustCompile(`\{\{[^{}\n]*\}\}|\*\*\*`)

// highlight colours the placeholders in s by what they stand for, and the
// values masked in it as secrets. s is the request pane's text as clean
// has made it: highlight only puts styles around parts of it, so what a
// view shows, once the styles are left out, is still s.
func (m *Model) highlight(s string) string {
	return placeholder.ReplaceAllStringFunc(s, func(p string) string {
		class := env.Secret
		if p != "***" {
			pieces, err := core.ParseTemplate(p)
			if err != nil || len(pieces) != 1 || pieces[0].Ref == nil {
				return p
			}
			class = m.class(*pieces[0].Ref)
		}
		return placeholderStyles[class].Render(p)
	})
}

// class returns what the placeholder r of the selected request stands
// for. One that the error names is unresolved, whatever the environment
// says: a capture that took nothing, for one.
func (m *Model) class(r core.Ref) env.Class {
	name := strings.TrimSpace(r.Func + " " + r.Name)
	switch {
	case m.job == nil, m.preview.Error != nil && slices.Contains(m.preview.Error.Variables, name):
		return env.Unresolved
	}
	return m.job.Class(r)
}

// responseText is the latest response as vegtam run --verbose prints it:
// the status and the time, the headers, the body, the outcomes of the
// directives, and the error, if there is one. A curl command just copied
// is shown over it, and the run selected in the history over both.
func (m *Model) responseText() string {
	var b strings.Builder
	switch {
	case m.runsOpen:
		b.WriteString(m.runText())
	case m.curl != "":
		b.WriteString("Copied, if the terminal takes OSC 52; esc hides it.\n\n" + m.curl)
	case m.flight != nil:
		fmt.Fprintf(&b, "Sending %s\n\nesc cancels it\n", m.flight.ref)
	case m.result == nil:
		b.WriteString("enter sends the selected request\n")
	default:
		if r := m.result.Response; r != nil {
			// Masked whole before it is folded: a fold must not cut a
			// secret value in two and leave a part of it unmasked. The
			// rest of clean comes after, on the whole text, as the CLI
			// prints it: shown as \x7f, DEL and C1 characters, which JSON
			// allows in strings, would make the body no JSON.
			res, resp := *m.result, *r
			if resp.Encoding == "" {
				resp.Body = m.masker.Mask(resp.Body)
			}
			res.Response = &resp
			output.WriteResponse(&b, &res, true, m.fold)
		} else {
			output.WriteTrace(&b, m.result)
		}
		writeWarnings(&b, m.result.Warnings)
		writeError(&b, m.result.Error)
	}
	return b.String()
}

func writeWarnings(b *strings.Builder, ws []output.Warning) {
	for i, w := range ws {
		if i == 0 && b.Len() > 0 {
			b.WriteString("\n")
		}
		loc := w.File
		if loc != "" && w.Line > 0 {
			loc += ":" + strconv.Itoa(w.Line)
		}
		if loc != "" {
			loc += ": "
		}
		fmt.Fprintf(b, "! %s%s\n", loc, w.Message)
	}
}

func writeError(b *strings.Builder, e *output.Error) {
	if e == nil {
		return
	}
	if b.Len() > 0 {
		b.WriteString("\n")
	}
	loc := e.File
	if loc != "" && e.Line > 0 {
		loc += ":" + strconv.Itoa(e.Line)
	}
	if loc != "" {
		loc += ": "
	}
	fmt.Fprintf(b, "✗ %s: %s%s\n", e.Kind, loc, e.Message)
}

// helpColumn is the width of the first column of keys in the help.
const helpColumn = 40

// helpText lists the keys, one a line, in two columns if width allows
// (help's own columns would cut off what does not fit a narrow pane), and
// says what the colours of the request pane mean, in those colours; it
// is wrapped at words to width. On 80x24 it fits whole.
func (m *Model) helpText(width int) string {
	var keys []string
	for _, group := range m.keys.FullHelp() {
		for _, k := range group {
			keys = append(keys, fmt.Sprintf("%-10s %s", k.Help().Key, k.Help().Desc))
		}
	}
	var b strings.Builder
	if half := (len(keys) + 1) / 2; width >= helpColumn+30 {
		for i, k := range keys[:half] {
			fmt.Fprintf(&b, "%-*s", helpColumn, k)
			if i+half < len(keys) {
				b.WriteString(keys[i+half])
			}
			b.WriteString("\n")
		}
	} else {
		b.WriteString(strings.Join(keys, "\n") + "\n")
	}
	b.WriteString("\nIn the request and response panes j/k scroll, f/b by a page, d/u by half.\n\n" +
		"/ narrows the list by label, file or URL: enter keeps it, esc clears it.\n\n" +
		"enter asks first for a method other than GET, HEAD or OPTIONS, and for a request with an @note: enter again sends. " +
		"y copies the request as curl, its secrets as shell variables; esc hides it.\n\n" +
		"h lists the latest runs: enter goes to the request of one; esc closes it.\n\n")
	st := func(c env.Class, s string) string { return placeholderStyles[c].Render(s) }
	text := m.clean(b.String()) + "In the request, " + st(env.Plain, "green") + " is a value, " + st(env.Secret, "magenta") +
		" a secret, " + st(env.Captured, "yellow") + " a capture and " + st(env.Unresolved, "red") + " what does not resolve."
	return ansi.Wrap(text, width, "")
}

// minLeft is how many columns of the status line the environment and the
// note keep before the keys give way to the main ones.
const minLeft = 16

// statusLine shows the environment, what is going on and the keys. The
// keys come first: on a narrow terminal, the left part is cut short, and
// only the keys besides the main ones give way to it.
func (m *Model) statusLine() string {
	state := m.note
	switch {
	case m.flight == nil, state != "":
	case m.runsOpen: // where esc closes the list
		state = "sending"
	default:
		state = "sending; esc cancels"
	}
	left := " env: " + cmp.Or(m.env, "none") + "  " + state
	if m.opts.Transport.TLS.Insecure {
		left = " INSECURE " + left // --insecure: server certificates are not checked
	}
	left = m.line(left)
	keys, main := m.keys.ShortHelp(), m.keys.mainHelp()
	if m.runsOpen {
		keys = m.keys.runsHelp()
		main = keys
	}
	h := help.New()
	right := h.ShortHelpView(keys) + " "
	if lipgloss.Width(right)+minLeft > m.width {
		h.SetWidth(max(m.width-1, 1))
		right = h.ShortHelpView(main) + " "
	}
	if room := m.width - lipgloss.Width(right); lipgloss.Width(left) > room {
		left = ansi.Truncate(left, max(room-1, 0), "…")
	}
	line := left + strings.Repeat(" ", max(m.width-lipgloss.Width(left)-lipgloss.Width(right), 0)) + right
	return ansi.Truncate(line, m.width, "")
}
