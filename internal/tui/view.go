package tui

import (
	"cmp"
	"fmt"
	"strconv"
	"strings"

	"charm.land/bubbles/v2/help"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

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
}

func (m *Model) render() string {
	if m.width == 0 {
		return ""
	}
	tree := m.box(treePane, "Requests", m.treeText())
	if m.mode == choosingEnv {
		tree = m.box(treePane, "Environment", m.treeText())
	}
	request := m.box(requestPane, "Request "+m.ref(), m.request.View())
	response := m.box(responsePane, "Response "+m.resultRef(), m.response.View())
	switch m.mode {
	case browsing, choosingEnv, helping:
	case confirming:
		r := m.rows[m.cursor]
		response = m.box(responsePane, "Send?", m.clean(fmt.Sprintf("Send %s %s?\n\ny sends it, any other key does not.",
			r.file.Requests[r.index].Method, output.Ref(r.file, r.index))))
	}
	var panes string
	switch {
	case m.mode == helping: // over all three panes, so that it fits 80x24
		panes = m.frame(m.width, max(m.height-1, 3), true, "Keys", m.helpText())
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

// treeText lists the files and their requests, or the environments to
// choose from, as many lines as fit around the selected one.
func (m *Model) treeText() string {
	sz := m.sizes[treePane]
	w, h := max(sz.w-2, 1), max(sz.h-3, 1)
	item := func(s string, selected bool) string {
		st := lipgloss.NewStyle().MaxWidth(w)
		if selected {
			st = st.Reverse(true)
		}
		return st.Render(m.line(s))
	}
	var lines []string
	at := m.cursor
	if m.mode == choosingEnv {
		for i, name := range m.envs {
			lines = append(lines, item(cmp.Or(name, "(none)"), i == m.choice))
		}
		at = m.choice
	} else {
		for i, r := range m.rows {
			label := r.label
			switch {
			case r.index >= 0:
				label = "  " + label
			case r.err != nil:
				label += " ✗"
			}
			lines = append(lines, item(label, i == m.cursor))
		}
	}
	start := max(0, min(at-h/2, len(lines)-h))
	return strings.Join(lines[start:min(start+h, len(lines))], "\n")
}

// requestText is the selected request: its directives and the request
// as written, or as it would be sent, and what stops it from being sent.
func (m *Model) requestText() string {
	r := m.rows[m.cursor]
	var b strings.Builder
	if m.preview == nil {
		fmt.Fprintf(&b, "%s\n\n%d requests\n", r.path, len(r.file.Requests))
		return b.String()
	}
	if r.index >= 0 {
		for _, d := range r.file.Requests[r.index].Directives {
			fmt.Fprintf(&b, "# @%s %s\n", d.Kind, d.Value)
		}
	}
	if m.preview.Request != nil {
		output.WriteRequest(&b, m.preview.Request)
	}
	writeError(&b, m.preview.Error)
	return b.String()
}

// responseText is the latest response as vegtam run --verbose prints it:
// the status and the time, the headers, the body, the outcomes of the
// directives, and the error, if there is one.
func (m *Model) responseText() string {
	var b strings.Builder
	switch {
	case m.flight != nil:
		fmt.Fprintf(&b, "Sending %s\n\nesc cancels it\n", m.flight.ref)
	case m.result == nil:
		b.WriteString("enter sends the selected request\n")
	default:
		if m.result.Response != nil {
			output.WriteResponse(&b, m.result, true)
		}
		writeError(&b, m.result.Error)
	}
	return b.String()
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

// helpText lists the keys, one a line: in columns, as help lays them
// out, those that do not fit a narrow pane would be cut off.
func (m *Model) helpText() string {
	var b strings.Builder
	for _, group := range m.keys.FullHelp() {
		for _, k := range group {
			fmt.Fprintf(&b, "%-10s %s\n", k.Help().Key, k.Help().Desc)
		}
	}
	b.WriteString("\nIn the request and response panes, j/k scroll,\nf/b by a page and d/u by half of one.\n\n" +
		"enter asks before it sends a method other than\nGET, HEAD or OPTIONS.")
	return m.clean(b.String())
}

// statusLine shows the environment, what is going on and the main keys.
func (m *Model) statusLine() string {
	state := m.note
	if m.flight != nil && state == "" {
		state = "sending; esc cancels"
	}
	left := m.line(" env: " + cmp.Or(m.env, "none") + "  " + state)
	right := help.New().ShortHelpView(m.keys.ShortHelp()) + " "
	if gap := m.width - lipgloss.Width(left) - lipgloss.Width(right); gap > 0 {
		return left + strings.Repeat(" ", gap) + right
	}
	return lipgloss.NewStyle().MaxWidth(m.width).Render(left)
}
