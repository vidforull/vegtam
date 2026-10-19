package tui

import (
	"context"
	"slices"
	"strings"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/env"
	"github.com/vidforull/vegtam/internal/core/output"
	"github.com/vidforull/vegtam/internal/core/session"
)

type pane int

const (
	treePane pane = iota
	requestPane
	responsePane
	panes // how many there are
)

type mode int

const (
	browsing mode = iota
	choosingEnv
	confirming // asks before sending a request that may change something
	helping
)

// Model is the state of the interface. Bubble Tea calls its methods on
// one goroutine; only the command of a request in flight runs on another,
// and while it does, it alone uses the session.
type Model struct {
	opts Options
	ctx  context.Context
	stop context.CancelFunc

	rows          []row
	cursor        int
	focus         pane
	mode          mode
	width, height int
	sizes         [panes]size

	env    string
	envs   []string // to choose from; "" is none
	choice int

	send     *session.Session
	declared []string         // what send has declared, as of when it was last idle
	dry      *session.Session // the dry run that previews the selected request
	// The secrets of the sessions of earlier environments, and of send as
	// of when it was last idle. masker joins them with those of dry, for
	// everything View shows.
	past, sent *core.Masker
	masker     *core.Masker

	preview *output.Result // the selected request, as written or as it would be sent
	result  *output.Result // the latest response
	flight  *flight
	note    string // a message for the status line

	request, response viewport.Model
	keys              keyMap
	panicked          *Panic
}

type size struct{ w, h int }

type keyMap struct {
	Up, Down, Next, Prev, Send, Cancel, Env, Help, Quit key.Binding
}

func newKeys() keyMap {
	b := func(keys []string, help, desc string) key.Binding {
		return key.NewBinding(key.WithKeys(keys...), key.WithHelp(help, desc))
	}
	return keyMap{
		Up:     b([]string{"k", "up"}, "k/↑", "up"),
		Down:   b([]string{"j", "down"}, "j/↓", "down"),
		Next:   b([]string{"tab"}, "tab", "next pane"),
		Prev:   b([]string{"shift+tab"}, "shift+tab", "previous pane"),
		Send:   b([]string{"enter"}, "enter", "send the request"),
		Cancel: b([]string{"esc"}, "esc", "cancel the request in flight"),
		Env:    b([]string{"e"}, "e", "environment"),
		Help:   b([]string{"?"}, "?", "help"),
		Quit:   b([]string{"q", "ctrl+c"}, "q", "quit"),
	}
}

func (k keyMap) ShortHelp() []key.Binding { return []key.Binding{k.Send, k.Env, k.Help, k.Quit} }

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{k.Up, k.Down, k.Next, k.Prev}, {k.Send, k.Cancel, k.Env}, {k.Help, k.Quit}}
}

// Init does nothing: New and start have read everything.
func (m *Model) Init() tea.Cmd { return nil }

// Update handles a message. A panic in it ends the program, so that the
// terminal is restored before the panic is printed.
func (m *Model) Update(msg tea.Msg) (next tea.Model, cmd tea.Cmd) {
	defer func() {
		if v := recover(); v != nil {
			next, cmd, m.panicked = m, tea.Quit, caught(v)
		}
	}()
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resize()
	case sentMsg:
		m.answered(msg)
	case panicMsg:
		m.panicked, cmd = msg.p, tea.Quit
	case tea.KeyPressMsg:
		cmd = m.key(msg)
	}
	return m, cmd
}

func (m *Model) key(k tea.KeyPressMsg) tea.Cmd {
	if k.String() == "ctrl+c" {
		return m.quit()
	}
	switch m.mode {
	case browsing:
	case confirming:
		m.mode = browsing
		if k.String() == "y" {
			return m.sendSelected()
		}
		m.note = "not sent"
		return nil
	case helping:
		switch {
		case key.Matches(k, m.keys.Quit):
			return m.quit()
		case key.Matches(k, m.keys.Help, m.keys.Cancel):
			m.mode = browsing
		}
		return nil
	case choosingEnv:
		switch {
		case key.Matches(k, m.keys.Down):
			m.choice = min(m.choice+1, len(m.envs)-1)
		case key.Matches(k, m.keys.Up):
			m.choice = max(m.choice-1, 0)
		case key.Matches(k, m.keys.Send):
			m.mode = browsing
			m.chooseEnv(m.envs[m.choice])
		case key.Matches(k, m.keys.Quit):
			return m.quit()
		case key.Matches(k, m.keys.Cancel, m.keys.Env):
			m.mode = browsing
		}
		return nil
	}
	switch {
	case key.Matches(k, m.keys.Quit):
		return m.quit()
	case key.Matches(k, m.keys.Help):
		m.mode = helping
	case key.Matches(k, m.keys.Env):
		m.openEnvs()
	case key.Matches(k, m.keys.Next):
		m.focus = (m.focus + 1) % panes
	case key.Matches(k, m.keys.Prev):
		m.focus = (m.focus + panes - 1) % panes
	case key.Matches(k, m.keys.Cancel):
		if m.flight != nil {
			m.flight.cancel()
			m.note = "canceling"
		}
	case key.Matches(k, m.keys.Send):
		return m.confirmSend()
	case m.focus == treePane:
		switch {
		case key.Matches(k, m.keys.Down):
			m.move(1)
		case key.Matches(k, m.keys.Up):
			m.move(-1)
		}
	case m.focus == requestPane:
		m.request, _ = m.request.Update(k)
	case m.focus == responsePane:
		m.response, _ = m.response.Update(k)
	}
	return nil
}

func (m *Model) quit() tea.Cmd {
	if m.flight != nil {
		m.flight.cancel()
	}
	return tea.Quit
}

func (m *Model) move(by int) {
	m.cursor = max(0, min(m.cursor+by, len(m.rows)-1))
	m.note = ""
	m.refresh()
	m.request.GotoTop()
}

// confirmSend sends the selected request, or asks first if its method
// may change something on the server.
func (m *Model) confirmSend() tea.Cmd {
	r := m.rows[m.cursor]
	switch {
	case r.file == nil || r.index < 0:
		m.note = "select a request to send it"
	case m.flight != nil:
		m.note = "a request is in flight; esc cancels it"
	case slices.Contains([]string{"GET", "HEAD", "OPTIONS"}, strings.ToUpper(r.file.Requests[r.index].Method)):
		return m.sendSelected()
	default:
		m.mode = confirming
	}
	return nil
}

func (m *Model) openEnvs() {
	if m.flight != nil {
		m.note = "a request is in flight; esc cancels it"
		return
	}
	names, err := env.Names(m.rows[m.cursor].path)
	if err != nil {
		m.note = output.NewError(err, nil).Message
		return
	}
	m.envs = append([]string{""}, names...)
	m.choice = max(slices.Index(m.envs, m.env), 0)
	m.mode = choosingEnv
}

// chooseEnv starts a new session for the environment name. What the old
// one captured is gone, but its secrets stay masked.
func (m *Model) chooseEnv(name string) {
	if name == m.env {
		return
	}
	m.past = m.past.Join(m.send.Masker())
	m.env = name
	m.send = session.New(m.sessionOptions(false))
	m.declared, m.sent, m.result = nil, nil, nil
	m.refresh()
	m.showResponse()
}

// refresh resolves the selected request again, as written without an
// environment, and with one as it would be sent next: a dry run, in
// which the variables that the session has captured are placeholders.
func (m *Model) refresh() {
	m.preview, m.dry = nil, nil
	r := m.rows[m.cursor]
	switch {
	case r.err != nil:
		m.preview = &output.Result{Ref: r.path, Error: output.NewError(r.err, nil)}
	case r.index < 0:
	case m.env == "":
		m.preview = &output.Result{Ref: output.Ref(r.file, r.index), Request: output.Written(r.file.Requests[r.index])}
	default:
		m.dry = session.New(m.sessionOptions(true))
		m.dry.Declare(m.declared...)
		m.preview = m.dry.Run(m.ctx, m.dry.Prepare(m.ctx, r.file, r.index))
	}
	m.masker = m.past.Join(m.sent, masker(m.dry))
	m.request.SetContent(m.clean(m.requestText()))
}

// showResponse renders the response pane again. Moving in the tree does
// not: a large body would make every key slow, and its secrets are those
// of the sessions that sent it, which the masker still has.
func (m *Model) showResponse() {
	m.response.SetContent(m.clean(m.responseText()))
}

// masker returns the masker of s, or nil if there is no session.
func masker(s *session.Session) *core.Masker {
	if s == nil {
		return nil
	}
	return s.Masker()
}

// clean makes s fit for View: secret values masked, then control
// characters and bytes that are not UTF-8 shown as \xNN, as the CLI
// prints them, and tabs as spaces, which Lip Gloss measures as nothing.
// It comes before any layout, so that cutting a line to its pane cannot
// cut a secret value in two and leave part of it unmasked.
func (m *Model) clean(s string) string {
	return strings.ReplaceAll(output.Printable(m.masker.Mask(s)), "\t", "    ")
}
