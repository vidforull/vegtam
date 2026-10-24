package tui

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/colorprofile"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/env"
	"github.com/vidforull/vegtam/internal/core/history"
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
	browsing  mode = iota
	searching      // typing the search
	choosingEnv
	confirming // asks before sending a request that needs a confirmation
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
	shown         []int  // the rows the tree shows: those that match the search
	query         string // the search
	cursor        int
	focus         pane
	mode          mode
	width, height int
	sizes         [panes]size

	env    string
	envs   []string // to choose from; "" is none
	choice int

	send      *session.Session
	declared  []string            // what send has declared, as of when it was last idle
	plainVars []string            // and which of those a plain @capture takes
	lost      map[string]string   // and what it has lost
	bound     map[string][]string // and the origins each secret it captured may go back to
	dry       *session.Session    // the dry run that previews the selected request
	job       *session.Job        // the selected request, as dry prepared it
	// The secrets of the sessions of earlier environments and of earlier
	// dry runs, and of send as of when it was last idle. masker joins
	// them with those of dry, for everything View shows.
	past, sent *core.Masker
	masker     *core.Masker

	// The history of runs, while the tree pane lists it in place of the
	// requests: the runs h read, the latest first, those that match the
	// search of the history, and the selected one.
	runsOpen bool
	runs     []history.Entry
	runShown []int
	run      int
	runQuery string
	base     string // the absolute directory of opts.Path, which the history's refs are shown from
	now      func() time.Time
	asked    time.Time // when the question before sending was asked
	question string    // what it asks, not yet cleaned
	// refusal is the secret that the session refused to send, when the
	// question follows that refusal; nil otherwise.
	refusal *output.Secret

	preview *output.Result // the selected request as it would be sent, or what stops it
	result  *output.Result // the latest response
	curl    string         // the selected request as a curl command, cleaned; shown over the response
	fold    int            // the depth from which the JSON body of a response is folded; 0 for none
	flight  *flight
	note    string // a message for the status line

	request, response viewport.Model
	help              viewport.Model // the keys and what they do, over all panes
	plain             bool           // the terminal shows no styles, as with TERM=dumb
	keys              keyMap
	panicked          *Panic
}

type size struct{ w, h int }

type keyMap struct {
	Up, Down, Next, Prev, Search, Send, Cancel, Copy, Fold, Env, History, Redraw, Help, Quit key.Binding
}

func newKeys() keyMap {
	b := func(keys []string, help, desc string) key.Binding {
		return key.NewBinding(key.WithKeys(keys...), key.WithHelp(help, desc))
	}
	return keyMap{
		Up:      b([]string{"k", "up"}, "k/↑", "up"),
		Down:    b([]string{"j", "down"}, "j/↓", "down"),
		Next:    b([]string{"tab"}, "tab", "next pane"),
		Prev:    b([]string{"shift+tab"}, "shift+tab", "previous pane"),
		Search:  b([]string{"/"}, "/", "search the list"),
		Send:    b([]string{"enter"}, "enter", "send the request"),
		Cancel:  b([]string{"esc"}, "esc", "cancel the request in flight"),
		Copy:    b([]string{"y"}, "y", "copy as curl"),
		Fold:    b([]string{"z"}, "z", "fold the JSON body"),
		Env:     b([]string{"e"}, "e", "environment"),
		History: b([]string{"h"}, "h", "history of runs"),
		Redraw:  b([]string{"ctrl+l"}, "ctrl+l", "redraw the screen"),
		Help:    b([]string{"?"}, "?", "help"),
		Quit:    b([]string{"q", "ctrl+c"}, "q", "quit"),
	}
}

// ShortHelp returns the keys for the status line, described in a word.
func (k keyMap) ShortHelp() []key.Binding {
	short := func(b key.Binding, desc string) key.Binding {
		b.SetHelp(b.Help().Key, desc)
		return b
	}
	return []key.Binding{short(k.Send, "send"), short(k.Search, "search"), short(k.Copy, "curl"), short(k.Env, "env"), k.Help, k.Quit}
}

// runsHelp returns the keys for the status line while the tree pane
// lists the runs.
func (k keyMap) runsHelp() []key.Binding {
	short := func(b key.Binding, desc string) key.Binding {
		b.SetHelp(b.Help().Key, desc)
		return b
	}
	return []key.Binding{short(k.Send, "go to"), short(k.Search, "search"), short(k.Cancel, "close"), k.Help, k.Quit}
}

// mainHelp returns the keys the status line keeps when there is no room
// for the others.
func (k keyMap) mainHelp() []key.Binding {
	return []key.Binding{k.ShortHelp()[0], k.Help, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{k.Up, k.Down, k.Next, k.Prev, k.Search}, {k.Send, k.Cancel, k.Copy, k.Fold, k.Env}, {k.History, k.Redraw, k.Help, k.Quit}}
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
	case tea.ColorProfileMsg:
		m.plain = msg.Profile == colorprofile.NoTTY
	case sentMsg:
		m.answered(msg)
	case runsMsg:
		m.showRuns(msg)
	case panicMsg:
		m.panicked, cmd = msg.p, tea.Quit
	case tea.PasteMsg:
		if m.mode == searching {
			m.typed(strings.ReplaceAll(msg.Content, "\n", " "))
		}
	case tea.KeyPressMsg:
		cmd = m.key(msg)
	}
	return m, cmd
}

func (m *Model) key(k tea.KeyPressMsg) tea.Cmd {
	switch {
	case k.String() == "ctrl+c":
		return m.quit()
	case key.Matches(k, m.keys.Redraw): // over what something else wrote on the terminal
		return tea.ClearScreen
	}
	switch m.mode {
	case browsing:
	case searching:
		m.search(k)
		return nil
	case confirming:
		// Only enter again: y copies as curl, and a habit must not send.
		// Nor does an enter that repeats a key held down, or that comes
		// too soon to have read the question, as a key that bounces does:
		// the question stays.
		if key.Matches(k, m.keys.Send) && (k.IsRepeat || m.now().Sub(m.asked) < confirmAfter) {
			m.note = "too soon: enter again to send it"
			return nil
		}
		m.mode = browsing
		if !key.Matches(k, m.keys.Send) {
			m.note = "not sent"
			return nil
		}
		// The session reads the files again before it sends, and the
		// confirmation lets the request's secrets go where it goes then: if
		// the files now say otherwise than the question did, it is asked
		// again.
		m.refresh()
		if q := m.questionText(); q != m.question {
			m.mode, m.asked, m.question = confirming, m.now(), q
			m.note = "the request has changed: enter again to send it"
			return nil
		}
		return m.sendSelected(true)
	case helping:
		switch {
		case key.Matches(k, m.keys.Quit):
			return m.quit()
		case key.Matches(k, m.keys.Help, m.keys.Cancel):
			m.mode = browsing
		default: // a terminal too small for it all scrolls it
			m.help, _ = m.help.Update(k)
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
	if m.runsOpen {
		return m.runKey(k)
	}
	switch {
	case key.Matches(k, m.keys.Quit):
		return m.quit()
	case key.Matches(k, m.keys.Help):
		m.openHelp()
	case key.Matches(k, m.keys.History):
		return m.openRuns()
	case key.Matches(k, m.keys.Search):
		m.mode, m.focus = searching, treePane
	case key.Matches(k, m.keys.Env):
		m.openEnvs()
	case key.Matches(k, m.keys.Next):
		m.focus = (m.focus + 1) % panes
	case key.Matches(k, m.keys.Prev):
		m.focus = (m.focus + panes - 1) % panes
	case key.Matches(k, m.keys.Cancel):
		switch {
		case m.flight != nil:
			m.flight.cancel()
			m.note = "canceling"
		case m.curl != "":
			m.curl = ""
			m.showResponse()
		}
	case key.Matches(k, m.keys.Send):
		return m.confirmSend()
	case key.Matches(k, m.keys.Copy):
		return m.copyCurl()
	case key.Matches(k, m.keys.Fold):
		m.fold = (m.fold + 1) % (maxFold + 1)
		m.note = "JSON folded from depth " + strconv.Itoa(m.fold)
		if m.fold == 0 {
			m.note = "JSON unfolded"
		}
		m.showResponse()
		m.response.GotoTop()
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

// openHelp shows the keys over all panes, from the top.
func (m *Model) openHelp() {
	m.mode = helping
	m.help.SetContent(m.helpText(m.help.Width()))
	m.help.GotoTop()
}

func (m *Model) quit() tea.Cmd {
	if m.flight != nil {
		m.flight.cancel()
	}
	return tea.Quit
}

// move moves the cursor by rows that the tree shows.
func (m *Model) move(by int) {
	if i := slices.Index(m.shown, m.cursor); i >= 0 {
		m.choose(m.shown[max(0, min(i+by, len(m.shown)-1))])
	}
}

// choose selects row i.
func (m *Model) choose(i int) {
	m.cursor = i
	m.note = ""
	m.refresh()
	m.request.GotoTop()
}

// confirmAfter is how long after the question before sending the enter
// that answers it may come: an enter before that is a key held down, past
// the delay before a terminal repeats it on most systems, or one that
// bounced.
const confirmAfter = 500 * time.Millisecond

// maxFold is the deepest fold z gives before it unfolds again.
const maxFold = 2

// maxQuery is how long a search may be, in characters.
const maxQuery = 100

// search handles a key while the search is typed: enter keeps it, esc
// clears it, and the arrows move among the rows it shows. It searches the
// list the tree pane shows: the requests, or the runs.
func (m *Model) search(k tea.KeyPressMsg) {
	q, filter, move := m.searched()
	switch k.String() {
	case "esc":
		m.mode, *q = browsing, ""
		filter()
	case "enter":
		m.mode = browsing
	case "backspace":
		if r := []rune(*q); len(r) > 0 {
			*q = string(r[:len(r)-1])
			filter()
		}
	case "up":
		move(-1)
	case "down":
		move(1)
	default:
		m.typed(k.Text)
	}
}

// searched returns the search of the list the tree pane shows, and how
// to filter that list and move in it.
func (m *Model) searched() (q *string, filter func(), move func(int)) {
	if m.runsOpen {
		return &m.runQuery, m.filterRuns, m.moveRun
	}
	return &m.query, m.filter, m.move
}

// typed adds s to the search.
func (m *Model) typed(s string) {
	q, filter, _ := m.searched()
	if s == "" || utf8.RuneCountInString(*q+s) > maxQuery {
		return
	}
	*q += s
	filter()
}

// filter shows the rows that match the search, and moves the cursor to
// the nearest of them if its row is no longer shown.
func (m *Model) filter() {
	m.shown = m.match()
	if len(m.shown) == 0 || slices.Contains(m.shown, m.cursor) {
		return
	}
	i, _ := slices.BinarySearch(m.shown, m.cursor)
	m.choose(m.shown[min(i, len(m.shown)-1)])
}

// match returns the rows that match the search, ignoring case: a request
// by its label, the name of its file or its URL as written, and a file by
// its name or by any of its requests.
func (m *Model) match() []int {
	q := strings.ToLower(m.query)
	has := func(s string) bool { return strings.Contains(strings.ToLower(s), q) }
	var shown []int
	file := -1 // the row of the file of the requests that follow, until it is shown
	for i, r := range m.rows {
		switch {
		case r.index < 0:
			file = -1
			if has(r.label) {
				shown = append(shown, i)
			} else {
				file = i
			}
		case has(r.label) || has(r.in) || has(r.file.Requests[r.index].URL):
			if file >= 0 {
				shown, file = append(shown, file), -1
			}
			shown = append(shown, i)
		}
	}
	return shown
}

// confirmSend sends the selected request, or asks first if it needs a
// confirmation: the session sends nothing that needs one unless told
// that a person gave it (see session.Confirm). Whether a request would
// send a secret to an origin the secret is not bound to is known for sure
// only once the session resolves it to send it: the session refuses it
// then, before anything is sent, and the interface asks (see askSecret).
func (m *Model) confirmSend() tea.Cmd {
	r := m.rows[m.cursor]
	switch {
	case !slices.Contains(m.shown, m.cursor):
		m.note = "no request matches the search"
	case r.file == nil || r.index < 0:
		m.note = "select a request to send it"
	case m.flight != nil:
		m.note = "a request is in flight; esc cancels it"
	case session.Confirm{}.Needs(r.file.Requests[r.index]) == "":
		return m.sendSelected(false)
	default:
		// The confirmation lets its secrets go where it goes too: the
		// question says where, as the files say now.
		m.refresh()
		m.ask(nil)
	}
	return nil
}

// ask asks whether to send the selected request; refusal is the secret
// that the session has just refused to send with it, or nil.
func (m *Model) ask(refusal *output.Secret) {
	m.mode, m.asked, m.refusal = confirming, m.now(), refusal
	m.question = m.questionText()
}

// askSecret asks whether to send the request of row, which the session
// has refused to send for refusal, a secret that would go to an origin it
// is not bound to: a person may send it there this once. It asks only if
// the request is still selected, and shown, and nothing else is open;
// otherwise the response pane shows the refusal, and enter on the request
// asks.
func (m *Model) askSecret(row int, refusal *output.Secret) {
	if m.mode != browsing || m.runsOpen || m.cursor != row || !slices.Contains(m.shown, row) {
		return
	}
	m.ask(refusal)
}

// questionText returns the question before sending the selected request:
// its method and ref; each secret that it would send to an origin the
// secret is not bound to, as the preview gives them, or else the one the
// session refused; and the text of its @note. The secrets come before the
// note, which is text from the file: a long one must not push them out of
// the box.
func (m *Model) questionText() string {
	r := m.rows[m.cursor]
	req := r.file.Requests[r.index]
	var b strings.Builder
	fmt.Fprintf(&b, "Send %s %s?\n\n", req.Method, output.Ref(r.file, r.index))
	var why, late []string
	if m.dry != nil && m.job != nil {
		// Compared before they are masked: two origins may mask alike.
		for _, s := range m.dry.Bindings(m.job) {
			switch {
			case s.Refused():
				why = append(why, output.SecretWhy(*output.NewSecret(&s, m.masker))+".")
			case s.Origin == "":
				late = append(late, s.Name)
			}
		}
	}
	switch {
	case m.refusal != nil && len(why) == 0: // the preview cannot tell where it goes; the session could
		why = []string{output.SecretWhy(*m.refusal) + "."}
	case m.refusal == nil && len(late) > 0:
		// A command or a capture gives where it goes, and a confirmation
		// lets its secrets go there, whatever it is.
		why = append(why, "Where it goes is known only once it is sent, and "+strings.Join(late, ", ")+
			" would go there with it, wherever that is.")
	}
	if len(why) > 0 {
		b.WriteString(strings.Join(why, "\n") + "\n\n")
	}
	// The text of its @note, from the file: clean masks it and shows what
	// would drive the terminal as escapes.
	if note, ok := req.Note(); ok && note != "" {
		b.WriteString(note + "\n\n")
	}
	b.WriteString("enter sends it, any other key does not.")
	return b.String()
}

// copyCurl copies the selected request as a curl command, with the
// terminal's OSC 52, and shows it over the response, for a terminal that
// does not take OSC 52. Both are the same text, cleaned as all text is.
func (m *Model) copyCurl() tea.Cmd {
	switch {
	case !slices.Contains(m.shown, m.cursor):
		m.note = "no request matches the search"
		return nil
	case m.job == nil:
		m.note = "select a request to copy it"
		return nil
	case m.flight != nil: // esc would cancel the request, not hide the command
		m.note = "a request is in flight; esc cancels it"
		return nil
	}
	s, err := m.dry.Curl(m.ctx, m.job, m.masker)
	if err != nil {
		m.note = "not copied: " + output.NewError(err, m.masker).Message
		return nil
	}
	// The command holds no control character, so clean can change it
	// only by masking a secret value in what the command itself adds,
	// such as a private value "raw" in --data-raw: the copy would be
	// wrong, and is not made.
	if m.clean(s) != s {
		m.note = "not copied: a secret value is in the curl command"
		return nil
	}
	m.curl, m.note = s, "copied as curl; esc hides it"
	m.showResponse()
	m.response.GotoTop()
	return tea.SetClipboard(m.curl)
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
	m.declared, m.plainVars, m.lost, m.bound, m.sent, m.result = nil, nil, nil, nil, nil, nil
	m.refresh()
	m.showResponse()
}

// refresh resolves the selected request again, as it would be sent next:
// a dry run, in which the variables that the session has captured are
// placeholders, those it has lost are errors, as they would be when sent,
// and the secrets it has captured may go back where they came from.
func (m *Model) refresh() {
	// What the dry run read stays masked once it previews something else.
	m.past = m.past.Join(masker(m.dry))
	m.preview, m.dry, m.job, m.curl = nil, nil, nil, ""
	r := m.rows[m.cursor]
	switch {
	case r.err != nil:
		m.preview = &output.Result{Ref: r.path, Error: output.NewError(r.err, nil)}
	case r.index < 0:
	default:
		m.dry = session.New(m.sessionOptions(true))
		m.dry.Declare(m.declared...)
		m.dry.DeclarePlain(m.plainVars...)
		for name, ref := range m.lost {
			m.dry.Forget(name, ref)
		}
		for name, origins := range m.bound {
			m.dry.Bind(name, origins...)
		}
		m.job = m.dry.Prepare(m.ctx, r.file, r.index)
		m.preview = m.dry.Run(m.ctx, m.job)
	}
	m.masker = m.past.Join(m.sent, masker(m.dry))
	m.request.SetContent(m.highlight(m.clean(m.requestText())))
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
