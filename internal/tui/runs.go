package tui

import (
	"cmp"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"

	"github.com/vidforull/vegtam/internal/core/history"
	"github.com/vidforull/vegtam/internal/core/output"
)

// maxRuns is how many of the latest runs h lists.
const maxRuns = 200

type runsMsg struct {
	runs []history.Entry
	err  error
}

// openRuns returns the command that reads the latest runs from the
// history file as it is now: a command, so that a slow disk holds up no
// key. Reading touches nothing the interface or a request in flight
// holds, so the command needs no owner.
func (m *Model) openRuns() tea.Cmd {
	if m.opts.History == nil {
		m.note = "no history: it is turned off"
		return nil
	}
	log := m.opts.History
	return func() (msg tea.Msg) {
		defer func() {
			if v := recover(); v != nil {
				msg = panicMsg{caught(v)}
			}
		}()
		runs, err := log.Last(maxRuns)
		return runsMsg{runs, err}
	}
}

// showRuns lists the runs read in the tree pane, and shows the selected
// one in the response pane.
func (m *Model) showRuns(msg runsMsg) {
	if msg.err != nil {
		m.note = "history: " + msg.err.Error()
		return
	}
	m.runs, m.runQuery, m.runsOpen, m.focus = msg.runs, "", true, treePane
	m.runShown = m.matchRuns()
	m.run, m.note = 0, ""
	m.showResponse()
	m.response.GotoTop()
}

// closeRuns shows the tree again, and the latest response.
func (m *Model) closeRuns() {
	m.runsOpen, m.runs, m.runShown, m.note = false, nil, nil, ""
	m.showResponse()
	m.response.GotoTop()
}

// runKey handles a key while the tree pane lists the runs: enter goes to
// the request of the selected run, / searches the runs, esc or h closes
// them; the keys that act on a request do nothing here.
func (m *Model) runKey(k tea.KeyPressMsg) tea.Cmd {
	switch {
	case key.Matches(k, m.keys.Quit):
		return m.quit()
	case key.Matches(k, m.keys.Help):
		m.openHelp()
	case key.Matches(k, m.keys.Search):
		m.mode = searching
	case key.Matches(k, m.keys.Down):
		m.moveRun(1)
	case key.Matches(k, m.keys.Up):
		m.moveRun(-1)
	case key.Matches(k, m.keys.Send):
		m.goToRun()
	case key.Matches(k, m.keys.Cancel, m.keys.History):
		m.closeRuns()
	}
	return nil
}

// moveRun moves the selection by runs that the list shows.
func (m *Model) moveRun(by int) {
	if i := slices.Index(m.runShown, m.run); i >= 0 {
		m.run = m.runShown[max(0, min(i+by, len(m.runShown)-1))]
		m.showResponse()
		m.response.GotoTop()
	}
}

// filterRuns shows the runs that match the search, and selects the
// first of them if the selected one is no longer shown.
func (m *Model) filterRuns() {
	m.runShown = m.matchRuns()
	if len(m.runShown) > 0 && !slices.Contains(m.runShown, m.run) {
		m.run = m.runShown[0]
	}
	m.showResponse()
}

// matchRuns returns the runs that match the search, ignoring case: by
// their line in the list, their method, environment or URL as written.
func (m *Model) matchRuns() []int {
	q := strings.ToLower(m.runQuery)
	var shown []int
	for i, e := range m.runs {
		if strings.Contains(strings.ToLower(m.runLabel(e)+"\n"+e.Method+"\n"+e.Env+"\n"+e.URL), q) {
			shown = append(shown, i)
		}
	}
	return shown
}

// selectedRun returns the run the list selects, if the list shows one.
func (m *Model) selectedRun() (history.Entry, bool) {
	if !slices.Contains(m.runShown, m.run) {
		return history.Entry{}, false
	}
	return m.runs[m.run], true
}

// goToRun selects the request of the selected run in the tree, if the
// tree has it, and closes the list of runs.
func (m *Model) goToRun() {
	e, ok := m.selectedRun()
	switch {
	case len(m.runs) == 0:
		m.note = "no runs yet"
		return
	case !ok:
		m.note = "no run matches the search"
		return
	}
	i := m.rowOf(e.Ref)
	if i < 0 {
		m.note = "not in the list of requests: " + m.shortRef(e.Ref)
		return
	}
	m.closeRuns()
	if !slices.Contains(m.shown, i) { // the search of the tree hides it
		m.query = ""
		m.filter()
	}
	m.choose(i)
}

// rowOf returns the row of the request ref names, file#name or file#N
// with the file an absolute path, or -1 if the tree has none.
func (m *Model) rowOf(ref string) int {
	file, req, ok := strings.CutLast(ref, "#")
	if !ok {
		return -1
	}
	for i, r := range m.rows {
		if r.index >= 0 && r.abs == file && strings.TrimPrefix(output.Ref(r.file, r.index), r.file.Path+"#") == req {
			return i
		}
	}
	return -1
}

// shortRef returns ref with its file relative to the directory the
// interface was opened on, if the file is below it.
func (m *Model) shortRef(ref string) string {
	file, req, ok := strings.CutLast(ref, "#")
	if !ok {
		return ref
	}
	if rel, err := filepath.Rel(m.base, file); err == nil && filepath.IsLocal(rel) {
		return rel + "#" + req
	}
	return ref
}

// runLabel is the line of a run in the list, short enough for a narrow
// pane: when it started, in local time (the day only if not today), the
// status or what went wrong, and the request. The response pane shows
// the rest.
func (m *Model) runLabel(e history.Entry) string {
	outcome := e.Result
	if e.Result == "ok" && e.Status != 0 {
		outcome = strconv.Itoa(e.Status)
	}
	at, now := e.Time.Local(), m.now()
	when := at.Format("15:04")
	if at.Year() != now.Year() || at.YearDay() != now.YearDay() {
		when = at.Format("01-02")
	}
	return when + " " + outcome + " " + m.shortRef(e.Ref)
}

// runText describes the selected run for the response pane.
func (m *Model) runText() string {
	e, ok := m.selectedRun()
	switch {
	case len(m.runs) == 0:
		return "No runs yet: each request sent, here or with vegtam run, goes into the history.\n"
	case !ok:
		return "No run matches the search.\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n\n", e.Method, e.URL)
	row := func(name, value string) { fmt.Fprintf(&b, "%-10s%s\n", name, value) }
	row("request", e.Ref)
	row("env", cmp.Or(e.Env, "none"))
	row("started", e.Time.Local().Format("2006-01-02 15:04:05 MST"))
	if e.Status != 0 {
		row("status", strconv.Itoa(e.Status))
	}
	row("took", took(e.DurationMS))
	row("result", e.Result)
	if e.Truncated {
		row("body", "cut short at --max-body")
	}
	if m.rowOf(e.Ref) < 0 {
		b.WriteString("\nThe request is not in the list: its file is elsewhere, or it has changed.\n")
	} else {
		b.WriteString("\nenter goes to the request.\n")
	}
	return b.String()
}

// took formats a duration given in milliseconds.
func took(ms float64) string {
	d := time.Duration(ms * float64(time.Millisecond))
	if d < time.Millisecond {
		return d.Round(time.Microsecond).String()
	}
	return d.Round(time.Millisecond).String()
}
