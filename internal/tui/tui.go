package tui

import (
	"cmp"
	"context"
	"io"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"time"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/history"
	"github.com/vidforull/vegtam/internal/core/httpfile"
	"github.com/vidforull/vegtam/internal/core/output"
	"github.com/vidforull/vegtam/internal/core/policy"
	"github.com/vidforull/vegtam/internal/core/session"
)

// Options configure the interface.
type Options struct {
	Path      string // a .http file, or a directory of them
	Env       string // the environment at the start; "" for none
	Trust     *policy.Store
	Timeout   time.Duration
	MaxBody   int64
	UserAgent string
	History   *history.Log // what the requests sent go into, and h lists; nil for none
	Input     io.Reader    // a terminal
	Output    io.Writer    // a terminal
}

// Panic is a panic inside the interface. Bubble Tea would print its value
// as is, so the interface catches it first, quits so that the terminal is
// restored, and Run panics with it again for the caller to print masked.
type Panic struct {
	Value any
	Stack []byte
}

// caught returns v, the value of a panic that a deferred function
// recovered, with the stack of the panic, which it still runs on.
func caught(v any) *Panic { return &Panic{Value: v, Stack: debug.Stack()} }

// row is a line of the tree: a .http file, or one of its requests.
type row struct {
	path  string
	abs   string // path made absolute, as the history names it
	label string
	in    string     // the label of the file, for a request
	file  *core.File // nil if the file does not parse
	index int        // of the request in file; -1 for the file
	err   error      // why the file does not parse
}

// New reads the .http files at opts.Path for the interface. A file that
// does not parse is in the tree with its error.
func New(opts Options) (*Model, error) {
	paths, err := httpfile.Files(opts.Path)
	if err != nil {
		return nil, err
	}
	m := &Model{opts: opts, env: opts.Env, keys: newKeys(), cursor: -1, now: time.Now}
	if m.base, err = filepath.Abs(opts.Path); err != nil {
		return nil, core.Errorf(core.KindUsage, core.Source{}, "%v", err)
	}
	if len(paths) == 1 && paths[0] == opts.Path { // a file
		m.base = filepath.Dir(m.base)
	}
	for _, path := range paths {
		label := path
		if rel, err := filepath.Rel(opts.Path, path); err == nil && rel != "." {
			label = rel
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, core.Errorf(core.KindUsage, core.Source{}, "%v", err)
		}
		f, err := httpfile.ParseFile(path)
		m.rows = append(m.rows, row{path: path, abs: abs, label: label, file: f, index: -1, err: err})
		if err != nil {
			continue
		}
		for i, r := range f.Requests {
			name := r.Name
			if name == "" {
				name = "#" + strconv.Itoa(i+1)
			}
			if m.cursor < 0 {
				m.cursor = len(m.rows)
			}
			m.rows = append(m.rows, row{path: path, abs: abs, label: r.Method + " " + name, in: label, file: f, index: i})
		}
	}
	m.cursor = max(m.cursor, 0)
	m.shown = m.match()
	m.request, m.response, m.help = viewport.New(), viewport.New(), viewport.New()
	m.request.SoftWrap, m.response.SoftWrap = true, true // the help is wrapped at words
	return m, nil
}

// Run shows the interface until the user quits or ctx is done. A request
// in flight is canceled, and Run returns once it has ended.
func (m *Model) Run(ctx context.Context) error {
	parent := ctx
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	m.start(ctx, stop)
	// The root context of vegtam stops on SIGINT and SIGTERM already.
	p := tea.NewProgram(m, tea.WithContext(ctx), tea.WithInput(m.opts.Input), tea.WithOutput(m.opts.Output),
		tea.WithoutSignalHandler())
	_, err := p.Run()
	stop()
	if fl := m.flight; fl != nil {
		<-fl.done
		m.panicked = cmp.Or(m.panicked, fl.panic)
	}
	if m.panicked != nil {
		panic(m.panicked)
	}
	switch {
	case parent.Err() != nil:
		return core.Errorf(core.KindCanceled, core.Source{}, "interrupted")
	case err != nil:
		return core.Errorf(core.KindUsage, core.Source{}, "terminal: %v", err)
	}
	return nil
}

// start makes the interface ready to show: the session for the
// environment and the selected request. stop ends the program.
func (m *Model) start(ctx context.Context, stop context.CancelFunc) {
	m.ctx, m.stop = ctx, stop
	m.send = session.New(m.sessionOptions(false))
	m.refresh()
	m.showResponse()
}

func (m *Model) sessionOptions(dryRun bool) session.Options {
	o := m.opts
	return session.Options{
		Env: m.env, DryRun: dryRun, Trust: o.Trust, Timeout: o.Timeout, MaxBody: o.MaxBody, UserAgent: o.UserAgent, History: o.History,
		EnvHint: "e chooses one",
	}
}

// Masker returns a Masker for every secret the interface has read. Call
// it once Run has returned or panicked: a request in flight owns the
// session.
func (m *Model) Masker() *core.Masker {
	return m.past.Join(m.sent, masker(m.dry), masker(m.send))
}

// flight is the request in flight. Its goroutine owns the session until
// done is closed.
type flight struct {
	ref    string
	cancel context.CancelFunc
	done   chan struct{}
	result *output.Result
	panic  *Panic
}

type (
	sentMsg  struct{ flight *flight }
	panicMsg struct{ p *Panic }
)

// sendSelected sends the selected request with the session, as vegtam
// run does, and returns the command that brings back the result. The
// session reads the files again first, so that what is sent is what the
// preview showed, and runs the commands again. The request runs on a
// goroutine of its own, which Run waits for: Bubble Tea does not wait for
// the commands it runs, and drops one it is handed as the program ends.
func (m *Model) sendSelected() tea.Cmd {
	r := m.rows[m.cursor]
	m.send.Reload()
	ctx, cancel := context.WithCancel(m.ctx)
	fl := &flight{ref: output.Ref(r.file, r.index), cancel: cancel, done: make(chan struct{})}
	go fl.send(ctx, m.send, r)
	// Once it runs, Run waits for it: a panic from here on cannot leave
	// Run waiting for a goroutine that never started.
	m.flight, m.result, m.note, m.curl = fl, nil, "", ""
	m.showResponse()
	return func() tea.Msg {
		<-fl.done
		if fl.panic != nil {
			return panicMsg{fl.panic}
		}
		return sentMsg{fl}
	}
}

func (fl *flight) send(ctx context.Context, s *session.Session, r row) {
	defer close(fl.done)
	defer func() {
		if v := recover(); v != nil {
			fl.panic = caught(v)
		}
	}()
	fl.result = s.Run(ctx, s.Prepare(ctx, r.file, r.index))
}

// answered takes back the session from the request that has ended, and
// shows its result.
func (m *Model) answered(msg sentMsg) {
	msg.flight.cancel()
	m.flight, m.result, m.note = nil, msg.flight.result, ""
	m.declared, m.lost, m.sent = m.send.Declared(), m.send.Lost(), m.send.Masker()
	if err := m.send.HistoryError(); err != nil {
		m.note = "history: " + err.Error()
	}
	m.refresh()
	m.showResponse()
	m.response.GotoTop()
}
