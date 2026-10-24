package tui

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"
	"go.uber.org/goleak"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/env"
	vexec "github.com/vidforull/vegtam/internal/core/exec"
	"github.com/vidforull/vegtam/internal/core/history"
	"github.com/vidforull/vegtam/internal/core/policy"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

// The secrets of the tests: one from the private environment file, one
// from the process environment, and the session the server hands out.
const (
	privateSecret = "Pr1vT0k/en+x"
	envSecret     = "EnvK3y/v+al"
	sessionSecret = "S3ss/10n+id"
)

// fixture is a copy of testdata/tui with environment files for the
// environment "test", and the server its requests go to.
type fixture struct {
	dir  string
	host string

	// secrets are what the operator's policy says of the secrets of the
	// fixture: where {{$env VEGTAM_TEST_KEY}} may go.
	secrets policy.Secrets

	mu        sync.Mutex
	seen      []string // the paths the server was asked for
	noSession bool     // the sign-in hands out no session
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	fx := &fixture{dir: t.TempDir()}
	srv := httptest.NewServer(fx.handler())
	t.Cleanup(srv.Close)
	fx.host = srv.URL
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	if err := os.CopyFS(fx.dir, os.DirFS("../../testdata/tui")); err != nil {
		t.Fatal(err)
	}
	// The secrets may go to the servers of the fixture, as the person
	// whose secrets they are allows them to: the private file's value in
	// its $allow, the environment variable in the policy (see model).
	origins := []string{srv.URL, closed.URL}
	fx.secrets = policy.Secrets{Env: map[string][]string{"VEGTAM_TEST_KEY": origins}}
	envs := map[string]map[string]map[string]any{
		"http-client.env.json":         {"test": {"host": srv.URL, "closed": closed.URL}, "other": {"host": srv.URL}},
		"http-client.private.env.json": {"test": {"token": privateSecret, "$allow": map[string][]string{"token": origins}}},
	}
	for name, v := range envs {
		b, _ := json.Marshal(v)
		if err := os.WriteFile(filepath.Join(fx.dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("VEGTAM_TEST_KEY", envSecret)
	return fx
}

func (fx *fixture) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(map[string]string{
			"query": r.URL.RawQuery, "authorization": r.Header.Get("Authorization"), "key": r.URL.Query().Get("key"),
		})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Echo", r.URL.RawQuery)
		fmt.Fprintf(w, `{"echo": %s, "php": %s}`, b, strings.ReplaceAll(string(b), "/", `\/`))
	})
	mux.HandleFunc("/escapes", func(w http.ResponseWriter, r *http.Request) {
		// net/http refuses a header with ESC or BEL, but not 8-bit CSI.
		w.Header().Set("X-Escape", "\x9b31m \u009b31m")
		fmt.Fprint(w, "\u202eevil\u200b\U000e0041 \x1b[2J\x1b[H\x1b]0;title\x07 \u009b31m \x1b[31mred\x1b[0m \x7f\r\x08 "+r.URL.Query().Get("key"))
	})
	mux.HandleFunc("/binary", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "\xff\xfe"+r.URL.RawQuery+"\x00")
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", 100)+r.URL.Query().Get("key"))
	})
	mux.HandleFunc("/slow", func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	mux.HandleFunc("PUT /items/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "%s %s\n%s\n%s", r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), body)
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, _ *http.Request) {
		fx.mu.Lock()
		defer fx.mu.Unlock()
		if fx.noSession {
			fmt.Fprint(w, `{}`)
			return
		}
		fmt.Fprintf(w, `{"session": %q}`, sessionSecret)
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Session", r.Header.Get("X-Session"))
		fmt.Fprintf(w, `{"session": %q}`, r.Header.Get("X-Session"))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fx.mu.Lock()
		fx.seen = append(fx.seen, r.Method+" "+r.URL.Path)
		fx.mu.Unlock()
		mux.ServeHTTP(w, r)
	})
}

// asked returns the requests the server has had, as "METHOD /path".
func (fx *fixture) asked() []string {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	return append([]string(nil), fx.seen...)
}

// newModel returns the interface on path, ready as Run would make it, on
// a terminal of the given size.
func newModel(t *testing.T, path, envName string, width, height int) *Model {
	t.Helper()
	return open(t, Options{Path: path, Env: envName, Transport: vexec.Transport{Total: 5 * time.Second}, MaxBody: 1 << 20, UserAgent: "vegtam/test"}, width, height)
}

// model returns the interface on the fixture, ready as Run would make it
// with the operator's policy of the fixture, on a terminal of the given
// size.
func (fx *fixture) model(t *testing.T, envName string, width, height int) *Model {
	t.Helper()
	return open(t, Options{
		Path: fx.dir, Env: envName, Transport: vexec.Transport{Total: 5 * time.Second}, MaxBody: 1 << 20, UserAgent: "vegtam/test", Secrets: fx.secrets,
	}, width, height)
}

// open returns the interface with opts, ready as Run would make it, on
// a terminal of the given size.
func open(t *testing.T, opts Options, width, height int) *Model {
	t.Helper()
	m, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	m.start(t.Context(), func() {})
	m.Update(tea.WindowSizeMsg{Width: width, Height: height})
	tick(m)
	return m
}

// tick gives m a clock that moves a second each time it is read, so
// that every key comes long enough after the one before it.
func tick(m *Model) {
	clock := time.Now()
	m.now = func() time.Time {
		clock = clock.Add(time.Second)
		return clock
	}
}

// keyMsg returns the message Bubble Tea makes of a key press.
func keyMsg(k string) tea.KeyPressMsg {
	special := map[string]tea.KeyPressMsg{
		"enter": {Code: tea.KeyEnter}, "esc": {Code: tea.KeyEscape}, "tab": {Code: tea.KeyTab},
		"shift+tab": {Code: tea.KeyTab, Mod: tea.ModShift}, "ctrl+c": {Code: 'c', Mod: tea.ModCtrl},
		"up": {Code: tea.KeyUp}, "down": {Code: tea.KeyDown}, "backspace": {Code: tea.KeyBackspace},
	}
	if msg, ok := special[k]; ok {
		return msg
	}
	return tea.KeyPressMsg{Code: []rune(k)[0], Text: k}
}

// press hands the keys to m and runs the commands they return to the
// end, as Bubble Tea would, but on this goroutine.
func press(m *Model, keys ...string) {
	for _, k := range keys {
		_, cmd := m.Update(keyMsg(k))
		run(m, cmd)
	}
}

func run(m *Model, cmd tea.Cmd) {
	for cmd != nil {
		_, cmd = m.Update(cmd())
	}
}

// goTo selects the request named name in the tree.
func goTo(t *testing.T, m *Model, name string) {
	t.Helper()
	for i, r := range m.rows {
		if r.index >= 0 && r.file.Requests[r.index].Name == name {
			m.focus = treePane
			for m.cursor != i {
				if m.cursor < i {
					press(m, "j")
				} else {
					press(m, "k")
				}
			}
			return
		}
	}
	t.Fatalf("no request %s", name)
}

func view(m *Model) string { return m.View().Content }

func TestNavigation(t *testing.T) {
	fx := newFixture(t)
	m := fx.model(t, "", 100, 30)
	if r := m.rows[m.cursor]; r.index != 0 || !strings.Contains(m.requestText(), "GET {{host}}/echo?key={{token}}") {
		t.Fatalf("the first request is not selected and shown as written:\n%s", view(m))
	}
	press(m, "j", "down")
	if got := m.rows[m.cursor].label; got != "GET escapes" {
		t.Errorf("after j and down: %q selected", got)
	}
	press(m, "k")
	if got := m.rows[m.cursor].label; got != "POST create" {
		t.Errorf("after k: %q selected", got)
	}
	for _, k := range []string{"k", "k", "k"} {
		press(m, k)
	}
	if m.cursor != 0 || !strings.HasSuffix(m.requestText(), "api.http\n\n10 requests\n") {
		t.Errorf("at the top the file is selected and described:\n%s", view(m))
	}
	for _, want := range []pane{requestPane, responsePane, treePane} {
		press(m, "tab")
		if m.focus != want {
			t.Errorf("tab: focus %d, want %d", m.focus, want)
		}
	}
	press(m, "shift+tab")
	if m.focus != responsePane {
		t.Errorf("shift+tab: focus %d", m.focus)
	}
	press(m, "?")
	if !strings.Contains(view(m), "next pane") {
		t.Errorf("? shows no keys:\n%s", view(m))
	}
	press(m, "esc")
	if m.mode != browsing {
		t.Error("esc does not close the help")
	}
	goTo(t, m, "echo")
	press(m, "j", "j", "j", "j", "j", "j", "j", "j", "j", "j")
	if r := m.rows[m.cursor]; r.err == nil || !strings.Contains(view(m), "broken.http ✗") ||
		!strings.Contains(m.requestText(), `broken.http:4: expected a header "Name: value"`) {
		t.Errorf("the broken file is not shown with its error:\n%s", view(m))
	}
}

func TestEnvironment(t *testing.T) {
	fx := newFixture(t)
	m := fx.model(t, "", 100, 30)
	press(m, "e")
	if m.mode != choosingEnv || strings.Join(m.envs, ",") != ",other,test" || !strings.Contains(view(m), "(none)") {
		t.Fatalf("e: mode %d, environments %q\n%s", m.mode, m.envs, view(m))
	}
	press(m, "j", "j", "enter")
	if m.env != "test" || !strings.Contains(view(m), "env: test") ||
		!strings.Contains(m.requestText(), "GET "+fx.host+"/echo?key={{token}}&env={{$env VEGTAM_TEST_KEY}}") {
		t.Errorf("after choosing test, the request is not shown as it would be sent:\n%s", view(m))
	}
	press(m, "e", "esc")
	if m.mode != browsing || m.env != "test" {
		t.Errorf("esc in the list: mode %d, env %q", m.mode, m.env)
	}
}

// TestSendNeedsConfirmation checks that the session holds the
// confirmation, not the interface alone: a POST sent without the
// question is refused, and the server gets nothing.
func TestSendNeedsConfirmation(t *testing.T) {
	fx := newFixture(t)
	m := fx.model(t, "test", 150, 40)
	goTo(t, m, "create")
	run(m, m.sendSelected(false))
	if got := fx.asked(); len(got) != 0 || m.result == nil || m.result.Error == nil || m.result.Error.Kind != core.KindConfirm {
		t.Errorf("the server had %q; result %+v", got, m.result)
	}
	run(m, m.sendSelected(true))
	if got := fx.asked(); len(got) != 1 || m.result.Error != nil {
		t.Errorf("confirmed: the server had %q; error %+v", got, m.result.Error)
	}
}

// TestSendNote checks a request with an @note: the interface asks before
// sending it, a GET too, with the note in the question, masked and made
// fit for the terminal; enter again sends it.
func TestSendNote(t *testing.T) {
	fx := newFixture(t)
	src := "# @name noted\n# @note Sends {{token}} " + privateSecret + " \x1b]0;t\x07 \u202edone\nGET {{host}}/echo?key={{token}}\n"
	if err := os.WriteFile(filepath.Join(fx.dir, "note.http"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	m := fx.model(t, "test", 150, 40)
	goTo(t, m, "noted")
	press(m, "enter")
	v := view(m)
	if m.mode != confirming || !strings.Contains(v, "Send GET") || !strings.Contains(v, `Sends {{token}} *** \x1b]0;t\x07 \u202edone`) ||
		strings.Contains(v, privateSecret) || strings.Contains(v, "\x1b]0;t") || len(fx.asked()) != 0 {
		t.Fatalf("enter on a GET with a note does not ask with the note:\n%s", v)
	}
	press(m, "enter")
	if got := fx.asked(); len(got) != 1 || got[0] != "GET /echo" || m.result == nil || m.result.Error != nil {
		t.Errorf("enter again: the server had %q", got)
	}
}

func TestSend(t *testing.T) {
	fx := newFixture(t)
	m := fx.model(t, "test", 150, 40)
	press(m, "enter")
	if m.result == nil || m.result.Response == nil || !strings.Contains(view(m), "HTTP/1.1 200 OK") ||
		!strings.Contains(m.responseText(), "✓ status == 200") {
		t.Fatalf("enter on a GET: no response\n%s", view(m))
	}

	goTo(t, m, "create")
	press(m, "enter")
	if m.mode != confirming || !strings.Contains(view(m), "Send POST") || !strings.Contains(view(m), "#create?") {
		t.Fatalf("enter on a POST does not ask first:\n%s", view(m))
	}
	if !strings.Contains(view(m), "enter sends it, any other key does not") {
		t.Errorf("the question does not say which key sends:\n%s", view(m))
	}
	// y, which copies as curl, does not send, nor does any other key.
	for _, k := range []string{"n", "y", " ", "esc"} {
		press(m, k)
		if got := fx.asked(); len(got) != 1 || m.mode != browsing || !strings.Contains(view(m), "not sent") {
			t.Errorf("%s: the server had %q\n%s", k, got, view(m))
		}
		press(m, "enter")
	}
	press(m, "enter")
	if got := fx.asked(); len(got) != 2 || got[1] != "POST /echo" || m.mode != browsing {
		t.Errorf("enter again: the server had %q", got)
	}

	// An enter that repeats a key held down, or that comes too soon after
	// the question, as a key that bounces does, sends nothing: the
	// question stays.
	at := time.Now()
	m.now = func() time.Time { return at }
	press(m, "enter")
	m.Update(tea.KeyPressMsg{Code: tea.KeyEnter, IsRepeat: true})
	at = at.Add(100 * time.Millisecond)
	press(m, "enter")
	if got := fx.asked(); len(got) != 2 || m.mode != confirming || !strings.Contains(view(m), "too soon: enter again") {
		t.Errorf("a held or bouncing enter: the server had %q, mode %d\n%s", got, m.mode, view(m))
	}
	at = at.Add(time.Second)
	press(m, "enter")
	if got := fx.asked(); len(got) != 3 || m.mode != browsing {
		t.Errorf("enter a second after the question: the server had %q", got)
	}
	tick(m)

	// The session the sign-in captures is sent by the next request, and
	// shown as its placeholder until then.
	goTo(t, m, "me")
	if !strings.Contains(m.requestText(), "unresolved variables: session") {
		t.Errorf("before the sign-in, session is not unresolved:\n%s", view(m))
	}
	goTo(t, m, "login")
	press(m, "enter", "enter")
	goTo(t, m, "me")
	if !strings.Contains(m.requestText(), "X-Session: {{session}}") {
		t.Errorf("after the sign-in, session is not a placeholder:\n%s", view(m))
	}
	press(m, "enter")
	if m.result.Error != nil || !strings.Contains(m.responseText(), `"session": "***"`) {
		t.Errorf("me: error %+v\n%s", m.result.Error, view(m))
	}

	// The session reads the files again for each request, so that what is
	// sent is what the preview shows, and keeps what it captured.
	b, _ := json.Marshal(map[string]map[string]string{"test": {"host": fx.host + "/v2"}, "other": {}})
	if err := os.WriteFile(filepath.Join(fx.dir, "http-client.env.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	goTo(t, m, "echo")
	press(m, "enter")
	if got := fx.asked(); got[len(got)-1] != "GET /v2/echo" || !strings.Contains(m.requestText(), fx.host+"/v2/echo") {
		t.Errorf("after the environment file changed, the server had %q; preview:\n%s", got, m.requestText())
	}
	if !slices.Equal(m.declared, []string{"session"}) {
		t.Errorf("declared = %q after the files were read again", m.declared)
	}

	// Another environment starts a new session: nothing captured.
	press(m, "e", "k", "enter")
	if m.env != "other" || len(m.declared) != 0 || m.result != nil {
		t.Errorf("after choosing other: env %q, declared %q", m.env, m.declared)
	}
}

func TestCancel(t *testing.T) {
	fx := newFixture(t)
	m := fx.model(t, "test", 100, 30)
	goTo(t, m, "slow")
	_, cmd := m.Update(keyMsg("enter"))
	if cmd == nil || m.flight == nil || !strings.Contains(view(m), "sending; esc cancels") {
		t.Fatalf("enter: no request in flight\n%s", view(m))
	}
	for _, k := range []string{"enter", "e"} {
		if _, again := m.Update(keyMsg(k)); again != nil || !strings.Contains(view(m), "a request is in flight") {
			t.Errorf("%s while a request is in flight:\n%s", k, view(m))
		}
	}
	press(m, "esc")
	done := make(chan tea.Msg)
	go func() { done <- cmd() }()
	select {
	case msg := <-done:
		m.Update(msg)
	case <-time.After(10 * time.Second):
		t.Fatal("the canceled request did not end")
	}
	if m.flight != nil || m.result.Error == nil || m.result.Error.Kind != core.KindCanceled {
		t.Errorf("after esc: result %+v", m.result)
	}
	if !strings.Contains(m.responseText(), "✗ canceled: ") {
		t.Errorf("the cancellation is not shown:\n%s", view(m))
	}
}

// TestLayouts checks that every layout fills the terminal exactly, from
// one column to three.
func TestLayouts(t *testing.T) {
	fx := newFixture(t)
	for _, sz := range []size{{40, 16}, {60, 24}, {80, 24}, {100, 30}, {139, 40}, {140, 40}, {200, 60}} {
		m := fx.model(t, "test", sz.w, sz.h)
		press(m, "enter")
		lines := strings.Split(view(m), "\n")
		if len(lines) != sz.h {
			t.Errorf("%dx%d: %d lines", sz.w, sz.h, len(lines))
		}
		for i, l := range lines {
			if w := lipgloss.Width(l); w > sz.w {
				t.Errorf("%dx%d: line %d is %d wide: %q", sz.w, sz.h, i, w, l)
			}
		}
	}
}

// TestPanic checks that a panic in Update, in View and in the command
// of a request ends the program with the panic kept for Run.
func TestPanic(t *testing.T) {
	fx := newFixture(t)
	m := fx.model(t, "", 100, 30)
	m.rows = nil
	if _, cmd := m.Update(keyMsg("j")); m.panicked == nil || cmd == nil {
		t.Fatal("a panic in Update: nothing kept, or no quit")
	} else if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("a panic in Update does not quit")
	}

	m = fx.model(t, "", 100, 30)
	stopped := false
	m.stop = func() { stopped = true }
	m.rows, m.mode = nil, confirming
	if v := m.View(); m.panicked == nil || !stopped || v.Content != "" {
		t.Errorf("a panic in View: kept %v, stopped %v", m.panicked, stopped)
	}

	// Before the request's goroutine starts, the panic leaves no request
	// in flight for Run to wait for.
	m = fx.model(t, "test", 100, 30)
	m.send = nil
	if _, cmd := m.Update(keyMsg("enter")); m.panicked == nil || cmd == nil || m.flight != nil {
		t.Errorf("a panic before sending: kept %v, flight %v", m.panicked, m.flight)
	}

	// In the request's goroutine, it comes back as a message.
	fl := &flight{done: make(chan struct{})}
	fl.send(t.Context(), nil, m.rows[1])
	<-fl.done
	m = fx.model(t, "test", 100, 30)
	if _, quit := m.Update(panicMsg{fl.panic}); fl.panic == nil || m.panicked != fl.panic || quit == nil {
		t.Error("a panic in the request's goroutine: nothing kept, or no quit")
	}
}

// typeText presses the keys of the characters of s.
func typeText(m *Model, s string) {
	for _, r := range s {
		press(m, string(r))
	}
}

// shownLabels returns the labels of the rows the tree shows.
func shownLabels(m *Model) []string {
	var labels []string
	for _, i := range m.shown {
		labels = append(labels, m.rows[i].label)
	}
	return labels
}

func TestSearch(t *testing.T) {
	fx := newFixture(t)
	m := fx.model(t, "test", 100, 30)
	press(m, "tab", "/")
	if m.mode != searching || m.focus != treePane {
		t.Fatalf("/: mode %d, focus %d", m.mode, m.focus)
	}
	press(m, "M", "e")
	if got := shownLabels(m); !slices.Equal(got, []string{"api.http", "GET me"}) || m.rows[m.cursor].label != "GET me" ||
		!strings.Contains(view(m), "/Me_") || strings.Contains(view(m), "GET echo") {
		t.Errorf("/Me: shown %q, selected %q\n%s", got, m.rows[m.cursor].label, view(m))
	}
	// The URL as written counts, the environment's value does not.
	press(m, "backspace", "backspace")
	typeText(m, "{{closed}}")
	if got := shownLabels(m); !slices.Equal(got, []string{"api.http", "GET refused"}) {
		t.Errorf("/{{closed}}: shown %q", got)
	}
	press(m, "enter")
	if m.mode != browsing || m.query != "{{closed}}" || !strings.Contains(view(m), "/{{closed}}") || strings.Contains(view(m), "{{closed}}_") {
		t.Errorf("enter: mode %d, query %q\n%s", m.mode, m.query, view(m))
	}
	// The file name counts too, and j and k move among the rows shown.
	press(m, "/")
	for range len("{{closed}}") {
		press(m, "backspace")
	}
	typeText(m, "BROKEN")
	press(m, "enter", "k", "k", "j")
	if got := shownLabels(m); !slices.Equal(got, []string{"broken.http"}) || m.rows[m.cursor].label != "broken.http" {
		t.Errorf("/BROKEN: shown %q, selected %q", got, m.rows[m.cursor].label)
	}
	// Nothing matches: nothing is sent.
	press(m, "/", "z", "z", "enter")
	if !strings.Contains(view(m), "no request matches") {
		t.Errorf("no match:\n%s", view(m))
	}
	press(m, "enter")
	if got := fx.asked(); len(got) != 0 || !strings.Contains(view(m), "no request matches the search") {
		t.Errorf("enter with nothing shown: the server had %q\n%s", got, view(m))
	}
	// esc clears the search and leaves the cursor where it was.
	press(m, "/", "esc")
	if m.mode != browsing || m.query != "" || len(m.shown) != len(m.rows) || m.rows[m.cursor].label != "broken.http" {
		t.Errorf("esc: mode %d, query %q, %d of %d rows shown", m.mode, m.query, len(m.shown), len(m.rows))
	}
	// A paste goes into the search, on one line.
	press(m, "/")
	m.Update(tea.PasteMsg{Content: "slo\nw"})
	if m.query != "slo w" {
		t.Errorf("after a paste, the search is %q", m.query)
	}
}

// styled returns p as the request pane shows a placeholder of class c.
func styled(c env.Class, p string) string { return placeholderStyles[c].Render(p) }

// TestHighlight checks the colour of each kind of placeholder in the
// request pane, as sent and as written, and of a capture that took no
// value, which the preview shows as the error that sending would give.
func TestHighlight(t *testing.T) {
	fx := newFixture(t)
	m := fx.model(t, "", 150, 40)
	text := m.request.GetContent()
	for _, want := range []string{
		"GET " + styled(env.Unresolved, "{{host}}") + "/echo?key=" + styled(env.Unresolved, "{{token}}") +
			"&env=" + styled(env.Secret, "{{$env VEGTAM_TEST_KEY}}"),
		"unresolved variables: host, token (no environment selected",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("without an environment, the request pane does not show %q:\n%q", want, text)
		}
	}
	press(m, "e", "j", "j", "enter")
	if text = m.request.GetContent(); !strings.Contains(text, "/echo?key="+styled(env.Secret, "{{token}}")+"&env=") {
		t.Errorf("as sent, the secret is not coloured:\n%q", text)
	}
	if got := m.highlight("a *** b {{nope}} {{ host }} {{$x y z}}"); got != "a "+styled(env.Secret, "***")+" b "+
		styled(env.Unresolved, "{{nope}}")+" "+styled(env.Plain, "{{ host }}")+" {{$x y z}}" {
		t.Errorf("highlight = %q", got)
	}

	goTo(t, m, "me")
	if text = m.request.GetContent(); !strings.Contains(text, "GET "+styled(env.Plain, "{{host}}")+"/me\nX-Session: "+
		styled(env.Unresolved, "{{session}}")) || !strings.Contains(text, "unresolved variables: session") {
		t.Errorf("before the sign-in:\n%q", text)
	}
	fx.mu.Lock()
	fx.noSession = true
	fx.mu.Unlock()
	goTo(t, m, "login")
	press(m, "enter", "enter")
	goTo(t, m, "me")
	if text = m.request.GetContent(); !strings.Contains(text, "X-Session: "+styled(env.Unresolved, "{{session}}")) ||
		!strings.Contains(text, "✗ variable: ") || !strings.Contains(text, "not captured: session (") ||
		!strings.Contains(text, "api.http#login took no value)") {
		t.Errorf("after a sign-in that took no session:\n%q", text)
	}
	press(m, "enter")
	if m.result.Error == nil || !strings.Contains(m.result.Error.Message, "not captured: session (") {
		t.Errorf("sending gives %+v", m.result.Error)
	}
	fx.mu.Lock()
	fx.noSession = false
	fx.mu.Unlock()
	goTo(t, m, "login")
	press(m, "enter", "enter")
	goTo(t, m, "me")
	if text = m.request.GetContent(); !strings.Contains(text, "X-Session: "+styled(env.Captured, "{{session}}")) {
		t.Errorf("after a sign-in that took the session:\n%q", text)
	}
}

// clipboard returns what the command cmd puts on the clipboard, and
// whether it does.
func clipboard(cmd tea.Cmd) (string, bool) {
	if cmd == nil {
		return "", false
	}
	msg := cmd()
	v := reflect.ValueOf(msg)
	if v.Kind() != reflect.String || v.Type().Name() != "setClipboardMsg" {
		return "", false
	}
	return v.String(), true
}

// TestCopyCurl copies requests as curl commands: the command is on the
// clipboard and in the response pane, and in bash, with the secrets set
// as the comment says, it gives curl the request that vegtam sends.
func TestCopyCurl(t *testing.T) {
	fx := newFixture(t)
	m := fx.model(t, "test", 150, 40)
	goTo(t, m, "everywhere")
	_, cmd := m.Update(keyMsg("y"))
	got, ok := clipboard(cmd)
	if !ok || got != m.curl || !strings.Contains(view(m), "curl "+fx.dir) || !strings.Contains(view(m), "Copied, if the terminal") {
		t.Fatalf("y: clipboard %q (%v), shown %q\n%s", got, ok, m.curl, view(m))
	}
	if found := leaks(got); len(found) > 0 {
		t.Errorf("the command holds %q:\n%s", found, got)
	}
	want := "# Set first: token for {{token}}, VEGTAM_TEST_KEY for {{$env VEGTAM_TEST_KEY}}\n" +
		`: "${token?}" "${VEGTAM_TEST_KEY?}" && curl -X PUT --globoff --path-as-is '` + fx.host + `/items/'"$token"'?key='"$VEGTAM_TEST_KEY"'&q=it'\''s' \` + "\n" +
		`  -H 'Authorization: Bearer '"$token" \` + "\n" +
		`  -H 'Content-Type: application/json' \` + "\n" +
		`  --data-raw '{"token": "'"$token"'", "key": "'"$VEGTAM_TEST_KEY"$'", "tab": "\t"}'` + "\n"
	if got != want {
		t.Errorf("the command:\n%s\nwant\n%s", got, want)
	}
	script := "curl() { printf '%s\\0' \"$@\"; }\n" + got
	sh := exec.CommandContext(t.Context(), "bash", "--noprofile", "--norc", "-c", script)
	sh.Env = []string{"token=" + privateSecret, "VEGTAM_TEST_KEY=" + envSecret}
	out, err := sh.Output()
	if err != nil {
		t.Fatalf("bash: %v", err)
	}
	args := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	if wantArgs := []string{
		"-X", "PUT", "--globoff", "--path-as-is", fx.host + "/items/" + privateSecret + "?key=" + envSecret + "&q=it's",
		"-H", "Authorization: Bearer " + privateSecret, "-H", "Content-Type: application/json",
		"--data-raw", `{"token": "` + privateSecret + `", "key": "` + envSecret + "\", \"tab\": \"\t\"}",
	}; !slices.Equal(args, wantArgs) {
		t.Errorf("curl got\n%q\nwant\n%q", args, wantArgs)
	}

	// esc hides it, as does choosing another request.
	press(m, "esc")
	if m.curl != "" || strings.Contains(view(m), "Copied, if") {
		t.Errorf("esc does not hide the command:\n%s", view(m))
	}
	press(m, "y", "k")
	if m.curl != "" {
		t.Error("the command stays after k")
	}

	// A captured value is a shell variable too.
	goTo(t, m, "login")
	press(m, "enter", "enter")
	goTo(t, m, "me")
	if got, _ = yank(m); !strings.HasPrefix(got, "# Set first: session for {{session}} from an @capture\n") ||
		!strings.HasSuffix(got, `  -H 'X-Session: '"$session"`+"\n") {
		t.Errorf("me:\n%s", got)
	}

	// No command for a file, nor for a request that cannot be sent.
	goTo(t, m, "echo")
	press(m, "k")
	if _, ok = yank(m); ok || !strings.Contains(view(m), "select a request to copy it") {
		t.Errorf("y on a file:\n%s", view(m))
	}
	m = fx.model(t, "", 150, 40)
	if _, ok = yank(m); ok || !strings.Contains(view(m), "not copied: unresolved variables: host, token") {
		t.Errorf("y without an environment:\n%s", view(m))
	}

	// Nor while a request is in flight: esc would cancel it, not hide
	// the command.
	m = fx.model(t, "test", 150, 40)
	goTo(t, m, "slow")
	_, sent := m.Update(keyMsg("enter"))
	if _, ok = yank(m); ok || m.curl != "" || !strings.Contains(view(m), "Sending ") {
		t.Errorf("y in flight:\n%s", view(m))
	}
	press(m, "esc")
	m.Update(sent())

	// Nor for a request whose text holds a secret value outside a
	// placeholder: quoted for the shell, the value could slip past the
	// masker.
	src := "# @name literal\nGET {{host}}/echo?q=it's\nX-Copy: " + privateSecret + "\n"
	if err = os.WriteFile(filepath.Join(fx.dir, "literal.http"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	m = fx.model(t, "test", 150, 40)
	goTo(t, m, "literal")
	if got, ok = yank(m); ok || m.curl != "" || m.note != "not copied: a secret value is in the request outside a placeholder, in header X-Copy" {
		t.Errorf("y with a secret in the text: %q\n%s", got, view(m))
	}

	// Nor if a secret value is in what the command adds: masked, the
	// command would be wrong.
	goTo(t, m, "create")
	m.masker = m.masker.Join(core.NewMasker([]string{"raw"}))
	if got, ok = yank(m); ok || m.curl != "" || m.note != "not copied: a secret value is in the curl command" {
		t.Errorf("y with a secret in --data-raw: %q\n%s", got, view(m))
	}
}

// TestPastSecrets checks that a secret that only a preview read stays
// masked in the views and keeps a request that holds it from being
// copied, once another environment is chosen.
func TestPastSecrets(t *testing.T) {
	fx := newFixture(t)
	src := "# @name literal\nGET {{host}}/echo\nX-Copy: " + privateSecret + "\n"
	if err := os.WriteFile(filepath.Join(fx.dir, "literal.http"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	m := fx.model(t, "test", 150, 40) // the preview of echo reads the private file
	press(m, "e", "k", "enter")
	if m.env != "other" {
		t.Fatalf("env %q", m.env)
	}
	goTo(t, m, "literal")
	if found := leaks(view(m)); len(found) > 0 || !strings.Contains(sgr.ReplaceAllString(view(m), ""), "X-Copy: ***") {
		t.Errorf("secret forms %q in\n%s", found, view(m))
	}
	if got, ok := yank(m); ok || m.note != "not copied: a secret value is in the request outside a placeholder, in header X-Copy" {
		t.Errorf("y: %q\n%s", got, view(m))
	}
}

// yank presses y and returns what the command it gives back puts on the
// clipboard, and whether it does.
func yank(m *Model) (string, bool) {
	_, cmd := m.Update(keyMsg("y"))
	return clipboard(cmd)
}

// TestFold folds the JSON body of a response with z: all of it, from
// depth 1, from depth 2, then all of it again, for the next response too.
func TestFold(t *testing.T) {
	fx := newFixture(t)
	m := fx.model(t, "test", 150, 40)
	press(m, "enter")
	full := m.response.GetContent()
	if !strings.Contains(full, "\"echo\": {\n    \"authorization\": \"Bearer ***\",") {
		t.Fatalf("the body is not indented:\n%s", full)
	}
	for _, want := range []string{
		"{\n  \"echo\": {… 3 keys},\n  \"php\": {… 3 keys}\n}\n",
		"\"echo\": {\n    \"authorization\": \"Bearer ***\",",
		full,
	} {
		press(m, "z")
		if got := m.response.GetContent(); !strings.Contains(got, want) {
			t.Errorf("fold %d: no %q in\n%s", m.fold, want, got)
		}
	}
	press(m, "z")
	if m.fold != 1 || !strings.Contains(view(m), "(folded from depth 1)") || !strings.Contains(view(m), "JSON folded from depth 1") {
		t.Errorf("z: fold %d\n%s", m.fold, view(m))
	}
	press(m, "enter")
	if got := m.response.GetContent(); !strings.Contains(got, "\"echo\": {… 3 keys}") || !strings.Contains(got, "✓ status == 200") {
		t.Errorf("the next response is not folded as the last:\n%s", got)
	}
	// A body is masked whole before it is folded: a secret value cut in
	// two by a fold would leave its end unmasked.
	secret := `"b": 1}, "c": "S3cr3tTail`
	m.result.Response.Body = `{"a": {"b": 1}, "c": "S3cr3tTail"}`
	m.masker = core.NewMasker([]string{secret})
	m.showResponse()
	if got := m.response.GetContent(); strings.Contains(got, "S3cr3tTail") || !strings.Contains(got, `{"a": {***"}`) {
		t.Errorf("a secret across a fold:\n%s", got)
	}
	// DEL and C1 characters, which JSON allows in strings, do not keep a
	// body from being folded; they are shown escaped.
	m.result.Response.Body = "{\"a\": {\"b\": \"x\x7f\u0080y\"}}"
	m.showResponse()
	if got := m.response.GetContent(); !strings.Contains(got, "\"a\": {… 1 key}") {
		t.Errorf("a body with DEL and C1, folded:\n%s", got)
	}
	press(m, "z", "z")
	if got := m.response.GetContent(); !strings.Contains(got, `"b": "x\x7f\x80y"`) {
		t.Errorf("a body with DEL and C1:\n%s", got)
	}

	// A body that is not JSON is shown as it is.
	goTo(t, m, "big")
	press(m, "enter")
	if got := m.response.GetContent(); !strings.Contains(got, strings.Repeat("x", 100)+"***") {
		t.Errorf("a body that is not JSON, folded:\n%s", got)
	}
}

// TestStatusLine checks that the status line fills the width exactly and
// keeps the main keys whole, cutting the environment and the note short.
func TestStatusLine(t *testing.T) {
	fx := newFixture(t)
	for _, w := range []int{12, 20, 30, 40, 60, 72, 73, 80, 100, 160} {
		m := fx.model(t, "test", w, 24)
		m.note = "a note long enough not to fit beside the keys of any terminal this test tries"
		line := sgr.ReplaceAllString(m.statusLine(), "")
		if got := lipgloss.Width(line); got != w {
			t.Errorf("%d columns: the status line is %d wide: %q", w, got, line)
		}
		var want []string
		if w >= 30 {
			want = []string{"enter send", "? help", "q quit"}
		}
		if w >= 80 {
			want = append(want, "/ search", "y curl", "e env")
		}
		for _, k := range want {
			if !strings.Contains(line, k) {
				t.Errorf("%d columns: no %q in %q", w, k, line)
			}
		}
		if w > 30 && w < 160 && (!strings.HasPrefix(line, " env: ") || !strings.Contains(line, "…")) {
			t.Errorf("%d columns: the left part is not cut short: %q", w, line)
		}
	}
}

// TestStatusLineInsecure checks that --insecure is on the screen while the
// interface is: the banner on stderr is hidden under it.
func TestStatusLineInsecure(t *testing.T) {
	fx := newFixture(t)
	opts := Options{Path: fx.dir, Transport: vexec.Transport{TLS: vexec.TLS{Insecure: true}}, MaxBody: 1 << 20}
	for _, w := range []int{40, 100} {
		if line := sgr.ReplaceAllString(open(t, opts, w, 24).statusLine(), ""); !strings.HasPrefix(line, " INSECURE") {
			t.Errorf("%d columns: %q", w, line)
		}
	}
	if line := fx.model(t, "", 100, 24).statusLine(); strings.Contains(line, "INSECURE") {
		t.Errorf("without --insecure: %q", line)
	}
}

// TestRedraw checks that ctrl+l, in any mode, has Bubble Tea clear the
// screen and draw it again, over what something else wrote on it.
func TestRedraw(t *testing.T) {
	fx := newFixture(t)
	m := fx.model(t, "", 100, 30)
	for _, mode := range []mode{browsing, searching, helping} {
		m.mode = mode
		_, cmd := m.Update(tea.KeyPressMsg{Code: 'l', Mod: tea.ModCtrl})
		if cmd == nil || reflect.TypeOf(cmd()).Name() != "clearScreenMsg" {
			t.Errorf("ctrl+l in mode %d: no clear screen", mode)
		}
	}
}

// TestHistory checks h: the latest runs, the latest first, searched with
// /, each shown in the response pane, and enter that goes to its request
// in the tree.
func TestHistory(t *testing.T) {
	fx := newFixture(t)
	m := fx.model(t, "test", 150, 40)
	if press(m, "h"); m.runsOpen || !strings.Contains(view(m), "no history: it is turned off") {
		t.Errorf("h without a history:\n%s", view(m))
	}

	log := history.New(filepath.Join(t.TempDir(), "vegtam"))
	m = open(t, Options{Path: fx.dir, Env: "test", Transport: vexec.Transport{Total: 5 * time.Second}, MaxBody: 1 << 20, History: log, Secrets: fx.secrets}, 150, 40)
	if press(m, "h"); !m.runsOpen || !strings.Contains(view(m), "History") || !strings.Contains(view(m), "no runs yet") ||
		!strings.Contains(m.responseText(), "No runs yet") {
		t.Errorf("h before any run:\n%s", view(m))
	}
	if press(m, "enter"); !m.runsOpen || !strings.Contains(m.statusLine(), "no runs yet") {
		t.Errorf("enter before any run:\n%s", view(m))
	}
	press(m, "esc")
	goTo(t, m, "echo")
	press(m, "enter")
	goTo(t, m, "create")
	press(m, "enter", "enter")
	goTo(t, m, "refused")
	press(m, "enter")

	press(m, "h")
	if len(m.runs) != 3 {
		t.Fatalf("%d runs", len(m.runs))
	}
	today := m.runs[0].Time
	m.now = func() time.Time { return today }
	var labels, want []string
	for i, outcome := range []string{"network api.http#refused", "200 api.http#create", "200 api.http#echo"} {
		labels = append(labels, m.runLabel(m.runs[m.runShown[i]]))
		want = append(want, m.runs[i].Time.Local().Format("15:04 ")+outcome)
	}
	if !slices.Equal(labels, want) {
		t.Errorf("the runs: %q, want %q", labels, want)
	}
	if line := sgr.ReplaceAllString(m.statusLine(), ""); !strings.Contains(line, "enter go to") || !strings.Contains(line, "esc close") {
		t.Errorf("the status line while the runs are listed: %q", line)
	}
	if v := view(m); !strings.Contains(v, "Run") || !strings.Contains(m.responseText(), "GET {{closed}}/?key={{token}}") ||
		!strings.Contains(m.responseText(), "result    network") || len(leaks(v)) > 0 {
		t.Errorf("the selected run:\n%s", v)
	}
	press(m, "j")
	if text := m.responseText(); !strings.Contains(text, "POST {{host}}/echo?key={{token}}") || !strings.Contains(text, "status    200") {
		t.Errorf("the second run:\n%s", text)
	}

	// The search narrows the runs; enter goes to the request of the run.
	press(m, "/")
	typeText(m, "get")
	if len(m.runShown) != 2 || !strings.Contains(view(m), "/get_") {
		t.Errorf("searching the runs for get: %d shown\n%s", len(m.runShown), view(m))
	}
	press(m, "enter", "j", "enter")
	if m.runsOpen || m.rows[m.cursor].file.Requests[m.rows[m.cursor].index].Name != "echo" || m.focus != treePane {
		t.Errorf("enter on the run of echo: open %v, cursor on %q", m.runsOpen, m.rows[m.cursor].label)
	}
	if !strings.Contains(m.responseText(), "✗ network: ") { // of the latest run, refused
		t.Errorf("after the history, the response is not back:\n%s", m.responseText())
	}

	// A request that the search of the tree hides is shown again.
	press(m, "/")
	typeText(m, "refused")
	press(m, "enter", "h", "j", "enter")
	if m.query != "" || m.rows[m.cursor].label != "POST create" {
		t.Errorf("going to a request the search hides: query %q, cursor on %q", m.query, m.rows[m.cursor].label)
	}

	// A run of a request that is not in the tree stays in the history.
	elsewhere := history.Entry{Time: today.AddDate(0, 0, -1), Ref: "/elsewhere/x.http#gone", Method: "GET", URL: "{{host}}", Result: "ok"}
	if err := log.Add(elsewhere); err != nil {
		t.Fatal(err)
	}
	press(m, "h")
	if text := m.responseText(); !strings.Contains(text, "/elsewhere/x.http#gone") || !strings.Contains(text, "not in the list") {
		t.Errorf("a run from elsewhere:\n%s", text)
	}
	if got, want := m.runLabel(m.runs[0]), today.AddDate(0, 0, -1).Local().Format("01-02")+" ok /elsewhere/x.http#gone"; got != want {
		t.Errorf("a run of yesterday: %q, want %q", got, want)
	}
	press(m, "enter")
	if !m.runsOpen || !strings.Contains(view(m), "not in the list of requests: /elsewhere/x.http#gone") {
		t.Errorf("enter on a run from elsewhere:\n%s", view(m))
	}
	press(m, "h")
	if m.runsOpen {
		t.Error("h does not close the history")
	}
	if got, err := log.Last(10); err != nil || len(got) != 4 {
		t.Errorf("the history has %d runs, %v", len(got), err)
	}

	// While a request is in flight, esc closes the list first, and the
	// status line does not say that it cancels.
	goTo(t, m, "slow")
	_, sent := m.Update(keyMsg("enter"))
	press(m, "h")
	if line := sgr.ReplaceAllString(m.statusLine(), ""); !m.runsOpen || !strings.Contains(line, " sending ") || strings.Contains(line, "esc cancels") {
		t.Errorf("the status line with the runs open, sending: %q", line)
	}
	press(m, "esc")
	if m.runsOpen || m.flight == nil || !strings.Contains(m.statusLine(), "esc cancels") {
		t.Errorf("esc with the runs open: open %v, flight %v", m.runsOpen, m.flight)
	}
	press(m, "esc")
	m.Update(sent())
	if m.flight != nil || m.result.Error == nil || m.result.Error.Kind != core.KindCanceled {
		t.Errorf("the request was not canceled: %+v", m.result)
	}

	// A history that cannot be written is a note, after the response.
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	m = open(t, Options{Path: fx.dir, Env: "test", Transport: vexec.Transport{Total: 5 * time.Second}, MaxBody: 1 << 20, History: history.New(blocked), Secrets: fx.secrets}, 150, 40)
	press(m, "enter")
	if m.result.Error != nil || !strings.Contains(m.statusLine(), "history: ") {
		t.Errorf("with no place for the history: %+v\n%s", m.result.Error, m.statusLine())
	}
}

// TestHelpScrolls checks that the help, on a terminal too small for it,
// keeps its frame and scrolls, and that it fits 80x24 as a whole.
func TestHelpScrolls(t *testing.T) {
	fx := newFixture(t)
	for _, sz := range []size{{40, 16}, {60, 24}, {80, 24}, {150, 40}} {
		m := fx.model(t, "test", sz.w, sz.h)
		press(m, "?")
		lines := strings.Split(sgr.ReplaceAllString(view(m), ""), "\n")
		if len(lines) != sz.h || !strings.HasPrefix(lines[sz.h-2], "╰") {
			t.Errorf("%dx%d: %d lines, the frame ends with %q", sz.w, sz.h, len(lines), lines[sz.h-2])
		}
		scrolls := strings.Contains(lines[1], "scroll")
		if want := sz.w < 80; scrolls != want {
			t.Errorf("%dx%d: the title says it scrolls: %v\n%s", sz.w, sz.h, scrolls, strings.Join(lines, "\n"))
		}
		for range 20 {
			press(m, "f")
		}
		if v := sgr.ReplaceAllString(view(m), ""); !strings.Contains(v, "what does not resolve.") || !strings.Contains(v, "╰") {
			t.Errorf("%dx%d: the end of the help is not reached:\n%s", sz.w, sz.h, v)
		}
		press(m, "esc")
		if m.mode != browsing {
			t.Errorf("%dx%d: esc leaves mode %d", sz.w, sz.h, m.mode)
		}
	}
}

// TestPlainTerminal checks that, on a terminal that shows no styles, a
// mark shows the selected line of the list.
func TestPlainTerminal(t *testing.T) {
	fx := newFixture(t)
	m := fx.model(t, "", 100, 30)
	goTo(t, m, "create")
	m.Update(tea.ColorProfileMsg{Profile: colorprofile.NoTTY})
	v := sgr.ReplaceAllString(view(m), "")
	if !strings.Contains(v, ">   POST create") || !strings.Contains(v, "    GET echo") || strings.Count(v, "> ") != 1 {
		t.Errorf("no mark on the selected line:\n%s", v)
	}
	press(m, "e")
	if v = sgr.ReplaceAllString(view(m), ""); !strings.Contains(v, "> (none)") {
		t.Errorf("no mark on the selected environment:\n%s", v)
	}
	m.Update(tea.ColorProfileMsg{Profile: colorprofile.ANSI})
	if v = view(m); strings.Contains(v, "> (none)") {
		t.Errorf("a mark on a terminal with styles:\n%s", v)
	}
}

// TestNoEnvironmentHint checks that, without an environment, the error
// of an unresolved variable points to e, not to -e.
func TestNoEnvironmentHint(t *testing.T) {
	fx := newFixture(t)
	m := fx.model(t, "", 100, 30)
	goTo(t, m, "echo")
	if text := m.requestText(); !strings.Contains(text, "(no environment selected; e chooses one)") || strings.Contains(text, "-e") {
		t.Errorf("preview:\n%s", text)
	}
	press(m, "enter")
	if m.result.Error == nil || !strings.HasSuffix(m.result.Error.Message, "(no environment selected; e chooses one)") {
		t.Errorf("sent: %+v", m.result.Error)
	}
}
