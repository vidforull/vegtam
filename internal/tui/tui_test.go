package tui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"go.uber.org/goleak"

	"github.com/vidforull/vegtam/internal/core"
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

	mu   sync.Mutex
	seen []string // the paths the server was asked for
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
	envs := map[string]map[string]map[string]string{
		"http-client.env.json":         {"test": {"host": srv.URL, "closed": closed.URL}, "other": {"host": srv.URL}},
		"http-client.private.env.json": {"test": {"token": privateSecret}},
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
		fmt.Fprint(w, "\x1b[2J\x1b[H\x1b]0;title\x07 \u009b31m \x1b[31mred\x1b[0m \x7f\r\x08 "+r.URL.Query().Get("key"))
	})
	mux.HandleFunc("/binary", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "\xff\xfe"+r.URL.RawQuery+"\x00")
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", 100)+r.URL.Query().Get("key"))
	})
	mux.HandleFunc("/slow", func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, _ *http.Request) {
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
func newModel(t *testing.T, path, envName string, maxBody int64, width, height int) *Model {
	t.Helper()
	m, err := New(Options{Path: path, Env: envName, Timeout: 5 * time.Second, MaxBody: maxBody, UserAgent: "vegtam/test"})
	if err != nil {
		t.Fatal(err)
	}
	m.start(t.Context(), func() {})
	m.Update(tea.WindowSizeMsg{Width: width, Height: height})
	return m
}

// keyMsg returns the message Bubble Tea makes of a key press.
func keyMsg(k string) tea.KeyPressMsg {
	special := map[string]tea.KeyPressMsg{
		"enter": {Code: tea.KeyEnter}, "esc": {Code: tea.KeyEscape}, "tab": {Code: tea.KeyTab},
		"shift+tab": {Code: tea.KeyTab, Mod: tea.ModShift}, "ctrl+c": {Code: 'c', Mod: tea.ModCtrl},
		"up": {Code: tea.KeyUp}, "down": {Code: tea.KeyDown},
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
	m := newModel(t, fx.dir, "", 1<<20, 100, 30)
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
	if m.cursor != 0 || !strings.HasSuffix(m.requestText(), "api.http\n\n9 requests\n") {
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
	m := newModel(t, fx.dir, "", 1<<20, 100, 30)
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

func TestSend(t *testing.T) {
	fx := newFixture(t)
	m := newModel(t, fx.dir, "test", 1<<20, 150, 40)
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
	press(m, "n")
	if got := fx.asked(); len(got) != 1 || m.mode != browsing || !strings.Contains(view(m), "not sent") {
		t.Errorf("n: the server had %q\n%s", got, view(m))
	}
	press(m, "enter", "y")
	if got := fx.asked(); len(got) != 2 || got[1] != "POST /echo" {
		t.Errorf("y: the server had %q", got)
	}

	// The session the sign-in captures is sent by the next request, and
	// shown as its placeholder until then.
	goTo(t, m, "me")
	if !strings.Contains(m.requestText(), "unresolved variables: session") {
		t.Errorf("before the sign-in, session is not unresolved:\n%s", view(m))
	}
	goTo(t, m, "login")
	press(m, "enter", "y")
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
	m := newModel(t, fx.dir, "test", 1<<20, 100, 30)
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
		m := newModel(t, fx.dir, "test", 1<<20, sz.w, sz.h)
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
	m := newModel(t, fx.dir, "", 1<<20, 100, 30)
	m.rows = nil
	if _, cmd := m.Update(keyMsg("j")); m.panicked == nil || cmd == nil {
		t.Fatal("a panic in Update: nothing kept, or no quit")
	} else if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("a panic in Update does not quit")
	}

	m = newModel(t, fx.dir, "", 1<<20, 100, 30)
	stopped := false
	m.stop = func() { stopped = true }
	m.rows, m.mode = nil, confirming
	if v := m.View(); m.panicked == nil || !stopped || v.Content != "" {
		t.Errorf("a panic in View: kept %v, stopped %v", m.panicked, stopped)
	}

	// Before the request's goroutine starts, the panic leaves no request
	// in flight for Run to wait for.
	m = newModel(t, fx.dir, "test", 1<<20, 100, 30)
	m.send = nil
	if _, cmd := m.Update(keyMsg("enter")); m.panicked == nil || cmd == nil || m.flight != nil {
		t.Errorf("a panic before sending: kept %v, flight %v", m.panicked, m.flight)
	}

	// In the request's goroutine, it comes back as a message.
	fl := &flight{done: make(chan struct{})}
	fl.send(t.Context(), nil, m.rows[1])
	<-fl.done
	m = newModel(t, fx.dir, "test", 1<<20, 100, 30)
	if _, quit := m.Update(panicMsg{fl.panic}); fl.panic == nil || m.panicked != fl.panic || quit == nil {
		t.Error("a panic in the request's goroutine: nothing kept, or no quit")
	}
}
