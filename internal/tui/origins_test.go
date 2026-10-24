package tui

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/vidforull/vegtam/internal/core"
	vexec "github.com/vidforull/vegtam/internal/core/exec"
	"github.com/vidforull/vegtam/internal/core/output"
	"github.com/vidforull/vegtam/internal/core/policy"
)

// trap is a server that counts the connections it takes and keeps what
// it was sent: a secret refused must reach no server at all. /login hands
// out a session; every other path answers {}.
type trap struct {
	origin string
	conns  atomic.Int32

	mu   sync.Mutex
	sent []string // "METHOD /path?query" and the X-Session header of each request
}

func newTrap(t *testing.T) *trap {
	t.Helper()
	tr := &trap{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tr.mu.Lock()
		tr.sent = append(tr.sent, r.Method+" "+r.URL.RequestURI()+" "+r.Header.Get("X-Session"))
		tr.mu.Unlock()
		if r.URL.Path == "/login" {
			fmt.Fprintf(w, `{"session": %q}`, sessionSecret)
			return
		}
		fmt.Fprint(w, `{}`)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			tr.conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	tr.origin = srv.URL
	return tr
}

// requests returns what the server has been sent.
func (tr *trap) requests() []string {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return slices.Clone(tr.sent)
}

// allowedSecret is a value of the private file that its $allow binds to
// the origin of home.
const allowedSecret = "Al10w3d/v+al"

// originsDir writes a .http file whose requests go to the servers home
// and away, with a private token that no $allow binds to any origin, and
// a value that its $allow binds to home, for the environment "test", and
// returns its directory. host, in the public file, is home.
func originsDir(t *testing.T, home, away *trap) string {
	t.Helper()
	dir := t.TempDir()
	src := strings.NewReplacer("HOME", home.origin, "AWAY", away.origin).Replace(`### Sends the token where it is not bound
# @name steal
GET HOME/c?t={{token}}

### Signs in: the session it captures may go back to home alone
# @name login
# @capture session = $.session
POST HOME/login

### Sends the session back
# @name me
GET HOME/me
X-Session: {{session}}

### Sends the session elsewhere
# @name elsewhere
GET AWAY/me
X-Session: {{session}}

### Asks first for its method, and so for the token too
# @name post
POST {{host}}/c?t={{token}}

### Asks first for its note, which comes after the token
# @name noted
# @note Read this first
GET HOME/n?t={{token}}

### Sends what the policy and the private file bind to home
# @name bound
GET HOME/b?k={{$env VEGTAM_TEST_KEY}}&a={{allowed}}
`)
	private := map[string]any{"token": privateSecret, "allowed": allowedSecret, "$allow": map[string][]string{"allowed": {home.origin}}}
	files := map[string]any{
		"origins.http":                 src,
		"http-client.env.json":         map[string]map[string]string{"test": {"host": home.origin}},
		"http-client.private.env.json": map[string]map[string]any{"test": private},
	}
	for name, v := range files {
		b, ok := v.(string)
		if !ok {
			j, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			b = string(j)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// selectedRef returns the ref of the selected request.
func selectedRef(m *Model) string {
	r := m.rows[m.cursor]
	return output.Ref(r.file, r.index)
}

// TestSecretOrigin sends a request whose token is bound to no origin:
// the session refuses it before it connects, and the interface asks, in
// the window of the question, naming the secret and where it would go.
// Any other key than enter sends nothing, nor does an enter that comes
// too soon; enter once the question has been read sends it, this once.
func TestSecretOrigin(t *testing.T) {
	home, away := newTrap(t), newTrap(t)
	m := newModel(t, originsDir(t, home, away), "test", 200, 40)
	goTo(t, m, "steal")
	if text := m.requestText(); !strings.Contains(text, "Secrets:\n  {{token}}  bound to no origin; refused for "+home.origin+"\n") {
		t.Errorf("the preview does not say where the token may go:\n%s", text)
	}

	press(m, "enter")
	question := "Send GET " + selectedRef(m) + "?\n\n{{token}} goes to " + home.origin + ", but it is bound to no origin.\n\n" +
		"enter sends it, any other key does not."
	v := view(m)
	if e := m.result.Error; m.mode != confirming || e == nil || e.Kind != core.KindConfirm || e.Confirm == nil ||
		e.Confirm.Reason != core.ReasonSecret || e.Secret == nil || e.Secret.Name != "{{token}}" {
		t.Fatalf("enter: mode %d, result %+v\n%s", m.mode, m.result.Error, v)
	}
	if m.question != question || !strings.Contains(v, "Send?") || !strings.Contains(v, "{{token}} goes to "+home.origin) {
		t.Errorf("the question is\n%s\nwant\n%s\n%s", m.question, question, v)
	}
	if n := home.conns.Load(); n != 0 || len(leaks(v)) > 0 {
		t.Errorf("refused: %d connections, %q in the view", n, leaks(v))
	}

	// Any other key does not send it; the refusal is shown.
	press(m, "n")
	if n := home.conns.Load(); n != 0 || m.mode != browsing || !strings.Contains(view(m), "not sent") ||
		!strings.Contains(m.responseText(), "✗ confirm: ") {
		t.Errorf("n: %d connections, mode %d\n%s", n, m.mode, view(m))
	}

	// A held enter, or one that comes too soon, does not either.
	at := time.Now()
	m.now = func() time.Time { return at }
	press(m, "enter")
	m.Update(tea.KeyPressMsg{Code: tea.KeyEnter, IsRepeat: true})
	at = at.Add(100 * time.Millisecond)
	press(m, "enter")
	if n := home.conns.Load(); n != 0 || m.mode != confirming || !strings.Contains(view(m), "too soon: enter again") {
		t.Errorf("a held or bouncing enter: %d connections, mode %d\n%s", n, m.mode, view(m))
	}
	at = at.Add(time.Second)
	press(m, "enter")
	if got := home.requests(); len(got) != 1 || got[0] != "GET /c?t="+privateSecret+" " || m.mode != browsing ||
		m.result.Error != nil || m.result.Response == nil {
		t.Errorf("enter a second after the question: the server had %q; mode %d, error %+v", got, m.mode, m.result.Error)
	}
	tick(m)

	// The confirmation was for that once.
	press(m, "enter")
	if got := home.requests(); len(got) != 1 || m.mode != confirming {
		t.Errorf("enter again: the server had %q, mode %d", got, m.mode)
	}
	press(m, "esc")
	if n := home.conns.Load(); n != 1 || len(leaks(view(m))) > 0 {
		t.Errorf("%d connections; %q in the view", n, leaks(view(m)))
	}
}

// TestSecretOriginCaptured checks a secret captured from a response: the
// preview, as the request that sends it, knows that it may go back to
// where it came from, and to nowhere else without the question.
func TestSecretOriginCaptured(t *testing.T) {
	home, away := newTrap(t), newTrap(t)
	m := newModel(t, originsDir(t, home, away), "test", 200, 40)
	goTo(t, m, "login")
	press(m, "enter", "enter")
	goTo(t, m, "me")
	if text := m.requestText(); !strings.Contains(text, "Secrets:\n  {{session}}  captured from "+home.origin+"\n") {
		t.Errorf("the preview does not say where the session may go:\n%s", text)
	}
	press(m, "enter")
	if got := home.requests(); len(got) != 2 || got[1] != "GET /me "+sessionSecret || m.mode != browsing || m.result.Error != nil {
		t.Errorf("me: the server had %q; mode %d, error %+v", got, m.mode, m.result.Error)
	}

	goTo(t, m, "elsewhere")
	if text := m.requestText(); !strings.Contains(text, "  {{session}}  captured from "+home.origin+"; refused for "+away.origin+"\n") {
		t.Errorf("the preview does not refuse the session elsewhere:\n%s", text)
	}
	press(m, "enter")
	want := "{{session}} goes to " + away.origin + ", but it came from a response of " + home.origin + " and may go back only there."
	if n := away.conns.Load(); n != 0 || m.mode != confirming || !strings.Contains(m.question, "\n\n"+want+"\n\n") {
		t.Errorf("elsewhere: %d connections, mode %d, question\n%s", n, m.mode, m.question)
	}
	press(m, "esc")
	if n := away.conns.Load(); n != 0 || m.mode != browsing || len(leaks(view(m))) > 0 {
		t.Errorf("esc: %d connections, mode %d; %q in the view", n, m.mode, leaks(view(m)))
	}
}

// TestSecretOriginAsked checks requests that are asked about before they
// are sent, for their method or their @note: the question names the
// secrets that the confirmation lets go where the request goes, before
// the note, and is asked again if the files have changed where it goes
// by the time it is answered.
func TestSecretOriginAsked(t *testing.T) {
	home, away := newTrap(t), newTrap(t)
	dir := originsDir(t, home, away)
	m := newModel(t, dir, "test", 200, 40)
	goTo(t, m, "noted")
	press(m, "enter")
	secret := "{{token}} goes to " + home.origin + ", but it is bound to no origin."
	if m.mode != confirming || !strings.Contains(m.question, "?\n\n"+secret+"\n\nRead this first\n\nenter sends it") ||
		home.conns.Load() != 0 {
		t.Errorf("a note: mode %d, question\n%s", m.mode, m.question)
	}
	press(m, "enter")
	if got := home.requests(); len(got) != 1 || got[0] != "GET /n?t="+privateSecret+" " {
		t.Errorf("enter again: the server had %q", got)
	}

	goTo(t, m, "post")
	press(m, "enter")
	if m.mode != confirming || !strings.Contains(m.question, secret) {
		t.Errorf("a POST: mode %d, question\n%s", m.mode, m.question)
	}
	b, err := json.Marshal(map[string]map[string]string{"test": {"host": away.origin}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "http-client.env.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	press(m, "enter")
	moved := "{{token}} goes to " + away.origin + ", but it is bound to no origin."
	if m.mode != confirming || !strings.Contains(m.question, moved) || !strings.Contains(view(m), "the request has changed") ||
		away.conns.Load() != 0 || len(home.requests()) != 1 {
		t.Errorf("after host changed: mode %d, question\n%s", m.mode, m.question)
	}
	press(m, "enter")
	if got := away.requests(); len(got) != 1 || got[0] != "POST /c?t="+privateSecret+" " || m.result.Error != nil {
		t.Errorf("enter again: the server had %q; error %+v", got, m.result.Error)
	}
}

// TestSecretOriginPolicy checks that both sessions of the interface take
// the operator's policy: an environment variable that it binds to home,
// with a value that the private file binds there, is shown as bound, and
// goes there without a question.
func TestSecretOriginPolicy(t *testing.T) {
	home, away := newTrap(t), newTrap(t)
	t.Setenv("VEGTAM_TEST_KEY", envSecret)
	m := open(t, Options{
		Path: originsDir(t, home, away), Env: "test", Transport: vexec.Transport{Total: 5 * time.Second}, MaxBody: 1 << 20,
		Secrets: policy.Secrets{Env: map[string][]string{"VEGTAM_TEST_KEY": {home.origin}}},
	}, 200, 40)
	goTo(t, m, "bound")
	want := "Secrets:\n  {{$env VEGTAM_TEST_KEY}}  " + home.origin + "\n  {{allowed}}               " + home.origin + "\n"
	if text := m.requestText(); !strings.Contains(text, want) {
		t.Errorf("the preview does not bind them to home:\n%s\nwant:\n%s", text, want)
	}
	press(m, "enter")
	if got := home.requests(); len(got) != 1 || got[0] != "GET /b?k="+envSecret+"&a="+allowedSecret+" " || m.mode != browsing ||
		m.result.Error != nil {
		t.Errorf("enter: the server had %q; mode %d, error %+v", got, m.mode, m.result.Error)
	}
	if found := leaks(view(m)); len(found) > 0 || strings.Contains(view(m), allowedSecret) {
		t.Errorf("%q in the view\n%s", found, view(m))
	}
}
