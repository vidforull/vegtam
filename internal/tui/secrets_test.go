package tui

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/env"
	"github.com/vidforull/vegtam/internal/core/history"
)

// sgr matches the styles Lip Gloss writes: the only escape sequences a
// view may hold.
var sgr = regexp.MustCompile(`\x1b\[[0-9;:]*m`)

// secretStyle starts the colour of a secret's placeholder: the views hold
// the text as styled, which the test checks as such.
var secretStyle = strings.TrimSuffix(placeholderStyles[env.Secret].Render("x"), "x\x1b[m")

// leaks returns the forms of the test secrets that s contains: the value,
// its escaped forms, and its first four characters, which is what a value
// cut off by a pane or by --max-body would leave.
func leaks(s string) []string {
	s += "\n" + sgr.ReplaceAllString(s, "")
	var found []string
	for _, secret := range []string{privateSecret, envSecret, sessionSecret} {
		j, _ := json.Marshal(secret)
		for _, f := range []string{
			secret, url.QueryEscape(secret), url.PathEscape(secret), string(j[1 : len(j)-1]),
			strings.ReplaceAll(secret, "/", `\/`), strings.ReplaceAll(secret, "+", `\u002B`),
			strings.ReplaceAll(secret, "+", " "), secret[:4],
		} {
			if strings.Contains(s, f) {
				found = append(found, f)
			}
		}
	}
	return found
}

// TestNoSecretInTUI goes through every screen and state of the interface,
// in each layout and with a body limit that cuts responses, and checks
// that no view holds a secret in any form. The secrets come back from
// the server in bodies, headers and errors.
func TestNoSecretInTUI(t *testing.T) {
	fx := newFixture(t)
	for _, sz := range []size{{60, 24}, {100, 30}, {150, 40}} {
		for _, maxBody := range []int64{1 << 20, 106} {
			m := open(t, Options{
				Path: fx.dir, Timeout: 5 * time.Second, MaxBody: maxBody, UserAgent: "vegtam/test",
				History: history.New(filepath.Join(t.TempDir(), "vegtam")),
			}, sz.w, sz.h)
			views, styled := 0, 0
			snap := func(state string) {
				t.Helper()
				views++
				if strings.Contains(view(m), secretStyle) {
					styled++
				}
				if found := leaks(view(m)); len(found) > 0 {
					t.Errorf("%dx%d, max body %d, %s: secret forms %q in\n%s", sz.w, sz.h, maxBody, state, found, view(m))
				}
			}
			snap("start")
			press(m, "e")
			snap("environments")
			press(m, "j", "j", "enter")
			for _, name := range []string{"echo", "create", "escapes", "binary", "big", "refused", "slow", "everywhere", "login", "me"} {
				goTo(t, m, name)
				snap(name + " selected")
				switch name {
				case "slow":
					_, cmd := m.Update(keyMsg("enter"))
					snap(name + " in flight")
					press(m, "esc")
					m.Update(cmd())
				case "create", "login", "everywhere":
					press(m, "enter")
					snap(name + " to confirm")
					press(m, "enter")
				default:
					press(m, "enter")
				}
				snap(name + " sent")
				press(m, "tab", "tab", "j", "j", "j", "f")
				snap(name + " scrolled")
				press(m, "tab")
				if cmd, ok := yank(m); !ok || len(leaks(cmd)) > 0 {
					t.Errorf("%s copied as curl: %v, secret forms %q in\n%s", name, ok, leaks(cmd), cmd)
				}
				snap(name + " as curl")
				press(m, "esc")
				press(m, "z")
				snap(name + " folded from depth 1")
				press(m, "z")
				snap(name + " folded from depth 2")
				press(m, "z")
			}
			if !strings.Contains(m.responseText(), `"session": "***"`) {
				t.Errorf("the captured session is not masked in:\n%s", m.responseText())
			}
			press(m, "h")
			for range m.runs {
				snap("run in the history")
				press(m, "j")
			}
			press(m, "/", "e", "c")
			snap("history searched")
			press(m, "esc", "esc")
			press(m, "?")
			snap("help")
			press(m, "esc", "/", "e", "c")
			snap("searching")
			press(m, "enter")
			snap("searched")
			press(m, "/", "esc", "e", "k", "enter")
			snap("another environment")
			if views != 81 || styled < 10 {
				t.Errorf("%d views, %d with a secret's placeholder coloured", views, styled)
			}
		}
	}
	m := newModel(t, fx.dir, "test", 100, 30)
	press(m, "enter")
	if text := m.responseText(); !strings.Contains(text, `"key": "***"`) || !strings.Contains(text, "X-Echo: key=***&env=***") {
		t.Errorf("the echo of the secrets is not masked, so the test proves nothing:\n%s", text)
	}
}

// TestTUIEscapes sends a request whose response has escape sequences in
// its body and a header, from a file whose name has one too: no view may
// hold any but the styles of Lip Gloss, nor a control character.
func TestTUIEscapes(t *testing.T) {
	fx := newFixture(t)
	src, err := os.ReadFile(filepath.Join(fx.dir, "api.http"))
	if err != nil {
		t.Fatal(err)
	}
	name := "evil\x1b]0;name\x07\x9b.http"
	if err = os.WriteFile(filepath.Join(fx.dir, name), src, 0o600); err != nil {
		t.Fatal(err)
	}
	ctl := "# @name ctl\nPOST {{host}}/echo\n\na \x1b]0;t\x07 \u009b\t\n\n###\n# @name file\nPOST {{host}}/echo\n\n< ./b\x1b[31m.json\n"
	for file, data := range map[string]string{"ctl.http": ctl, "b\x1b[31m.json": "{}"} {
		if err = os.WriteFile(filepath.Join(fx.dir, file), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, sz := range []size{{60, 24}, {100, 30}, {150, 40}} {
		m := newModel(t, fx.dir, "test", sz.w, sz.h)
		goTo(t, m, "escapes")
		press(m, "enter")
		for _, keys := range [][]string{nil, {"tab", "tab", "j", "j"}, {"G", "f"}, {"z"}, {"z"}} {
			press(m, keys...)
			v := sgr.ReplaceAllString(view(m), "")
			if !utf8.ValidString(v) {
				t.Errorf("%dx%d: the view is not UTF-8:\n%q", sz.w, sz.h, v)
			}
			if i := strings.IndexFunc(v, func(r rune) bool { return r != '\n' && (r < ' ' || r >= 0x7f && r < 0xa0 || core.Invisible(r)) }); i >= 0 {
				t.Errorf("%dx%d: %U at %d in the view:\n%q", sz.w, sz.h, []rune(v[i:])[0], i, v)
			}
		}
		text := m.clean(m.responseText())
		for _, want := range []string{
			`\u202eevil\u200b\U000e0041 `, `\x1b]0;title\x07 \x9b31m \x1b[31mred\x1b[0m \x7f\x0d\x08 ***`, `X-Escape: \x9b31m \x9b31m`,
		} {
			if !strings.Contains(text, want) {
				t.Errorf("%dx%d: the response does not show %q:\n%s", sz.w, sz.h, want, text)
			}
		}
		// A request with control characters, copied as curl: they are
		// escaped in the command, which the view shows as it is.
		goTo(t, m, "ctl")
		cmd, ok := yank(m)
		if !ok || strings.ContainsFunc(cmd, func(r rune) bool { return r != '\n' && unicode.IsControl(r) }) ||
			!strings.Contains(cmd, `--data-raw $'a \x1b]0;t\x07 \xc2\x9b\t'`) || !strings.Contains(view(m), `\x1b]0;t`) {
			t.Errorf("%dx%d: ctl copied as %q\n%s", sz.w, sz.h, cmd, view(m))
		}
		goTo(t, m, "file")
		if cmd, ok = yank(m); !ok || !strings.Contains(cmd, `--data-binary $'@`+fx.dir+`/b\x1b[31m.json'`) {
			t.Errorf("%dx%d: file copied as %q", sz.w, sz.h, cmd)
		}
		press(m, "esc")
		if v := sgr.ReplaceAllString(view(m), ""); strings.ContainsFunc(v, func(r rune) bool { return r != '\n' && unicode.IsControl(r) }) {
			t.Errorf("%dx%d: a control character in the view:\n%q", sz.w, sz.h, v)
		}

		// The search shows what is typed or pasted, escaped too.
		press(m, "/")
		m.Update(tea.PasteMsg{Content: "\x1b]0;title\x07\x9b2J"})
		if v := sgr.ReplaceAllString(view(m), ""); strings.ContainsFunc(v, func(r rune) bool { return r < ' ' && r != '\n' || r >= 0x7f && r < 0xa0 }) ||
			!strings.Contains(v, `/\x1b]0;title\x07\x9b2J_`) {
			t.Errorf("%dx%d: the search is not shown escaped:\n%q", sz.w, sz.h, v)
		}
		press(m, "esc")
		if !strings.Contains(m.clean(m.rows[len(m.rows)-1].path), `evil\x1b]0;name\x07\x9b.http`) {
			t.Errorf("the file name is not shown escaped: %q", m.clean(m.rows[len(m.rows)-1].path))
		}
	}
}

// TestRun runs the interface as vegtam does, on a pipe for the terminal:
// it quits on q, with a request in flight too, and a panic comes out of
// Run as a *Panic once the program has ended and given the terminal back.
func TestRun(t *testing.T) {
	fx := newFixture(t)
	for _, tt := range []struct {
		name, env, keys string
		panics          bool
	}{
		{"quit", "", "jjq", false},
		{"quit in flight", "test", "jjjjjj\rq", false},
		{"panic", "", "j", true},
	} {
		in, keys := io.Pipe()
		var out bytes.Buffer
		m, err := New(Options{Path: fx.dir, Env: tt.env, Timeout: time.Minute, MaxBody: 1 << 20, Input: in, Output: &out})
		if err != nil {
			t.Fatal(err)
		}
		if tt.panics {
			m.rows[2].file.Requests[1] = nil // selecting it panics
		}
		typed := make(chan error, 1)
		go func() {
			_, werr := keys.Write([]byte(tt.keys))
			typed <- werr
		}()
		var p *Panic
		func() {
			defer func() {
				if v := recover(); v != nil {
					var ok bool
					if p, ok = v.(*Panic); !ok {
						t.Errorf("%s: Run panicked with %T", tt.name, v)
					}
				}
			}()
			err = m.Run(t.Context())
		}()
		if cerr := in.Close(); cerr != nil {
			t.Fatal(cerr)
		}
		if werr := <-typed; werr != nil {
			t.Errorf("%s: typing: %v", tt.name, werr)
		}
		if err != nil || (p != nil) != tt.panics {
			t.Errorf("%s: Run = %v, panic %v", tt.name, err, p)
		}
		if strings.Contains(tt.keys, "\r") && m.flight == nil {
			t.Errorf("%s: no request was in flight", tt.name)
		}
		if p != nil && !strings.Contains(string(p.Stack), "tui.(*Model).refresh") {
			t.Errorf("the panic's stack is not where it happened:\n%s", p.Stack)
		}
		// The alternate screen is left at the end, panic or not.
		if s := out.String(); strings.LastIndex(s, "\x1b[?1049l") < strings.LastIndex(s, "\x1b[?1049h") || !strings.Contains(s, "\x1b[?1049h") {
			t.Errorf("%s: the terminal is not restored: %q", tt.name, s)
		}
	}
}

// syncBuffer is a bytes.Buffer that the program writes to while the test
// reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestRunCopy runs the program, copies the first request with y and
// quits once the terminal has had the command: OSC 52 carries it,
// base64-encoded, and nothing else. Bubble Tea runs the command that
// copies on a goroutine of its own, so a q typed at once could end the
// program first.
func TestRunCopy(t *testing.T) {
	fx := newFixture(t)
	in, keys := io.Pipe()
	out := &syncBuffer{}
	m, err := New(Options{Path: fx.dir, Env: "test", Timeout: time.Minute, MaxBody: 1 << 20, Input: in, Output: out})
	if err != nil {
		t.Fatal(err)
	}
	typed := make(chan error, 1)
	go func() {
		_, werr := keys.Write([]byte("y"))
		for deadline := time.Now().Add(10 * time.Second); werr == nil && !strings.Contains(out.String(), "\x1b]52;"); {
			if time.Now().After(deadline) {
				werr = errors.New("no OSC 52 within 10s")
			}
			time.Sleep(10 * time.Millisecond)
		}
		if _, qerr := keys.Write([]byte("q")); werr == nil {
			werr = qerr
		}
		typed <- werr
	}()
	err = m.Run(t.Context())
	if cerr := in.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	if werr := <-typed; err != nil || werr != nil {
		t.Fatalf("Run = %v; typing: %v", err, werr)
	}
	osc := "\x1b]52;c;" + base64.StdEncoding.EncodeToString([]byte(m.curl)) + "\x07"
	if m.curl == "" || strings.Count(out.String(), "\x1b]52;") != 1 || !strings.Contains(out.String(), osc) {
		t.Errorf("no OSC 52 with the command %q in %q", m.curl, out.String())
	}
	if found := leaks(m.curl); len(found) > 0 {
		t.Errorf("the command holds %q", found)
	}
}
