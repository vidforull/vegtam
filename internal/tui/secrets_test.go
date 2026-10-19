package tui

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// sgr matches the styles Lip Gloss writes: the only escape sequences a
// view may hold.
var sgr = regexp.MustCompile(`\x1b\[[0-9;:]*m`)

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
			m := newModel(t, fx.dir, "", maxBody, sz.w, sz.h)
			views := 0
			snap := func(state string) {
				t.Helper()
				views++
				if found := leaks(view(m)); len(found) > 0 {
					t.Errorf("%dx%d, max body %d, %s: secret forms %q in\n%s", sz.w, sz.h, maxBody, state, found, view(m))
				}
			}
			snap("start")
			press(m, "e")
			snap("environments")
			press(m, "j", "j", "enter")
			for _, name := range []string{"echo", "create", "escapes", "binary", "big", "refused", "slow", "login", "me"} {
				goTo(t, m, name)
				snap(name + " selected")
				switch name {
				case "slow":
					_, cmd := m.Update(keyMsg("enter"))
					snap(name + " in flight")
					press(m, "esc")
					m.Update(cmd())
				case "create", "login":
					press(m, "enter")
					snap(name + " to confirm")
					press(m, "y")
				default:
					press(m, "enter")
				}
				snap(name + " sent")
				press(m, "tab", "tab", "j", "j", "j", "f")
				snap(name + " scrolled")
				press(m, "tab")
			}
			if !strings.Contains(m.responseText(), `"session": "***"`) {
				t.Errorf("the captured session is not masked in:\n%s", m.responseText())
			}
			press(m, "?")
			snap("help")
			press(m, "esc", "e", "k", "enter")
			snap("another environment")
			if views != 34 {
				t.Errorf("%d views", views)
			}
		}
	}
	m := newModel(t, fx.dir, "test", 1<<20, 100, 30)
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
	for _, sz := range []size{{60, 24}, {100, 30}, {150, 40}} {
		m := newModel(t, fx.dir, "test", 1<<20, sz.w, sz.h)
		goTo(t, m, "escapes")
		press(m, "enter")
		for _, keys := range [][]string{nil, {"tab", "tab", "j", "j"}, {"G", "f"}} {
			press(m, keys...)
			v := sgr.ReplaceAllString(view(m), "")
			if !utf8.ValidString(v) {
				t.Errorf("%dx%d: the view is not UTF-8:\n%q", sz.w, sz.h, v)
			}
			if i := strings.IndexFunc(v, func(r rune) bool { return r != '\n' && (r < ' ' || r >= 0x7f && r < 0xa0) }); i >= 0 {
				t.Errorf("%dx%d: %U at %d in the view:\n%q", sz.w, sz.h, []rune(v[i:])[0], i, v)
			}
		}
		text := m.clean(m.responseText())
		for _, want := range []string{`\x1b]0;title\x07 \x9b31m \x1b[31mred\x1b[0m \x7f\x0d\x08 ***`, `X-Escape: \x9b31m \x9b31m`} {
			if !strings.Contains(text, want) {
				t.Errorf("%dx%d: the response does not show %q:\n%s", sz.w, sz.h, want, text)
			}
		}
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
		if tt.env != "" && m.flight == nil {
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
