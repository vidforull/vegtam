package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core/output"
)

// The values the flow server hands out at sign-in.
const (
	loginToken = "L0gin/t0k+en"
	sessionID  = "s3ss/10n+id"
)

// newFlowFixture copies testdata/flow, writes its environment file and
// returns the directory and the server address. The server signs in with
// POST /login and answers GET /users/7 only with the token and session it
// gave; GET /users/1 needs neither.
func newFlowFixture(t *testing.T) (dir, host string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Session", sessionID)
		fmt.Fprintf(w, `{"ok": true, "token": %q, "user": {"id": 7}}`, loginToken)
	})
	mux.HandleFunc("GET /users/7", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+loginToken || r.Header.Get("X-Session") != sessionID {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id": 7, "token": %q}`, loginToken)
	})
	mux.HandleFunc("GET /users/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id": 1}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	dir = t.TempDir()
	if err := os.CopyFS(dir, os.DirFS("../../testdata/flow")); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]map[string]string{"test": {"host": srv.URL, "closed": closed.URL, "user": "1"}})
	if err := os.WriteFile(filepath.Join(dir, "http-client.env.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, srv.URL
}

// flowLeaks returns the forms of the captured secrets that s contains.
func flowLeaks(s string) []string {
	var found []string
	for _, secret := range []string{loginToken, sessionID} {
		for _, f := range []string{secret, url.QueryEscape(secret), strings.ReplaceAll(secret, "/", `\/`), secret[:4]} {
			if strings.Contains(s, f) {
				found = append(found, f)
			}
		}
	}
	return found
}

func TestRunCaptures(t *testing.T) {
	dir, host := newFlowFixture(t)
	t.Chdir(dir)
	fx := &fixture{dir: dir, host: host}

	// The secrets captured at sign-in are masked in the very response they
	// come from, and the next request sends them.
	code, stdout, stderr := runCLI(t, true, "run", "login.http", "-e", "test")
	want := `### login.http#before
HTTP/1.1 200 OK (TIME)

{
  "id": 1
}

✓ jsonpath $.id == 1

### login.http#login
HTTP/1.1 200 OK (TIME)

{
  "ok": true,
  "token": "***",
  "user": {
    "id": 7
  }
}

✓ status == 200
captured: token, session, user (plain)

### login.http#me
HTTP/1.1 200 OK (TIME)

{
  "id": 7,
  "token": "***"
}

✓ status == 200
✓ jsonpath $.id == 7
`
	if got := normalize(fx, stdout); code != exitOK || got != want || stderr != "" {
		t.Errorf("run = %d\n%s\nwant\n%s\nstderr: %s", code, got, want, stderr)
	}

	// The captures are listed without their values; a plain one shows in
	// the request, a secret one as its placeholder.
	for _, m := range []struct {
		tty, json bool
		args      []string
	}{{true, false, []string{"-v"}}, {false, true, nil}, {true, true, []string{"--json", "-v"}}} {
		code, stdout, stderr := runCLI(t, m.tty, append([]string{"run", "login.http", "-e", "test"}, m.args...)...)
		if found := flowLeaks(stdout + stderr); len(found) > 0 || code != exitOK {
			t.Errorf("run %q = %d, secret forms %q in the output\n%s\n%s", m.args, code, found, stdout, stderr)
		}
		if !m.json {
			if !strings.Contains(normalize(fx, stdout), "GET HOST/users/7\nAuthorization: Bearer {{token}}\nX-Session: {{session}}\n") {
				t.Errorf("verbose request after the captures:\n%s", stdout)
			}
			continue
		}
		validateJSON(t, stdout)
		var doc output.Document
		json.Unmarshal([]byte(stdout), &doc)
		wantCaptures := []output.Capture{{Name: "token", Source: "$.token", Secret: true},
			{Name: "session", Source: "header X-Session", Secret: true}, {Name: "user", Source: "$.user.id"}}
		if len(doc.Results) != 3 || !slices.Equal(doc.Results[1].Captures, wantCaptures) || doc.Results[2].Captures != nil {
			t.Fatalf("captures:\n%s", stdout)
		}
		if before := doc.Results[0].Request; before.URL != host+"/users/1" {
			t.Errorf("request before the captures: %+v", before)
		}
		me := doc.Results[2].Request
		if me.URL != host+"/users/7" || me.Headers[0].Value != "Bearer {{token}}" || me.Headers[1].Value != "{{session}}" {
			t.Errorf("request after the captures: %+v", me)
		}
	}

	// The whole directory: failures.http first. A capture that finds
	// nothing is an error, and so is the request that needs its value;
	// login.http still runs, and refused.http after it fails on the
	// network, the token hidden.
	type outcome struct{ ref, kind, msg string }
	runDir := func() (int, []outcome, *output.Document) {
		t.Helper()
		code, stdout, stderr := runCLI(t, false, "run", ".", "-e", "test")
		validateJSON(t, stdout)
		if found := flowLeaks(stdout + stderr); len(found) > 0 {
			t.Errorf("run .: secret forms %q in the output\n%s\n%s", found, stdout, stderr)
		}
		var doc output.Document
		json.Unmarshal([]byte(stdout), &doc)
		var got []outcome
		for _, r := range doc.Results {
			o := outcome{ref: r.Ref}
			if r.Error != nil {
				o.kind, o.msg = string(r.Error.Kind), normalize(fx, r.Error.Message)
			}
			got = append(got, o)
		}
		return code, got, &doc
	}
	code, got, doc := runDir()
	wantOutcomes := []outcome{
		{"failures.http#wrong", "assert", "2 of 3 assertions failed: status == 201; jsonpath $.ok == false"},
		{"failures.http#nothing", "capture", "capture failed: session = $.session: the body has no such value"},
		{"failures.http#after", "variable", "not captured: session (failures.http#nothing took no value)"},
		{"login.http#before", "", ""},
		{"login.http#login", "", ""},
		{"login.http#me", "", ""},
		{"refused.http#refused", "network", ""},
	}
	if len(got) == len(wantOutcomes) {
		got[6].msg = "" // the wording of the network stack
	}
	if code != exitNetwork || !slices.Equal(got, wantOutcomes) || doc.Results[0].Response == nil || doc.Results[1].Response == nil ||
		!slices.Equal(doc.Results[2].Error.Variables, []string{"session"}) {
		t.Errorf("run . = %d, %q\nwant %q", code, got, wantOutcomes)
	}
	if msg := doc.Results[6].Error.Message; !strings.Contains(msg, "/?t={{token}}") {
		t.Errorf("network error: %s", msg)
	}

	// A file that does not parse still declares its captures: the
	// requests after it do not fall back on the environment's user.
	if err := os.WriteFile("0-broken.http", []byte("# @capture user = $.user.id\nGET\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, got, _ = runDir()
	if len(got) < 5 || got[0].kind != "parse" || got[4] != (outcome{"login.http#before", "variable", "not captured: user (0-broken.http took no value)"}) ||
		got[6] != (outcome{"login.http#me", "", ""}) {
		t.Errorf("run . with a broken file: %q", got)
	}
	os.Remove("0-broken.http")

	// A dry run sends nothing and captures nothing: captured variables stay
	// placeholders, and nothing that depends on them is an error.
	code, stdout, _ = runCLI(t, false, "run", ".", "-e", "test", "--dry-run")
	validateJSON(t, stdout)
	*doc = output.Document{}
	json.Unmarshal([]byte(stdout), doc)
	if code != exitOK || len(doc.Results) != 7 || doc.Results[2].Request.URL != host+"/users/{{session}}" ||
		doc.Results[3].Request.URL != host+"/users/1" || doc.Results[5].Request.URL != host+"/users/{{user}}" ||
		strings.Contains(stdout, `"captures"`) {
		t.Errorf("dry run = %d\n%s", code, stdout)
	}

	// One request alone has no earlier requests: user comes from the
	// environment, and token and session have no value.
	code, _, stderr = runCLI(t, false, "run", "login.http#me", "-e", "test")
	if code != exitUsage || !strings.Contains(stderr, "unresolved variables: token, session") {
		t.Errorf("run login.http#me = %d, %s", code, stderr)
	}
}
