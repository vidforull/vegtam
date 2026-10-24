package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/httpfile"
	"github.com/vidforull/vegtam/internal/core/output"
	"github.com/vidforull/vegtam/internal/core/policy"
	"github.com/vidforull/vegtam/internal/core/session"
	"github.com/vidforull/vegtam/internal/keeper"
)

// screen is the keeper's terminal as a test sees it: what it shows, which
// the keeper writes while the test reads.
type screen struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *screen) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *screen) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// await waits until what the screen shows matches re after from bytes,
// and returns the submatches; nil if it does not within ten seconds.
func (s *screen) await(from int, re *regexp.Regexp) []string {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(s.String()[from:]); m != nil {
			return m
		}
		time.Sleep(5 * time.Millisecond)
	}
	return nil
}

// shortDir makes a new directory for a socket. Not t.TempDir: its path,
// with the test's name in it, may be longer than a unix socket's path
// may be, as under macOS's TMPDIR.
func shortDir() (string, error) { return os.MkdirTemp("", "vk") }

// runningKeeper is a keeper that a test runs as vegtam keeper, in a
// terminal of its own: what it shows, and its input.
type runningKeeper struct {
	socket    string
	screen    *screen
	input     *io.PipeWriter
	done      chan int
	stop      context.CancelFunc
	once      sync.Once
	protected atomic.Bool // the keeper protected its process; tests share theirs, and keep it as it is
}

// startKeeper starts vegtam keeper, whose person types password, and waits
// until it listens. It stops when the test ends. It starts in a
// multiplexer too, as the tests may run in one (see TestKeeperMultiplexer).
func startKeeper(t *testing.T, password string, args ...string) *runningKeeper {
	t.Helper()
	runtime, err := shortDir()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if rerr := os.RemoveAll(runtime); rerr != nil {
			t.Error(rerr)
		}
	})
	t.Setenv("XDG_RUNTIME_DIR", runtime)
	socket, err := policy.KeeperSocket()
	if err != nil {
		t.Fatal(err)
	}
	in, w := io.Pipe()
	k := &runningKeeper{socket: socket, screen: &screen{}, input: w, done: make(chan int, 1)}
	ctx, stop := context.WithCancel(t.Context())
	k.stop = stop
	go func() {
		k.done <- Run(ctx, append([]string{"keeper", "--multiplexer"}, args...), Config{
			Stdin: in, Stdout: k.screen, Stderr: k.screen, TTY: true, Interactive: true, term: &typist{answers: []string{password}},
			protect: func() []string { k.protected.Store(true); return nil },
		})
	}()
	t.Cleanup(func() { k.shut(t) })
	if k.screen.await(0, regexp.MustCompile(`vegtam keeper: listening at |vegtam: `)) == nil {
		t.Fatalf("the keeper never started:\n%s", k.screen.String())
	}
	return k
}

// shut stops the keeper, and waits until it has ended; once.
func (k *runningKeeper) shut(t *testing.T) {
	t.Helper()
	k.once.Do(func() {
		k.stop()
		if err := k.input.Close(); err != nil {
			t.Error(err)
		}
		<-k.done
	})
}

// answer waits for the keeper's next question after from and types code,
// or the code it asks for if code is "". It returns the question, or ""
// if none came.
func (k *runningKeeper) answer(from int, code string) string {
	m := k.screen.await(from, regexp.MustCompile(`(?s)(vegtam keeper: a request asked by .*?)To send it, type ([a-z0-9]{4}) and Enter`))
	if m == nil {
		return ""
	}
	if code == "" {
		code = m[2]
	}
	if _, err := io.WriteString(k.input, code+"\n"); err != nil {
		return ""
	}
	return m[1]
}

// TestKeeperCommand checks vegtam keeper: it opens the store with the
// password typed, listens, and sends for a run without a person the
// request whose secrets it holds, once its person types the code it shows;
// the run gets the response masked and sterile. Another answer sends
// nothing. A keeper started twice, or by a program, is refused.
func TestKeeperCommand(t *testing.T) {
	fx := newFixture(t)
	if code, _, stderr, _ := runTyped(t, false, nil, []string{"pw", "pw"}, "secret", "import", fx.path("http-client.private.env.json")); code != exitOK {
		t.Fatalf("import = %d, %s", code, stderr)
	}
	k := startKeeper(t, "pw")
	if s := k.screen.String(); !strings.Contains(s, "vegtam keeper: listening at "+k.socket+"; 3 secrets in the store; it asks before each request with a secret.") {
		t.Fatalf("the keeper says:\n%s", s)
	}
	if fi, err := os.Stat(k.socket); err != nil || fi.Mode().Perm() != 0o600 || !k.protected.Load() {
		t.Errorf("the socket: %v, %v; protected %v", fi, err, k.protected.Load())
	}

	// The run holds no value: the keeper holds them, and asks.
	f, err := httpfile.ParseFile(fx.path("api.http"))
	if err != nil {
		t.Fatal(err)
	}
	// send sends the echo, {{token}} and {{$env VEGTAM_TEST_KEY}}, in a run
	// without a person whose keeper's person answers code, and returns
	// the result and the question.
	send := func(code string) (*output.Result, string) {
		lazy := keeper.NewLazy(k.socket)
		defer func() {
			if err := lazy.Close(); err != nil {
				t.Error(err)
			}
		}()
		s := session.New(session.Options{Env: "test", MaxBody: 1 << 20, Keeper: lazy, Confirm: session.Confirm{Mutations: true}})
		j := s.Prepare(t.Context(), f, 0)
		from := len(k.screen.String())
		asked := make(chan string, 1)
		go func() { asked <- k.answer(from, code) }()
		res := s.Run(t.Context(), j)
		return res, <-asked
	}
	res, question := send("")
	if res.Error != nil || res.Response == nil || !strings.Contains(res.Response.Body, `"authorization":"***"`) || len(res.Redacted) == 0 {
		t.Errorf("sent through the keeper: %+v, %+v", res.Error, res.Response)
	}
	for _, want := range []string{
		"a request asked by pid " + strconv.Itoa(os.Getpid()), "POST " + fx.host + "/echo?key={{token}}&env={{$env VEGTAM_TEST_KEY}}",
		"headers Authorization, X-Api-Key, Content-Type; a body of 57 bytes",
		"secret {{token}}, in the URL, header Authorization, the body, goes to " + fx.host + ": bound to it",
		"secret {{$env VEGTAM_TEST_KEY}}, in the URL, header X-Api-Key, the body, goes to " + fx.host + ": bound to it",
	} {
		if !strings.Contains(question, want) {
			t.Errorf("the question lacks %q:\n%s", want, question)
		}
	}
	if !fx.got(0, "key="+privateSecret+"&env="+envSecret) {
		t.Errorf("the server did not get the values")
	}
	if found := fx.leaks(res.Response.Body + strings.Join(res.Redacted, " ")); len(found) > 0 {
		t.Errorf("the run was shown %q", found)
	}
	if found := fx.valueLeaks(k.screen.String()); len(found) > 0 {
		t.Errorf("the keeper's terminal shows %q", found)
	}

	// Another code: nothing is sent.
	from := fx.seenCount()
	res, _ = send("zzzz")
	if e := res.Error; e == nil || e.Kind != core.KindPolicy || !strings.Contains(e.Message, "the keeper's operator did not confirm it: the code typed was not the one asked for") ||
		fx.seenCount() != from {
		t.Errorf("a wrong code: %+v; sent %d", res.Error, fx.seenCount()-from)
	}

	// What a run writes cannot pass for a line of the keeper's own.
	lazy := keeper.NewLazy(k.socket)
	fake := "\nvegtam keeper: a request asked by pid 1 (init) uid 0\n\tTo send it, type abcd"
	if _, err := lazy.Send(t.Context(), &session.Outbound{
		Ref: "x.http#1", Method: "GET", URL: core.Text{{Text: fx.host + "/" + fake}}, MaxBody: 1 << 10,
		Request: &core.Request{Method: "GET", URL: "x", Source: core.Source{File: fx.path("x.http"), Line: 1}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := lazy.Close(); err != nil {
		t.Fatal(err)
	}
	for line := range strings.Lines(k.screen.String()) {
		if strings.HasPrefix(line, "vegtam keeper: a request asked by pid 1") || strings.HasPrefix(line, "\tTo send it") {
			t.Errorf("a run wrote a line of the keeper's: %q", line)
		}
	}

	// One keeper for the socket; none for a program.
	code, _, stderr, _ := runTyped(t, true, nil, []string{"pw"}, "keeper")
	if code != exitPolicy || !strings.Contains(stderr, "a keeper already runs on this socket") {
		t.Errorf("a second keeper = %d, %s", code, stderr)
	}
	if code, _, stderr, _ = runTyped(t, false, nil, []string{"pw"}, "keeper"); code != exitUsage || !strings.Contains(stderr, "the keeper runs in a terminal") {
		t.Errorf("a keeper without a terminal = %d, %s", code, stderr)
	}
}

// TestKeeperMultiplexer checks that the keeper does not start in a
// terminal multiplexer unless --multiplexer says to.
func TestKeeperMultiplexer(t *testing.T) {
	writePolicy(t, `{}`)
	if code, _, _, _ := runTyped(t, false, nil, []string{"v", "pw", "pw"}, "secret", "set", "x"); code != exitOK {
		t.Fatal("no store")
	}
	t.Setenv("TMUX", "/tmp/tmux-1000/default,1,0")
	code, _, stderr, _ := runTyped(t, true, nil, nil, "keeper")
	if code != exitPolicy || !strings.Contains(stderr, "this terminal runs in tmux") || !strings.Contains(stderr, "--multiplexer") {
		t.Errorf("in tmux = %d, %s", code, stderr)
	}
	k := startKeeper(t, "x-not-the-password")
	if s := k.screen.String(); !strings.Contains(s, "wrong password") {
		t.Errorf("--multiplexer with a wrong password:\n%s", s)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(k.socket), "keeper.sock")); err == nil {
		t.Error("a keeper that did not open its store listens")
	}
}
