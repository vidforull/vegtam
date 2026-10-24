//go:build linux || darwin

package keeper

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/output"
	"github.com/vidforull/vegtam/internal/core/session"
)

// shortDir makes a new directory for a socket. Not t.TempDir: its path,
// with the test's name in it, may be longer than a unix socket's path
// may be, as under macOS's TMPDIR.
func shortDir() (string, error) { return os.MkdirTemp("", "vk") }

// socketPath returns the path of a socket in a new directory, which is
// removed once the test ends.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := shortDir()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "keeper.sock")
}

// serve listens at path and serves it with newConn until the test ends.
func serve(t *testing.T, path string, newConn func(Peer) Conn) {
	t.Helper()
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- l.Serve(ctx, newConn) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
		if err := l.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
}

// fake is a Conn that gives back, for each request, a result with the
// request's ref, or the error err; with wait set, it waits for ctx to end
// and gives back the cause.
type fake struct {
	err  error
	wait bool

	mu     sync.Mutex
	peer   Peer
	sent   []*session.Outbound
	closed bool
	asked  chan struct{} // closed once Send is called, if wait is set
}

func (f *fake) Send(ctx context.Context, o *session.Outbound) (*session.Inbound, error) {
	f.mu.Lock()
	f.sent = append(f.sent, o)
	f.mu.Unlock()
	if f.wait {
		close(f.asked)
		<-ctx.Done()
		return nil, context.Cause(ctx)
	}
	if f.err != nil {
		return nil, f.err
	}
	return &session.Inbound{Result: &output.Result{Ref: o.Ref}}, nil
}

func (f *fake) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
}

// state returns what f was sent, and whether it is closed.
func (f *fake) state() ([]*session.Outbound, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sent, f.closed
}

// one returns a newConn that gives f to the first run, and nil, which
// refuses it, to any other.
func one(f *fake) func(Peer) Conn {
	var once sync.Once
	return func(p Peer) Conn {
		var c Conn
		once.Do(func() {
			f.mu.Lock()
			f.peer = p
			f.mu.Unlock()
			c = f
		})
		return c
	}
}

// dial dials the keeper at path; the client is closed once the test ends.
func dial(t *testing.T, path string) *Client {
	t.Helper()
	c, err := Dial(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	return c
}

// wantError fails the test unless err is a *core.Error of kind k whose
// message holds want.
func wantError(t *testing.T, err error, k core.Kind, want string) {
	t.Helper()
	e, ok := errors.AsType[*core.Error](err)
	switch {
	case !ok:
		t.Fatalf("error %v (%T), want a *core.Error of kind %s", err, err, k)
	case e.Kind != k || !strings.Contains(e.Msg, want):
		t.Fatalf("error %s: %q, want kind %s with %q", e.Kind, e.Msg, k, want)
	}
}

func TestSend(t *testing.T) {
	path := socketPath(t)
	f := &fake{}
	serve(t, path, one(f))
	c := dial(t, path)
	for _, ref := range []string{"a.http#1", "a.http#2"} {
		in, err := c.Send(t.Context(), &session.Outbound{Ref: ref, Method: "GET", URL: core.Text{{Text: "https://api.example/"}}})
		if err != nil {
			t.Fatal(err)
		}
		if in.Result.Ref != ref {
			t.Errorf("ref %q, want %q", in.Result.Ref, ref)
		}
	}
	sent, _ := f.state()
	if len(sent) != 2 || sent[1].URL.Masked() != "https://api.example/" {
		t.Errorf("the keeper was sent %+v", sent)
	}
	f.mu.Lock()
	p := f.peer
	f.mu.Unlock()
	if p.UID != os.Geteuid() || p.PID != os.Getpid() {
		t.Errorf("peer %s, want uid %d and pid %d", p, os.Geteuid(), os.Getpid())
	}
}

func TestSendErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		kind core.Kind
		msg  string
	}{
		{"kind as is", core.Errorf(core.KindNetwork, core.Source{}, "dial tcp: refused"), core.KindNetwork, "dial tcp: refused"},
		{"other as policy", errors.New("the person said no"), core.KindPolicy, "the person said no"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := socketPath(t)
			serve(t, path, one(&fake{err: tc.err}))
			c := dial(t, path)
			for range 2 { // the connection stays
				_, err := c.Send(t.Context(), &session.Outbound{Ref: "a.http#1"})
				wantError(t, err, tc.kind, tc.msg)
			}
		})
	}
}

func TestNoKeeper(t *testing.T) {
	path := socketPath(t)
	_, err := Dial(t.Context(), path)
	wantError(t, err, core.KindPolicy, "no keeper is running at "+path+": start vegtam keeper in your terminal")

	// A socket that no keeper listens on any more.
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	discard(l)
	_, err = Dial(t.Context(), path)
	wantError(t, err, core.KindPolicy, "no keeper is running at "+path)
}

// fakeKeeper listens at a new socket and runs script with the first
// connection to it; it returns the socket's path.
func fakeKeeper(t *testing.T, script func(c *net.UnixConn, r *bufio.Reader)) string {
	t.Helper()
	path := socketPath(t)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		c, err := ln.AcceptUnix()
		if err != nil {
			return
		}
		defer discard(c)
		script(c, bufio.NewReader(c))
	})
	t.Cleanup(func() {
		discard(ln)
		wg.Wait()
	})
	return path
}

// drain reads r until the run closes the connection.
func drain(r *bufio.Reader) {
	for {
		if _, err := r.ReadString('\n'); err != nil {
			return
		}
	}
}

func TestDialFails(t *testing.T) {
	for _, tc := range []struct {
		name   string
		keeper string // its first line, or none
		want   string
	}{
		{"another version", `{"keeper":2,"pid":1}` + "\n", "the keeper speaks version 2; this vegtam speaks 1"},
		{"no version", `{"pid":1}` + "\n", "names no version"},
		{"no pid", `{"keeper":1}` + "\n", "did not say its pid"},
		{"garbage", "SSH-2.0-OpenSSH_9.6\n", "a line that is not the protocol's"},
		{"refused", `{"error":{"kind":"policy","message":"the keeper refuses pid 1"}}` + "\n", "the keeper refuses pid 1"},
		{"closed", "", "the keeper closed the connection"},
		{"truncated", `{"keeper":1,`, "the keeper closed the connection"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := fakeKeeper(t, func(c *net.UnixConn, r *bufio.Reader) {
				fmt.Fprint(c, tc.keeper)
				if tc.keeper != "" && strings.HasSuffix(tc.keeper, "\n") {
					drain(r)
				}
			})
			_, err := Dial(t.Context(), path)
			wantError(t, err, core.KindPolicy, tc.want)
		})
	}
}

// handshake plays the keeper's first lines on c: its own, then the
// run's, read from r.
func handshake(c *net.UnixConn, r *bufio.Reader) bool {
	fmt.Fprintf(c, `{"keeper":1,"pid":%d}`+"\n", os.Getpid())
	_, err := r.ReadString('\n')
	return err == nil
}

func TestSendFails(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply string // to the first request; "" closes the connection
		want  string
	}{
		{"closed", "", "the keeper closed the connection"},
		{"another id", `{"id":7,"inbound":{"result":{}}}` + "\n", "the keeper answered request 7, not 1"},
		{"no result", `{"id":1,"inbound":{}}` + "\n", "gives back no result"},
		{"both", `{"id":1,"inbound":{"result":{}},"error":{"kind":"policy","message":"no"}}` + "\n", "both a result and an error"},
		{"last line", `{"error":{"kind":"policy","message":"request 1 came with more after it"}}` + "\n", "request 1 came with more after it"},
		{"garbage", "{\n", "a line that is not the protocol's"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := fakeKeeper(t, func(c *net.UnixConn, r *bufio.Reader) {
				if !handshake(c, r) {
					return
				}
				if _, err := r.ReadString('\n'); err != nil {
					return
				}
				fmt.Fprint(c, tc.reply)
				if tc.reply != "" {
					drain(r)
				}
			})
			c := dial(t, path)
			_, err := c.Send(t.Context(), &session.Outbound{Ref: "a.http#1"})
			wantError(t, err, core.KindPolicy, tc.want)
			// The connection is lost: the next request gets the same.
			_, err2 := c.Send(t.Context(), &session.Outbound{Ref: "a.http#2"})
			if err2 == nil || err2.Error() != err.Error() {
				t.Errorf("the next request: %v, want %v", err2, err)
			}
		})
	}
}

func TestSendKeepsGoing(t *testing.T) {
	// Fields that a later version adds are ignored.
	path := fakeKeeper(t, func(c *net.UnixConn, r *bufio.Reader) {
		fmt.Fprintf(c, `{"keeper":1,"pid":%d,"features":["x"]}`+"\n", os.Getpid())
		if _, err := r.ReadString('\n'); err != nil {
			return
		}
		for id := 1; ; id++ {
			if _, err := r.ReadString('\n'); err != nil {
				return
			}
			fmt.Fprintf(c, `{"id":%d,"inbound":{"result":{"ref":"r%d","later":true}},"later":1}`+"\n", id, id)
		}
	})
	c := dial(t, path)
	for i := 1; i <= 3; i++ {
		in, err := c.Send(t.Context(), &session.Outbound{})
		if err != nil {
			t.Fatal(err)
		}
		if want := "r" + strconv.Itoa(i); in.Result.Ref != want {
			t.Errorf("ref %q, want %q", in.Result.Ref, want)
		}
	}
}

func TestSendInterrupted(t *testing.T) {
	path := socketPath(t)
	f := &fake{wait: true, asked: make(chan struct{})}
	serve(t, path, one(f))
	c := dial(t, path)
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	wg.Go(func() {
		select {
		case <-f.asked:
		case <-ctx.Done():
		}
		cancel()
	})
	_, err := c.Send(ctx, &session.Outbound{Ref: "a.http#1"})
	wg.Wait()
	wantError(t, err, core.KindCanceled, "interrupted")
	_, err = c.Send(t.Context(), &session.Outbound{Ref: "a.http#2"})
	wantError(t, err, core.KindCanceled, "interrupted")
	// The keeper's side sees the run go: its request is withdrawn, and
	// the Conn closed.
	waitFor(t, func() bool {
		_, closed := f.state()
		return closed
	})
}

func TestRunGoesAway(t *testing.T) {
	path := socketPath(t)
	f := &fake{wait: true, asked: make(chan struct{})}
	serve(t, path, one(f))
	c := dial(t, path)
	errc := make(chan error, 1)
	go func() {
		_, err := c.Send(t.Context(), &session.Outbound{Ref: "a.http#1"})
		errc <- err
	}()
	<-f.asked
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	wantError(t, <-errc, core.KindPolicy, "the connection to the keeper is closed")
	waitFor(t, func() bool {
		_, closed := f.state()
		return closed
	})
}

// waitFor waits for cond, polling, for at most 10 seconds.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !cond(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
	}
}

func TestMaxBody(t *testing.T) {
	path := socketPath(t)
	f := &fake{}
	serve(t, path, one(f))
	c := dial(t, path)
	for _, n := range []int64{0, -1, 1 << 40, MaxBody, 1024} {
		if _, err := c.Send(t.Context(), &session.Outbound{MaxBody: n}); err != nil {
			t.Fatal(err)
		}
	}
	sent, _ := f.state()
	var got []int64
	for _, o := range sent {
		got = append(got, o.MaxBody)
	}
	if want := []int64{MaxBody, MaxBody, MaxBody, MaxBody, 1024}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("max bodies %v, want %v", got, want)
	}
}

func TestLazy(t *testing.T) {
	path := socketPath(t)
	l := NewLazy(path)
	defer func() {
		if err := l.Close(); err != nil {
			t.Error(err)
		}
	}()
	// No keeper yet: the request fails, and the next one dials again.
	_, first := l.Send(t.Context(), &session.Outbound{Ref: "a.http#1"})
	wantError(t, first, core.KindPolicy, "no keeper is running")

	var mu sync.Mutex
	conns := 0
	serve(t, path, func(Peer) Conn {
		mu.Lock()
		defer mu.Unlock()
		conns++
		return &fake{}
	})
	for _, ref := range []string{"a.http#2", "a.http#3"} {
		in, err := l.Send(t.Context(), &session.Outbound{Ref: ref})
		if err != nil {
			t.Fatal(err)
		}
		if in.Result.Ref != ref {
			t.Errorf("ref %q, want %q", in.Result.Ref, ref)
		}
	}
	mu.Lock()
	if conns != 1 {
		t.Errorf("%d connections, want one for the run", conns)
	}
	mu.Unlock()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := l.Send(t.Context(), &session.Outbound{})
	wantError(t, err, core.KindPolicy, "closed")
}

// raw connects to the keeper at path as a run, says the version v, and
// returns the connection and its reader.
func raw(t *testing.T, path string, v int) (*net.UnixConn, *bufio.Reader) {
	t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { discard(c) })
	r := bufio.NewReader(c)
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf(`{"keeper":1,"pid":%d}`+"\n", os.Getpid()); line != want {
		t.Fatalf("the keeper's first line %q, want %q", line, want)
	}
	fmt.Fprintf(c, `{"keeper":%d}`+"\n", v)
	return c, r
}

// lastLine reads the keeper's last line from r, and checks that the
// connection ends after it.
func lastLine(t *testing.T, r *bufio.Reader) wireError {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("no last line: %v", err)
	}
	var rep reply
	if err := json.Unmarshal([]byte(line), &rep); err != nil || rep.Error == nil || rep.ID != 0 {
		t.Fatalf("last line %q, want an error without an id", line)
	}
	if rest, err := r.ReadString('\n'); err == nil {
		t.Fatalf("a line after the last: %q", rest)
	}
	return *rep.Error
}

func TestServeRefuses(t *testing.T) {
	path := socketPath(t)
	f := &fake{}
	serve(t, path, func(Peer) Conn { return f })
	request := func(id int) string { return fmt.Sprintf(`{"id":%d,"send":{"ref":"a.http#1"}}`+"\n", id) }
	for _, tc := range []struct {
		name    string
		version int
		lines   string
		want    string
	}{
		{"another version", 2, "", "the keeper speaks version 1; this vegtam speaks 2"},
		{"garbage", 1, "GET / HTTP/1.1\n", "a line that is not the protocol's"},
		{"no id", 1, `{"send":{}}` + "\n", "a request without an id"},
		{"nothing to send", 1, `{"id":1}` + "\n", "request 1 has nothing to send"},
		{"ids that do not increase", 1, request(1), "request 1 after request 1"},
		{"two at once", 1, request(1) + request(2), "request 1 came with more after it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, r := raw(t, path, tc.version)
			fmt.Fprint(c, tc.lines)
			if tc.name == "ids that do not increase" {
				if _, err := r.ReadString('\n'); err != nil {
					t.Fatal(err)
				}
				fmt.Fprint(c, request(1))
			}
			if e := lastLine(t, r); e.Kind != core.KindPolicy || !strings.Contains(e.Message, tc.want) {
				t.Errorf("last line %+v, want kind policy with %q", e, tc.want)
			}
		})
	}
	t.Run("truncated", func(t *testing.T) {
		c, r := raw(t, path, 1)
		fmt.Fprint(c, `{"id":1,"send":`)
		if err := c.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if e := lastLine(t, r); !strings.Contains(e.Message, "unexpected EOF") {
			t.Errorf("last line %+v", e)
		}
	})
	t.Run("too long", func(t *testing.T) {
		c, r := raw(t, path, 1)
		var wg sync.WaitGroup
		wg.Go(func() {
			// The keeper stops reading at the limit, and may close the
			// connection before all is written.
			line := make([]byte, MaxLine+2)
			for i := range line {
				line[i] = 'a'
			}
			line[len(line)-1] = '\n'
			fmt.Fprintf(c, "%s", line)
		})
		e := lastLine(t, r)
		wg.Wait()
		if !strings.Contains(e.Message, fmt.Sprintf("a line longer than %d bytes", MaxLine)) {
			t.Errorf("last line %+v", e)
		}
	})
	// The keeper still serves.
	if _, err := dial(t, path).Send(t.Context(), &session.Outbound{Ref: "a.http#1"}); err != nil {
		t.Fatal(err)
	}
}

func TestServeStops(t *testing.T) {
	path := socketPath(t)
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	idle, busy := &fake{}, &fake{wait: true, asked: make(chan struct{})}
	conns := make(chan *fake, 2)
	conns <- idle
	conns <- busy
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- l.Serve(ctx, func(Peer) Conn { return <-conns }) }()
	dial(t, path)
	waitFor(t, func() bool { return len(conns) == 1 }) // the idle run's Conn is made
	busyRun := dial(t, path)
	errc := make(chan error, 1)
	go func() {
		_, err := busyRun.Send(t.Context(), &session.Outbound{})
		errc <- err
	}()
	<-busy.asked
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Serve: %v", err)
	}
	for _, f := range []*fake{idle, busy} {
		if _, closed := f.state(); !closed {
			t.Error("a Conn is not closed")
		}
	}
	wantError(t, <-errc, core.KindPolicy, "the keeper closed the connection")
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, path + ".lock"} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s is still there: %v", p, err)
		}
	}
}

func TestListenLock(t *testing.T) {
	path := socketPath(t)
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Listen(path)
	wantError(t, err, core.KindPolicy, "a keeper already runs on this socket, pid "+strconv.Itoa(os.Getpid()))
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Mode().Type() != fs.ModeSocket {
		t.Errorf("socket %v, %v; want a socket of mode 0600", fi, err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err = Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestListenLeftBehind(t *testing.T) {
	path := socketPath(t)
	// A socket that a keeper left: removed.
	old, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	old.SetUnlinkOnClose(false)
	discard(old)
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	// Anything else: kept, and refused.
	if err = os.WriteFile(path, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Listen(path)
	wantError(t, err, core.KindPolicy, "not a socket")
	if b, err := os.ReadFile(path); err != nil || string(b) != "mine" {
		t.Errorf("the file is %q, %v", b, err)
	}
	if _, err := os.Lstat(path + ".lock"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the lock file is still there: %v", err)
	}
}

func TestListenDir(t *testing.T) {
	path := filepath.Join(filepath.Dir(socketPath(t)), "new", "keeper.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	fi, err := os.Stat(dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("directory %v, %v; want mode 0700", fi, err)
	}
	if err = os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	_, err = Listen(path)
	wantError(t, err, core.KindPolicy, "others can write its directory")

	_, err = Listen(filepath.Join(filepath.Dir(dir), strings.Repeat("d", 200), "keeper.sock"))
	wantError(t, err, core.KindPolicy, "set XDG_RUNTIME_DIR to a shorter directory")
}

// TestServeLimits checks that the keeper serves maxRuns runs at a time and
// refuses one more: each holds what others could use.
func TestServeLimits(t *testing.T) {
	path := socketPath(t)
	serve(t, path, func(Peer) Conn { return &fake{} })
	for range maxRuns {
		dial(t, path)
	}
	if _, err := Dial(t.Context(), path); err == nil || !strings.Contains(err.Error(), "the keeper serves 8 runs at a time") {
		t.Errorf("one run more: %v", err)
	}
}

// TestServeIdle checks that the keeper closes a run that sends no request
// in time.
func TestServeIdle(t *testing.T) {
	old := idleTimeout
	idleTimeout = 50 * time.Millisecond
	t.Cleanup(func() { idleTimeout = old })
	path := socketPath(t)
	f := &fake{}
	serve(t, path, func(Peer) Conn { return f })
	c := dial(t, path)
	time.Sleep(200 * time.Millisecond)
	_, err := c.Send(t.Context(), &session.Outbound{Ref: "late"})
	if e, ok := errors.AsType[*core.Error](err); !ok || e.Kind != core.KindPolicy ||
		!strings.Contains(e.Msg, "no request came in 50ms") && !strings.Contains(e.Msg, "the keeper closed the connection") {
		t.Errorf("a late request: %v", err)
	}
	if sent, closed := f.state(); len(sent) != 0 || !closed {
		t.Errorf("the keeper took %d requests, closed %v", len(sent), closed)
	}
}
