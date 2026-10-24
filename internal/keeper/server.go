package keeper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/policy"
	"github.com/vidforull/vegtam/internal/core/session"
)

// Conn is the keeper's side of the connection of one run: it sends the
// run's requests, as session.Session.Relay does, and is closed when the
// run goes. Send is given a ctx that ends if the run goes away while its
// request is being sent, or asked about.
type Conn interface {
	Send(ctx context.Context, o *session.Outbound) (*session.Inbound, error)
	Close()
}

// Listener is the keeper's socket, with the lock that makes its process
// the one keeper of the socket.
type Listener struct {
	path string
	ln   *net.UnixListener
	lock int // the descriptor of the lock file
	once sync.Once
}

// Listen listens at path, the keeper's socket (see policy.KeeperSocket).
// The socket's directory is made, private, if it is missing, and refused
// if it belongs to another user or others can write it: whoever can write
// it could put their own socket in the keeper's place. The lock file
// beside the socket, path.lock, is held as long as the Listener is open,
// so that one keeper serves a socket: a second one is refused, with the
// pid of the first. A socket left at path by a keeper that is gone is
// removed, under the lock, and nothing else. The socket is the user's
// alone, mode 0600. Where the keeper cannot tell which process connects
// to it (see Peer), it does not listen.
func Listen(path string) (*Listener, error) {
	fail := func(format string, args ...any) error {
		return core.Errorf(core.KindPolicy, core.Source{File: path}, format, args...)
	}
	switch {
	case !peerSupported:
		return nil, fail("the keeper runs on Linux and macOS: here it cannot tell which process asks it to send a request")
	case len(path) > maxSocketPath:
		return nil, fail("the path is %d bytes, more than a unix socket's %d: set XDG_RUNTIME_DIR to a shorter directory", len(path), maxSocketPath)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fail("%v", err)
	}
	switch di, err := os.Stat(dir); {
	case err != nil:
		return nil, fail("%v", err)
	case !di.IsDir():
		return nil, fail("%s is not a directory", dir)
	case !policy.OwnedByUser(di):
		return nil, fail("its directory belongs to another user, so the keeper does not listen there")
	case di.Mode().Perm()&0o022 != 0:
		return nil, fail("others can write its directory, so the keeper does not listen there; make it private: chmod 700 %s", dir)
	}
	lock, err := lockFile(path + ".lock")
	if err != nil {
		return nil, fail("%v", err)
	}
	l, err := listen(path)
	if err != nil {
		return nil, fail("%v", errors.Join(err, unlockFile(lock, path+".lock")))
	}
	return &Listener{path: path, ln: l, lock: lock}, nil
}

// listen listens at path, once the lock is held: a socket there is one
// that a keeper left behind.
func listen(path string) (*net.UnixListener, error) {
	switch fi, err := os.Lstat(path); {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	case fi.Mode().Type() != fs.ModeSocket:
		return nil, fmt.Errorf("there is a file that is not a socket at %s; the keeper does not remove it", path)
	default:
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	l.SetUnlinkOnClose(false) // Close removes it, under the lock
	// The umask that Protect sets makes it so; a keeper that runs without
	// it, as tests do, gets it all the same.
	if err := os.Chmod(path, 0o600); err != nil {
		err = errors.Join(err, l.Close())
		os.Remove(path)
		return nil, err
	}
	return l, nil
}

// Close closes the socket, and removes it and the lock file, then lets
// the lock go. Close it once Serve has returned.
func (l *Listener) Close() error {
	var err error
	l.once.Do(func() {
		if cerr := l.ln.Close(); cerr != nil && !errors.Is(cerr, net.ErrClosed) {
			err = cerr
		}
		if rerr := os.Remove(l.path); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			err = errors.Join(err, rerr)
		}
		err = errors.Join(err, unlockFile(l.lock, l.path+".lock"))
	})
	return err
}

// Serve accepts the connections of runs until ctx is done, each in a
// goroutine of its own, and returns once every one has ended. For each it
// learns the Peer, which must be of the keeper's own user, says the
// protocol's version and checks the run's, then calls newConn with the
// peer: a nil Conn refuses the run. It reads the run's requests one at a
// time and answers each with what the Conn's Send gives back, and calls
// its Close when the run goes away, or the keeper stops. A run that does
// not speak the protocol is told so, and its connection closed. An error
// of Send that is a *core.Error goes back with its kind, any other with
// kind policy. It serves maxRuns runs at a time, and refuses more: each
// may hold a line of up to MaxLine bytes.
func (l *Listener) Serve(ctx context.Context, newConn func(Peer) Conn) error {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	runs := make(chan struct{}, maxRuns)
	stop := closeOnDone(ctx, l.ln)
	defer stop()
	backoff := 5 * time.Millisecond
	for {
		c, err := l.ln.AcceptUnix()
		switch {
		case ctx.Err() != nil:
			if c != nil {
				discard(c)
			}
			return nil
		case errors.Is(err, net.ErrClosed):
			return err
		case err != nil:
			// Such as too many open files: wait, as net/http does, for
			// some to close.
			t := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
			case <-t.C:
			}
			t.Stop()
			backoff = min(2*backoff, time.Second)
			continue
		}
		backoff = 5 * time.Millisecond
		select {
		case runs <- struct{}{}:
			wg.Go(func() {
				defer func() { <-runs }()
				serveConn(ctx, c, newConn)
			})
		default:
			wg.Go(func() {
				defer discard(c)
				(&served{c: c}).refuse("the keeper serves %d runs at a time, and has as many: try again once one has ended", maxRuns)
			})
		}
	}
}

// served is the keeper's side of the connection of one run.
type served struct {
	c     *net.UnixConn
	lines *lineReader
}

// serveConn serves the run at c until it goes away or ctx is done.
func serveConn(ctx context.Context, c *net.UnixConn, newConn func(Peer) Conn) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer discard(c)
	stop := closeOnDone(ctx, c)
	defer stop()
	s := &served{c: c, lines: newLineReader(c, MaxLine)}
	peer, err := peerOf(c)
	switch {
	case err != nil:
		s.refuse("the keeper cannot tell which process connects: %v", err)
		return
	case peer.UID != os.Geteuid():
		s.refuse("the keeper serves the processes of its own user, and %s is not one", peer)
		return
	}
	if !s.handshake() {
		return
	}
	conn := newConn(peer)
	if conn == nil {
		s.refuse("the keeper refuses %s", peer)
		return
	}
	defer conn.Close()
	var last int64
	for {
		// A run sends its next request at once: one that keeps a
		// connection and sends nothing, or a line a byte at a time, holds
		// what others could use.
		if s.c.SetReadDeadline(time.Now().Add(idleTimeout)) != nil {
			return
		}
		line, err := s.lines.next()
		switch {
		case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
			return
		case errors.Is(err, os.ErrDeadlineExceeded):
			s.refuse("no request came in %s: the connection is closed", idleTimeout)
			return
		case err != nil:
			s.refuse("%v", err)
			return
		}
		r, err := decodeRequest(line)
		switch {
		case err != nil:
			s.refuse("%v", err)
			return
		case r.ID <= last:
			s.refuse("request %d after request %d: the ids of a run's requests increase", r.ID, last)
			return
		case s.lines.r.Buffered() > 0:
			s.refuse("request %d came with more after it: a run sends a request once the one before is answered", r.ID)
			return
		}
		last = r.ID
		in, gone, err := s.send(ctx, conn, r.Send)
		if gone || ctx.Err() != nil { // the run, or the keeper, has gone
			return
		}
		if !s.answer(r.ID, in, err) {
			return
		}
	}
}

// handshake writes the keeper's first line and reads the run's, and
// reports whether the run speaks the keeper's version.
func (s *served) handshake() bool {
	mux, _ := Multiplexer()
	b, err := encode(hello{Keeper: Version, PID: os.Getpid(), Multiplexer: mux})
	if err == nil {
		err = s.c.SetDeadline(time.Now().Add(handshakeTimeout))
	}
	if err == nil {
		_, err = s.c.Write(b)
	}
	if err != nil {
		return false
	}
	line, err := s.lines.next()
	if err != nil {
		return false
	}
	if _, err := decodeRunHello(line); err != nil {
		s.refuse("%v", err)
		return false
	}
	return s.c.SetDeadline(time.Time{}) == nil
}

// send hands o to conn, with a ctx that ends if the run goes away while
// it is sent, or writes before its answer: its person is not asked on
// behalf of a run that is gone. It reports whether the run went.
func (s *served) send(ctx context.Context, conn Conn, o *session.Outbound) (*session.Inbound, bool, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	// Whatever the run asks, the keeper keeps at most MaxBody bytes of a
	// response body: the result must fit in a line (see MaxLine).
	if o.MaxBody <= 0 || o.MaxBody > MaxBody {
		o.MaxBody = MaxBody
	}
	// The request may take its time, a question to its person too: the
	// limit of an idle run does not hold while it is sent.
	if err := s.c.SetReadDeadline(time.Time{}); err != nil {
		return nil, true, err
	}
	gone := make(chan bool, 1)
	var wg sync.WaitGroup
	// Nothing is buffered (see serveConn): what the run writes now, the
	// connection itself has.
	wg.Go(func() {
		var b [1]byte
		n, err := s.c.Read(b[:])
		lost := n > 0 || !errors.Is(err, os.ErrDeadlineExceeded)
		if lost {
			cancel(errGone)
		}
		gone <- lost
	})
	in, err := conn.Send(ctx, o)
	derr := s.c.SetReadDeadline(time.Now())
	wg.Wait()
	lost := <-gone
	if derr == nil {
		derr = s.c.SetReadDeadline(time.Time{})
	}
	return in, lost || derr != nil, err
}

// maxRuns is how many runs the keeper serves at a time.
const maxRuns = 8

// idleTimeout is how long the keeper waits for a run's next request,
// whole; tests shorten it.
var idleTimeout = 2 * time.Minute

// errGone is why the request of a run that went away is not sent.
var errGone = errors.New("the run went away")

// answer writes the answer to request id: in, or err. It reports whether
// the run is still there to send another.
func (s *served) answer(id int64, in *session.Inbound, err error) bool {
	r := reply{ID: id, Inbound: in}
	switch {
	case err != nil:
		r.Inbound, r.Error = nil, errorOf(err)
	case in == nil || in.Result == nil:
		r.Inbound, r.Error = nil, errorOf(errors.New("the keeper gave back no result"))
	}
	b, err := encode(r)
	if err != nil {
		b, err = encode(reply{ID: id, Error: errorOf(fmt.Errorf("the result is too large to give back: %w", err))})
	}
	return err == nil && s.write(b)
}

// refuse writes the keeper's last line to the run: the error of what it
// refuses, said as format and args say. The connection is closed after.
func (s *served) refuse(format string, args ...any) {
	b, err := encode(reply{Error: &wireError{Kind: core.KindPolicy, Message: fmt.Sprintf(format, args...)}})
	if err != nil {
		return
	}
	// A run that reads nothing does not hold the keeper.
	if s.c.SetWriteDeadline(time.Now().Add(time.Second)) == nil {
		s.write(b)
	}
}

// write writes the line b, and reports whether it went: a run that is
// gone is not told.
func (s *served) write(b []byte) bool {
	_, err := s.c.Write(b)
	return err == nil
}
