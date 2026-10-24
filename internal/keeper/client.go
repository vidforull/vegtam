package keeper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/session"
)

// Client is a run's connection to the keeper, which sends the run's
// requests one at a time. It is a session.Keeper.
type Client struct {
	path   string
	conn   *net.UnixConn
	lines  *lineReader
	closed atomic.Bool

	mu  sync.Mutex // held by the request being sent
	id  int64      // of the latest request
	err error      // why the connection is lost: every request after it gets it

	pid         int    // the keeper's, as it says
	multiplexer string // the terminal multiplexer it runs in, as it says; "" for none
}

// Keeper returns what the keeper says of itself: its pid, and the
// terminal multiplexer it runs in, "" for none.
func (c *Client) Keeper() (pid int, multiplexer string) { return c.pid, c.multiplexer }

// Dial connects to the keeper that listens at path (see
// policy.KeeperSocket), and says the protocol's version. The process at
// the other end must be of the run's own user: a socket that another
// user's process holds is no keeper of the run's. Its errors, as those of
// the Client, are of kind policy, and say what to do.
func Dial(ctx context.Context, path string) (*Client, error) {
	var d net.Dialer
	conn, err := d.DialUnix(ctx, "unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	switch {
	case err != nil && ctx.Err() != nil:
		return nil, interrupted(ctx)
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ECONNREFUSED):
		return nil, policyError("no keeper is running at %s: start vegtam keeper in your terminal", path)
	case err != nil:
		return nil, policyError("the keeper at %s cannot be reached: %v", path, err)
	}
	c := &Client{path: path, conn: conn, lines: newLineReader(conn, MaxLine)}
	if err := c.handshake(ctx); err != nil {
		discard(conn)
		return nil, err
	}
	return c, nil
}

// handshake checks whose process the keeper is, reads its first line and
// writes the run's.
func (c *Client) handshake(ctx context.Context) error {
	if peer, err := peerOf(c.conn); peerSupported && err != nil {
		return policyError("whose process listens at %s cannot be told: %v", c.path, err)
	} else if peerSupported && peer.UID != os.Geteuid() {
		return policyError("the process at %s, %s, is another user's: it is no keeper of yours", c.path, peer)
	}
	stop := closeOnDone(ctx, c.conn)
	defer stop()
	if err := c.conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return c.lost(ctx, err)
	}
	line, err := c.lines.next()
	if err != nil {
		return c.lost(ctx, err)
	}
	h, err := decodeKeeperHello(line)
	switch {
	case err != nil:
		return c.lost(ctx, err)
	case h.Error != nil:
		return h.Error.err()
	}
	c.pid, c.multiplexer = h.PID, h.Multiplexer
	b, err := encode(hello{Keeper: Version})
	if err == nil {
		_, err = c.conn.Write(b)
	}
	if err == nil {
		err = c.conn.SetDeadline(time.Time{})
	}
	if err != nil {
		return c.lost(ctx, err)
	}
	return nil
}

// Send sends o through the keeper and returns what it gives back. A
// keeper's error for o is the error, with its kind; the connection stays.
// Once ctx is done, or the connection is lost, the connection is closed:
// every request after gets the error.
func (c *Client) Send(ctx context.Context, o *session.Outbound) (*session.Inbound, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	b, err := encode(request{ID: c.id + 1, Send: o})
	if err != nil {
		return nil, policyError("the request cannot go to the keeper: %v", err)
	}
	c.id++
	stop := closeOnDone(ctx, c.conn)
	in, err := c.exchange(ctx, b)
	if stop() && err == nil {
		// ctx ended as the answer came, and the connection with it.
		c.err = interrupted(ctx)
		c.closed.Store(true)
	}
	return in, err
}

// exchange writes the request b and reads its answer.
func (c *Client) exchange(ctx context.Context, b []byte) (*session.Inbound, error) {
	if _, err := c.conn.Write(b); err != nil {
		return nil, c.lost(ctx, err)
	}
	line, err := c.lines.next()
	if err != nil {
		return nil, c.lost(ctx, err)
	}
	r, err := decodeReply(line)
	switch {
	case err != nil:
		return nil, c.lost(ctx, err)
	case r.ID == 0: // its last line
		return nil, c.lost(ctx, r.Error.err())
	case r.ID != c.id:
		return nil, c.lost(ctx, fmt.Errorf("the keeper answered request %d, not %d", r.ID, c.id))
	case r.Error != nil:
		return nil, r.Error.err()
	}
	return r.Inbound, nil
}

// Close closes the connection. A request being sent ends with an error.
func (c *Client) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	if err := c.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// lost closes the connection, lost for err, and returns the error that
// the run gets for it, which every request after gets too.
func (c *Client) lost(ctx context.Context, err error) error {
	var ke *core.Error
	switch e, ok := errors.AsType[*core.Error](err); {
	case ctx.Err() != nil:
		ke = interrupted(ctx)
	case c.closed.Load():
		ke = policyError("the connection to the keeper is closed")
	case ok:
		ke = e
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		ke = policyError("the keeper closed the connection")
	case errors.Is(err, os.ErrDeadlineExceeded):
		ke = policyError("the keeper at %s did not answer in %s: is it a keeper?", c.path, handshakeTimeout)
	default:
		ke = policyError("the keeper at %s: %v", c.path, err)
	}
	c.err = ke
	c.closed.Store(true)
	discard(c.conn)
	return ke
}

// interrupted returns the error of a request through the keeper that ctx
// ended: kind timeout for its deadline, canceled otherwise.
func interrupted(ctx context.Context) *core.Error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return core.Errorf(core.KindTimeout, core.Source{}, "no answer from the keeper in time")
	}
	return core.Errorf(core.KindCanceled, core.Source{}, "the request through the keeper was interrupted")
}

// policyError returns an error of kind policy, which a run without a
// person exits with: the keeper cannot do what the run asks.
func policyError(format string, args ...any) *core.Error {
	return core.Errorf(core.KindPolicy, core.Source{}, format, args...)
}

// Lazy is a session.Keeper that dials the keeper at its path on the first
// request that needs it, and sends every request of the run through that
// connection: a run that needs no keeper never reaches it, and the cookies
// and captured secrets that the keeper holds for the run stay with the
// one connection. A dial that fails is tried again by the next request.
type Lazy struct {
	path   string
	mu     sync.Mutex
	c      *Client
	closed bool
}

// NewLazy returns a Lazy for the keeper at path.
func NewLazy(path string) *Lazy { return &Lazy{path: path} }

// Send sends o through the keeper, dialing it first if it has not yet.
func (l *Lazy) Send(ctx context.Context, o *session.Outbound) (*session.Inbound, error) {
	c, err := l.client(ctx)
	if err != nil {
		return nil, err
	}
	return c.Send(ctx, o)
}

// client returns the connection, dialed if it is not yet.
func (l *Lazy) client(ctx context.Context) (*Client, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, policyError("the connection to the keeper is closed")
	}
	if l.c == nil {
		c, err := Dial(ctx, l.path)
		if err != nil {
			return nil, err
		}
		l.c = c
	}
	return l.c, nil
}

// Close closes the connection, if there is one. A request after it is an
// error.
func (l *Lazy) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	if l.c == nil {
		return nil
	}
	return l.c.Close()
}
