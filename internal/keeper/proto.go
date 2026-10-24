package keeper

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/session"
)

// Version is the version of the protocol between a run and the keeper.
// The protocol is JSON, one message to a line, over the keeper's unix
// socket, one connection for each run:
//
//	keeper: {"keeper":1,"pid":4242}
//	run:    {"keeper":1}
//	run:    {"id":1,"send":<session.Outbound>}
//	keeper: {"id":1,"inbound":<session.Inbound>}
//	run:    {"id":2,"send":<session.Outbound>}
//	keeper: {"id":2,"error":{"kind":"policy","message":"..."}}
//
// Each side says its version first, and speaks no other: a run that hears
// another fails, and a keeper that hears another says so in an error and
// closes the connection. The run sends one request at a time, each with an
// id greater than the one before, and the keeper answers each with the
// same id. An error without an id is the keeper's last line: it refuses
// the run, or what the run wrote, and closes the connection. Fields that
// a side does not know are ignored, so that a later version may add some;
// a field that a message needs is not optional.
const Version = 1

// The limits of the protocol. A line holds at most MaxLine bytes, its
// newline aside: a request with a body of up to 16 MiB, which is as much
// as a run reads from a file, and a result with that body as sent and a
// response body of up to MaxBody, with what JSON makes of them. Whatever
// a run asks for, the keeper keeps at most MaxBody bytes of a response
// body, so that its result fits in a line.
const (
	MaxLine = 64 << 20
	MaxBody = 32 << 20
)

// handshakeTimeout is how long each side waits for the first line of the
// other, which writes it at once.
const handshakeTimeout = 10 * time.Second

// hello is the first line of each side: the keeper's with its pid, and
// the terminal multiplexer it runs in, if it does; or, in its place, the
// error of a keeper that refuses the run.
type hello struct {
	Keeper      int        `json:"keeper,omitempty"`
	PID         int        `json:"pid,omitempty"`
	Multiplexer string     `json:"multiplexer,omitempty"`
	Error       *wireError `json:"error,omitempty"`
}

// request is a line of the run: a request for the keeper to send.
type request struct {
	ID   int64             `json:"id"`
	Send *session.Outbound `json:"send"`
}

// reply is a line of the keeper: what it gives back for the request of
// the same id, or its error. An error without an id ends the connection.
type reply struct {
	ID      int64            `json:"id,omitempty"`
	Inbound *session.Inbound `json:"inbound,omitempty"`
	Error   *wireError       `json:"error,omitempty"`
}

// wireError is an error of the keeper, of a core.Kind.
type wireError struct {
	Kind    core.Kind `json:"kind"`
	Message string    `json:"message"`
}

// errorOf returns err as the keeper writes it: a *core.Error with its
// kind, any other error of kind policy.
func errorOf(err error) *wireError {
	e := &wireError{Kind: core.KindPolicy, Message: err.Error()}
	if ce, ok := errors.AsType[*core.Error](err); ok && ce.Kind != "" {
		e.Kind = ce.Kind
	}
	if e.Message == "" {
		e.Message = "the keeper gave no reason"
	}
	return e
}

// check reports what e lacks.
func (e *wireError) check() error {
	if e.Kind == "" || e.Message == "" {
		return errors.New("an error without a kind or a message")
	}
	return nil
}

// err returns e as the run gets it: its kind and its message, as is.
func (e *wireError) err() *core.Error { return &core.Error{Kind: e.Kind, Msg: e.Message} }

// decodeKeeperHello decodes the first line of the keeper, as the run reads
// it. A refusal in its place decodes with its Error.
func decodeKeeperHello(line []byte) (hello, error) {
	var h hello
	if err := unmarshal(line, &h); err != nil {
		return h, err
	}
	switch {
	case h.Error != nil:
		return h, h.Error.check()
	case h.Keeper == 0:
		return h, errors.New("its first line names no version: is it a keeper?")
	case h.Keeper != Version:
		return h, policyError("the keeper speaks version %d; this vegtam speaks %d: run vegtam keeper of this version", h.Keeper, Version)
	case h.PID <= 0:
		return h, errors.New("the keeper did not say its pid")
	}
	return h, nil
}

// decodeRunHello decodes the first line of the run, as the keeper reads it.
func decodeRunHello(line []byte) (hello, error) {
	var h hello
	if err := unmarshal(line, &h); err != nil {
		return h, err
	}
	switch {
	case h.Keeper == 0:
		return h, errors.New("its first line names no version: is it a vegtam run?")
	case h.Keeper != Version:
		// Said to the run, in its words.
		return h, fmt.Errorf("the keeper speaks version %d; this vegtam speaks %d: run vegtam keeper of this version", Version, h.Keeper)
	}
	return h, nil
}

// decodeRequest decodes a line of the run after its first.
func decodeRequest(line []byte) (request, error) {
	var r request
	if err := unmarshal(line, &r); err != nil {
		return r, err
	}
	switch {
	case r.ID <= 0:
		return r, errors.New("a request without an id")
	case r.Send == nil:
		return r, fmt.Errorf("request %d has nothing to send", r.ID)
	}
	return r, nil
}

// decodeReply decodes a line of the keeper after its first.
func decodeReply(line []byte) (reply, error) {
	var r reply
	if err := unmarshal(line, &r); err != nil {
		return r, err
	}
	switch {
	case r.ID < 0:
		return r, fmt.Errorf("a reply to request %d, which no run sends", r.ID)
	case r.Error != nil && r.Inbound != nil:
		return r, fmt.Errorf("reply %d gives back both a result and an error", r.ID)
	case r.Error != nil:
		return r, r.Error.check()
	case r.ID == 0:
		return r, errors.New("a reply without an id")
	case r.Inbound == nil:
		return r, fmt.Errorf("reply %d gives back nothing", r.ID)
	case r.Inbound.Result == nil:
		return r, fmt.Errorf("reply %d gives back no result", r.ID)
	}
	return r, nil
}

// unmarshal decodes line, one JSON value and nothing after it, into v.
func unmarshal(line []byte, v any) error {
	if err := json.Unmarshal(line, v); err != nil {
		return fmt.Errorf("a line that is not the protocol's: %w", err)
	}
	return nil
}

// encode returns v as a line: JSON and a newline. One longer than MaxLine
// is an error.
func encode(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if n := b.Len() - 1; n > MaxLine {
		return nil, &tooLongError{n: n, max: MaxLine}
	}
	return b.Bytes(), nil
}

// tooLongError is the error of a line longer than the protocol allows.
type tooLongError struct {
	n   int // its length, if known; 0 if it was not read to its end
	max int
}

func (e *tooLongError) Error() string {
	if e.n == 0 {
		return fmt.Sprintf("a line longer than %d bytes", e.max)
	}
	return fmt.Sprintf("a line of %d bytes, longer than %d", e.n, e.max)
}

// lineReader reads the lines of a connection, each at most max bytes, its
// newline aside: a longer one is an error, and so is a stream that ends
// inside a line. It never holds more of a line than max bytes and the
// newline, whatever the other side writes.
type lineReader struct {
	r   *bufio.Reader
	max int
}

func newLineReader(r io.Reader, maxLine int) *lineReader {
	return &lineReader{r: bufio.NewReaderSize(r, 64<<10), max: maxLine}
}

// next returns the next line without its newline; io.EOF at the end of
// the stream, between two lines.
func (l *lineReader) next() ([]byte, error) {
	var line []byte
	for {
		chunk, err := l.r.ReadSlice('\n')
		n := len(line) + len(chunk)
		if err == nil {
			n-- // the newline
		}
		if n > l.max {
			return nil, &tooLongError{max: l.max}
		}
		if cap(line)-len(line) < len(chunk) {
			grown := make([]byte, len(line), min(max(2*cap(line), len(line)+len(chunk)), l.max+1))
			copy(grown, line)
			line = grown
		}
		line = append(line, chunk...)
		switch {
		case err == nil:
			return line[:len(line)-1], nil
		case errors.Is(err, bufio.ErrBufferFull):
		case errors.Is(err, io.EOF) && len(line) == 0:
			return nil, io.EOF
		case errors.Is(err, io.EOF):
			return nil, io.ErrUnexpectedEOF
		default:
			return nil, err
		}
	}
}

// discard closes c, a connection on its way out: whatever its Close
// says, the connection ends with the error that ended it, or with none.
func discard(c io.Closer) { c.Close() }

// closeOnDone closes c once ctx is done, and returns the func that stops
// that, waits for a close already begun, and reports whether there was
// one. It is called once.
func closeOnDone(ctx context.Context, c io.Closer) func() bool {
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(closed)
		c.Close()
	})
	return func() bool {
		if stop() {
			return false
		}
		<-closed
		return true
	}
}
