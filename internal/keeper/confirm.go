package keeper

import (
	"bufio"
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/output"
)

// Terminal is the keeper's terminal, where its person answers its
// questions. ReadLine returns the next line typed after the latest
// Write, without its newline: a line typed before a question was put is
// no answer to it, nor is one typed too late for the question before.
type Terminal interface {
	Write(s string) error
	ReadLine(ctx context.Context) (string, error)
}

// defaultTimeout is how long a question waits for its answer if the
// Asker does not say.
const defaultTimeout = 60 * time.Second

// codeLetters are those of a code, of which each is as likely.
const codeLetters = "abcdefghijklmnopqrstuvwxyz0123456789"

// codeLength is the length of a code: 36^4 codes, of which a guess or a
// stray line is one.
const codeLength = 4

// Asker asks the keeper's person, at its terminal, whether to send a
// request, one question at a time. The person answers by typing the code
// that the question shows, which is drawn anew for each: anything else is
// no, and so is no answer in Timeout. Not a yes, nor Enter: a key pressed
// by reflex, or for something else, or a line typed ahead, sends nothing.
type Asker struct {
	Term    Terminal
	Timeout time.Duration // 60s if 0

	once sync.Once
	turn chan struct{} // held by the question being asked
}

// Ask asks the keeper's person whether to send p, the request that peer
// asks the keeper to send, with the secrets of bs; nil means yes. Bound
// to its peer, it is session.Serve.Ask. The question shows the peer, the
// method, the URL with its placeholders, and each secret with where the
// request goes and whether the secret is bound to it: p holds no secret
// value to show. What the run wrote is shown with its control characters
// escaped, so that it cannot drive the terminal.
func (a *Asker) Ask(ctx context.Context, peer Peer, p *core.Prepared, bs []core.Bound) error {
	a.once.Do(func() { a.turn = make(chan struct{}, 1) })
	select {
	case a.turn <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("not asked: %w", context.Cause(ctx))
	}
	defer func() { <-a.turn }()
	code, err := newCode()
	if err != nil {
		return err
	}
	timeout := cmp.Or(a.Timeout, defaultTimeout)
	if err = a.Term.Write(question(peer, p, bs, code, timeout)); err != nil {
		return fmt.Errorf("the question cannot be put: %w", err)
	}
	actx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	answer, err := a.Term.ReadLine(actx)
	outcome := ""
	if err != nil {
		outcome = "\n" // the person typed nothing: the prompt is still open
	}
	switch {
	case err == nil && strings.TrimSpace(answer) == code:
	case err == nil && strings.TrimSpace(answer) == "":
		err = errors.New("no code was typed")
	case err == nil:
		err = errors.New("the code typed was not the one asked for")
	case ctx.Err() != nil:
		err = fmt.Errorf("the question was withdrawn: %w", context.Cause(ctx))
	case errors.Is(err, context.DeadlineExceeded):
		err = fmt.Errorf("no answer in %gs", timeout.Seconds())
	case errors.Is(err, io.EOF):
		err = ErrInputEnded
	default:
		err = fmt.Errorf("no answer: %w", err)
	}
	if err != nil {
		outcome += "  not sent: " + oneLine(err.Error()) + ".\n"
	} else {
		outcome += "  sending it.\n"
	}
	if werr := a.Term.Write(outcome); werr != nil && err == nil {
		err = fmt.Errorf("the answer cannot be acknowledged: %w", werr)
	}
	return err
}

// ErrInputEnded is the refusal of a keeper whose terminal's input has
// ended: no one can answer it any more.
var ErrInputEnded = errors.New("no answer: the terminal's input has ended")

// question returns the question for p, which peer asks to send with the
// secrets of bs, and whose answer is code.
func question(peer Peer, p *core.Prepared, bs []core.Bound, code string, timeout time.Duration) string {
	lines := []string{
		"vegtam keeper: a request asked by " + peer.String(),
		"  " + p.Method + " " + p.URL.Masked(),
		"  " + shape(p),
	}
	for _, b := range bs {
		var l string
		switch {
		case b.Origin == "":
			l = fmt.Sprintf("  secret %s, in %s, goes where the URL leads, which is known only once it is sent; %s", b.Name, places(p, b.Name), allowed(b))
		case !b.Refused():
			l = fmt.Sprintf("  secret %s, in %s, goes to %s: bound to it", b.Name, places(p, b.Name), b.Origin)
		default:
			l = fmt.Sprintf("  secret %s, in %s, goes to %s: NOT bound to it; %s", b.Name, places(p, b.Name), b.Origin, allowed(b))
		}
		lines = append(lines, l)
	}
	lines = append(lines, fmt.Sprintf("To send it, type %s and Enter; anything else, or no answer in %gs, does not send it.", code, timeout.Seconds()))
	var s strings.Builder
	for _, l := range lines {
		s.WriteString(oneLine(l) + "\n")
	}
	s.WriteString("> ")
	return s.String()
}

// shape says what p sends besides its URL: the names of its headers and
// the size of its body, its secrets as their placeholders.
func shape(p *core.Prepared) string {
	var names []string
	for _, h := range p.Headers {
		names = append(names, h.Name)
	}
	what := "no header"
	if len(names) > 0 {
		what = "headers " + strings.Join(names, ", ")
	}
	if n := len(p.Body.Masked()); n > 0 {
		return fmt.Sprintf("%s; a body of %d bytes", what, n)
	}
	return what + "; no body"
}

// places says where in p the secret name, a placeholder, is: the URL,
// a header by its name, the body.
func places(p *core.Prepared, name string) string {
	in := func(t core.Text) bool {
		return slices.ContainsFunc(t, func(s core.Segment) bool { return s.Secret != nil && "{{"+s.Secret.Name+"}}" == name })
	}
	var where []string
	if in(p.URL) {
		where = append(where, "the URL")
	}
	for _, h := range p.Headers {
		if in(h.Value) {
			where = append(where, "header "+h.Name)
		}
	}
	if in(p.Body) {
		where = append(where, "the body")
	}
	if len(where) == 0 {
		return "the request"
	}
	return strings.Join(where, ", ")
}

// allowed says where the secret of b may go, as core.Why says it.
func allowed(b core.Bound) string {
	switch {
	case b.Capture && len(b.Allowed) > 0:
		return "it was captured from a response of " + strings.Join(b.Allowed, ", ") + ", and goes back there alone"
	case b.Capture:
		return "it was captured from a response whose origin is not known, and goes nowhere"
	case len(b.Allowed) == 0:
		return "it is bound to no origin"
	}
	return "its allowed origins are " + strings.Join(b.Allowed, ", ")
}

// Line returns s as one line of the keeper's terminal: its line feeds and
// tabs escaped as well as what output.Printable escapes, so that what a
// run wrote can neither drive the terminal nor pass for a line of its own,
// such as a question.
func Line(s string) string { return oneLine(s) }

// oneLine returns s as one line of the terminal: its line feeds and tabs
// escaped as well as what output.Printable escapes.
func oneLine(s string) string {
	return output.Printable(strings.NewReplacer("\n", `\x0a`, "\t", `\x09`).Replace(s))
}

// newCode returns a code of codeLength letters of codeLetters, drawn with
// crypto/rand.
func newCode() (string, error) {
	b := make([]byte, codeLength)
	n := big.NewInt(int64(len(codeLetters)))
	for i := range b {
		k, err := rand.Int(rand.Reader, n)
		if err != nil {
			return "", err
		}
		b[i] = codeLetters[k.Int64()]
	}
	return string(b), nil
}

// maxAnswer is the most bytes of a line typed at the keeper's terminal
// that are kept: an answer is a code, and the rest of a longer line is
// dropped.
const maxAnswer = 256

// lineBuffer is how many lines typed with no question to answer are held
// before more are dropped: each is no answer, as Write drops them.
const lineBuffer = 16

// tty is a Terminal on a reader and a writer.
type tty struct {
	out   io.Writer
	lines chan typed // closed once the input ends, after err is set
	err   error      // why the input ended

	mu    sync.Mutex
	asked time.Time // of the latest Write
}

// typed is a line, and when it was read.
type typed struct {
	text string
	at   time.Time
}

// NewTTY returns the keeper's Terminal on in and out, and the func that
// stops it. One goroutine reads the lines of in as they are typed, so
// that each is known for one typed before a question or after it; stop
// ends it and waits for it. A file is polled while it has nothing to
// read, so that stop ends the reading of a terminal whatever its mode,
// and is not closed. Any other reader is closed by stop, if it is an
// io.Closer: its Read must then return.
func NewTTY(in io.Reader, out io.Writer) (Terminal, func()) {
	t := &tty{out: out, lines: make(chan typed, lineBuffer)}
	quit := make(chan struct{})
	ended := make(chan struct{})
	r := in
	f, file := in.(*os.File)
	if file {
		r = polled{f: f, quit: quit}
	}
	go func() {
		defer close(ended)
		t.read(r)
	}()
	var once sync.Once
	return t, func() {
		once.Do(func() {
			close(quit)
			if c, ok := in.(io.Closer); ok && !file {
				c.Close()
			}
			<-ended
		})
	}
}

// read reads the lines of r until its end, and closes the channel of
// lines then.
func (t *tty) read(r io.Reader) {
	br := bufio.NewReaderSize(r, maxAnswer)
	for {
		var line []byte
		chunk, err := br.ReadSlice('\n')
		for errors.Is(err, bufio.ErrBufferFull) {
			line = append(line, chunk[:min(len(chunk), maxAnswer-len(line))]...)
			chunk, err = br.ReadSlice('\n')
		}
		line = append(line, chunk[:min(len(chunk), maxAnswer-len(line))]...)
		if err == nil || len(line) > 0 {
			l := typed{text: strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r"), at: time.Now()}
			select {
			case t.lines <- l:
			default: // no question has been put since they were typed
			}
		}
		if err != nil {
			t.err = err
			close(t.lines)
			return
		}
	}
}

// Write writes s, the lines typed before it dropped.
func (t *tty) Write(s string) error {
	t.mu.Lock()
	t.asked = time.Now()
	t.mu.Unlock()
	for drained := false; !drained; {
		select {
		case _, ok := <-t.lines:
			drained = !ok
		default:
			drained = true
		}
	}
	_, err := io.WriteString(t.out, s)
	return err
}

// ReadLine returns the next line typed after the latest Write, or the
// error that ended the input, io.EOF at its end.
func (t *tty) ReadLine(ctx context.Context) (string, error) {
	t.mu.Lock()
	asked := t.asked
	t.mu.Unlock()
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case l, ok := <-t.lines:
			switch {
			case !ok:
				return "", t.err
			case l.at.Before(asked): // read before the question, sent after
			default:
				return l.text, nil
			}
		}
	}
}

// polled is a file that is read once it has something to read, which
// waitReadable waits for, and not after quit is closed.
type polled struct {
	f    *os.File
	quit <-chan struct{}
}

func (p polled) Read(b []byte) (int, error) {
	if err := waitReadable(p.f, p.quit); err != nil {
		return 0, err
	}
	return p.f.Read(b)
}

// errStopped is the error of a terminal that its stop func stopped.
var errStopped = errors.New("the terminal is stopped")
