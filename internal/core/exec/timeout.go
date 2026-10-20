package exec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/vidforull/vegtam/internal/core"
)

// Settings are what a request is sent with.
type Settings struct {
	Version              string        // see Transport
	Connect, Read, Total time.Duration // see Transport; 0 for none
}

// Settings returns what r is sent with: the HTTP version of its line
// unless the flags give one, and the limits of the transport, each
// lowered by the directive for it. A directive may not raise a limit: one
// above it is a warning, and the limit of the flag or the policy holds.
func (c *Client) Settings(r *core.Request) (Settings, []core.Warning) {
	t := c.opts.Transport
	st := Settings{Version: t.Version, Connect: t.Connect, Read: t.Read, Total: t.Total}
	if r == nil {
		return st, nil
	}
	if st.Version == "" {
		st.Version = r.Version
	}
	var warnings []core.Warning
	for _, d := range r.Directives {
		var limit *time.Duration
		var flag, from string
		switch d.Kind {
		case core.Timeout:
			limit, flag, from = &st.Read, "--read-timeout", t.ReadFrom
		case core.ConnectionTimeout:
			limit, flag, from = &st.Connect, "--connect-timeout", t.ConnectFrom
		case core.MaxTime:
			limit, flag, from = &st.Total, "--max-time", t.TotalFrom
		default:
			continue
		}
		if from != "" {
			flag = from
		}
		v, err := core.ParseTimeout(d.Value)
		if err != nil { // the parser refuses such a file
			continue
		}
		if ceiling := *limit; ceiling > 0 && (v == 0 || v > ceiling) {
			warnings = append(warnings, core.Warning{
				Source: core.Source{File: r.Source.File, Line: d.Line},
				Msg:    fmt.Sprintf("@%s %s is more than %s allows, %s, which holds", d.Kind, d.Value, flag, core.FormatTimeout(ceiling)),
			})
			continue
		}
		*limit = v
	}
	return st, warnings
}

// The causes of the context of a request that a time limit ends.
var (
	errMaxTime        = errors.New("max time")
	errReadTimeout    = errors.New("read timeout")
	errConnectTimeout = errors.New("connect timeout")
)

// watch keeps two limits of a request. The read timeout runs while data
// is awaited: from when the request is written, again from the first
// byte of a response, and during each read of the body. The connect
// timeout runs while a connection is got for a hop, a proxy's CONNECT
// included, which the dialer's own limits do not cover. Either ends the
// request with its cause. watch also knows whether the request is
// getting a connection, for the error of a timeout. net/http calls the
// hooks of its trace from several goroutines.
type watch struct {
	connect, read time.Duration
	cancel        context.CancelCauseFunc

	mu          sync.Mutex
	timer, dial *time.Timer
	connecting  bool
}

// wait starts the read timeout anew.
func (w *watch) wait() {
	if w.read <= 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timer == nil {
		w.timer = time.AfterFunc(w.read, func() { w.cancel(errReadTimeout) })
	} else {
		w.timer.Reset(w.read)
	}
}

// idle stops the read timeout: data came, or none is awaited.
func (w *watch) idle() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timer != nil {
		w.timer.Stop()
	}
}

// stop stops both limits, once the request is over.
func (w *watch) stop() {
	w.idle()
	w.setConnecting(false)
}

// setConnecting starts or stops the connect timeout.
func (w *watch) setConnecting(v bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.connecting = v
	switch {
	case !v && w.dial != nil:
		w.dial.Stop()
	case !v, w.connect <= 0:
	case w.dial == nil:
		w.dial = time.AfterFunc(w.connect, func() { w.cancel(errConnectTimeout) })
	default:
		w.dial.Reset(w.connect)
	}
}

func (w *watch) isConnecting() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.connecting
}

// watched is a response body whose reads w watches.
type watched struct {
	r io.Reader
	w *watch
}

func (b watched) Read(p []byte) (int, error) {
	b.w.wait()
	defer b.w.idle()
	return b.r.Read(p)
}
