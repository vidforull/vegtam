package exec

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vidforull/vegtam/internal/core"
)

// silent starts a TCP server that answers each request with say and then
// says nothing more until the test ends. It returns its address.
func silent(t *testing.T, say string) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	t.Cleanup(func() {
		close(done)
		if err := ln.Close(); err != nil {
			t.Error(err)
		}
		wg.Wait()
	})
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				// Not before the request: net/http drops what comes first.
				if say != "" {
					for r := bufio.NewReader(c); ; {
						if line, err := r.ReadString('\n'); err != nil || line == "\r\n" {
							break
						}
					}
					fmt.Fprint(c, say)
				}
				<-done
				if err := c.Close(); err != nil {
					t.Error(err)
				}
			})
		}
	})
	return ln.Addr().String()
}

// TestTimeoutPhases checks each limit against a server that stops where
// that limit is the one to end the request, and that the error names it.
func TestTimeoutPhases(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl, _ := w.(http.Flusher)
		for i := range 10 {
			if r.URL.Path == "/stops" && i == 1 {
				<-r.Context().Done()
				return
			}
			fmt.Fprint(w, "x")
			fl.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}))
	defer srv.Close()
	hang := func(ctx context.Context, _, _ string, _ syscall.RawConn) error {
		<-ctx.Done()
		return ctx.Err()
	}
	const short, long = 50 * time.Millisecond, 5 * time.Second
	tests := []struct {
		name  string
		url   string
		limit Transport
		dial  bool   // the dialer hangs
		phase string // "" for no error
	}{
		{"dialling", "http://127.0.0.1:9/", Transport{Connect: short, Read: long, Total: long}, true, core.PhaseConnect},
		{"TLS handshake", "https://" + silent(t, ""), Transport{Connect: short, Read: long, Total: long}, false, core.PhaseConnect},
		{"no headers", "http://" + silent(t, ""), Transport{Connect: long, Read: short, Total: long}, false, core.PhaseRead},
		{"half the headers", "http://" + silent(t, "HTTP/1.1 200 OK\r\nX-A: "), Transport{Connect: long, Read: short, Total: long}, false, core.PhaseRead},
		{"the body stops", srv.URL + "/stops", Transport{Connect: long, Read: short, Total: long}, false, core.PhaseRead},
		{"the body trickles", srv.URL + "/trickles", Transport{Connect: long, Read: long, Total: 100 * time.Millisecond}, false, core.PhaseTotal},
		// Each read of it waits 20ms, under the read timeout: the body
		// comes, in 200ms.
		{"the body trickles, no max time", srv.URL + "/trickles", Transport{Connect: long, Read: short}, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(Options{MaxBody: 1 << 20, Transport: tt.limit})
			if tt.dial {
				c.control = hang
			}
			start := time.Now()
			r, _, err := c.Do(t.Context(), prepared(http.MethodGet, lit(tt.url), nil), testSecrets)
			if tt.phase == "" {
				if err != nil || string(r.Body) != "xxxxxxxxxx" {
					t.Errorf("Do = %+v, %v", r, err)
				}
				return
			}
			e, ok := errors.AsType[*core.Error](err)
			if !ok || e.Kind != core.KindTimeout || e.Phase != tt.phase || !strings.Contains(e.Msg, "("+map[string]string{
				core.PhaseConnect: "connect timeout", core.PhaseRead: "read timeout", core.PhaseTotal: "max time",
			}[tt.phase]+")") {
				t.Errorf("Do = %#v, want a timeout in phase %s", err, tt.phase)
			}
			if u := strings.TrimPrefix(strings.TrimPrefix(tt.url, "http://"), "https://"); err != nil && !strings.Contains(err.Error(), u) {
				t.Errorf("the error does not say where: %v", err)
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Errorf("it took %v: another limit ended it", d)
			}
		})
	}
}

func TestSettings(t *testing.T) {
	flags := Transport{Connect: 10 * time.Second, Read: 30 * time.Second, Total: 2 * time.Minute}
	request := func(ds ...core.Directive) *core.Request {
		return &core.Request{Source: core.Source{File: "t.http", Line: 9}, Directives: ds}
	}
	d := func(kind, value string, line int) core.Directive {
		return core.Directive{Kind: kind, Value: value, Line: line}
	}
	tests := []struct {
		name     string
		flags    Transport
		r        *core.Request
		want     Settings
		warnings []string
	}{
		{"the flags", flags, request(), Settings{Connect: 10 * time.Second, Read: 30 * time.Second, Total: 2 * time.Minute}, nil},
		{
			"lowered", flags, request(d(core.ConnectionTimeout, "500ms", 1), d(core.Timeout, "5", 2), d(core.MaxTime, "1 m", 3)),
			Settings{Connect: 500 * time.Millisecond, Read: 5 * time.Second, Total: time.Minute},
			nil,
		},
		{"raised", flags, request(d(core.Timeout, "5 m", 1), d(core.MaxTime, "0", 3)), Settings{Connect: 10 * time.Second, Read: 30 * time.Second, Total: 2 * time.Minute}, []string{
			"t.http:1: @timeout 5 m is more than --read-timeout allows, 30s, which holds",
			"t.http:3: @max-time 0 is more than --max-time allows, 2m, which holds",
		}},
		{"no limit to raise", Transport{}, request(d(core.MaxTime, "3m", 1)), Settings{Total: 3 * time.Minute}, nil},
	}
	for _, tt := range tests {
		got, warnings := New(Options{Transport: tt.flags}).Settings(tt.r)
		var ws []string
		for _, w := range warnings {
			ws = append(ws, w.String())
		}
		if got != tt.want || strings.Join(ws, "\n") != strings.Join(tt.warnings, "\n") {
			t.Errorf("%s: %+v, %q; want %+v, %q", tt.name, got, ws, tt.want, tt.warnings)
		}
	}
}

// TestReadTimeoutRedirect checks that the read timeout is a pause, not a
// sum: the headers of a redirect and its body each come within it, which
// together they do not, and net/http reads that body itself.
func TestReadTimeoutRedirect(t *testing.T) {
	const read, pause = 300 * time.Millisecond, 200 * time.Millisecond
	wait := func(r *http.Request) bool {
		select {
		case <-r.Context().Done():
			return false
		case <-time.After(pause):
			return true
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/moved" {
			fmt.Fprint(w, "here")
			return
		}
		if !wait(r) {
			return
		}
		w.Header().Set("Location", "/here")
		w.WriteHeader(http.StatusFound)
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		if wait(r) {
			fmt.Fprint(w, "moved")
		}
	}))
	defer srv.Close()
	r, _, err := New(Options{MaxBody: 1 << 20, Transport: Transport{Read: read}}).Do(t.Context(), prepared(http.MethodGet, lit(srv.URL+"/moved"), nil), testSecrets)
	if err != nil || string(r.Body) != "here" {
		t.Errorf("Do = %+v, %v", r, err)
	}
}

// TestConnectTimeout checks the limit of getting a connection on its
// own, as for a proxy that never answers CONNECT, which the limits of the
// dialer and of the TLS handshake do not cover.
func TestConnectTimeout(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	w := &watch{connect: 50 * time.Millisecond, read: time.Hour, cancel: cancel}
	defer w.stop()
	w.trace(&hopTrace{t: &tracer{}}).GetConn("proxy.example.test:3128")
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
	}
	if !errors.Is(context.Cause(ctx), errConnectTimeout) || !w.isConnecting() {
		t.Errorf("cause %v, connecting %v", context.Cause(ctx), w.isConnecting())
	}
	// Got in time, the connection ends the limit.
	ctx, cancel = context.WithCancelCause(t.Context())
	defer cancel(nil)
	w = &watch{connect: 50 * time.Millisecond, cancel: cancel}
	tr := w.trace(&hopTrace{t: &tracer{}})
	tr.GetConn("api.example.test:443")
	tr.GotConn(httptrace.GotConnInfo{})
	time.Sleep(100 * time.Millisecond)
	if ctx.Err() != nil {
		t.Errorf("canceled after the connection: %v", context.Cause(ctx))
	}
}
