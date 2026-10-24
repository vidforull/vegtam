package keeper

import (
	"context"
	"errors"
	"io"
	"regexp"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/vidforull/vegtam/internal/core"
)

// person is a Terminal whose person answers each question with what
// answer makes of it.
type person struct {
	answer func(ctx context.Context, question string) (string, error)

	mu   sync.Mutex
	out  strings.Builder
	last string // the latest Write
}

func (p *person) Write(s string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.out.WriteString(s)
	p.last = s
	return nil
}

func (p *person) ReadLine(ctx context.Context) (string, error) {
	p.mu.Lock()
	q := p.last
	p.mu.Unlock()
	return p.answer(ctx, q)
}

func (p *person) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out.String()
}

var codeRE = regexp.MustCompile(`type ([a-z0-9]{4}) and Enter`)

// codeOf returns the code that question asks for.
func codeOf(question string) string {
	m := codeRE.FindStringSubmatch(question)
	if m == nil {
		return ""
	}
	return m[1]
}

// typing returns an answer that types what typed makes of the code.
func typing(typed func(code string) string) func(context.Context, string) (string, error) {
	return func(_ context.Context, q string) (string, error) { return typed(codeOf(q)), nil }
}

// prepared is a request with two secrets: one bound to where it goes, one
// not.
func prepared() (*core.Prepared, []core.Bound) {
	p := &core.Prepared{
		Method: "POST",
		URL:    core.Text{{Text: "https://api.example/items/"}, {Secret: &core.Secret{Name: "id", Capture: true}}},
		Headers: []core.PreparedHeader{
			{Name: "Authorization", Value: core.Text{{Text: "Bearer "}, {Secret: &core.Secret{Name: "$env API_TOKEN"}}}},
			{Name: "X-Literal", Value: core.Text{{Text: "literal-header-text"}}},
		},
		Body: core.Text{{Text: "literal-body-text"}},
	}
	bs := []core.Bound{
		{Name: "{{id}}", Origin: "https://api.example", Allowed: []string{"https://api.example"}, Capture: true},
		{Name: "{{$env API_TOKEN}}", Origin: "https://api.example", Allowed: []string{"https://other.example"}},
	}
	return p, bs
}

var peer = Peer{UID: 501, PID: 4242, Name: "agent"}

func TestAsk(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  func(code string) string
		want string // the error; "" for yes
	}{
		{"the code", func(c string) string { return c }, ""},
		{"the code with spaces", func(c string) string { return "  " + c + "\t" }, ""},
		{"another code", func(c string) string { return c[1:] + c[:1] + "x" }, "the code typed was not the one asked for"},
		{"yes", func(string) string { return "y" }, "the code typed was not the one asked for"},
		{"Enter", func(string) string { return "" }, "no code was typed"},
		{"spaces", func(string) string { return "   " }, "no code was typed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			term := &person{answer: typing(tc.typ)}
			a := &Asker{Term: term}
			p, bs := prepared()
			err := a.Ask(t.Context(), peer, p, bs)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("error %v", err)
			case tc.want != "" && (err == nil || err.Error() != tc.want):
				t.Fatalf("error %v, want %q", err, tc.want)
			}
			out := term.output()
			if tc.want == "" && !strings.HasSuffix(out, "> "+"  sending it.\n") {
				t.Errorf("output %q does not say it sends", out)
			}
			if tc.want != "" && !strings.HasSuffix(out, "  not sent: "+tc.want+".\n") {
				t.Errorf("output %q does not say it is not sent", out)
			}
		})
	}
}

func TestAskCase(t *testing.T) {
	// A code with a letter, typed in upper case, is another code.
	for {
		term := &person{answer: typing(strings.ToUpper)}
		p, bs := prepared()
		err := (&Asker{Term: term}).Ask(t.Context(), peer, p, bs)
		if code := codeOf(term.output()); strings.ToUpper(code) == code {
			continue // digits alone: try another
		}
		if err == nil || err.Error() != "the code typed was not the one asked for" {
			t.Fatalf("error %v", err)
		}
		return
	}
}

func TestAskQuestion(t *testing.T) {
	term := &person{answer: typing(func(c string) string { return c })}
	p, bs := prepared()
	bs = append(bs,
		core.Bound{Name: "{{sid}}", Allowed: nil, Capture: true},
		core.Bound{Name: "{{key}}", Origin: "https://api.example"},
	)
	if err := (&Asker{Term: term}).Ask(t.Context(), peer, p, bs); err != nil {
		t.Fatal(err)
	}
	out := term.output()
	code := codeOf(out)
	want := "vegtam keeper: a request asked by pid 4242 (agent) uid 501\n" +
		"  POST https://api.example/items/{{id}}\n" +
		"  headers Authorization, X-Literal; a body of 17 bytes\n" +
		"  secret {{id}}, in the URL, goes to https://api.example: bound to it\n" +
		"  secret {{$env API_TOKEN}}, in header Authorization, goes to https://api.example: NOT bound to it; its allowed origins are https://other.example\n" +
		"  secret {{sid}}, in the request, goes where the URL leads, which is known only once it is sent; it was captured from a response whose origin is not known, and goes nowhere\n" +
		"  secret {{key}}, in the request, goes to https://api.example: NOT bound to it; it is bound to no origin\n" +
		"To send it, type " + code + " and Enter; anything else, or no answer in 60s, does not send it.\n" +
		"> "
	if !strings.HasPrefix(out, want) {
		t.Errorf("question:\n%s\nwant:\n%s", out, want)
	}
	// Placeholders alone: p holds no secret value, and of its headers and
	// body the names and the size are shown.
	for _, s := range []string{"literal-header-text", "literal-body-text", "Bearer"} {
		if strings.Contains(out, s) {
			t.Errorf("the question shows %q", s)
		}
	}
}

func TestAskEscapes(t *testing.T) {
	term := &person{answer: typing(func(c string) string { return c })}
	p := &core.Prepared{Method: "GET\x1b[2J", URL: core.Text{{Text: "https://a.example/\x1b]52;c;cHduZWQ=\x07\nType zzzz\t\u202e"}}}
	sly := Peer{UID: 501, PID: 7, Name: "x\x1b[31m"}
	if err := (&Asker{Term: term}).Ask(t.Context(), sly, p, nil); err != nil {
		t.Fatal(err)
	}
	out := term.output()
	if strings.ContainsAny(out, "\x1b\x07\t\u202e") {
		t.Errorf("control characters reach the terminal: %q", out)
	}
	for _, want := range []string{`GET\x1b[2J`, `\x1b]52;c;cHduZWQ=\x07\x0aType zzzz\x09\u202e`, `(x\x1b[31m)`} {
		if !strings.Contains(out, want) {
			t.Errorf("%q is not in %q", want, out)
		}
	}
	if n := strings.Count(out, "\n"); n != 5 {
		t.Errorf("%d lines, want 5: %q", n, out)
	}
}

func TestAskNoAnswer(t *testing.T) {
	waits := func(ctx context.Context, _ string) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}
	synctest.Test(t, func(t *testing.T) {
		term := &person{answer: waits}
		p, bs := prepared()
		start := time.Now()
		err := (&Asker{Term: term}).Ask(t.Context(), peer, p, bs)
		if err == nil || err.Error() != "no answer in 60s" {
			t.Fatalf("error %v", err)
		}
		if d := time.Since(start); d != 60*time.Second {
			t.Errorf("waited %s, want 60s", d)
		}
		if out := term.output(); !strings.HasSuffix(out, "> \n  not sent: no answer in 60s.\n") {
			t.Errorf("output %q", out)
		}
	})
	t.Run("withdrawn", func(t *testing.T) {
		ctx, cancel := context.WithCancelCause(t.Context())
		cancel(errGone)
		err := (&Asker{Term: &person{answer: waits}}).Ask(ctx, peer, &core.Prepared{}, nil)
		if err == nil || !errors.Is(err, errGone) {
			t.Errorf("error %v", err)
		}
	})
	t.Run("end of input", func(t *testing.T) {
		eof := func(context.Context, string) (string, error) { return "", io.EOF }
		err := (&Asker{Term: &person{answer: eof}}).Ask(t.Context(), peer, &core.Prepared{}, nil)
		if err == nil || err.Error() != "no answer: the terminal's input has ended" {
			t.Errorf("error %v", err)
		}
	})
}

func TestAskOneAtATime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		open := 0 // questions put and not answered
		term := &person{answer: func(_ context.Context, q string) (string, error) {
			mu.Lock()
			open++
			if open > 1 {
				t.Error("two questions at once")
			}
			mu.Unlock()
			time.Sleep(time.Second) // the person reads it
			mu.Lock()
			open--
			mu.Unlock()
			return codeOf(q), nil
		}}
		a := &Asker{Term: term}
		var wg sync.WaitGroup
		for range 3 {
			wg.Go(func() {
				p, bs := prepared()
				if err := a.Ask(t.Context(), peer, p, bs); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		out := term.output()
		if n := strings.Count(out, "vegtam keeper:"); n != 3 {
			t.Fatalf("%d questions, want 3", n)
		}
		for i, q := range strings.Split(out, "vegtam keeper:")[1:] {
			if !strings.HasSuffix(q, "  sending it.\n") || strings.Count(q, "> ") != 1 {
				t.Errorf("question %d is not one whole: %q", i, q)
			}
		}
	})
}
