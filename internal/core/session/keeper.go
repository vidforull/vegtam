package session

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/assert"
	"github.com/vidforull/vegtam/internal/core/env"
	"github.com/vidforull/vegtam/internal/core/output"
)

// Keeper sends requests for a run without a person, which holds no secret
// value (see env.Options.Held). The keeper is a process of the person's:
// it holds the values, puts them in, checks where each may go, asks its
// person, sends the request, and gives back its result with every secret
// masked and the output made sterile (see output.Result.Redact). Once one
// request of a run needs it, every request of the run goes through it, so
// that the cookies its responses set and the secret values its captures
// take, which stay with it, go with the requests after them.
type Keeper interface {
	// Send sends o and returns what the keeper gives back. The error is
	// the keeper's own: it cannot be reached, speaks another protocol, or
	// refused the request; the result has the request's own.
	Send(ctx context.Context, o *Outbound) (*Inbound, error)
}

// Outbound is a request that a run sends through a keeper: as written,
// for its directives and its place in its file, and as the run resolved
// it, its secrets named and not resolved.
type Outbound struct {
	Ref     string                `json:"ref"`
	Env     string                `json:"env,omitempty"`
	Request *core.Request         `json:"request"`
	Method  string                `json:"method"`
	URL     core.Text             `json:"url"`
	Headers []core.PreparedHeader `json:"headers"`
	Body    core.Text             `json:"body"`
	MaxBody int64                 `json:"max_body"`
	Fail    bool                  `json:"fail,omitempty"`
	// Captured are the secret values that the run's own captures took and
	// the request sends: it took them from responses it got before the
	// keeper sent any of its requests, and they are its own to give.
	Captured []Held `json:"captured,omitempty"`
}

// Inbound is what a keeper gives back for a request: its result, masked
// and sterile, and what its captures took.
type Inbound struct {
	Result   *output.Result `json:"result"`
	Captured []Held         `json:"captured,omitempty"`
}

// Held is a value an @capture took in a keeper: a plain one with its
// value, a secret one by its name alone, which the keeper keeps.
type Held struct {
	Name    string   `json:"name"`
	Secret  bool     `json:"secret,omitempty"`
	Value   string   `json:"value,omitempty"`   // of a plain one
	Origins []string `json:"origins,omitempty"` // of the response it came from
}

// Serve configures the session of a keeper, which sends the requests that
// runs without a person relay to it (see Relay), and asks its person.
type Serve struct {
	// Ask asks the keeper's person whether to send the request, which
	// holds the secrets of bs, each with where the request goes and where
	// it may go, and whose {{$cmd NAME}} run the commands of cmds once
	// the person says yes; nil means yes. It is asked for every request
	// with a secret with Always, and otherwise for one whose secrets are
	// not all bound to where it goes, or that runs a command: a command
	// runs as the person.
	Ask    func(ctx context.Context, p *core.Prepared, bs []core.Bound, cmds []env.NamedCommand) error
	Always bool
}

// held reports whether the session is a run without a person, which holds
// no secret value.
func (s *Session) held() bool { return !s.opts.Confirm.Person && s.opts.Serve == nil }

// heldSecret returns the first secret of p that a run without a person
// would need the value of, or nil. A variable that an @capture took is one
// if the value is a secret; one that none has taken yet, if the latest
// @capture of it does not say plain.
func (s *Session) heldSecret(j *Job, p *core.Prepared) *core.Bound {
	texts := p.Texts()
	for _, t := range texts {
		for _, seg := range t {
			sec := seg.Secret
			if sec == nil {
				continue
			}
			if _, secret, _, ok := s.loader.Captured(sec.Name); sec.Capture && (ok && !secret || !ok && s.plain[sec.Name]) {
				continue
			}
			origins, _, _ := p.Origins(s.src(j))
			name := "{{" + sec.Name + "}}"
			for _, b := range core.Bindings(s.src(j), first(origins), texts...) {
				if b.Name == name {
					return &b
				}
			}
		}
	}
	return nil
}

// denied returns the error of the request of j, which needs the value of
// the secret b in a run without a person: such a run has none, and the
// operator's policy sends it through no keeper. It names the command a
// person at a terminal runs to send it.
func (s *Session) denied(j *Job, b *core.Bound) *core.Error {
	cmd := "vegtam run " + core.ShellQuote(j.Ref)
	if s.opts.Env != "" {
		cmd += " -e " + core.ShellQuote(s.opts.Env)
	}
	if _, ok := j.Request.Note(); ok {
		cmd += " --confirm=" + core.ShellQuote(j.Ref)
	}
	e := core.Errorf(core.KindPolicy, j.Request.Source,
		`secret %s is not available to a run without a person (policy: secrets.unattended is "deny"); ask the operator to run it: %s`, b.Name, cmd)
	e.Secret, e.PersonCommand = b, cmd
	return e
}

// relayed sends the request of j through the keeper, and sets res from
// what it gives back: the run takes the plain values its captures took,
// and of the secret ones the names alone.
func (s *Session) relayed(ctx context.Context, j *Job, res *output.Result) error {
	p, err := s.loader.Fill(j.Prepared)
	if err != nil {
		return err
	}
	res.Request = output.Sent(p, s.Masker())
	o := &Outbound{
		Ref: j.Ref, Env: s.opts.Env, Request: j.Request, Method: p.Method, URL: p.URL, Headers: p.Headers, Body: p.Body,
		MaxBody: s.opts.MaxBody, Fail: s.opts.Fail,
	}
	for _, t := range p.Texts() {
		for _, seg := range t {
			if sec := seg.Secret; sec != nil && sec.Capture && !slices.ContainsFunc(o.Captured, func(h Held) bool { return h.Name == sec.Name }) {
				if v, _, origins, ok := s.loader.Captured(sec.Name); ok && v != "" {
					o.Captured = append(o.Captured, Held{Name: sec.Name, Secret: true, Value: v, Origins: origins})
				}
			}
		}
	}
	j.kept = true
	in, err := s.opts.Keeper.Send(ctx, o)
	if e, ok := errors.AsType[*core.Error](err); ok {
		return e
	} else if err != nil {
		return core.Errorf(core.KindPolicy, j.Request.Source, "the keeper: %v", err)
	}
	if in == nil || in.Result == nil {
		return core.Errorf(core.KindPolicy, j.Request.Source, "the keeper gave back no result")
	}
	for _, h := range in.Captured {
		if !slices.Contains(j.captures, h.Name) {
			continue // the keeper's to say only of what the request captures
		}
		if h.Secret {
			s.loader.Hold(h.Name, h.Origins...)
		} else {
			s.loader.Capture(h.Name, h.Value, false, h.Origins...)
		}
	}
	r, m := in.Result, s.Masker()
	res.Response, res.Timing, res.RemoteAddr, res.ResolvedBy, res.Proxy, res.TLS = r.Response, r.Timing, r.RemoteAddr, r.ResolvedBy, r.Proxy, r.TLS
	res.Redirects, res.Cookies, res.Asserts, res.Captures, res.Redacted = r.Redirects, r.Cookies, r.Asserts, r.Captures, r.Redacted
	res.Warnings = append(res.Warnings, r.Warnings...)
	res.Error = r.Error
	if res.Error != nil {
		res.Error.Message = m.Mask(res.Error.Message)
	}
	return nil
}

// Relay sends o, a request that a run without a person relays to the
// keeper, as Run sends one of the session's own: with the secret values
// the session holds, and those the run gives with it, to where they are
// bound, once the keeper's person says yes (see Serve). Its captures take
// their values here: the secret ones stay, and the run gets their names.
// The session must have Serve.
func (s *Session) Relay(ctx context.Context, o *Outbound) *Inbound {
	req := o.Request
	if req == nil {
		req = &core.Request{Method: o.Method, URL: o.URL.Masked()}
	}
	j := &Job{Ref: o.Ref, Request: req}
	j.settings, j.Warnings = s.client.Settings(req)
	j.vars, j.Err = s.loader.For(req.Source.File)
	j.Prepared = &core.Prepared{Request: req, Method: o.Method, URL: o.URL, Headers: o.Headers, Body: o.Body}
	if j.Err == nil { // checked now, run once its person says yes (see askKeeper)
		_, j.Err = j.vars.Commands(ctx, j.Prepared, false)
	}
	for _, h := range o.Captured {
		s.Declare(h.Name)
		s.loader.Capture(h.Name, h.Value, true, h.Origins...)
	}
	_, captures, _ := assert.Directives(req)
	for _, c := range captures {
		if c.Secret {
			s.Declare(c.Name)
		} else {
			s.DeclarePlain(c.Name)
		}
		j.captures = append(j.captures, c.Name)
	}
	res := s.Run(ctx, j)
	in := &Inbound{Result: res}
	for _, c := range res.Captures {
		v, secret, origins, ok := s.loader.Captured(c.Name)
		switch {
		case !ok:
		case secret:
			in.Captured = append(in.Captured, Held{Name: c.Name, Secret: true, Origins: origins})
		default:
			in.Captured = append(in.Captured, Held{Name: c.Name, Value: v, Origins: origins})
		}
	}
	return in
}

// askKeeper asks the keeper's person, through Serve, whether to send p, the
// request of j, which goes to origins, as far as they are known, would
// send the secrets of refused where they are not bound, and runs the
// commands of cmds. A request without a secret is not asked about, nor,
// unless Serve.Always, one whose secrets are all bound to where it goes
// and that runs no command. It returns vars with origins granted to every
// secret once the person says yes; the error of kind policy otherwise.
func (s *Session) askKeeper(ctx context.Context, j *Job, p *core.Prepared, vars core.Secrets, origins []string, refused []core.Bound,
	cmds []env.NamedCommand,
) (core.Secrets, error) {
	texts := p.Texts()
	bs := core.Bindings(vars, first(origins), texts...)
	for _, o := range origins[min(1, len(origins)):] {
		bs = append(bs, core.Bindings(vars, o, texts...)...)
	}
	if len(cmds) == 0 && (len(bs) == 0 || !s.opts.Serve.Always && len(origins) > 0 && len(refused) == 0) {
		return vars, nil
	}
	if err := s.opts.Serve.Ask(ctx, p, masked(bs, s.Masker()), cmds); err != nil {
		what := p.Method + " " + p.URL.Masked() + " is not sent"
		if len(refused) > 0 {
			e := core.SecretError(core.KindPolicy, j.Request.Source, what, refused)
			e.Msg += fmt.Sprintf("; and the keeper's operator did not confirm it: %v", err)
			return nil, e
		}
		return nil, core.Errorf(core.KindPolicy, j.Request.Source, "%s: the keeper's operator did not confirm it: %v", what, err)
	}
	for _, o := range origins {
		vars = core.Grant(vars, o)
	}
	return vars, nil
}

// masked returns bs with every secret value in their origins hidden by m,
// as a host that a secret gives would show it to the keeper's person.
func masked(bs []core.Bound, m *core.Masker) []core.Bound {
	out := slices.Clone(bs)
	for i, b := range out {
		out[i].Origin = m.Mask(b.Origin)
		out[i].Allowed = nil
		for _, o := range b.Allowed {
			out[i].Allowed = append(out[i].Allowed, m.Mask(o))
		}
	}
	return out
}
