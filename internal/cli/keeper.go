package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/net/http/httpproxy"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/env"
	"github.com/vidforull/vegtam/internal/core/exec"
	"github.com/vidforull/vegtam/internal/core/history"
	"github.com/vidforull/vegtam/internal/core/policy"
	"github.com/vidforull/vegtam/internal/core/session"
	"github.com/vidforull/vegtam/internal/core/store"
	"github.com/vidforull/vegtam/internal/keeper"
)

// The keeper's times.
const (
	// keeperWatch is how often the keeper looks at the policy's file.
	keeperWatch = 2 * time.Second
	// keeperAsk is how long the keeper waits for its person's answer.
	keeperAsk = 60 * time.Second
)

func newKeeperCmd(cfg *Config) *cobra.Command {
	var multiplexer bool
	cmd := &cobra.Command{
		Use:   "keeper",
		Short: "Hold your secrets for programs that run vegtam without you",
		Long: `Run the keeper in a terminal of your own: it holds the secrets of your
store (see vegtam secret --help) and sends, for a run without a person,
the requests that need them, so that the program that runs vegtam never
sees a value. The operator's policy sends such runs to it,
"secrets": {"unattended": "keeper"} (see vegtam policy --help).

It asks for the store's password once, then listens at its socket,
$XDG_RUNTIME_DIR/vegtam/keeper.sock, or vegtam's directory under your
cache directory, readable by you alone. For each request with a secret
it shows here what the request is, the secrets it sends and whether each
is bound to where it goes, and which process asks; it sends the request
once you type the code it shows, and refuses it for anything else or no
answer within a minute. With secrets.keeper_asks "unbound" in the policy,
it asks only for a request that would send a secret where it is not
bound. It checks where each secret may go as any run does, with the
origins of the store and of the policy, and sends with the policy's
rules for a run without a person; the program gets the response with
every secret masked and with nothing of a credential that a response
hands out (see vegtam run --help). Values that a request captures stay
here, for the requests of the same run.

It reads the policy once, when it starts: a change to its secrets is
shown here, and applies once the keeper starts again. It reads no
http-client.private.env.json: a program could have put one where it
looks. It keeps other processes of yours from reading its memory where
the system lets it, and refuses to start in a terminal multiplexer, or
under script, where another process can read the screen and type into
it, unless --multiplexer is given. Ctrl-C stops it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runKeeper(cmd.Context(), cfg, multiplexer) },
	}
	cmd.Flags().BoolVar(&multiplexer, "multiplexer", false, "start in a terminal multiplexer or under script, where another process can see and type")
	return cmd
}

// runKeeper runs the keeper until ctx is done, or its terminal's input
// ends.
func runKeeper(ctx context.Context, cfg *Config, multiplexer bool) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if cfg.unattended() {
		return usage("the keeper runs in a terminal of a person's, who answers it: stdin and stdout must be terminals, without --json")
	}
	protect := keeper.Protect
	if cfg.protect != nil {
		protect = cfg.protect
	}
	for _, w := range protect() {
		fmt.Fprintf(cfg.errOut, "vegtam: warning: %s\n", cfg.text(w))
	}
	if name, ok := keeper.Multiplexer(); ok && !multiplexer {
		return core.Errorf(core.KindPolicy, core.Source{}, "this terminal runs in %s, where another process can read what the keeper shows "+
			"and type its codes: start the keeper in a terminal of its own, or pass --multiplexer", name)
	}
	pol, err := cfg.loadPolicy()
	if err != nil {
		return err
	}
	// It sends as a run without a person does: what weakens a check comes
	// from the policy alone.
	defaults := newNetFlags()
	tr, warnings, err := merge(pol, &defaults, true, httpproxy.FromEnvironment(), env.Lookup)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Fprintf(cfg.errOut, "vegtam: warning: %s\n", cfg.text(w))
	}
	st, err := cfg.keeperStore()
	if err != nil {
		return err
	}
	defer st.Close()
	socket, err := policy.KeeperSocket()
	if err != nil {
		return usage("no place for the keeper's socket: %v", err)
	}
	l, err := keeper.Listen(socket)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := l.Close(); cerr != nil {
			fmt.Fprintf(cfg.errOut, "vegtam: %s\n", cfg.text(cerr.Error()))
		}
	}()
	term, stop := keeper.NewTTY(cfg.Stdin, cfg.out)
	defer stop()
	say := func(s string) {
		if werr := term.Write(s + "\n"); werr != nil {
			fmt.Fprintf(cfg.errOut, "vegtam: %s\n", cfg.text(werr.Error()))
		}
	}
	held := fmt.Sprintf("%d secrets", len(st.Names()))
	if len(st.Names()) == 1 {
		held = "1 secret"
	}
	say(fmt.Sprintf("vegtam keeper: listening at %s; %s in the store; it asks %s. Ctrl-C stops it.", socket, held, asksWhen(pol)))
	var wg sync.WaitGroup
	wg.Go(func() { keeper.Watch(ctx, pol.Path, pol, keeperWatch, say) })
	defer wg.Wait()
	k := &keeperRuns{
		cfg: cfg, pol: pol, tr: tr, store: unlocked{st}, history: cfg.history(false),
		asker: &keeper.Asker{Term: term, Timeout: keeperAsk}, say: say, stop: cancel,
	}
	return l.Serve(ctx, k.conn)
}

// keeperStore opens the store with its password, typed at the terminal,
// with the password's memory and the key's locked, so that the system does
// not write them to swap, where it lets them be.
func (c *Config) keeperStore() (*store.Store, error) {
	path, err := store.Path()
	if err != nil {
		return nil, storeError(err)
	}
	if ok, xerr := store.Exists(path); xerr != nil || !ok {
		return nil, usage("no store of secrets at %s: put the secrets the keeper holds there first (see vegtam secret --help)", path)
	}
	pw, err := c.readSecret("password of the store of secrets (" + path + "): ")
	defer keeper.Wipe(pw)
	if err != nil {
		return nil, usage("the password: %v", err)
	}
	locked := keeper.Lock(pw) == nil
	if !locked {
		fmt.Fprintf(c.errOut, "vegtam: warning: the password's memory is not locked: the system may write it to swap\n")
	}
	st, err := store.Open(path, pw)
	if locked {
		if uerr := keeper.Unlock(pw); uerr != nil {
			fmt.Fprintf(c.errOut, "vegtam: warning: %s\n", c.text(uerr.Error()))
		}
	}
	if err != nil {
		return nil, storeError(err)
	}
	if err := st.Lock(keeper.Lock); err != nil {
		fmt.Fprintf(c.errOut, "vegtam: warning: the key's memory is not locked: %s\n", c.text(err.Error()))
	}
	return st, nil
}

// asksWhen says when the keeper asks its person, by the policy.
func asksWhen(pol *policy.Policy) string {
	if pol.Secrets.AsksAlways() {
		return "before each request with a secret"
	}
	return "before a request that would send a secret where it is not bound"
}

// keeperRuns makes the keeper's side of each run that connects to it.
type keeperRuns struct {
	cfg   *Config
	pol   *policy.Policy
	tr    exec.Transport
	store env.Store
	// history is the person's history of runs, as it was when the keeper
	// started: the keeper's entries go there, each with the process it
	// sent for.
	history *history.Log
	asker   *keeper.Asker
	say     func(string)
	stop    func() // once no one can answer: the input of the terminal ended
}

// conn returns the keeper's side of the run of peer: a session of its own,
// with its cookies and captures, made with the first request.
func (k *keeperRuns) conn(peer keeper.Peer) keeper.Conn { return &keeperConn{k: k, peer: peer} }

// keeperConn is the keeper's side of one run.
type keeperConn struct {
	k    *keeperRuns
	peer keeper.Peer
	s    *session.Session
}

func (c *keeperConn) Send(ctx context.Context, o *session.Outbound) (*session.Inbound, error) {
	k := c.k
	if c.s == nil {
		c.s = session.New(session.Options{
			Trust: policy.DefaultStore(), Transport: k.tr, MaxBody: o.MaxBody, UserAgent: "vegtam/" + k.cfg.Version,
			Fail: o.Fail, Secrets: k.pol.Secrets, History: k.history, For: c.peer.String(), Store: k.store, NoPrivate: true,
			Confirm: session.Confirm{Mutations: true},
			Serve: &session.Serve{Always: k.pol.Secrets.AsksAlways(), Ask: func(ctx context.Context, p *core.Prepared, bs []core.Bound) error {
				err := k.asker.Ask(ctx, c.peer, p, bs)
				if errors.Is(err, keeper.ErrInputEnded) {
					k.say("vegtam keeper: the terminal's input ended, so no one can answer: the keeper stops.")
					k.stop()
				}
				return err
			}},
		})
	}
	in := c.s.Relay(ctx, o)
	outcome := "sent"
	if r := in.Result; r.Error != nil {
		outcome = string(r.Error.Kind) + ": " + oneLine(r.Error.Message)
	} else if r.Response != nil {
		outcome = fmt.Sprintf("HTTP %d", r.Response.Status)
	}
	k.say(keeper.Line(fmt.Sprintf("%s: %s %s: %s", c.peer, o.Method, o.URL.Masked(), outcome)))
	return in, nil
}

func (c *keeperConn) Close() {}

// oneLine returns s on one line, cut short.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	return s
}

// unlocked is an open store as the keeper's runs read it.
type unlocked struct{ s *store.Store }

func (u unlocked) Origins() map[string][]string {
	out := map[string][]string{}
	for _, name := range u.s.Names() {
		sec, _ := u.s.Get(name)
		out[name] = sec.Origins
	}
	return out
}

func (u unlocked) Value(name string) (string, error) {
	sec, ok := u.s.Get(name)
	if !ok {
		return "", fmt.Errorf("the keeper's store holds no secret %s", name)
	}
	return sec.Value, nil
}
