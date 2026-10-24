package cli

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/session"
)

// testKeeper is the keeper of the tests' runs without a person, when their
// policy says secrets.unattended "keeper": a session of the test's own
// process that holds the values, as the person's keeper would, and sends
// with the options of the run. Its person is asked only of a request that
// would send a secret where it is not bound, and says no. What goes
// between it and the run goes through JSON, as on the keeper's socket.
func testKeeper(opts session.Options) session.Keeper {
	opts.History, opts.Keeper = nil, nil
	opts.Confirm = session.Confirm{Mutations: true}
	opts.Serve = &session.Serve{Ask: func(context.Context, *core.Prepared, []core.Bound) error { return errDeclined }}
	return &relay{session.New(opts)}
}

// errDeclined is the answer of the test keeper's person.
var errDeclined = errors.New("declined")

// relay is a keeper in the test's process.
type relay struct{ s *session.Session }

func (r *relay) Send(ctx context.Context, o *session.Outbound) (*session.Inbound, error) {
	b, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}
	var got session.Outbound
	if uerr := json.Unmarshal(b, &got); uerr != nil {
		return nil, uerr
	}
	if b, err = json.Marshal(r.s.Relay(ctx, &got)); err != nil {
		return nil, err
	}
	var in session.Inbound
	return &in, json.Unmarshal(b, &in)
}
