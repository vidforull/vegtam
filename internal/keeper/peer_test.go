package keeper

import "testing"

func TestPeerString(t *testing.T) {
	for _, tc := range []struct {
		p    Peer
		want string
	}{
		{Peer{UID: 501, PID: 4242, Name: "agent"}, "pid 4242 (agent) uid 501"},
		{Peer{UID: 0, PID: 1}, "pid 1 uid 0"},
		{Peer{UID: -1, PID: -1}, "pid unknown uid unknown"},
	} {
		if got := tc.p.String(); got != tc.want {
			t.Errorf("%+v: %q, want %q", tc.p, got, tc.want)
		}
	}
}
