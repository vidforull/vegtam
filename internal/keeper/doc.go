// Package keeper is the way between a run without a person and the
// keeper, and the keeper's own side of it. The keeper is a process that a
// person runs in their terminal, vegtam keeper: it holds the secret values
// that a run without a person never gets (see session.Keeper), asks its
// person before it sends a request with one, sends it through the same
// core as any run, and gives back the result masked and made sterile.
//
// This package holds the protocol between the two, JSON lines over a unix
// socket (see Version); the client that a run dials (Dial, NewLazy); the
// keeper's listener (Listen), which tells it which process connects
// (Peer); the question it puts to its person (Asker); the protections it
// takes for itself (Protect); and its watch on the policy file (Watch).
package keeper
