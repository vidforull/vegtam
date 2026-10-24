package keeper

import (
	"os"
	"strings"

	"github.com/vidforull/vegtam/internal/core/env"
)

// Wipe sets every byte of b to zero, as the keeper does with a secret
// value it is done with.
func Wipe(b []byte) { clear(b) }

// Multiplexer reports whether the keeper's terminal is one that a
// multiplexer shares, and which: tmux or screen, as the environment says
// (TMUX, STY, TERM_PROGRAM), or tmux, screen or script as one of the
// keeper's ancestors, its shell's under script too. Another process of
// the user can read such a terminal and type in it, as tmux send-keys
// does: the code of a question, too.
func Multiplexer() (string, bool) {
	switch v, _ := env.Lookup("TERM_PROGRAM"); {
	case env.Has("TMUX"), v == "tmux":
		return "tmux", true
	case env.Has("STY"):
		return "screen", true
	}
	pid := os.Getppid()
	for range maxAncestors {
		if pid <= 1 {
			break
		}
		if name := multiplexer(procName(pid)); name != "" {
			return name, true
		}
		pid = procParent(pid)
	}
	return "", false
}

// maxAncestors is how many of its ancestors the keeper looks at.
const maxAncestors = 32

// multiplexer returns the multiplexer that a process named name is, or "".
func multiplexer(name string) string {
	name = strings.ToLower(name)
	switch {
	case strings.HasPrefix(name, "tmux"): // "tmux: server" as it names itself
		return "tmux"
	case strings.HasPrefix(name, "screen"):
		return "screen"
	case name == "script":
		return "script"
	}
	return ""
}
